#!/usr/bin/env python3

import argparse
import base64
import functools
import json
import logging
import os
import uuid
from pathlib import Path
from typing import Optional

import asn1tools
import asn1tools.codecs.ber
import asn1tools.codecs.der
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, dh
from cryptography.hazmat.primitives.serialization import Encoding, ParameterFormat, PublicFormat
from klein import Klein
from twisted.web.iweb import IRequest

from osmocom.utils import b2h

import pySim.esim.rsp as rsp
from pySim.esim import saip
from pySim.esim.es2p import Es2pApiClient
from pySim.esim.zk_utils import (
    ecdsa_der_to_tr03111,
    extract_pcert_from_bf,
    hash_fn,
    serialize_proof,
)


DATA_DIR = './smdpp-data'
DEFAULT_MNO_PORT = 4443
FIXED_MNO_PRIVATE_SCALAR = int('1f1e1d1c1b1a19181716151413121110ffeeddccbbaa99887766554433221100', 16)
FIXED_LEA_PRIVATE_SCALAR = int('0a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526272829', 16)
FIXED_MNOID = b'MNO_id'
FIXED_EXPIRY = b'4102444800'
FIXED_ZK_MATCHING_ID = 'TS48V1-A-UNIQUE'
FIXED_ZK_UPP = FIXED_ZK_MATCHING_ID + '.der'
# The SMDP+ TLS leaf cert is signed by the test "Certificate Issuer" (CI),
# so trusting that CI's cert is what lets `requests` verify the chain.
DEFAULT_SMDP_CACERT = os.path.join(DATA_DIR, 'certs', 'CertificateIssuer', 'CERT_CI_ECDSA_NIST.pem')


def load_zk_profile_iccid(data_dir: str) -> str:
    """Read the ICCID out of the fixed test profile UPP so the MNO can hand
    it to the SM-DP+ as the ES2+ DownloadOrder iccid (the schema rejects
    None / placeholder values).  Returns the decimal-only form with the
    BCD F padding stripped."""
    path = os.path.join(data_dir, 'upp', FIXED_ZK_UPP)
    with open(path, 'rb') as f:
        pes = saip.ProfileElementSequence.from_der(f.read())
    raw = b2h(pes.get_pe_for_type('header').decoded['iccid'])
    return raw.rstrip('fF')


logger = logging.getLogger(__name__)


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode('ascii')


def unb64(data: str) -> bytes:
    return base64.b64decode(data.encode('ascii'))


def public_point(private_key) -> bytes:
    return private_key.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)


class MnoServer:
    app = Klein()

    def __init__(self, smdp_url: str, data_dir: str, smdp_cacert: Optional[str] = None):
        self.smdp_url = smdp_url
        self.data_dir = data_dir
        self.requests = {}
        self.sk_mno = ec.derive_private_key(FIXED_MNO_PRIVATE_SCALAR, ec.SECP256R1())
        self.pk_mno = self.sk_mno.public_key()
        self.pk_mno_point = public_point(self.sk_mno)
        self.sk_lea = ec.derive_private_key(FIXED_LEA_PRIVATE_SCALAR, ec.SECP256R1())
        self.pk_lea_point = public_point(self.sk_lea)
        # The SMDP+ uses a self-signed test cert; tell the underlying
        # `requests.Session` to trust it (or pass an empty string / None
        # to disable verification entirely).
        self.es2p = Es2pApiClient(url_prefix=smdp_url, func_req_id='mno-test',
                                  server_cert_verify=smdp_cacert)
        if smdp_cacert is False or smdp_cacert == '':
            # Allow callers to explicitly disable verification by passing
            # an empty string; requests treats `verify=False` as off.
            self.es2p.session.verify = False
        self.zk_profile_iccid = load_zk_profile_iccid(data_dir)
        self.zk_matching_id = FIXED_ZK_MATCHING_ID
        logger.info('MNO bound to fixed ZK profile %s (iccid=%s); SMDP+ cacert=%s',
                    self.zk_matching_id, self.zk_profile_iccid, smdp_cacert)

    @staticmethod
    def json_endpoint(func):
        @functools.wraps(func)
        def wrapper(self, request: IRequest):
            request.setHeader('Content-Type', 'application/json;charset=UTF-8')
            raw = request.content.read()
            content = json.loads(raw.decode('utf-8') or '{}')
            try:
                response = json.dumps(func(self, request, content))
                logger.info('%s -> %s', request.path.decode('ascii', errors='replace'), response)
                return response
            except ValueError as exc:
                request.setResponseCode(400)
                response = json.dumps({'error': str(exc)})
                logger.warning('%s -> %s', request.path.decode('ascii', errors='replace'), response)
                return response
        return wrapper

    @app.route('/health', methods=['GET'])
    def health(self, request: IRequest):
        request.setHeader('Content-Type', 'application/json;charset=UTF-8')
        return json.dumps({'ok': True})

    @app.route('/zk-esim/v1/getMNOChallenge', methods=['POST'])
    @json_endpoint
    def get_mno_challenge(self, request: IRequest, content: dict) -> dict:
        request_id = uuid.uuid4().hex
        challenge = os.urandom(16)
        self.requests[request_id] = {'mnoChallenge': challenge}
        return {
            'requestId': request_id,
            'mnoChallenge': b64(challenge),
            'expiry': FIXED_EXPIRY.decode('ascii')
        }

    @app.route('/zk-esim/v1/zkRequest', methods=['POST'])
    @json_endpoint
    def zk_request(self, request: IRequest, content: dict) -> dict:
        request_id = content['requestId']
        state = self.requests.get(request_id)
        if state is None:
            raise ValueError('unknown requestId')

        zk_resp_bin = unb64(content['zkProfileResponse_b64'])
        zk_resp = rsp.asn1.decode('ZKProfileResponse', zk_resp_bin)
        if zk_resp[0] != 'zkProfileResponseOk':
            raise ValueError('ZKProfileResponse returned an error')

        ok = zk_resp[1]
        stmt = ok['zkStatement']
        # h_cert MUST be computed over the exact on-wire DER bytes of the
        # eUICC cert so the SMDP+ verify side (which extracts from BF38 the
        # same way) produces an identical hash.  asn1tools encode/decode is
        # not guaranteed to round-trip byte-for-byte for a hand-rolled cert.
        pcert_der = extract_pcert_from_bf(zk_resp_bin, 0xbf42)
        proof = ok['zkProof']

        if stmt['mnoChallenge'] != state['mnoChallenge']:
            raise ValueError('challenge mismatch')
        if stmt['pkMno'] != self.pk_mno_point:
            raise ValueError('pkMno mismatch')
        if stmt['pkLea'] != self.pk_lea_point:
            raise ValueError('pkLea mismatch')

        cert = x509.load_der_x509_certificate(pcert_der)
        pk_u = cert.public_key()
        zk_statement_der = rsp.asn1.encode('ZKStatement', stmt)
        try:
            pk_u.verify(proof, zk_statement_der, ec.ECDSA(hashes.SHA256()))
        except InvalidSignature:
            raise ValueError('invalid ZKProfile proof')

        eid = self._eid_from_cert(cert)
        pid = stmt['pid']
        h_pid = hash_fn(pid)
        h_cert = hash_fn(pcert_der)

        l_auth = rsp.MerkleAccumulator()
        h_pid_hex = h_pid.hex()
        l_auth.add(h_pid_hex)
        root_auth = bytes(l_auth.get_root())
        pi_inc = serialize_proof(l_auth.generateProof(h_pid_hex))

        # ICCID and matchingId are pinned to the fixed test profile
        # smdpp-data/upp/TS48V1-A-UNIQUE.der so the SMDP+ side can serve
        # the same UPP every time without inventing identifiers.
        dl_order = self.es2p.call_downloadOrder({
            'eid': eid,
            'iccid': self.zk_profile_iccid,
            'profileType': 'ZK_TEST'
        })
        iccid = dl_order['iccid']
        conf = self.es2p.call_confirmOrder({
            'iccid': iccid,
            'eid': eid,
            'matchingId': content.get('matchingId') or self.zk_matching_id,
            'releaseFlag': True
        })

        sig_cred = self._sign_raw(h_pid + h_cert + FIXED_MNOID)
        sig_root = self._sign_raw(root_auth)
        auth_token = self._sign_raw(h_pid + h_cert + FIXED_MNOID + FIXED_EXPIRY)

        set_req = rsp.asn1.encode('SetEligibilityDataRequest', {
            'eligibilityData': {
                'hpid': h_pid,
                'sigCred': sig_cred,
                'authToken': auth_token,
                'accRoot': root_auth,
                'sigRoot': sig_root,
                'accProof': pi_inc,
            }
        })

        state.update({'encEid': stmt['encEid'], 'iccid': iccid})
        return {
            'setEligibilityDataRequest': b64(set_req),
            'iccid': iccid,
            'matchingId': conf['matchingId'],
            'smdpAddress': conf.get('smdpAddress') or self._smdp_host()
        }

    @app.route('/zk-esim/v1/ack', methods=['POST'])
    @json_endpoint
    def ack(self, request: IRequest, content: dict) -> dict:
        request_id = content.get('requestId')
        if request_id in self.requests:
            self.requests[request_id]['ack'] = bool(content.get('ok'))
        return {'ok': True}

    def _sign_raw(self, data: bytes) -> bytes:
        return ecdsa_der_to_tr03111(self.sk_mno.sign(data, ec.ECDSA(hashes.SHA256())))

    def _eid_from_cert(self, cert: x509.Certificate) -> str:
        for attr in cert.subject:
            if attr.oid.dotted_string == '2.5.4.5':
                return attr.value
        return '89049032000000000000012345678901'

    def _smdp_host(self) -> str:
        return self.smdp_url.split('://', 1)[-1].split(':', 1)[0]


def main():
    logging.basicConfig(level=logging.INFO)
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', default='localhost')
    parser.add_argument('--port', type=int, default=DEFAULT_MNO_PORT)
    parser.add_argument('--smdp-url', default='https://testsmdpplus1.example.com:8000')
    parser.add_argument('--data-dir', default=DATA_DIR)
    parser.add_argument('--smdp-cacert', default=DEFAULT_SMDP_CACERT,
                        help='PEM the MNO trusts when calling the SMDP+ ES2+ endpoints '
                             '(use --smdp-no-verify to disable verification)')
    parser.add_argument('--smdp-no-verify', action='store_true', default=False,
                        help='disable TLS verification on outbound SMDP+ ES2+ calls')
    parser.add_argument('--nossl', action='store_true', default=False)
    args = parser.parse_args()

    smdp_cacert = '' if args.smdp_no_verify else args.smdp_cacert
    server = MnoServer(args.smdp_url, args.data_dir, smdp_cacert=smdp_cacert)
    if args.nossl:
        server.app.run(args.host, args.port)
        return

    cert_dir = Path(args.data_dir) / 'certs' / 'MNO'
    cert_pem = cert_dir / 'CERT_MNO_TLS_NIST.pem'
    key_pem = cert_dir / 'SK_MNO_TLS_NIST.pem'
    dhparam = Path(args.data_dir) / 'certs' / 'dhparam2048.pem'
    if not dhparam.exists():
        parameters = dh.generate_parameters(generator=2, key_size=2048)
        dhparam.write_bytes(parameters.parameter_bytes(Encoding.PEM, ParameterFormat.PKCS3))
    server.app.run(endpoint_description=f'ssl:{args.port}:interface={args.host}:privateKey={key_pem}:certKey={cert_pem}:dhParameters={dhparam}')


if __name__ == '__main__':
    main()
