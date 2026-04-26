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
    parse_zk_profile_response,
    schnorr_verify_p256,
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
P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
FIXED_DEVICE_W = bytes([
    0x04, 0x1D, 0xD0, 0x96, 0xDE, 0x35, 0x6A, 0x2F,
    0x4F, 0xEC, 0xC2, 0x41, 0x1F, 0x0C, 0xD0, 0x60,
    0x37, 0x53, 0xED, 0x27, 0x2E, 0x41, 0xCC, 0x2A,
    0xDD, 0x4A, 0x45, 0x71, 0x35, 0x28, 0xC2, 0x50,
    0xFE, 0xFF, 0x72, 0x4F, 0x2D, 0xAA, 0xC5, 0x70,
    0xCE, 0x7F, 0x71, 0xE7, 0x51, 0x01, 0x46, 0x8D,
    0xBC, 0xD5, 0xAE, 0xD6, 0xBB, 0xB8, 0xA3, 0xAC,
    0x3C, 0x1C, 0x36, 0xEE, 0x6D, 0xEA, 0xAF, 0x4D,
    0xC1,
])
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


def get_field(content: dict, *names: str) -> str:
    for name in names:
        value = content.get(name)
        if value is not None:
            return value
    raise ValueError('missing ' + '/'.join(names))


class MnoServer:
    app = Klein()

    def __init__(self, smdp_url: str, data_dir: str, smdp_cacert: Optional[str] = None):
        self.smdp_url = smdp_url
        self.data_dir = data_dir
        self.requests = {}
        self.phase0_sessions = {}
        self.l_auth = rsp.MerkleAccumulator()
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

    @app.route('/zk-esim/v1/registerChallenge', methods=['POST'])
    @json_endpoint
    def register_challenge(self, request: IRequest, content: dict) -> dict:
        r_mno = int.from_bytes(os.urandom(32), 'big') % P256_ORDER
        if r_mno == 0:
            r_mno = 1
        mno_nonce_commitment = ec.derive_private_key(r_mno, ec.SECP256R1()).public_key().public_bytes(
            Encoding.X962, PublicFormat.UncompressedPoint)
        request_id = uuid.uuid4().hex
        self.phase0_sessions[request_id] = {'r_mno': r_mno, 'complete': False}
        commitment_b64 = b64(mno_nonce_commitment)
        return {
            'requestId': request_id,
            'mnoNonceCommitment': commitment_b64,
            # Compatibility alias for older workflow prototypes.
            'rMno': commitment_b64,
        }

    @app.route('/zk-esim/v1/registerCredential', methods=['POST'])
    @json_endpoint
    def register_credential(self, request: IRequest, content: dict) -> dict:
        request_id = content.get('requestId')
        if not request_id:
            raise ValueError('missing requestId')
        state = self.phase0_sessions.get(request_id)
        if state is None:
            raise ValueError('unknown Phase 0 requestId')
        if state.get('complete'):
            raise ValueError('Phase 0 requestId already consumed')

        blinded_challenge = unb64(get_field(content, 'blindedEligibilityChallenge', 'e'))
        device_auth_signature = unb64(get_field(content, 'deviceAuthSignature', 'piAuth'))
        if len(blinded_challenge) != 32:
            raise ValueError('blindedEligibilityChallenge must be 32 bytes')

        pk_b = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), FIXED_DEVICE_W)
        try:
            pk_b.verify(device_auth_signature, blinded_challenge, ec.ECDSA(hashes.SHA256()))
        except InvalidSignature:
            raise ValueError('deviceAuthSignature verification failed')

        e_int = int.from_bytes(blinded_challenge, 'big')
        sk_mno_int = self.sk_mno.private_numbers().private_value
        s_int = (state['r_mno'] - e_int * sk_mno_int) % P256_ORDER
        partial_sig = s_int.to_bytes(32, 'big')
        state['complete'] = True
        partial_sig_b64 = b64(partial_sig)
        return {
            'mnoPartialSignature': partial_sig_b64,
            # Compatibility alias for older workflow prototypes.
            's': partial_sig_b64,
        }

    @app.route('/zk-esim/v1/zkRequest', methods=['POST'])
    @json_endpoint
    def zk_request(self, request: IRequest, content: dict) -> dict:
        request_id = content['requestId']
        state = self.requests.get(request_id)
        if state is None:
            raise ValueError('unknown requestId')

        zk_resp_bin = unb64(get_field(content, 'zkProfileResponse', 'zkProfileResponse_b64'))
        stmt = parse_zk_profile_response(zk_resp_bin)
        # h_cert MUST be computed over the exact on-wire DER bytes of the
        # eUICC cert so the SMDP+ verify side (which extracts from BF38 the
        # same way) produces an identical hash.  asn1tools encode/decode is
        # not guaranteed to round-trip byte-for-byte for a hand-rolled cert.
        pcert_der = extract_pcert_from_bf(zk_resp_bin, 0xbf42)
        proof = stmt['requestProof']

        if stmt['mnoChallenge'] != state['mnoChallenge']:
            raise ValueError('challenge mismatch')
        if stmt['mnoPublicKey'] != self.pk_mno_point:
            raise ValueError('pkMno mismatch')
        if stmt['leaPublicKey'] != self.pk_lea_point:
            raise ValueError('pkLea mismatch')

        cert = x509.load_der_x509_certificate(pcert_der)
        pk_u_bytes = cert.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
        if pk_u_bytes != stmt['userPublicKey']:
            raise ValueError('userPublicKey mismatch with PCert_U')

        binding_oid = x509.ObjectIdentifier('2.23.146.1.2.1.8')
        try:
            cert_hash = cert.extensions.get_extension_for_oid(binding_oid).value.value
        except x509.ExtensionNotFound:
            raise ValueError('PCert_U missing credentialBindingHash extension')
        if cert_hash != stmt['credentialBindingHash']:
            raise ValueError('credentialBindingHash mismatch with PCert_U')

        if not schnorr_verify_p256(stmt['userPublicKey'], stmt['statementRaw'], proof):
            raise ValueError('invalid ZKProfile proof')

        eid = self._eid_from_cert(cert)
        pid = stmt['pseudonymId']
        h_pid = hash_fn(pid)
        h_cert = hash_fn(pcert_der)

        h_pid_hex = h_pid.hex()
        if h_pid_hex in self.l_auth.leaves:
            raise ValueError('hashedPseudonym replay')
        self.l_auth.add(h_pid_hex)
        root_auth = bytes(self.l_auth.get_root())
        pi_inc = serialize_proof(self.l_auth.generateProof(h_pid_hex))

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
                'hashedPseudonym': h_pid,
                'credentialSignature': sig_cred,
                'authorizationToken': auth_token,
                'authorizationRoot': root_auth,
                'rootSignature': sig_root,
                'inclusionProof': pi_inc,
            }
        })

        state.update({'encryptedEid': stmt['encryptedEid'], 'iccid': iccid})
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
