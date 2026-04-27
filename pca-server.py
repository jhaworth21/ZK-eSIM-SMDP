#!/usr/bin/env python3

import argparse
import base64
import functools
import json
import logging
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh, ec
from cryptography.hazmat.primitives.serialization import Encoding, ParameterFormat
from klein import Klein
from twisted.web.iweb import IRequest

from pySim.esim.zk_utils import _build_pcert_u, _build_std_cert_u


DATA_DIR = './smdpp-data'
DEFAULT_PCA_PORT = 5443
FIXED_PCA_PRIVATE_SCALAR = int('0102030405060708090a0b0c0d0e0f1011121314151617181920212223242526', 16)
FIXED_TEST_EID = b'89049032000000000000123456789012'

logger = logging.getLogger(__name__)


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode('ascii')


def unb64(data: str) -> bytes:
    return base64.b64decode(data.encode('ascii'))


def get_field(content: dict, *names: str) -> str:
    for name in names:
        value = content.get(name)
        if value is not None:
            return value
    raise ValueError('missing ' + '/'.join(names))


class PcaServer:
    app = Klein()

    def __init__(self):
        self.sk_pca = ec.derive_private_key(FIXED_PCA_PRIVATE_SCALAR, ec.SECP256R1())

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

    @app.route('/zk-esim/v1/certInitRequest', methods=['POST'])
    @json_endpoint
    def cert_init_request(self, request: IRequest, content: dict) -> dict:
        user_public_key = unb64(get_field(content, 'userPublicKey', 'pkU'))
        binding_signature = unb64(get_field(content, 'bindingSignature', 'piBind'))
        credential_binding_hash = unb64(get_field(content, 'credentialBindingHash', 'hSigmaEid'))

        if len(user_public_key) != 65 or user_public_key[0] != 0x04:
            raise ValueError('userPublicKey must be a 65-byte uncompressed P-256 point')
        if len(credential_binding_hash) != 32:
            raise ValueError('credentialBindingHash must be 32 bytes')

        pk_u = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), user_public_key)
        eid_bin = bytes.fromhex(FIXED_TEST_EID.decode('ascii'))[:16]
        bind_input = user_public_key + eid_bin
        try:
            pk_u.verify(binding_signature, bind_input, ec.ECDSA(hashes.SHA256()))
        except InvalidSignature:
            raise ValueError('bindingSignature verification failed')

        pcert_u = _build_pcert_u(
            user_public_key,
            self.sk_pca,
            FIXED_TEST_EID.decode('ascii'),
            credential_binding_hash,
        )
        cert_b64 = b64(pcert_u)
        return {
            'pseudonymCertificate': cert_b64,
            # Compatibility alias for the current shell/Python prototypes.
            'pCertU': cert_b64,
        }

    @app.route('/zk-esim/v1/certInitRequestStd', methods=['POST'])
    @json_endpoint
    def cert_init_request_std(self, request: IRequest, content: dict) -> dict:
        """Standard ECDSA cert issuance — no ZK proof, used only for timing comparison."""
        user_public_key = unb64(get_field(content, 'userPublicKey'))
        binding_signature = unb64(get_field(content, 'bindingSignature'))

        if len(user_public_key) != 65 or user_public_key[0] != 0x04:
            raise ValueError('userPublicKey must be a 65-byte uncompressed P-256 point')

        pk_u = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), user_public_key)
        eid_bin = bytes.fromhex(FIXED_TEST_EID.decode('ascii'))[:16]
        bind_input = user_public_key + eid_bin
        try:
            pk_u.verify(binding_signature, bind_input, ec.ECDSA(hashes.SHA256()))
        except Exception:
            raise ValueError('bindingSignature verification failed')

        cert = _build_std_cert_u(user_public_key, self.sk_pca, FIXED_TEST_EID.decode('ascii'))
        return {'certificate': b64(cert)}


def main():
    logging.basicConfig(level=logging.INFO)
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', default='localhost')
    parser.add_argument('--port', type=int, default=DEFAULT_PCA_PORT)
    parser.add_argument('--data-dir', default=DATA_DIR)
    parser.add_argument('--nossl', action='store_true', default=False)
    args = parser.parse_args()

    server = PcaServer()
    if args.nossl:
        server.app.run(args.host, args.port)
        return

    cert_dir = Path(args.data_dir) / 'certs' / 'PCA'
    cert_pem = cert_dir / 'CERT_PCA_TLS_NIST.pem'
    key_pem = cert_dir / 'SK_PCA_TLS_NIST.pem'
    dhparam = Path(args.data_dir) / 'certs' / 'dhparam2048.pem'
    if not dhparam.exists():
        parameters = dh.generate_parameters(generator=2, key_size=2048)
        dhparam.write_bytes(parameters.parameter_bytes(Encoding.PEM, ParameterFormat.PKCS3))
    server.app.run(endpoint_description=f'ssl:{args.port}:interface={args.host}:privateKey={key_pem}:certKey={cert_pem}:dhParameters={dhparam}')


if __name__ == '__main__':
    main()
