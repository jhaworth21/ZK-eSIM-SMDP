"""Shared utility functions for ZK-eSIM — used by osmo-smdpp.py and tests."""

import datetime as _dt

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicNumbers, SECP256R1
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import CertificateBuilder, Name, NameAttribute
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature


def hash_fn(data: bytes) -> bytes:
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    return digest.finalize()


def serialize_proof(proof: list) -> bytes:
    """Flatten a Merkle sibling list into a concatenated byte string."""
    if not proof:
        return b''
    out = b''
    for sibling in proof:
        out += sibling
    return out


def deserialize_proof(blob: bytes) -> list:
    """Reconstruct a Merkle sibling list from a concatenated byte string."""
    if not blob:
        return []
    if len(blob) % 32 != 0:
        return []
    return [blob[i:i + 32] for i in range(0, len(blob), 32)]


def ecdsa_tr03111_to_dss(sig: bytes) -> bytes:
    """Convert a 64-byte raw r||s (BSI TR-03111) signature to DER-encoded ECDSA."""
    assert len(sig) == 64
    r = int.from_bytes(sig[0:32], 'big')
    s = int.from_bytes(sig[32:64], 'big')
    return encode_dss_signature(r, s)


def ecdsa_der_to_tr03111(der: bytes) -> bytes:
    """Convert DER-encoded ECDSA to the 64-byte raw r||s form used in BF38."""
    r, s = decode_dss_signature(der)
    return r.to_bytes(32, 'big') + s.to_bytes(32, 'big')


def _read_tlv_len(data: bytes, offset: int) -> tuple[int, int]:
    first = data[offset]
    if first <= 0x7f:
        return first, offset + 1
    count = first & 0x7f
    if count == 0 or count > 2:
        raise ValueError(f'unsupported DER length byte 0x{first:02x}')
    end = offset + 1 + count
    if end > len(data):
        raise ValueError('truncated DER length')
    return int.from_bytes(data[offset + 1:end], 'big'), end


def _tlv_value_span(data: bytes, offset: int) -> tuple[int, int, int]:
    if offset >= len(data):
        raise ValueError('truncated TLV')
    tag_len = 2 if (data[offset] & 0x1f) == 0x1f else 1
    length, value_start = _read_tlv_len(data, offset + tag_len)
    value_end = value_start + length
    if value_end > len(data):
        raise ValueError('TLV length exceeds buffer')
    return value_start, value_end, value_end


def extract_pcert_from_bf(bf_blob: bytes, expected_outer_tag: int) -> bytes:
    """Extract raw PCert_U DER from BF42 ZKProfileResponse or BF38 AuthenticateServerResponse.

    The hash h_cert is defined over the certificate bytes as carried on wire.
    This helper deliberately returns the exact certificate TLV slice rather
    than an ASN.1 re-encoding.
    """
    expected = expected_outer_tag.to_bytes(2, 'big')
    if bf_blob[:2] != expected:
        raise ValueError(f'expected outer tag {expected.hex()}, got {bf_blob[:2].hex()}')

    pos, _, _ = _tlv_value_span(bf_blob, 0)
    if bf_blob[pos] != 0xa0:
        raise ValueError(f'expected success choice A0, got 0x{bf_blob[pos]:02x}')
    pos, _, _ = _tlv_value_span(bf_blob, pos)

    if expected_outer_tag == 0xbf42:
        # A0 { SEQUENCE { ZKStatement, Certificate, requestProof } }
        if bf_blob[pos] != 0x30:
            raise ValueError('expected ZKProfileResponseOk SEQUENCE')
        pos, _, _ = _tlv_value_span(bf_blob, pos)
        if bf_blob[pos] != 0x30:
            raise ValueError('expected ZKStatement SEQUENCE')
        _, _, pos = _tlv_value_span(bf_blob, pos)
        cert_start = pos
        if bf_blob[cert_start] != 0x30:
            raise ValueError('expected pseudonym certificate SEQUENCE')
        _, cert_end, _ = _tlv_value_span(bf_blob, cert_start)
        return bf_blob[cert_start:cert_end]

    if expected_outer_tag == 0xbf38:
        # A0 { euiccSigned1, euiccSignature1, euiccCertificate, eumCertificate }
        if bf_blob[pos] != 0x30:
            raise ValueError('expected euiccSigned1 SEQUENCE')
        _, _, pos = _tlv_value_span(bf_blob, pos)
        if bf_blob[pos:pos + 2] != b'\x5f\x37':
            raise ValueError('expected euiccSignature1 tag 5F37')
        _, _, pos = _tlv_value_span(bf_blob, pos)
        cert_start = pos
        if bf_blob[cert_start] != 0x30:
            raise ValueError('expected euiccCertificate SEQUENCE')
        _, cert_end, _ = _tlv_value_span(bf_blob, cert_start)
        return bf_blob[cert_start:cert_end]

    raise ValueError(f'unsupported outer tag 0x{expected_outer_tag:04x}')


def _build_pcert_u(pk_u_bytes: bytes, sk_pca, eid_ascii: str, credential_binding_hash: bytes) -> bytes:
    """Build a short-lived pseudonym certificate for CertInit.

    The custom extension 2.23.146.1.2.1.8 carries SHA-256(sigma_EID), letting
    the MNO bind the later BF42 statement back to the credential used here.
    """
    if len(pk_u_bytes) != 65 or pk_u_bytes[0] != 0x04:
        raise ValueError('user public key must be a 65-byte uncompressed P-256 point')
    if len(credential_binding_hash) != 32:
        raise ValueError('credential binding hash must be 32 bytes')

    x_coord = int.from_bytes(pk_u_bytes[1:33], 'big')
    y_coord = int.from_bytes(pk_u_bytes[33:65], 'big')
    pk_u = EllipticCurvePublicNumbers(x_coord, y_coord, SECP256R1()).public_key()
    binding_oid = x509.ObjectIdentifier('2.23.146.1.2.1.8')
    now = _dt.datetime.now(_dt.timezone.utc)

    cert = (
        CertificateBuilder()
        .subject_name(Name([NameAttribute(NameOID.SERIAL_NUMBER, eid_ascii)]))
        .issuer_name(Name([NameAttribute(NameOID.ORGANIZATION_NAME, 'ZK-eUICC-PCA')]))
        .public_key(pk_u)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + _dt.timedelta(days=1))
        .add_extension(x509.UnrecognizedExtension(binding_oid, credential_binding_hash), critical=False)
        .sign(sk_pca, ec.ECDSA(hashes.SHA256()))
    )
    return cert.public_bytes(Encoding.DER)


_P256_P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
_P256_A = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc
_P256_N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
_P256_GX = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
_P256_GY = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5


def _p256_add(p_point, q_point):
    if p_point is None:
        return q_point
    if q_point is None:
        return p_point
    x1, y1 = p_point
    x2, y2 = q_point
    if x1 == x2:
        if (y1 + y2) % _P256_P == 0:
            return None
        lam = (3 * x1 * x1 + _P256_A) * pow(2 * y1, _P256_P - 2, _P256_P) % _P256_P
    else:
        lam = (y2 - y1) * pow(x2 - x1, _P256_P - 2, _P256_P) % _P256_P
    x3 = (lam * lam - x1 - x2) % _P256_P
    y3 = (lam * (x1 - x3) - y1) % _P256_P
    return (x3, y3)


def _p256_mul(k: int, point):
    result = None
    addend = point
    while k > 0:
        if k & 1:
            result = _p256_add(result, addend)
        addend = _p256_add(addend, addend)
        k >>= 1
    return result


def schnorr_verify_p256(user_public_key: bytes, statement_message: bytes, proof: bytes) -> bool:
    """Verify the prototype BF42 proof over the encoded ASN.1 statement message."""
    if len(proof) != 97 or len(user_public_key) != 65:
        return False
    if proof[0] != 0x04 or user_public_key[0] != 0x04:
        return False

    rx = int.from_bytes(proof[1:33], 'big')
    ry = int.from_bytes(proof[33:65], 'big')
    s = int.from_bytes(proof[65:97], 'big')
    pkx = int.from_bytes(user_public_key[1:33], 'big')
    pky = int.from_bytes(user_public_key[33:65], 'big')

    digest = hashes.Hash(hashes.SHA256())
    digest.update(statement_message)
    digest.update(proof[:65])
    challenge = int.from_bytes(digest.finalize(), 'big') % _P256_N

    generator = (_P256_GX, _P256_GY)
    lhs = _p256_mul(s, generator)
    rhs = _p256_add((rx, ry), _p256_mul(challenge, (pkx, pky)))
    return lhs == rhs


def parse_zk_profile_response(data: bytes) -> dict:
    """Parse BF42 and preserve both encoded and raw statement bytes."""
    if data[0:2] != b'\xbf\x42':
        raise ValueError(f'expected BF42, got {data[0:2].hex()}')
    pos, _, _ = _tlv_value_span(data, 0)

    if data[pos] != 0xa0:
        raise ValueError(f'expected A0 success choice, got 0x{data[pos]:02x}')
    pos, _, _ = _tlv_value_span(data, pos)

    if data[pos] != 0x30:
        raise ValueError('expected ZKProfileResponseOk SEQUENCE')
    pos, _, _ = _tlv_value_span(data, pos)

    if data[pos] != 0x30:
        raise ValueError('expected ZKStatement SEQUENCE')
    statement_start = pos
    statement_value_start, statement_end, pos = _tlv_value_span(data, pos)

    fields = {}
    p = statement_value_start
    while p < statement_end:
        tag = data[p]
        value_start, value_end, p = _tlv_value_span(data, p)
        fields[tag] = data[value_start:value_end]

    for required in (0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86):
        if required not in fields:
            raise ValueError(f'ZKStatement missing field tag 0x{required:02x}')

    statement_raw = (
        fields[0x80] + fields[0x81] + fields[0x82] + fields[0x83] +
        fields[0x84] + fields[0x85] + fields[0x86]
    )

    cert_start = pos
    if data[cert_start] != 0x30:
        raise ValueError('expected pseudonym certificate SEQUENCE')
    _, cert_end, pos = _tlv_value_span(data, cert_start)

    if data[pos:pos + 2] != b'\x5f\x37':
        raise ValueError('expected requestProof tag 5F37')
    proof_start, proof_end, _ = _tlv_value_span(data, pos)

    return {
        'mnoPublicKey': fields[0x80],
        'leaPublicKey': fields[0x81],
        'userPublicKey': fields[0x82],
        'mnoChallenge': fields[0x83],
        'pseudonymId': fields[0x84],
        'encryptedEid': fields[0x85],
        'credentialBindingHash': fields[0x86],
        'statementRaw': statement_raw,
        'statementTlv': data[statement_start:statement_end],
        'pseudonymCertificate': data[cert_start:cert_end],
        'requestProof': data[proof_start:proof_end],
    }
