from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature


def hash_fn(data: bytes) -> bytes:
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    return digest.finalize()


def serialize_proof(proof) -> bytes:
    if not proof:
        return b''
    return b''.join(proof)


def deserialize_proof(blob: bytes):
    if not blob:
        return []
    if len(blob) % 32 != 0:
        return []
    return [blob[i:i + 32] for i in range(0, len(blob), 32)]


def ecdsa_tr03111_to_dss(sig: bytes) -> bytes:
    """Convert an ECDSA signature from BSI TR-03111 r||s form to DER."""
    assert len(sig) == 64
    r = int.from_bytes(sig[0:32], 'big')
    s = int.from_bytes(sig[32:64], 'big')
    return encode_dss_signature(r, s)


def ecdsa_der_to_tr03111(sig: bytes) -> bytes:
    r, s = decode_dss_signature(sig)
    return r.to_bytes(32, 'big') + s.to_bytes(32, 'big')
