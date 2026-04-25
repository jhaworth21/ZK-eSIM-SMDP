"""Shared utility functions for ZK-eSIM — used by osmo-smdpp.py and tests."""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature


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
