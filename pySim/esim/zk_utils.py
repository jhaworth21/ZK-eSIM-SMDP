"""Shared utility functions for ZK-eSIM — used by osmo-smdpp.py and tests."""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from osmocom.tlv import bertlv_parse_one_rawtag, bertlv_return_one_rawtlv


def hash_fn(data: bytes) -> bytes:
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    return digest.finalize()


def extract_pcert_from_bf(outer: bytes, expected_outer_tag: int) -> bytes:
    """Extract the raw DER bytes of a Certificate (universal SEQUENCE, tag 0x30)
    from a BF38 / BF42 wrapper.

    Both AuthenticateServerResponse (BF38) and ZKProfileResponse (BF42) place
    the eUICC certificate as the second universal-tag-30 child of their A0
    choice body.  Callers need the exact on-wire bytes so that
    h_cert = SHA256(cert_der) matches across MNO and SM-DP+ without relying on
    asn1tools round-tripping.
    """
    rawtag, _l, v, remainder = bertlv_parse_one_rawtag(outer)
    if remainder:
        raise ValueError('Excess data at end of outer TLV')
    if rawtag != expected_outer_tag:
        raise ValueError('Unexpected outer tag: %x' % rawtag)
    rawtag, _l, body, _rem = bertlv_parse_one_rawtag(v)
    if rawtag != 0xa0:
        raise ValueError('Expected A0 choice tag, got %x' % rawtag)

    seqs = []
    cursor = body
    while cursor:
        rawtag, _l, tlv, cursor = bertlv_return_one_rawtlv(cursor)
        if rawtag == 0x30:
            seqs.append(tlv)
        if len(seqs) == 2:
            return seqs[1]
    raise ValueError('Could not find second SEQUENCE child (certificate) inside A0')


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
