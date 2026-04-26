#!/usr/bin/env python3

# Early proof-of-concept towards a SM-DP+ HTTP service for GSMA consumer eSIM RSP
#
# (C) 2023-2024 by Harald Welte <laforge@osmocom.org>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

# asn1tools issue https://github.com/eerimoq/asn1tools/issues/194
# must be first here
from tokenize import String
import asn1tools
import asn1tools.codecs.ber
import asn1tools.codecs.der
# do not move the code
def fix_asn1_oid_decoding():
    fix_asn1_schema = """
    TestModule DEFINITIONS ::= BEGIN
        TestOid ::= SEQUENCE {
            oid OBJECT IDENTIFIER
        }
    END
    """

    fix_asn1_asn1 = asn1tools.compile_string(fix_asn1_schema, codec='der')
    fix_asn1_oid_string = '2.999.10'
    fix_asn1_encoded = fix_asn1_asn1.encode('TestOid', {'oid': fix_asn1_oid_string})
    fix_asn1_decoded = fix_asn1_asn1.decode('TestOid', fix_asn1_encoded)

    if (fix_asn1_decoded['oid'] != fix_asn1_oid_string):
        # ASN.1 OBJECT IDENTIFIER Decoding Issue:
        #
        # In ASN.1 BER/DER encoding, the first two arcs of an OBJECT IDENTIFIER are
        # combined into a single value: (40 * arc0) + arc1. This is encoded as a base-128
        # variable-length quantity (and commonly known as VLQ or base-128 encoding)
        # as specified in ITU-T X.690 §8.19, it can span multiple bytes if
        # the value is large.
        #
        # For arc0 = 0 or 1, arc1 must be in [0, 39]. For arc0 = 2, arc1 can be any non-negative integer.
        # All subsequent arcs (arc2, arc3, ...) are each encoded as a separate base-128 VLQ.
        #
        # The decoding bug occurs when the decoder does not properly split the first
        # subidentifier for arc0 = 2 and arc1 >= 40. Instead of decoding:
        #   - arc0 = 2
        #   - arc1 = (first_subidentifier - 80)
        # it may incorrectly interpret the first_subidentifier as arc0 = (first_subidentifier // 40),
        # arc1 = (first_subidentifier % 40), which is only valid for arc1 < 40.
        #
        # This patch handles it properly for all valid OBJECT IDENTIFIERs
        # with large second arcs, by applying the ASN.1 rules:
        #   - if first_subidentifier < 40: arc0 = 0, arc1 = first_subidentifier
        #   - elif first_subidentifier < 80: arc0 = 1, arc1 = first_subidentifier - 40
        #   - else: arc0 = 2, arc1 = first_subidentifier - 80
        #
        # This problem is not uncommon, see for example https://github.com/randombit/botan/issues/4023

        def fixed_decode_object_identifier(data, offset, end_offset):
            """Decode ASN.1 OBJECT IDENTIFIER from bytes to dotted string, fixing large second arc handling."""
            def read_subidentifier(data, offset):
                value = 0
                while True:
                    b = data[offset]
                    value = (value << 7) | (b & 0x7F)
                    offset += 1
                    if not (b & 0x80):
                        break
                return value, offset

            subid, offset = read_subidentifier(data, offset)
            if subid < 40:
                first = 0
                second = subid
            elif subid < 80:
                first = 1
                second = subid - 40
            else:
                first = 2
                second = subid - 80
            arcs = [first, second]

            while offset < end_offset:
                subid, offset = read_subidentifier(data, offset)
                arcs.append(subid)

            return '.'.join(str(x) for x in arcs)

        asn1tools.codecs.ber.decode_object_identifier = fixed_decode_object_identifier
        asn1tools.codecs.der.decode_object_identifier = fixed_decode_object_identifier

        # test our patch
        asn1 = asn1tools.compile_string(fix_asn1_schema, codec='der')
        decoded = asn1.decode('TestOid', fix_asn1_encoded)['oid']
        assert fix_asn1_oid_string == str(decoded)

fix_asn1_oid_decoding()

from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature, decode_dss_signature # noqa: E402
from cryptography import x509 # noqa: E402
from cryptography.exceptions import InvalidSignature # noqa: E402
from cryptography.hazmat.primitives import hashes # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, dh # noqa: E402
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption, ParameterFormat # noqa: E402
from pathlib import Path # noqa: E402
import json # noqa: E402
import sys # noqa: E402
import argparse # noqa: E402
import uuid # noqa: E402
import os # noqa: E402
import functools # noqa: E402
from typing import Optional, Dict, List # noqa: E402
from pprint import pprint as pp # noqa: E402

import datetime
import base64 # noqa: E402
from base64 import b64decode # noqa: E402
from klein import Klein # noqa: E402
from twisted.web.iweb import IRequest # noqa: E402

from osmocom.utils import h2b, b2h, swap_nibbles # noqa: E402
from osmocom.tlv import bertlv_parse_one_rawtag, bertlv_return_one_rawtlv # noqa: E402

import pySim.esim.rsp as rsp # noqa: E402
from pySim.esim import saip, PMO # noqa: E402
from pySim.esim.es8p import ProfileMetadata,UnprotectedProfilePackage,ProtectedProfilePackage,BoundProfilePackage,BspInstance # noqa: E402
from pySim.esim.zk_utils import deserialize_proof, ecdsa_tr03111_to_dss, extract_pcert_from_bf, hash_fn, serialize_proof # noqa: E402
from pySim.esim.x509_cert import oid, cert_policy_has_oid, cert_get_auth_key_id # noqa: E402
from pySim.esim.x509_cert import CertAndPrivkey, CertificateSet, cert_get_subject_key_id, VerifyError # noqa: E402
from pySim.esim.zk_utils import hash_fn, serialize_proof, deserialize_proof, ecdsa_tr03111_to_dss # noqa: E402

import logging # noqa: E402
import time # noqa: E402
logger = logging.getLogger(__name__)

# HACK: make this configurable
DATA_DIR = './smdpp-data'
HOSTNAME = 'testsmdpplus1.example.com' # must match certificates!

#* MNO-defined values - currently hardcoded or assigned via a function 
# server_challenge = 0x873ECFD6 # added for server challenge section 

# #* Accumulator values
# L_spent = None
# root_spent = None
# L_auth = None
# root_auth = None
# pi_inc = None

# #* Pseudonym Id values (both pid and the hash of pid - H_pid)
# pid = None
# h_pid = None
# h_cert = None

# #* MNO key and identifier values
# sk_mno = None
# pk_mno = None
# mnoid = None
# auth_tok = None

# #* MNO-based signatures
# sig_cred = None

FIXED_TEST_EID = b"89049032000000000000012345678901"
# Fixed expiry for ZK auth token — matches FIXED_EXPIRY in ZK-eSIM applet.
# ASCII Unix timestamp for 2100-01-01 00:00 UTC.
FIXED_EXPIRY = b"4102444800"
FIXED_MNOID = b"MNO_id"
FIXED_H_CERT_STUB = b"\x30\x00"
FIXED_MNO_PUBLIC_KEY = bytes.fromhex("040E042F54B8687E479C41A84CD007B13A5F7D5F6ACD8E90AF58F0C85EADCB67F613D125A6409703254ADC1C7BC423571C9914A5A45F61241C0E73431654BD4C75")
# Private scalar matching FIXED_MNO_PUBLIC_KEY — must equal FIXED_MNO_SCALAR in Crypto.java.
FIXED_MNO_PRIVATE_SCALAR = int.from_bytes(bytes.fromhex(
    "1F1E1D1C1B1A191817161514131211"
    "10FFEEDDCCBBAA99887766554433221100"
), 'big')
AUTH_TOKEN_VALIDITY_SECONDS = 3600


def utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def encode_expiry(dt: datetime.datetime) -> bytes:
    return str(int(dt.timestamp())).encode("ascii")


def decode_expiry(expiry_raw: bytes) -> datetime.datetime:
    expiry_ts = int(expiry_raw.decode("ascii"))
    return datetime.datetime.fromtimestamp(expiry_ts, tz=datetime.timezone.utc)


# ---------------------------------------------------------------------------
# Phase 0 constants — device public key matches FIXED_DEVICE_W in Crypto.java
# ---------------------------------------------------------------------------
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


def _build_phase0_apdu(outer_tag: int, payload: bytes) -> bytes:
    """Wrap payload in BF_TAG { 80 len payload } for Phase 0 APDUs."""
    inner = bytes([0x80]) + _der_length(len(payload)) + payload
    return bytes([0xBF, outer_tag]) + _der_length(len(inner)) + inner


def _der_length(n: int) -> bytes:
    if n < 128:
        return bytes([n])
    elif n < 256:
        return bytes([0x81, n])
    else:
        return bytes([0x82, (n >> 8) & 0xFF, n & 0xFF])


def _build_pcert_u(pk_u_bytes: bytes, sk_pca, eid_ascii: str, h_sigma_eid: bytes) -> bytes:
    """Issue a short-lived session certificate for pk_U signed by the PCA (sk_MNO).
    h_sigma_eid (32 B) is embedded as a custom non-critical extension so the server
    can later verify that the ZKStatement commitment matches the registered credential."""
    from cryptography.x509 import CertificateBuilder, NameAttribute, Name
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1, EllipticCurvePublicNumbers
    import datetime as _dt

    # OID 2.23.146.1.2.1.8 — ZK-eUICC credential binding hash
    _H_SIG_EID_OID = x509.ObjectIdentifier('2.23.146.1.2.1.8')

    x_coord = int.from_bytes(pk_u_bytes[1:33], 'big')
    y_coord = int.from_bytes(pk_u_bytes[33:65], 'big')
    pk_u = EllipticCurvePublicNumbers(x_coord, y_coord, SECP256R1()).public_key()

    now = _dt.datetime.now(_dt.timezone.utc)
    cert = (
        CertificateBuilder()
        .subject_name(Name([NameAttribute(NameOID.SERIAL_NUMBER, eid_ascii)]))
        .issuer_name(Name([NameAttribute(NameOID.ORGANIZATION_NAME, "ZK-eUICC-PCA")]))
        .public_key(pk_u)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + _dt.timedelta(days=1))
        .add_extension(x509.UnrecognizedExtension(_H_SIG_EID_OID, h_sigma_eid), critical=False)
        .sign(sk_pca, ec.ECDSA(hashes.SHA256()))
    )
    return cert.public_bytes(Encoding.DER)


def setupMNOValues(ss):
    # ZK test vectors: pk_mno is shared with the applet and MNO server.
    # The applet signs sig_cred / sig_root / auth_tok
    # at install time using the real h_cert from its self-signed euiccCertificate;
    # the SM-DP+ side merely verifies those signatures in authenticateClient.
    # We still set h_pid / L_auth here so the accumulator inclusion proof matches.
    pid = hash_fn(FIXED_TEST_EID)
    ss.pid = pid
    mnoid = FIXED_MNOID
    ss.mnoid = mnoid

    h_pid = hash_fn(pid)
    ss.h_pid = h_pid

    ss.pk_mno = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), FIXED_MNO_PUBLIC_KEY)

    # Single-leaf accumulator: root == h_pid, proof is empty.
    L_auth = rsp.MerkleAccumulator()
    h_pid_hex = h_pid.hex()
    L_auth.add(h_pid_hex)
    ss.L_auth = L_auth
    ss.root_auth = bytes(L_auth.get_root())
    L_spent = rsp.MerkleAccumulator()
    ss.L_spent = L_spent
    ss.root_spent = bytes(L_spent.get_root()) if L_spent.get_root() else b''
    pi_inc = L_auth.generateProof(h_pid_hex)
    ss.pi_inc = pi_inc
    ss.pi_inc_bytes = serialize_proof(pi_inc)

    # Use a fixed expiry that matches FIXED_EXPIRY in the applet; the applet's
    # auth_tok is bound to this same ASCII-encoded timestamp.
    ss.expiry = FIXED_EXPIRY

    # sig_cred / sig_root / auth_tok are populated from the applet's eligibility
    # data in authenticateClient (not pre-computed here).
    ss.sig_cred = None
    ss.sig_root = None
    ss.auth_tok = None

    return ss

# ---------------------------------------------------------------------------
# LEA public key — matches LEA_PUBLIC_W in Crypto.java (test scalar 0xAABBCCDD…)
# ---------------------------------------------------------------------------
FIXED_LEA_PUBLIC_W = bytes([
    0x04, 0x21, 0x90, 0x2A, 0x33, 0xC0, 0x72, 0xD4,
    0x67, 0xB0, 0xC5, 0x81, 0xBA, 0x68, 0x25, 0xA2,
    0x44, 0x0E, 0xC4, 0x04, 0xF2, 0xED, 0xCF, 0x3C,
    0x0D, 0x8A, 0xAF, 0x92, 0xF4, 0xEF, 0xCF, 0x4D,
    0x45, 0xBF, 0x51, 0x42, 0xCA, 0xF9, 0xF5, 0x59,
    0xE6, 0x94, 0xAD, 0x89, 0x1D, 0xF0, 0x98, 0xD3,
    0xE2, 0xAA, 0xF8, 0xA2, 0xD9, 0x01, 0x8B, 0xB2,
    0x0D, 0x40, 0x38, 0x3C, 0x55, 0x02, 0x97, 0x23,
    0x2C,
])

# ---------------------------------------------------------------------------
# P-256 EC arithmetic for Schnorr proof verification.
# Standard secp256r1 (NIST P-256) parameters.
# ---------------------------------------------------------------------------
_P256_P  = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
_P256_A  = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC  # -3 mod p
_P256_N  = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
_P256_GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
_P256_GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5


def _p256_add(P, Q):
    """Add two P-256 affine points (x,y) or None (point at infinity)."""
    if P is None: return Q
    if Q is None: return P
    x1, y1 = P
    x2, y2 = Q
    p = _P256_P
    if x1 == x2:
        if (y1 + y2) % p == 0:
            return None  # additive inverse
        # point doubling
        lam = (3 * x1 * x1 + _P256_A) * pow(2 * y1, p - 2, p) % p
    else:
        lam = (y2 - y1) * pow(x2 - x1, p - 2, p) % p
    x3 = (lam * lam - x1 - x2) % p
    y3 = (lam * (x1 - x3) - y1) % p
    return (x3, y3)


def _p256_mul(k, P):
    """Scalar multiplication k*P on P-256."""
    R, Q = None, P
    while k > 0:
        if k & 1:
            R = _p256_add(R, Q)
        Q = _p256_add(Q, Q)
        k >>= 1
    return R


def _schnorr_verify_p256(pk_u_bytes: bytes, stmt_raw: bytes, proof: bytes) -> bool:
    """Verify EC Schnorr PoK of sk_U bound to stmt_raw.
    Proof = R(65B) || s(32B).  Verifies: s*G == R + c*pk_U  where c = H(stmt||R) mod n."""
    if len(proof) != 97 or len(pk_u_bytes) != 65:
        return False
    if proof[0] != 0x04 or pk_u_bytes[0] != 0x04:
        return False

    Rx = int.from_bytes(proof[1:33], 'big')
    Ry = int.from_bytes(proof[33:65], 'big')
    s  = int.from_bytes(proof[65:97], 'big')
    PKx = int.from_bytes(pk_u_bytes[1:33], 'big')
    PKy = int.from_bytes(pk_u_bytes[33:65], 'big')

    dig = hashes.Hash(hashes.SHA256())
    dig.update(stmt_raw)
    dig.update(proof[:65])   # R bytes
    c = int.from_bytes(dig.finalize(), 'big') % _P256_N

    G = (_P256_GX, _P256_GY)
    lhs = _p256_mul(s, G)
    rhs = _p256_add((Rx, Ry), _p256_mul(c, (PKx, PKy)))
    return lhs == rhs


# ---------------------------------------------------------------------------
# BF43 SetEligibilityDataRequest TLV builder
# ---------------------------------------------------------------------------
def _build_set_eligibility_tlv(hpid: bytes, sig_cred: bytes, auth_tok: bytes,
                                root_auth: bytes, sig_root: bytes,
                                pi_inc_bytes: bytes) -> bytes:
    """Build a complete BF43 SetEligibilityDataRequest TLV ready for the applet."""
    def _tlv1(tag: int, value: bytes) -> bytes:
        n = len(value)
        if n <= 0x7F:   return bytes([tag, n]) + value
        if n <= 0xFF:   return bytes([tag, 0x81, n]) + value
        return bytes([tag, 0x82, (n >> 8) & 0xFF, n & 0xFF]) + value

    def _wrap(tag_bytes: bytes, value: bytes) -> bytes:
        n = len(value)
        if n <= 0x7F:   length = bytes([n])
        elif n <= 0xFF: length = bytes([0x81, n])
        else:           length = bytes([0x82, (n >> 8) & 0xFF, n & 0xFF])
        return tag_bytes + length + value

    elig_body = (
        _tlv1(0x80, hpid) +
        _tlv1(0x81, sig_cred) +
        _tlv1(0x82, auth_tok) +
        _tlv1(0x83, root_auth) +
        _tlv1(0x84, sig_root) +
        _tlv1(0x85, pi_inc_bytes)
    )
    return _wrap(b'\xbf\x43', _wrap(b'\x30', elig_body))


# ---------------------------------------------------------------------------
# BF42 ZKProfileResponse TLV parser
# ---------------------------------------------------------------------------
def _parse_zk_profile_response(data: bytes) -> dict:
    """Parse a BF42 ZKProfileResponse TLV produced by the applet.
    Returns dict with keys: pkMno, pkLea, pkU, mnoChallenge, pid, encEid, hSigmaEid,
    stmt_raw (356-byte raw concat for Schnorr hash), pcertU_der, proof."""

    def _rlen(d, p):
        b = d[p]
        if b <= 0x7F:  return b,           p + 1
        if b == 0x81:  return d[p+1],      p + 2
        if b == 0x82:  return (d[p+1] << 8) | d[p+2], p + 3
        raise ValueError(f"unsupported length byte 0x{b:02X}")

    def _enter(d, p):
        """Skip tag (1 or 2 bytes), return (val_start, val_end)."""
        tag_bytes = 2 if (d[p] & 0x1F) == 0x1F else 1
        n, vs = _rlen(d, p + tag_bytes)
        return vs, vs + n

    def _span(d, p):
        """Return (tag_start=p, val_start, val_end, next_pos=val_end)."""
        vs, ve = _enter(d, p)
        return p, vs, ve, ve

    # BF42 outer
    if data[0:2] != b'\xbf\x42':
        raise ValueError(f"expected BF42, got {data[0:2].hex()}")
    pos = _enter(data, 0)[0]              # skip to A0

    # A0 CHOICE [0] = zkProfileResponseOk
    if data[pos] != 0xA0:
        raise ValueError(f"expected A0 at pos {pos}, got 0x{data[pos]:02X}")
    pos = _enter(data, pos)[0]

    # 30 ZKProfileResponseOk SEQUENCE
    if data[pos] != 0x30:
        raise ValueError(f"expected 30 at pos {pos}, got 0x{data[pos]:02X}")
    pos = _enter(data, pos)[0]

    # 30 ZKStatement SEQUENCE
    if data[pos] != 0x30:
        raise ValueError(f"expected ZKStatement 30 at pos {pos}, got 0x{data[pos]:02X}")
    stmt_vs, stmt_ve = _enter(data, pos)
    pos = stmt_ve                         # advance past whole statement TLV after reading fields

    # Parse ZKStatement context-tagged fields 0x80–0x85
    fields: dict = {}
    p = stmt_vs
    while p < stmt_ve:
        tag = data[p]
        vs, ve = _enter(data, p)
        fields[tag] = data[vs:ve]
        p = ve

    for required in (0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86):
        if required not in fields:
            raise ValueError(f"ZKStatement missing field tag 0x{required:02X}")

    stmt_raw = (fields[0x80] + fields[0x81] + fields[0x82] + fields[0x83]
                + fields[0x84] + fields[0x85] + fields[0x86])

    # Certificate SEQUENCE — capture full TLV bytes
    if data[pos] != 0x30:
        raise ValueError(f"expected Certificate 30 at pos {pos}, got 0x{data[pos]:02X}")
    cert_start = pos
    _, cert_end = _enter(data, pos)
    pcertU_der = data[cert_start:cert_end]
    pos = cert_end

    # 5F37 zkProof
    if data[pos:pos+2] != b'\x5f\x37':
        raise ValueError(f"expected 5F37 at pos {pos}, got {data[pos:pos+2].hex()}")
    proof_vs, proof_ve = _enter(data, pos)

    return {
        'pkMno':        fields[0x80],
        'pkLea':        fields[0x81],
        'pkU':          fields[0x82],
        'mnoChallenge': fields[0x83],
        'pid':          fields[0x84],
        'encEid':       fields[0x85],
        'hSigmaEid':    fields[0x86],
        'stmt_raw':     stmt_raw,
        'pcertU_der':   pcertU_der,
        'proof':        data[proof_vs:proof_ve],
    }



def b64encode2str(req: bytes) -> str:
    """Encode given input bytes as base64 and return result as string."""
    return base64.b64encode(req).decode('ascii')

def set_headers(request: IRequest):
    """Set the request headers as mandatory by GSMA eSIM RSP."""
    request.setHeader('Content-Type', 'application/json;charset=UTF-8')
    request.setHeader('X-Admin-Protocol', 'gsma/rsp/v2.1.0')

def validate_request_headers(request: IRequest):
    """Validate mandatory HTTP headers according to SGP.22."""
    content_type = request.getHeader('Content-Type')
    if not content_type or not content_type.startswith('application/json'):
        raise ApiError('1.2.1', '2.1', 'Invalid Content-Type header')

    admin_protocol = request.getHeader('X-Admin-Protocol')
    if admin_protocol and not admin_protocol.startswith('gsma/rsp/v'):
        raise ApiError('1.2.2', '2.1', 'Unsupported X-Admin-Protocol version')

def get_eum_certificate_variant(eum_cert) -> str:
    """Determine EUM certificate variant by checking Certificate Policies extension.
    Returns 'O' for old variant, or 'NEW' for Ov3/A/B/C variants."""

    try:
        cert_policies_ext = eum_cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.CERTIFICATE_POLICIES
        )

        for policy in cert_policies_ext.value:
            policy_oid = policy.policy_identifier.dotted_string
            logger.debug(f"Found certificate policy: {policy_oid}")

            if policy_oid == '2.23.146.1.2.1.2':
                logger.debug("Detected EUM certificate variant: O (old)")
                return 'O'
            elif policy_oid == '2.23.146.1.2.1.0.0.0':
                logger.debug("Detected EUM certificate variant: Ov3/A/B/C (new)")
                return 'NEW'
    except x509.ExtensionNotFound:
        logger.debug("No Certificate Policies extension found")
    except Exception as e:
        logger.debug(f"Error checking certificate policies: {e}")

def parse_permitted_eins_from_cert(eum_cert) -> List[str]:
    """Extract permitted IINs from EUM certificate using the appropriate method
    based on certificate variant (O vs Ov3/A/B/C).
    Returns list of permitted IINs (basically prefixes that valid EIDs must start with)."""

    # Determine certificate variant first
    cert_variant = get_eum_certificate_variant(eum_cert)
    permitted_iins = []

    if cert_variant == 'O':
        # Old variant - use nameConstraints extension
        permitted_iins.extend(_parse_name_constraints_eins(eum_cert))

    else:
        # New variants (Ov3, A, B, C) - use GSMA permittedEins extension
        permitted_iins.extend(_parse_gsma_permitted_eins(eum_cert))

    unique_iins = list(set(permitted_iins))

    logger.debug(f"Total unique permitted IINs found: {len(unique_iins)}")
    return unique_iins

def _parse_gsma_permitted_eins(eum_cert) -> List[str]:
    """Parse the GSMA permittedEins extension using correct ASN.1 structure.
    PermittedEins ::= SEQUENCE OF PrintableString
    Each string contains an IIN (Issuer Identification Number) - a prefix of valid EIDs."""
    permitted_iins = []

    try:
        permitted_eins_oid = x509.ObjectIdentifier('2.23.146.1.2.2.0')  # sgp26: 2.23.146.1.2.2.0 = ASN1:SEQUENCE:permittedEins

        for ext in eum_cert.extensions:
            if ext.oid == permitted_eins_oid:
                logger.debug(f"Found GSMA permittedEins extension: {ext.oid}")

                # Get the DER-encoded extension value
                ext_der = ext.value.value if hasattr(ext.value, 'value') else ext.value

                if isinstance(ext_der, bytes):
                    try:
                        permitted_eins_schema = """
                        PermittedEins DEFINITIONS ::= BEGIN
                            PermittedEins ::= SEQUENCE OF PrintableString
                        END
                        """
                        decoder = asn1tools.compile_string(permitted_eins_schema)
                        decoded_strings = decoder.decode('PermittedEins', ext_der)

                        for iin_string in decoded_strings:
                            # Each string contains an IIN -> prefix of euicc EID
                            iin_clean = iin_string.strip().upper()

                            # IINs is 8 chars per sgp22, var len according to sgp29, fortunately we don't care
                            if (len(iin_clean) == 8 and
                                all(c in '0123456789ABCDEF' for c in iin_clean) and
                                    len(iin_clean) % 2 == 0):
                                permitted_iins.append(iin_clean)
                                logger.debug(f"Found permitted IIN (GSMA): {iin_clean}")
                            else:
                                logger.debug(f"Invalid IIN format: {iin_string} (cleaned: {iin_clean})")
                    except Exception as e:
                        logger.debug(f"Error parsing GSMA permittedEins extension: {e}")

    except Exception as e:
        logger.debug(f"Error accessing GSMA certificate extensions: {e}")

    return permitted_iins


def _parse_name_constraints_eins(eum_cert) -> List[str]:
    """Parse permitted IINs from nameConstraints extension (variant O)."""
    permitted_iins = []

    try:
        # Look for nameConstraints extension
        name_constraints_ext = eum_cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.NAME_CONSTRAINTS
        )

        name_constraints = name_constraints_ext.value

        # Check permittedSubtrees for IIN constraints
        if name_constraints.permitted_subtrees:
            for subtree in name_constraints.permitted_subtrees:

                if isinstance(subtree, x509.DirectoryName):
                    for attribute in subtree.value:
                        # IINs for O in serialNumber
                        if attribute.oid == x509.oid.NameOID.SERIAL_NUMBER:
                            serial_value = attribute.value.upper()
                            # sgp22 8, sgp29 var len, fortunately we don't care
                            if (len(serial_value) == 8 and
                                all(c in '0123456789ABCDEF' for c in serial_value) and
                                    len(serial_value) % 2 == 0):
                                permitted_iins.append(serial_value)
                                logger.debug(f"Found permitted IIN (nameConstraints/DN): {serial_value}")

    except x509.ExtensionNotFound:
        logger.debug("No nameConstraints extension found")
    except Exception as e:
        logger.debug(f"Error parsing nameConstraints: {e}")

    return permitted_iins


def validate_eid_range(eid: str, eum_cert) -> bool:
    """Validate that EID is within the permitted EINs of the EUM certificate."""
    if not eid or len(eid) != 32:
        logger.debug(f"Invalid EID format: {eid}")
        return False

    try:
        permitted_eins = parse_permitted_eins_from_cert(eum_cert)

        if not permitted_eins:
            logger.debug("Warning: No permitted EINs found in EUM certificate")
            return False

        eid_normalized = eid.upper()
        logger.debug(f"Validating EID {eid_normalized} against {len(permitted_eins)} permitted EINs")

        for permitted_ein in permitted_eins:
                if eid_normalized.startswith(permitted_ein):
                    logger.debug(f"EID {eid_normalized} matches permitted EIN {permitted_ein}")
                    return True

        logger.debug(f"EID {eid_normalized} is not in any permitted EIN list")
        return False

    except Exception as e:
        logger.debug(f"Error validating EID: {e}")
        return False

def build_status_code(subject_code: str, reason_code: str, subject_id: Optional[str], message: Optional[str]) -> Dict:
    r = {'subjectCode': subject_code, 'reasonCode': reason_code }
    if subject_id:
        r['subjectIdentifier'] = subject_id
    if message:
        r['message'] = message
    return r

def build_resp_header(js: dict, status: str = 'Executed-Success', status_code_data = None) -> None:
    # SGP.22 v3.0 6.5.1.4
    js['header'] = {
        'functionExecutionStatus': {
            'status': status,
        }
    }
    if status_code_data:
        js['header']['functionExecutionStatus']['statusCodeData'] = status_code_data


class ApiError(Exception):
    def __init__(self, subject_code: str, reason_code: str, message: Optional[str] = None,
                 subject_id: Optional[str] = None):
        self.status_code = build_status_code(subject_code, reason_code, subject_id, message)

    def encode(self) -> str:
        """Encode the API Error into a responseHeader string."""
        js = {}
        build_resp_header(js, 'Failed', self.status_code)
        return json.dumps(js)

class SmDppHttpServer:
    app = Klein()

    @staticmethod
    def load_certs_from_path(path: str) -> List[x509.Certificate]:
        """Load all DER + PEM files from given directory path and return them as list of x509.Certificate
        instances."""
        certs = []
        for dirpath, dirnames, filenames in os.walk(path):
            for filename in filenames:
                cert = None
                if filename.endswith('.der'):
                    with open(os.path.join(dirpath, filename), 'rb') as f:
                        cert = x509.load_der_x509_certificate(f.read())
                elif filename.endswith('.pem'):
                    with open(os.path.join(dirpath, filename), 'rb') as f:
                        cert = x509.load_pem_x509_certificate(f.read())
                if cert:
                    # verify it is a CI certificate (keyCertSign + i-rspRole-ci)
                    if not cert_policy_has_oid(cert, oid.id_rspRole_ci):
                        raise ValueError("alleged CI certificate %s doesn't have CI policy" % filename)
                    certs.append(cert)
        return certs

    def ci_get_cert_for_pkid(self, ci_pkid: bytes) -> Optional[x509.Certificate]:
        """Find CI certificate for given key identifier."""
        for cert in self.ci_certs:
            logger.debug("cert: %s" % cert)
            subject_exts = list(filter(lambda x: isinstance(x.value, x509.SubjectKeyIdentifier), cert.extensions))
            logger.debug(subject_exts)
            subject_pkid = subject_exts[0].value
            logger.debug(subject_pkid)
            if subject_pkid and subject_pkid.key_identifier == ci_pkid:
                return cert
        return None

    def validate_certificate_chain_for_verification(self, euicc_ci_pkid_list: List[bytes]) -> bool:
        """Validate that SM-DP+ has valid certificate chains for the given CI PKIDs."""
        for ci_pkid in euicc_ci_pkid_list:
            ci_cert = self.ci_get_cert_for_pkid(ci_pkid)
            if ci_cert:
                # Check if our DPauth certificate chains to this CI
                try:
                    cs = CertificateSet(ci_cert)
                    cs.verify_cert_chain(self.dp_auth.cert)
                    return True
                except VerifyError:
                    continue
        return False

    def __init__(self, server_hostname: str, ci_certs_path: str, common_cert_path: str,
                 use_brainpool: bool = False, in_memory: bool = False, zk_mode: bool = False):
        self.server_hostname = server_hostname
        self.zk_mode = zk_mode
        self.upp_dir = os.path.realpath(os.path.join(DATA_DIR, 'upp'))
        self.ci_certs = self.load_certs_from_path(ci_certs_path)
        # load DPauth cert + key
        self.dp_auth = CertAndPrivkey(oid.id_rspRole_dp_auth_v2)
        cert_dir = common_cert_path
        #* Defines all of the MNO values as specified in the protocol for algorithm 6 
        if use_brainpool:
            self.dp_auth.cert_from_der_file(os.path.join(cert_dir, 'DPauth', 'CERT_S_SM_DPauth_ECDSA_BRP.der'))
            self.dp_auth.privkey_from_pem_file(os.path.join(cert_dir, 'DPauth', 'SK_S_SM_DPauth_ECDSA_BRP.pem'))
        else:
            self.dp_auth.cert_from_der_file(os.path.join(cert_dir, 'DPauth', 'CERT_S_SM_DPauth_ECDSA_NIST.der'))
            self.dp_auth.privkey_from_pem_file(os.path.join(cert_dir, 'DPauth', 'SK_S_SM_DPauth_ECDSA_NIST.pem'))
        # load DPpb cert + key
        self.dp_pb = CertAndPrivkey(oid.id_rspRole_dp_pb_v2)
        if use_brainpool:
            self.dp_pb.cert_from_der_file(os.path.join(cert_dir, 'DPpb', 'CERT_S_SM_DPpb_ECDSA_BRP.der'))
            self.dp_pb.privkey_from_pem_file(os.path.join(cert_dir, 'DPpb', 'SK_S_SM_DPpb_ECDSA_BRP.pem'))
        else:
            self.dp_pb.cert_from_der_file(os.path.join(cert_dir, 'DPpb', 'CERT_S_SM_DPpb_ECDSA_NIST.der'))
            self.dp_pb.privkey_from_pem_file(os.path.join(cert_dir, 'DPpb', 'SK_S_SM_DPpb_ECDSA_NIST.pem'))
        if in_memory:
            self.rss = rsp.RspSessionStore(in_memory=True)
            logger.info("Using in-memory session storage")
        else:
            # Use different session database files for BRP and NIST to avoid file locking during concurrent runs
            session_db_suffix = "BRP" if use_brainpool else "NIST"
            db_path = os.path.join(DATA_DIR, f"sm-dp-sessions-{session_db_suffix}")
            self.rss = rsp.RspSessionStore(filename=db_path, in_memory=False)
            logger.info(f"Using file-based session storage: {db_path}")
        self._pending_orders = {}

        # MNO state — co-located with SM-DP+ to avoid a separate server process.
        # Keyed by requestId (UUID hex string).
        self._mno_sessions: Dict[str, dict] = {}
        # Pending ZK download orders: iccid → {eid, matchingId, state}
        self._zk_pending_orders: Dict[str, dict] = {}
        # MNO signing key (same scalar as FIXED_MNO_PRIVATE_SCALAR already in file)
        self._sk_mno = ec.derive_private_key(FIXED_MNO_PRIVATE_SCALAR, ec.SECP256R1())
        self._pk_mno_bytes = self._sk_mno.public_key().public_bytes(
            Encoding.X962, PublicFormat.UncompressedPoint)
        # Single shared accumulator for all ZK sessions (grows as devices register)
        self._L_auth = rsp.MerkleAccumulator()
        # Phase 0 sessions keyed by requestId
        self._phase0_sessions: Dict[str, dict] = {}

    @app.handle_errors(ApiError)
    def handle_apierror(self, request: IRequest, failure):
        request.setResponseCode(200)
        pp(failure)
        return failure.value.encode()

    @staticmethod
    def _ecdsa_verify(cert: x509.Certificate, signature: bytes, data: bytes) -> bool:
        pubkey = cert.public_key()
        dss_sig = ecdsa_tr03111_to_dss(signature)
        try:
            pubkey.verify(dss_sig, data, ec.ECDSA(hashes.SHA256()))
            return True
        except InvalidSignature:
            return False

    @staticmethod
    def rsp_api_wrapper(func):
        """Wrapper that can be used as decorator in order to perform common REST API endpoint entry/exit
        functionality, such as JSON decoding/encoding and debug-printing."""
        @functools.wraps(func)
        def _api_wrapper(self, request: IRequest):
            validate_request_headers(request)

            content = json.loads(request.content.read())
            logger.debug("Rx JSON: %s" % json.dumps(content))
            set_headers(request)

            t0 = time.perf_counter()
            output = func(self, request, content)
            elapsed_ms = (time.perf_counter() - t0) * 1000
            logger.info("[timing] %s: %.1f ms", func.__name__, elapsed_ms)

            if output == None:
                return ''

            build_resp_header(output)
            logger.debug("Tx JSON: %s" % json.dumps(output))
            return json.dumps(output)
        return _api_wrapper

    @staticmethod
    def mno_api_wrapper(func):
        """Lightweight wrapper for MNO routes: JSON in / JSON out, no ES9+ headers."""
        @functools.wraps(func)
        def _mno_wrapper(self, request: IRequest):
            request.setHeader('Content-Type', 'application/json;charset=UTF-8')
            try:
                body = request.content.read()
                content = json.loads(body) if body.strip() else {}
            except Exception:
                content = {}
            logger.debug("MNO Rx JSON: %s" % json.dumps(content))
            t0 = time.perf_counter()
            try:
                result = func(self, request, content)
                elapsed_ms = (time.perf_counter() - t0) * 1000
                logger.info("[timing] %s: %.1f ms", func.__name__, elapsed_ms)
                logger.debug("MNO Tx JSON: %s" % json.dumps(result))
                return json.dumps(result)
            except ApiError as exc:
                elapsed_ms = (time.perf_counter() - t0) * 1000
                logger.info("[timing] %s: %.1f ms (error)", func.__name__, elapsed_ms)
                request.setResponseCode(400)
                return exc.encode()
            except Exception as exc:
                elapsed_ms = (time.perf_counter() - t0) * 1000
                logger.info("[timing] %s: %.1f ms (exception)", func.__name__, elapsed_ms)
                logger.exception("MNO handler error")
                request.setResponseCode(500)
                return json.dumps({'error': str(exc)})
        return _mno_wrapper

    @app.route('/gsma/rsp2/es9plus/initiateAuthentication', methods=['POST'])
    @rsp_api_wrapper
    def initiateAutentication(self, request: IRequest, content: dict) -> dict:
        """See ES9+ InitiateAuthentication SGP.22 Section 5.6.1"""
        # Verify that the received address matches its own SM-DP+ address, where the comparison SHALL be
        # case-insensitive. Otherwise, the SM-DP+ SHALL return a status code "SM-DP+ Address - Refused".
        if content['smdpAddress'] != self.server_hostname:
           raise ApiError('8.8.1', '3.8', 'Invalid SM-DP+ Address')

        euiccChallenge = b64decode(content['euiccChallenge'])
        if len(euiccChallenge) != 16:
            raise ValueError

        euiccInfo1_bin = b64decode(content['euiccInfo1'])
        euiccInfo1 = rsp.asn1.decode('EUICCInfo1', euiccInfo1_bin)
        logger.debug("Rx euiccInfo1: %s" % euiccInfo1)
        #euiccInfo1['svn']

        pkid_list = euiccInfo1['euiccCiPKIdListForSigning']
        if 'euiccCiPKIdListForSigningV3' in euiccInfo1:
            pkid_list = pkid_list + euiccInfo1['euiccCiPKIdListForSigningV3']

        # Validate that SM-DP+ supports certificate chains for verification
        verification_pkid_list = euiccInfo1.get('euiccCiPKIdListForVerification', [])
        if verification_pkid_list and not self.validate_certificate_chain_for_verification(verification_pkid_list):
            raise ApiError('8.8.4', '3.7', 'The SM-DP+ has no CERT.DPauth.SIG which chains to one of the eSIM CA Root CA Certificate with a Public Key supported by the eUICC')

        # verify it supports one of the keys indicated by euiccCiPKIdListForSigning
        ci_cert = None
        for x in pkid_list:
            ci_cert = self.ci_get_cert_for_pkid(x)
            # we already support multiple CI certificates but only one set of DPauth + DPpb keys. So we must
            # make sure we choose a CI key-id which has issued both the eUICC as well as our own SM-DP side
            # certs.
            if ci_cert and cert_get_subject_key_id(ci_cert) == self.dp_auth.get_authority_key_identifier().key_identifier:
                break
            else:
                ci_cert = None
        if not ci_cert:
           raise ApiError('8.8.2', '3.1', 'None of the proposed Public Key Identifiers is supported by the SM-DP+')

        # Generate a TransactionID which is used to identify the ongoing RSP session. The TransactionID
        # SHALL be unique within the scope and lifetime of each SM-DP+.
        transactionId = uuid.uuid4().hex.upper()
        assert not transactionId in self.rss

        # Generate a serverChallenge for eUICC authentication attached to the ongoing RSP session.
        serverChallenge = os.urandom(16)

        # Generate a serverSigned1 data object as expected by the eUICC and described in section 5.7.13 "ES10b.AuthenticateServer". If and only if both eUICC and LPA indicate crlStaplingV3Support, the SM-DP+ SHALL indicate crlStaplingV3Used in sessionContext.
        serverSigned1 = {
            'transactionId': h2b(transactionId),    #* Corresponds to I_t
            'euiccChallenge': euiccChallenge,       #* Corresponds to N_u
            'serverAddress': self.server_hostname,  #* Corresponds to sid
            'serverChallenge': serverChallenge,     #* Corresponds to N_s

            }
        logger.debug("Tx serverSigned1: %s" % serverSigned1)
        serverSigned1_bin = rsp.asn1.encode('ServerSigned1', serverSigned1)
        logger.debug("Tx serverSigned1: %s" % rsp.asn1.decode('ServerSigned1', serverSigned1_bin))
        output = {}
        output['serverSigned1'] = b64encode2str(serverSigned1_bin)

        # Generate a signature (serverSignature1) as described in section 5.7.13 "ES10b.AuthenticateServer" using the SK related to the selected CERT.DPauth.SIG.
        # serverSignature1 SHALL be created using the private key associated to the RSP Server Certificate for authentication, and verified by the eUICC using the contained public key as described in section 2.6.9. serverSignature1 SHALL apply on serverSigned1 data object.
        output['serverSignature1'] = b64encode2str(b'\x5f\x37\x40' + self.dp_auth.ecdsa_sign(serverSigned1_bin))

        output['transactionId'] = transactionId
        server_cert_aki = self.dp_auth.get_authority_key_identifier()
        output['euiccCiPKIdToBeUsed'] = b64encode2str(b'\x04\x14' + server_cert_aki.key_identifier)
        output['serverCertificate'] = b64encode2str(self.dp_auth.get_cert_as_der()) # CERT.DPauth.SIG
        # FIXME: add those certificate
        #output['otherCertsInChain'] = b64encode2str()

        # create SessionState and store it in rss
        self.rss[transactionId] = rsp.RspSessionState(transactionId, serverChallenge,
                                                      cert_get_subject_key_id(ci_cert))
        ss = self.rss[transactionId]
        ss.euicc_challenge = euiccChallenge
        if self.zk_mode:
            self.rss[transactionId] = setupMNOValues(ss)
        else:
            self.rss[transactionId] = ss
        ss = self.rss[transactionId]

        if self.zk_mode and getattr(ss, 'expiry', None):
            # Modified protocol extension consumed by patched LPA clients.
            output['zkAuthTokenExpiry'] = ss.expiry.decode('ascii')

        return output

    @app.route('/gsma/rsp2/es9plus/authenticateClient', methods=['POST'])
    @rsp_api_wrapper
    def authenticateClient(self, request: IRequest, content: dict) -> dict:
        """See ES9+ AuthenticateClient in SGP.22 Section 5.6.3"""
        transactionId = content['transactionId']

        authenticateServerResp_bin = b64decode(content['authenticateServerResponse'])
        authenticateServerResp = rsp.asn1.decode('AuthenticateServerResponse', authenticateServerResp_bin)
        logger.debug("Rx %s: %s" % authenticateServerResp)
        if authenticateServerResp[0] == 'authenticateResponseError':
            r_err = authenticateServerResp[1]
            #r_err['transactionId']
            #r_err['authenticateErrorCode']
            raise ValueError("authenticateResponseError %s" % r_err)

        # TODO - update on the LPA side 
        r_ok = authenticateServerResp[1]
        euiccSigned1 = r_ok['euiccSigned1']
        euiccSigned1_bin = rsp.extract_euiccSigned1(authenticateServerResp_bin)
        euiccSignature1_bin = r_ok['euiccSignature1']
        euiccCertificate_dec = r_ok['euiccCertificate']
        euiccCertificate_bin = rsp.asn1.encode('Certificate', euiccCertificate_dec)
        eumCertificate_dec = r_ok['eumCertificate']
        eumCertificate_bin = rsp.asn1.encode('Certificate', eumCertificate_dec)

        # load certificate
        try:
            euicc_cert = x509.load_der_x509_certificate(euiccCertificate_bin)
        except ValueError:
            if self.zk_mode:
                logger.warning('Rejecting malformed euiccCertificate in zk mode')
                raise ApiError('8.1', '6.1', 'Verification failed (invalid euiccCertificate)')
            raise
        try:
            eum_cert = x509.load_der_x509_certificate(eumCertificate_bin)
        except ValueError:
            if self.zk_mode:
                logger.warning('Rejecting malformed eumCertificate in zk mode')
                raise ApiError('8.1', '6.1', 'Verification failed (invalid eumCertificate)')
            raise

        # Verify that the transactionId is known and relates to an ongoing RSP session.  Otherwise, the SM-DP+
        # SHALL return a status code "TransactionId - Unknown"
        ss = self.rss.get(transactionId, None)

        if ss is None:
            raise ApiError('8.10.1', '3.9', 'Unknown')
        ss.euicc_cert = euicc_cert
        ss.eum_cert = eum_cert

        #* h_cert (ie H''(PCert_U)) — must hash the EXACT on-wire DER bytes of
        # the eUICC certificate.  asn1tools encode/decode is not guaranteed to
        # round-trip byte-for-byte for the applet's hand-rolled cert, and the
        # MNO does the same raw-byte extraction on its BF42 path, so we use
        # the same helper here to keep h_cert consistent across both servers.
        h_cert = hash_fn(extract_pcert_from_bf(authenticateServerResp_bin, 0xbf38))
        ss.setHCert(h_cert)
        self.rss[transactionId] = ss

        # EUM chain validation: SGP.22 mandates it, but zk mode uses a self-signed
        # eUICC cert without an EUM issuer, so walking the chain would fail.  Skip
        # the chain check in zk mode — we still verify euiccSignature1 below.
        if not self.zk_mode:
            # Verify that the Root Certificate of the eUICC certificate chain corresponds to the
            # euiccCiPKIdToBeUsed
            if cert_get_auth_key_id(eum_cert) != ss.ci_cert_id:
                raise ApiError('8.11.1', '3.9', 'Unknown')

            # Verify the validity of the eUICC certificate chain
            cs = CertificateSet(self.ci_get_cert_for_pkid(ss.ci_cert_id))
            cs.add_intermediate_cert(eum_cert)
            try:
                cs.verify_cert_chain(euicc_cert)
            except VerifyError:
                raise ApiError('8.1.3', '6.1', 'Verification failed (certificate chain)')
            #   raise ApiError('8.1.3', '6.3', 'Expired')

        # TODO - change to verify the pseudonymous certificate
        # TODO - check that this works with the updated EuiccSigned1
        # Verify euiccSignature1 over euiccSigned1 using pubkey from euiccCertificate.
        # Otherwise, the SM-DP+ SHALL return a status code "eUICC - Verification failed"
        # This runs in BOTH zk and normal mode — the zk mode skips only chain walking.
        if not self._ecdsa_verify(euicc_cert, euiccSignature1_bin, euiccSigned1_bin):
            raise ApiError('8.1', '6.1', 'Verification failed (euiccSignature1 over euiccSigned1)')

        if self.zk_mode:
            elig = euiccSigned1.get('eligibilityData', None)
            if elig is None:
                raise ApiError('8.1', '6.1', 'Eligibility data missing (--zk mode)')

            # Enforce dynamic token-expiry window at the LPA-facing authenticateClient step.
            if not ss.expiry:
                raise ApiError('0.1', '2.2', 'Missing auth token expiry')
            try:
                expiry_dt = decode_expiry(ss.expiry)
            except Exception:
                raise ApiError('0.1', '2.2', 'Malformed auth token expiry')
            if utcnow() > expiry_dt:
                raise ApiError('0.1', '1.4', 'Authorization token expired')

            ss.h_pid = elig['hpid']
            ss.sig_cred = elig['sigCred']
            ss.auth_tok = elig['authToken']
            ss.root_auth = elig['accRoot']
            ss.sig_root = elig['sigRoot']
            ss.pi_inc_bytes = elig['accProof']
            ss.pi_inc = deserialize_proof(ss.pi_inc_bytes)
    

        ss.eid = ss.euicc_cert.subject.get_attributes_for_oid(x509.oid.NameOID.SERIAL_NUMBER)[0].value
        logger.debug("EID (from eUICC cert): %s" % ss.eid)

        # Verify EID is within permitted range of EUM certificate
        # if not validate_eid_range(ss.eid, eum_cert):
        #     raise ApiError('8.1.4', '6.1', 'EID is not within the permitted range of the EUM certificate')

        # Verify that the serverChallenge attached to the ongoing RSP session matches the
        # serverChallenge returned by the eUICC. Otherwise, the SM-DP+ SHALL return a status code "eUICC -
        # Verification failed".
        if euiccSigned1['serverChallenge'] != ss.serverChallenge:
            raise ApiError('8.1', '6.1', 'Verification failed (serverChallenge)')

        # #* Added validation for the 
        # # TODO - update encoding type if necessary
        # # TODO - check that the euiccSigned1 is the correct type - ie a dictionary of the expected values
        # if not self.validateEligibilityBundle(cs.root_cert.public_bytes(Encoding.X962), euiccSignature1_bin, euiccSigned1):
        #     raise ApiError('20.1', '6.1', 'Failed to validate Eligibility Bundle')

        # If ctxParams1 contains a ctxParamsForCommonAuthentication data object, the SM-DP+ Shall [...]
        # considering all the various cases, profile state, etc.
        iccid_str = None
        if euiccSigned1['ctxParams1'][0] == 'ctxParamsForCommonAuthentication':
            cpca = euiccSigned1['ctxParams1'][1]
            matchingId = cpca.get('matchingId', None)
            if not matchingId:
                raise ApiError('8.2.6', '3.8', 'Refused')
            if matchingId:
                # look up profile based on matchingID.  We simply check if a given file exists for now..
                path = os.path.join(self.upp_dir, matchingId) + '.der'
                # prevent directory traversal attack
                if os.path.commonprefix((os.path.realpath(path),self.upp_dir)) != self.upp_dir:
                    raise ApiError('8.2.6', '3.8', 'Refused')
                if not os.path.isfile(path) or not os.access(path, os.R_OK):
                    raise ApiError('8.2.6', '3.8', 'Refused')
                ss.matchingId = matchingId
                with open(path, 'rb') as f:
                    pes = saip.ProfileElementSequence.from_der(f.read())
                    iccid_str = b2h(pes.get_pe_for_type('header').decoded['iccid'])
        else:
            # there's currently no other option in the ctxParams1 choice, so this cannot happen
            raise ApiError('1.3.1', '2.2', 'ctxParams1 missing mandatory ctxParamsForCommonAuthentication')

        # FIXME: we actually want to perform the profile binding herr, and read the profile metadata from the profile

        if self.zk_mode:
            if not isinstance(ss.pk_mno, ec.EllipticCurvePublicKey):
                raise ApiError('0.1', '2.2', 'MNO public key not of compatible type')

            # The applet signs sig_cred / sig_root / auth_tok over the real h_cert
            # (SHA256 of its euiccCertificate_bin) using its local FIXED_MNO scalar.
            # Signatures arrive as raw 64-byte r||s — convert to DER before verify.
            try:
                ss.pk_mno.verify(ecdsa_tr03111_to_dss(ss.sig_cred),
                                 ss.h_pid + h_cert + ss.mnoid,
                                 ec.ECDSA(hashes.SHA256()))
            except InvalidSignature:
                raise ApiError('0.1', '1.2', 'Failed to verify MNO credential signature')

            try:
                # Verify MNO signature over root_auth (== h_pid for single-leaf accumulator)
                ss.pk_mno.verify(ecdsa_tr03111_to_dss(ss.sig_root),
                                 ss.root_auth,
                                 ec.ECDSA(hashes.SHA256()))
            except InvalidSignature:
                raise ApiError('0.1', '1.3', 'Failed to verify root signature')

            try:
                # Verify MNO signature over auth_tok payload (h_pid || h_cert || mnoid || expiry)
                ss.pk_mno.verify(ecdsa_tr03111_to_dss(ss.auth_tok),
                                 ss.h_pid + h_cert + ss.mnoid + ss.expiry,
                                 ec.ECDSA(hashes.SHA256()))
            except InvalidSignature:
                raise ApiError('0.1', '1.2', 'Failed to verify authorization token signature')

            if isinstance(ss.L_auth, rsp.MerkleAccumulator):
                if not ss.h_pid:
                    raise ApiError('0.1', '1.3', 'Missing H_pid')
                if not ss.root_auth:
                    raise ApiError('0.1', '1.3', 'Missing root_auth')
                if not ss.L_auth.verifyProof(ss.h_pid.hex(), ss.pi_inc, ss.root_auth):
                    raise ApiError('0.1', '1.3', 'Failed to Verify Inclusion Proof')
            else:
                raise ApiError('0.1', '2.3', 'Accumulator not of a valid type (ie Merkle Accumulator defined in rsp.py)')

            # Spend token once eligibility is validated.
            if isinstance(ss.L_spent, rsp.MerkleAccumulator) and ss.auth_tok:
                ss.L_spent.add(ss.auth_tok.hex())
         

        # Put together profileMetadata + _bin
        ss.profileMetadata = ProfileMetadata(iccid_bin=h2b(swap_nibbles(iccid_str)), spn="OsmocomSPN", profile_name=matchingId)
        # enable notifications for all operations
        for event in ['enable', 'disable', 'delete']:
            ss.profileMetadata.add_notification(event, self.server_hostname)
        profileMetadata_bin = ss.profileMetadata.gen_store_metadata_request()

        # Put together smdpSigned2 + _bin
        smdpSigned2 = {
            'transactionId': h2b(ss.transactionId),
            'ccRequiredFlag': False,        # whether the Confirmation Code is required
            #'bppEuiccOtpk': None,           # whether otPK.EUICC.ECKA already used for binding the BPP, tag '5F49'
            }
        smdpSigned2_bin = rsp.asn1.encode('SmdpSigned2', smdpSigned2)

        ss.smdpSignature2_do = b'\x5f\x37\x40' + self.dp_pb.ecdsa_sign(smdpSigned2_bin + b'\x5f\x37\x40' + euiccSignature1_bin)

        # update non-volatile state with updated ss object
        self.rss[transactionId] = ss
        return {
            'transactionId': transactionId,
            'profileMetadata': b64encode2str(profileMetadata_bin),
            'smdpSigned2': b64encode2str(smdpSigned2_bin),
            'smdpSignature2': b64encode2str(ss.smdpSignature2_do),
            'smdpCertificate': b64encode2str(self.dp_pb.get_cert_as_der()), # CERT.DPpb.SIG
        }

    @app.route('/gsma/rsp2/es9plus/getBoundProfilePackage', methods=['POST'])
    @rsp_api_wrapper
    def getBoundProfilePackage(self, request: IRequest, content: dict) -> dict:
        """See ES9+ GetBoundProfilePackage SGP.22 Section 5.6.2"""
        transactionId = content['transactionId']

        # Verify that the received transactionId is known and relates to an ongoing RSP session
        ss = self.rss.get(transactionId, None)
        if not ss:
            raise ApiError('8.10.1', '3.9', 'The RSP session identified by the TransactionID is unknown')

        prepDownloadResp_bin = b64decode(content['prepareDownloadResponse'])
        prepDownloadResp = rsp.asn1.decode('PrepareDownloadResponse', prepDownloadResp_bin)
        logger.debug("Rx %s: %s" % prepDownloadResp)

        if prepDownloadResp[0] == 'downloadResponseError':
            err_code = prepDownloadResp[1]
            raise ApiError('8.1', '6.1', 'PrepareDownload failed: downloadErrorCode=%s' % err_code)

        r_ok = prepDownloadResp[1]

        # Verify the euiccSignature2 computed over euiccSigned2 and smdpSignature2 using the PK.EUICC.SIG attached to the ongoing RSP session
        euiccSigned2 = r_ok['euiccSigned2']
        euiccSigned2_bin = rsp.extract_euiccSigned2(prepDownloadResp_bin)
        if not self._ecdsa_verify(ss.euicc_cert, r_ok['euiccSignature2'], euiccSigned2_bin + ss.smdpSignature2_do):
            raise ApiError('8.1', '6.1', 'eUICC signature is invalid')

        # not in spec: Verify that signed TransactionID is outer transaction ID
        if h2b(transactionId) != euiccSigned2['transactionId']:
            raise ApiError('8.10.1', '3.9', 'The signed transactionId != outer transactionId')

        # store otPK.EUICC.ECKA in session state
        ss.euicc_otpk = euiccSigned2['euiccOtpk']
        logger.debug("euiccOtpk: %s" % (b2h(ss.euicc_otpk)))

        # Generate a one-time ECKA key pair (ot{PK,SK}.DP.ECKA) using the curve indicated by the Key Parameter
        # Reference value of CERT.DPpb.ECDDSA
        logger.debug("curve = %s" % self.dp_pb.get_curve())
        ss.smdp_ot = ec.generate_private_key(self.dp_pb.get_curve())
        # extract the public key in (hopefully) the right format for the ES8+ interface
        ss.smdp_otpk = ss.smdp_ot.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
        logger.debug("smdpOtpk: %s" % b2h(ss.smdp_otpk))
        logger.debug("smdpOtsk: %s" % b2h(ss.smdp_ot.private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption())))

        ss.host_id = b'mahlzeit'

        # Generate Session Keys using the CRT, otPK.eUICC.ECKA and otSK.DP.ECKA according to annex G
        euicc_public_key = ec.EllipticCurvePublicKey.from_encoded_point(ss.smdp_ot.curve, ss.euicc_otpk)
        ss.shared_secret = ss.smdp_ot.exchange(ec.ECDH(), euicc_public_key)
        logger.debug("shared_secret: %s" % b2h(ss.shared_secret))

        #  Perform actual protection + binding of profile package (or return  pre-bound one)
        with open(os.path.join(self.upp_dir, ss.matchingId)+'.der', 'rb') as f:
            upp = UnprotectedProfilePackage.from_der(f.read(), metadata=ss.profileMetadata)
            # HACK: Use empty PPP as we're still debugging the configureISDP step, and we want to avoid
            # cluttering the log with stuff happening after the failure
            #upp = UnprotectedProfilePackage.from_der(b'', metadata=ss.profileMetadata)
        if False:
            # Use random keys
            bpp = BoundProfilePackage.from_upp(upp)
        elif self.zk_mode:
            from pySim.esim.bsp import bsp_key_derivation
            # bsp_key_derivation() returns (s_enc, s_mac, initial_mcv).
            s_enc, s_mac, initial_mcv = bsp_key_derivation(
                ss.shared_secret,
                key_type=0x88,
                key_length=16,
                host_id=ss.host_id,
                eid=h2b(ss.eid),
            )
            ppp = ProtectedProfilePackage.from_upp(upp, BspInstance(s_enc, s_mac, initial_mcv))
            bpp = BoundProfilePackage.from_ppp(ppp)
        else:
            ppp = ProtectedProfilePackage.from_upp(upp, BspInstance(b'\x00'*16, b'\x11'*16, b'\x22'*16))
            bpp = BoundProfilePackage.from_ppp(ppp)

        # update non-volatile state with updated ss object
        self.rss[transactionId] = ss
        return {
            'transactionId': transactionId,
            'boundProfilePackage': b64encode2str(bpp.encode(ss, self.dp_pb)),
        }

    @app.route('/gsma/rsp2/es2plus/downloadOrder', methods=['POST'])
    @rsp_api_wrapper
    def downloadOrder(self, request: IRequest, content: dict) -> dict:
        eid = content.get('eid')
        iccid = content.get('iccid') or self._allocate_zk_iccid(eid)
        self._pending_orders[iccid] = {
            'eid': eid,
            'state': 'ordered',
            'profileType': content.get('profileType')
        }
        return {'iccid': iccid}

    @app.route('/gsma/rsp2/es2plus/confirmOrder', methods=['POST'])
    @rsp_api_wrapper
    def confirmOrder(self, request: IRequest, content: dict) -> dict:
        iccid = content['iccid']
        order = self._pending_orders.get(iccid)
        if order is None:
            raise ApiError('8.2.6', '3.8', 'Refused')

        matching_id = content.get('matchingId') or self._allocate_matching_id(iccid, order.get('eid'))
        order['matchingId'] = matching_id
        order['state'] = 'confirmed'
        self._ensure_upp_for_matching_id(matching_id)
        return {
            'eid': order.get('eid'),
            'matchingId': matching_id,
            'smdpAddress': self.server_hostname
        }

    @app.route('/gsma/rsp2/es2plus/releaseProfile', methods=['POST'])
    @rsp_api_wrapper
    def releaseProfile(self, request: IRequest, content: dict) -> dict:
        iccid = content['iccid']
        if iccid in self._pending_orders:
            self._pending_orders[iccid]['state'] = 'released'
        return {}

    def _allocate_zk_iccid(self, eid: Optional[str]) -> str:
        digest = hash_fn((eid or FIXED_TEST_EID.decode('ascii')).encode('ascii')).hex()
        digits = ''.join(c for c in digest if c.isdigit())
        return ('89049032' + digits + '0000000000')[:18]

    def _allocate_matching_id(self, iccid: str, eid: Optional[str]) -> str:
        digest = hash_fn((iccid + (eid or '')).encode('ascii')).hex().upper()
        return 'ZK' + digest[:14]

    def _ensure_upp_for_matching_id(self, matching_id: str) -> None:
        target = os.path.join(self.upp_dir, matching_id) + '.der'
        if os.path.exists(target):
            return

        candidates = ['zkesimTest.der', 'algtestJc305.der', 'TS48V1-A-UNIQUE.der']
        source = None
        for candidate in candidates:
            path = os.path.join(self.upp_dir, candidate)
            if os.path.isfile(path):
                source = path
                break
        if source is None:
            for name in os.listdir(self.upp_dir):
                if name.endswith('.der'):
                    source = os.path.join(self.upp_dir, name)
                    break
        if source is None:
            raise ApiError('8.2.6', '3.8', 'No UPP available for ordered profile')

        try:
            os.symlink(os.path.basename(source), target)
        except OSError:
            with open(source, 'rb') as src:
                data = src.read()
            with open(target, 'wb') as dst:
                dst.write(data)

    @app.route('/gsma/rsp2/es9plus/handleNotification', methods=['POST'])
    @rsp_api_wrapper
    def handleNotification(self, request: IRequest, content: dict) -> dict:
        """See ES9+ HandleNotification in SGP.22 Section 5.6.4"""
        # SGP.22 Section 6.3: "A normal notification function execution status (MEP Notification)
        # SHALL be indicated by the HTTP status code '204' (No Content) with an empty HTTP response body"
        request.setResponseCode(204)
        pendingNotification_bin = b64decode(content['pendingNotification'])
        pendingNotification = rsp.asn1.decode('PendingNotification', pendingNotification_bin)
        logger.debug("Rx %s: %s" % pendingNotification)
        if pendingNotification[0] == 'profileInstallationResult':
            profileInstallRes = pendingNotification[1]
            pird = profileInstallRes['profileInstallationResultData']
            transactionId = b2h(pird['transactionId'])
            ss = self.rss.get(transactionId, None)
            if ss is None:
                logger.warning(f"Unable to find session for transactionId: {transactionId}")
                return None  # Will return HTTP 204 with empty body
            profileInstallRes['euiccSignPIR']
            pird_bin = rsp.asn1.encode('ProfileInstallationResultData', pird)
            # verify eUICC signature
            if not self._ecdsa_verify(ss.euicc_cert, profileInstallRes['euiccSignPIR'], pird_bin):
                raise Exception('ECDSA signature verification failed on notification')
            logger.debug("Profile Installation Final Result: %s", pird['finalResult'])
            # remove session state
            del self.rss[transactionId]
        elif pendingNotification[0] == 'otherSignedNotification':
            otherSignedNotif = pendingNotification[1]
            euiccCertificate_bin = rsp.asn1.encode('Certificate', otherSignedNotif['euiccCertificate'])
            eumCertificate_bin = rsp.asn1.encode('Certificate', otherSignedNotif['eumCertificate'])
            euicc_cert = x509.load_der_x509_certificate(euiccCertificate_bin)
            eum_cert = x509.load_der_x509_certificate(eumCertificate_bin)
            ci_cert_id = cert_get_auth_key_id(eum_cert)
            # Verify the validity of the eUICC certificate chain
            cs = CertificateSet(self.ci_get_cert_for_pkid(ci_cert_id))
            cs.add_intermediate_cert(eum_cert)
            cs.verify_cert_chain(euicc_cert)
            tbs_bin = rsp.asn1.encode('NotificationMetadata', otherSignedNotif['tbsOtherNotification'])
            if not self._ecdsa_verify(euicc_cert, otherSignedNotif['euiccNotificationSignature'], tbs_bin):
                raise Exception('ECDSA signature verification failed on notification')
            other_notif = otherSignedNotif['tbsOtherNotification']
            pmo = PMO.from_bitstring(other_notif['profileManagementOperation'])
            eid = euicc_cert.subject.get_attributes_for_oid(x509.oid.NameOID.SERIAL_NUMBER)[0].value
            iccid = other_notif.get('iccid', None)
            if iccid:
                iccid = swap_nibbles(b2h(iccid))
            logger.debug("handleNotification: EID %s: %s of %s" % (eid, pmo, iccid))
        else:
            raise ValueError(pendingNotification)

    #@app.route('/gsma/rsp3/es9plus/handleDeviceChangeRequest, methods=['POST']')
    #@rsp_api_wrapper
        #"""See ES9+ ConfirmDeviceChange in SGP.22 Section 5.6.6"""
        # TODO: implement this

    @app.route('/gsma/rsp2/es9plus/cancelSession', methods=['POST'])
    @rsp_api_wrapper
    def cancelSession(self, request: IRequest, content: dict) -> dict:
        """See ES9+ CancelSession in SGP.22 Section 5.6.5"""
        logger.debug("Rx JSON: %s" % content)
        transactionId = content['transactionId']

        # Verify that the received transactionId is known and relates to an ongoing RSP session
        ss = self.rss.get(transactionId, None)
        if ss is None:
            raise ApiError('8.10.1', '3.9', 'The RSP session identified by the transactionId is unknown')

        cancelSessionResponse_bin = b64decode(content['cancelSessionResponse'])
        cancelSessionResponse = rsp.asn1.decode('CancelSessionResponse', cancelSessionResponse_bin)
        logger.debug("Rx %s: %s" % cancelSessionResponse)

        if cancelSessionResponse[0] == 'cancelSessionResponseError':
            # FIXME: print some error
            return
        cancelSessionResponseOk = cancelSessionResponse[1]
        ecsr = cancelSessionResponseOk['euiccCancelSessionSigned']
        ecsr_bin = rsp.asn1.encode('EuiccCancelSessionSigned', ecsr)
        # Verify the eUICC signature (euiccCancelSessionSignature) using the PK.EUICC.SIG attached to the ongoing RSP session
        if not self._ecdsa_verify(ss.euicc_cert, cancelSessionResponseOk['euiccCancelSessionSignature'], ecsr_bin):
            raise ApiError('8.1', '6.1', 'eUICC signature is invalid')

        # Verify that the received smdpOid corresponds to one advertised in
        # CERT.DPauth.SIG SubjectAltName.  Depending on cert profile/tooling,
        # this may appear either as OtherName(type_id=...) or RegisteredID.
        subj_alt_name = self.dp_auth.get_subject_alt_name()
        smdp_oid = x509.ObjectIdentifier(ecsr['smdpOid'])
        other_name_oids = [on.type_id for on in subj_alt_name.get_values_for_type(x509.OtherName)]
        registered_ids = subj_alt_name.get_values_for_type(x509.RegisteredID)
        if smdp_oid not in other_name_oids and smdp_oid not in registered_ids:
            raise ApiError('8.8', '3.10', 'The provided SM-DP+ OID is invalid.')

        if ecsr['transactionId'] != h2b(transactionId):
            raise ApiError('8.10.1', '3.9', 'The signed transactionId != outer transactionId')

        # TODO: 1. Notify the Operator using the function "ES2+.HandleNotification" function
        # TODO: 2. Terminate the corresponding pending download process.
        # TODO: 3. If required, execute the SM-DS Event Deletion procedure described in section 3.6.3.

        # delete actual session data
        del self.rss[transactionId]
        return { 'transactionId': transactionId }

    # -------------------------------------------------------------------------
    # MNO helper methods (internal — not HTTP routes)
    # -------------------------------------------------------------------------

    def _mno_sign_raw(self, data: bytes) -> bytes:
        """Sign data with sk_MNO, return raw 64-byte r||s (TR-03111 format)."""
        der_sig = self._sk_mno.sign(data, ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der_sig)
        return r.to_bytes(32, 'big') + s.to_bytes(32, 'big')

    def _zk_download_order_internal(self, eid: str) -> str:
        """Allocate a deterministic ICCID for a ZK download order."""
        h = hash_fn(eid.encode('ascii'))
        # '89049032' prefix + 10 decimal digits derived from hash = 18 digits
        suffix = str(int.from_bytes(h[:5], 'big') % 10**10).zfill(10)
        iccid = '89049032' + suffix
        self._zk_pending_orders[iccid] = {'eid': eid, 'state': 'ordered'}
        logger.info(f"MNO ES2+: downloadOrder eid={eid} → iccid={iccid}")
        return iccid

    def _zk_confirm_order_internal(self, iccid: str, hpid: bytes) -> str:
        """Confirm order and ensure a UPP symlink exists for the derived matchingId."""
        # Deterministic matchingId: 'ZK-' + first 6 bytes of hash as hex
        raw = hash_fn(iccid.encode('ascii') + hpid)
        matching_id = 'ZK-' + raw[:6].hex().upper()

        target = os.path.join(self.upp_dir, matching_id + '.der')
        if not os.path.exists(target):
            # Symlink to the first real (non-symlink) UPP in the directory
            for fname in sorted(os.listdir(self.upp_dir)):
                candidate = os.path.join(self.upp_dir, fname)
                if fname.endswith('.der') and not os.path.islink(candidate):
                    os.symlink(os.path.abspath(candidate), target)
                    logger.info(f"MNO ES2+: confirmOrder symlink {matching_id}.der → {fname}")
                    break
            else:
                raise ApiError('8.2', '3.8', 'No test UPP available for ZK download')

        if iccid in self._zk_pending_orders:
            self._zk_pending_orders[iccid].update({'matchingId': matching_id, 'state': 'confirmed'})
        logger.info(f"MNO ES2+: confirmOrder iccid={iccid} matchingId={matching_id}")
        return matching_id

    # -------------------------------------------------------------------------
    # MNO HTTP routes  (Phase 1 / 2 — ZK-eSIM protocol)
    # -------------------------------------------------------------------------

    @app.route('/zk-esim/v1/getMNOChallenge', methods=['POST'])
    @mno_api_wrapper
    def getMNOChallenge(self, request: IRequest, content: dict) -> dict:
        """Phase 1 step 2: issue a fresh 16-byte MNO challenge."""
        mno_challenge = os.urandom(16)
        request_id = uuid.uuid4().hex.upper()
        self._mno_sessions[request_id] = {
            'mnoChallenge': mno_challenge,
            'created_at':   utcnow().isoformat(),
            'complete':     False,
        }
        logger.info(f"MNO: getMNOChallenge requestId={request_id}")
        return {
            'requestId':     request_id,
            'mnoChallenge':  base64.b64encode(mno_challenge).decode('ascii'),
        }

    @app.route('/zk-esim/v1/zkRequest', methods=['POST'])
    @mno_api_wrapper
    def zkRequest(self, request: IRequest, content: dict) -> dict:
        """Phase 1/2 main handler: verify ZK proof, run internal ES2+ order, issue credentials."""
        request_id   = content.get('requestId')
        zk_resp_b64  = content.get('zkProfileResponse')
        if not request_id or not zk_resp_b64:
            raise ApiError('1.1', '2.2', 'Missing requestId or zkProfileResponse')

        session = self._mno_sessions.get(request_id)
        if session is None:
            raise ApiError('1.2', '3.9', 'Unknown requestId')
        if session.get('complete'):
            raise ApiError('1.2', '1.2', 'requestId already consumed')

        # --- Parse BF42 TLV ---
        zk_resp_bin = base64.b64decode(zk_resp_b64)
        try:
            parsed = _parse_zk_profile_response(zk_resp_bin)
        except Exception as exc:
            raise ApiError('1.3', '2.2', f'Malformed ZKProfileResponse: {exc}')

        # --- Challenge replay check ---
        if parsed['mnoChallenge'] != session['mnoChallenge']:
            raise ApiError('1.4', '6.1', 'mnoChallenge mismatch')

        # --- pkMno / pkLea integrity: applet must use our hardcoded keys ---
        if parsed['pkMno'] != self._pk_mno_bytes:
            raise ApiError('1.5', '6.1', 'pkMno in ZKStatement does not match MNO key')
        if parsed['pkLea'] != FIXED_LEA_PUBLIC_W:
            raise ApiError('1.5', '6.1', 'pkLea in ZKStatement does not match LEA key')

        # --- Extract pk_U, EID and H(σ_EID) from pcertU ---
        try:
            euicc_cert = x509.load_der_x509_certificate(parsed['pcertU_der'])
        except Exception as exc:
            raise ApiError('1.6', '6.1', f'Cannot parse pcertU: {exc}')
        pk_u_bytes = euicc_cert.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
        eid = euicc_cert.subject.get_attributes_for_oid(x509.oid.NameOID.SERIAL_NUMBER)[0].value

        # --- Verify credential binding: H(σ_EID) in ZKStatement == H(σ_EID) in PCert_U ---
        _H_SIG_EID_OID = x509.ObjectIdentifier('2.23.146.1.2.1.8')
        try:
            cert_ext = euicc_cert.extensions.get_extension_for_oid(_H_SIG_EID_OID)
            h_sigma_eid_cert = cert_ext.value.value  # raw bytes from UnrecognizedExtension
        except x509.ExtensionNotFound:
            raise ApiError('1.6', '6.1', 'PCert_U missing hSigmaEid extension')
        if h_sigma_eid_cert != parsed['hSigmaEid']:
            raise ApiError('1.6', '6.1', 'hSigmaEid mismatch: ZKStatement does not match PCert_U')

        # --- Verify Schnorr proof π_req ---
        if not _schnorr_verify_p256(pk_u_bytes, parsed['stmt_raw'], parsed['proof']):
            raise ApiError('1.7', '6.1', 'Schnorr proof verification failed')
        logger.info(f"MNO: Schnorr proof verified for EID={eid}")

        # --- Compute hpid, h_cert; replay check ---
        h_pid     = hash_fn(parsed['pid'])
        h_pid_hex = h_pid.hex()
        h_cert    = hash_fn(parsed['pcertU_der'])

        if h_pid_hex in self._L_auth.leaves:
            raise ApiError('1.8', '1.2', 'Replay: hpid already in accumulator')

        # --- Internal ES2+: downloadOrder + confirmOrder ---
        iccid      = self._zk_download_order_internal(eid)
        matching_id = self._zk_confirm_order_internal(iccid, h_pid)

        # --- Accumulator update ---
        self._L_auth.add(h_pid_hex)
        root_auth    = bytes(self._L_auth.get_root())
        pi_inc       = self._L_auth.generateProof(h_pid_hex)
        pi_inc_bytes = serialize_proof(pi_inc)

        # --- MNO signs credentials (raw 64-byte r||s, TR-03111) ---
        sig_cred = self._mno_sign_raw(h_pid + h_cert + FIXED_MNOID)
        sig_root = self._mno_sign_raw(root_auth)
        auth_tok = self._mno_sign_raw(h_pid + h_cert + FIXED_MNOID + FIXED_EXPIRY)

        # --- Build BF43 SetEligibilityDataRequest TLV ---
        set_elig_tlv = _build_set_eligibility_tlv(
            h_pid, sig_cred, auth_tok, root_auth, sig_root, pi_inc_bytes)

        # --- Mark session complete ---
        session.update({
            'eid': eid, 'hpid': h_pid, 'iccid': iccid,
            'matchingId': matching_id, 'complete': True,
        })
        self._mno_sessions[request_id] = session

        logger.info(f"MNO: zkRequest complete requestId={request_id} matchingId={matching_id}")
        return {
            'setEligibilityDataRequest': base64.b64encode(set_elig_tlv).decode('ascii'),
            'iccid':       iccid,
            'matchingId':  matching_id,
            'smdpAddress': self.server_hostname,
        }

    @app.route('/zk-esim/v1/ack', methods=['POST'])
    @mno_api_wrapper
    def zkAck(self, request: IRequest, content: dict) -> dict:
        """Phase 2 ack: LPA reports SetEligibilityDataResponse outcome."""
        request_id = content.get('requestId', '?')
        ok = content.get('ok', False)
        logger.info(f"MNO: ack requestId={request_id} ok={ok}")
        return {}

    # -------------------------------------------------------------------------
    # MNO Phase 0 routes (RegisterAndIssue + CertInit)
    # -------------------------------------------------------------------------

    @app.route('/zk-esim/v1/registerChallenge', methods=['POST'])
    @mno_api_wrapper
    def registerChallenge(self, request: IRequest, content: dict) -> dict:
        """Phase 0.a step 1: generate blind-Schnorr nonce commitment R_MNO = r_MNO·G."""
        q = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
        r_mno = int.from_bytes(os.urandom(32), 'big') % q
        if r_mno == 0:
            r_mno = 1
        R_mno = ec.derive_private_key(r_mno, ec.SECP256R1()).public_key().public_bytes(
            Encoding.X962, PublicFormat.UncompressedPoint
        )  # 65 bytes
        request_id = uuid.uuid4().hex.upper()
        self._phase0_sessions[request_id] = {
            'r_mno': r_mno,
            'type': 'register',
            'complete': False,
        }
        logger.info(f"Phase0: registerChallenge requestId={request_id}")
        return {
            'requestId': request_id,
            'rMno': base64.b64encode(R_mno).decode('ascii'),
        }

    @app.route('/zk-esim/v1/registerCredential', methods=['POST'])
    @mno_api_wrapper
    def registerCredential(self, request: IRequest, content: dict) -> dict:
        """Phase 0.a step 2: verify π_auth, compute blind-Schnorr partial sig s = (r_MNO − e·sk_MNO) mod q."""
        request_id = content.get('requestId')
        e_b64 = content.get('e')
        pi_auth_b64 = content.get('piAuth')
        if not request_id or not e_b64 or not pi_auth_b64:
            raise ApiError('0.1', '2.2', 'Missing requestId, e or piAuth')

        session = self._phase0_sessions.get(request_id)
        if session is None or session.get('type') != 'register':
            raise ApiError('0.2', '3.9', 'Unknown Phase 0.a requestId')
        if session.get('complete'):
            raise ApiError('0.2', '1.2', 'requestId already consumed')

        e_bytes = base64.b64decode(e_b64)       # 32 bytes
        pi_auth_der = base64.b64decode(pi_auth_b64)

        # Verify π_auth = ECDSA(sk_b, e) — proves device is authorised without revealing m
        pk_b = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), FIXED_DEVICE_W)
        try:
            pk_b.verify(pi_auth_der, e_bytes, ec.ECDSA(hashes.SHA256()))
        except Exception:
            raise ApiError('0.3', '6.1', 'π_auth verification failed')

        # Blind-Schnorr partial signature: s = (r_MNO − e·sk_MNO) mod q
        q = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
        r_mno = session['r_mno']
        sk_mno_int = self._sk_mno.private_numbers().private_value
        e_int = int.from_bytes(e_bytes, 'big')
        s_int = (r_mno - e_int * sk_mno_int) % q
        s_bytes = s_int.to_bytes(32, 'big')

        session.update({'complete': True})
        logger.info(f"Phase0: registerCredential OK requestId={request_id}")
        return {
            's': base64.b64encode(s_bytes).decode('ascii'),
        }

    @app.route('/zk-esim/v1/certInitRequest', methods=['POST'])
    @mno_api_wrapper
    def certInitRequest(self, request: IRequest, content: dict) -> dict:
        """Phase 0.b step 1: verify eUICC binding proof and credential hash; issue PCert_U."""
        pk_u_b64 = content.get('pkU')
        pi_bind_b64 = content.get('piBind')
        h_sigma_eid_b64 = content.get('hSigmaEid')
        if not pk_u_b64 or not pi_bind_b64 or not h_sigma_eid_b64:
            raise ApiError('0.4', '2.2', 'Missing pkU, piBind or hSigmaEid')

        pk_u_bytes = base64.b64decode(pk_u_b64)          # 65 bytes uncompressed
        pi_bind_der = base64.b64decode(pi_bind_b64)
        h_sigma_eid = base64.b64decode(h_sigma_eid_b64)  # 32 bytes SHA-256(σ_EID)
        if len(h_sigma_eid) != 32:
            raise ApiError('0.4', '2.2', 'hSigmaEid must be 32 bytes')

        # Verify π_bind: ECDSA(sk_U, pk_U || EID_BIN) using the received pk_U
        eid_bin = bytes.fromhex(FIXED_TEST_EID.decode('ascii'))[:16]
        bind_input = pk_u_bytes + eid_bin
        pk_u = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pk_u_bytes)
        try:
            pk_u.verify(pi_bind_der, bind_input, ec.ECDSA(hashes.SHA256()))
        except Exception:
            raise ApiError('0.5', '6.1', 'π_bind verification failed')

        # Issue PCert_U signed by sk_MNO acting as PCA; embed H(σ_EID) for later binding check
        eid_ascii = FIXED_TEST_EID.decode('ascii')
        pcert_u_der = _build_pcert_u(pk_u_bytes, self._sk_mno, eid_ascii, h_sigma_eid)

        logger.info("Phase0: certInitRequest OK — issued PCert_U")
        return {
            'pCertU': base64.b64encode(pcert_u_der).decode('ascii'),
        }

    @app.route('/health', methods=['GET'])
    def health(self, request: IRequest):
        request.setHeader('Content-Type', 'application/json')
        return json.dumps({'status': 'ok', 'zk_mode': self.zk_mode,
                           'mno_sessions': len(self._mno_sessions)})

    # -------------------------------------------------------------------------
    # Legacy ZK-eSIM helper (kept for reference)
    # -------------------------------------------------------------------------

        # ----------- ZK-ESIM based functions for protocol functionality -----------

    def validateEligibilityBundle(self, pkU: bytes, sig: bytes, dat: dict) -> bool:
        uePk = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pkU)
        data_bytes = json.dumps(dat).encode("utf-8")
        try:
            uePk.verify(sig, data_bytes, ec.ECDSA(hashes.SHA256()))
        except InvalidSignature:
            return False
        return True


def main(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument("-H", "--host", help="Host/IP to bind HTTP(S) to", default="localhost")
    parser.add_argument("-p", "--port", help="TCP port to bind HTTP(S) to", default=443)
    parser.add_argument("-c", "--certdir", help=f"cert subdir relative to {DATA_DIR}", default="certs")
    parser.add_argument("-s", "--nossl", help="disable built in SSL/TLS support", action='store_true', default=False)
    parser.add_argument("-v", "--verbose", help="dump more raw info", action='store_true', default=False)
    parser.add_argument("-b", "--brainpool", help="Use Brainpool curves instead of NIST",
                        action='store_true', default=False)
    parser.add_argument("-m", "--in-memory", help="Use ephermal in-memory session storage (for concurrent runs)",
                        action='store_true', default=False)
    parser.add_argument("-z", "--zk", help="Enable ZK-eSIM eligibility verification",
                        action='store_true', default=False)
    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.WARNING)

    common_cert_path = os.path.join(DATA_DIR, args.certdir)
    hs = SmDppHttpServer(
        server_hostname=HOSTNAME,
        ci_certs_path=os.path.join(common_cert_path, 'CertificateIssuer'),
        common_cert_path=common_cert_path,
        use_brainpool=args.brainpool,
        zk_mode=args.zk
    )
    if(args.nossl):
        hs.app.run(args.host, args.port)
    else:
        curve_type = 'BRP' if args.brainpool else 'NIST'
        cert_derpath = Path(common_cert_path) / 'DPtls' / f'CERT_S_SM_DP_TLS_{curve_type}.der'
        cert_pempath = Path(common_cert_path) / 'DPtls' / f'CERT_S_SM_DP_TLS_{curve_type}.pem'
        cert_skpath = Path(common_cert_path) / 'DPtls' / f'SK_S_SM_DP_TLS_{curve_type}.pem'
        dhparam_path = Path(common_cert_path) / "dhparam2048.pem"
        if not dhparam_path.exists():
            print("Generating dh params, this takes a few seconds..")
            # Generate DH parameters with 2048-bit key size and generator 2
            parameters = dh.generate_parameters(generator=2, key_size=2048)
            pem_data = parameters.parameter_bytes(encoding=Encoding.PEM,format=ParameterFormat.PKCS3)
            with open(dhparam_path, 'wb') as file:
                file.write(pem_data)
            print("DH params created successfully")

        if not cert_pempath.exists():
            print("Translating tls server cert from DER to PEM..")
            with open(cert_derpath, 'rb') as der_file:
                der_cert_data = der_file.read()

            cert = x509.load_der_x509_certificate(der_cert_data)
            pem_cert = cert.public_bytes(Encoding.PEM) #.decode('utf-8')

            with open(cert_pempath, 'wb') as pem_file:
                pem_file.write(pem_cert)

        SERVER_STRING = f'ssl:{args.port}:privateKey={cert_skpath}:certKey={cert_pempath}:dhParameters={dhparam_path}'
        print(SERVER_STRING)

        hs.app.run(host=HOSTNAME, port=args.port, endpoint_description=SERVER_STRING)

if __name__ == "__main__":
    main(sys.argv)
