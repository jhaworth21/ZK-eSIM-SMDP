#!/usr/bin/env python3
# Copyright (C) 2024 ZK-eSIM contributors
#
# Server-side performance benchmark for the additional overhead that the
# ZK-eSIM design introduces over a standard SGP.22 profile download.
#
# This is a *CPU microbenchmark*, reported PER SERVER: the three roles of the
# deployment are separate processes on separate hosts, so their costs are timed
# and totalled independently rather than pooled into one figure.
#
#   1. SM-DP+  (osmo-smdpp.py)  -- per profile download; the only role that
#                                  also pays the baseline SGP.22 transport cost
#   2. MNO     (mno-server.py)  -- per profile download (zkRequest) AND per
#                                  device enrollment (registerCredential)
#   3. PCA     (pca-server.py)  -- per profile download (certInitRequest)
#
# The PCA is on the *download* path, not the one-time enrollment path: Phase 1
# CertInit runs before every download (zkesim_workflow.sh phase0_certinit), and
# each call issues a fresh PCert_U over a freshly derived sk_U.  That freshness
# is what makes successive downloads unlinkable, so a pseudonym cert cannot be
# amortised across downloads and the PCA pays its cost once per download.
# Only the MNO's Phase 0 registerCredential is genuinely one-time per device.
#
# For each server the report gives the per-transaction cost, the cost per
# thousand / per million transactions, single-core throughput and the number of
# cores needed to sustain a target daily volume -- so each role can be sized on
# its own hardware.  A final table puts the three side by side.
#
# It deliberately excludes TLS / HTTP / ASN.1 framing and disk I/O: a standard
# (non-ZK) download pays those too, so they are not the *additional* overhead
# introduced by zkesim.  What is measured is exactly the extra public-key and
# hash work the ZK eligibility check adds on top of a baseline download.
#
# The functions exercised here are imported from the production modules
# (pySim.esim.rsp, pySim.esim.zk_utils) or invoked with the identical
# `cryptography` call patterns the servers use, so the numbers reflect the
# deployed code rather than a re-implementation.
"""ZK-eSIM server-side overhead benchmark, measured per server role.

Run inside the same environment the servers run in (the `pysim` conda env)::

    python3 zk_server_bench.py
    python3 zk_server_bench.py --iters 5000 --accumulator-size 4096
    python3 zk_server_bench.py --server mno            # one role only
    python3 zk_server_bench.py --json /tmp/zk_bench.json --csv /tmp/zk_bench.csv
"""

import argparse
import csv
import datetime
import math
import os
import platform
import statistics
import sys
import time

# Make `pySim` importable whether or not the package is pip-installed: the
# servers live in this same directory, so adding it to sys.path mirrors how
# they resolve `import pySim...` when launched from PYSIM_ROOT.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

import pySim.esim.rsp as rsp
from pySim.esim import zk_utils
from pySim.esim.zk_utils import (
    _build_pcert_u,
    _build_std_cert_u,
    ecdsa_der_to_tr03111,
    ecdsa_tr03111_to_dss,
    hash_fn,
    schnorr_verify_p256,
)

# ---------------------------------------------------------------------------
# Constants mirrored from the servers so message composition matches the wire.
# ---------------------------------------------------------------------------
FIXED_MNOID = b'MNO_id'                                          # mno-server.py
FIXED_EXPIRY = b'4102444800'                                     # mno-server.py (year 2100)
FIXED_TEST_EID = b'89049032000000000000123456789012'            # pca-server.py
EID_BIN = bytes.fromhex(FIXED_TEST_EID.decode('ascii'))[:16]    # pca-server.py bind_input

# P-256 group parameters (re-used from zk_utils so a proof we build here is
# guaranteed to verify under the production verifier).
_P256_N = zk_utils._P256_N
_P256_P = zk_utils._P256_P
_P256_A = zk_utils._P256_A
_G = (zk_utils._P256_GX, zk_utils._P256_GY)
_CURVE_P256 = ec.SECP256R1()

# ---------------------------------------------------------------------------
# The three server roles.  Every timed op is tagged with the server that runs
# it and the transaction phase it runs in, so the totals never mix roles.
# ---------------------------------------------------------------------------
SMDP, MNO, PCA = 'smdp', 'mno', 'pca'
SERVER_ORDER = (SMDP, MNO, PCA)

SERVERS = {
    SMDP: {
        'label': 'SM-DP+',
        'module': 'osmo-smdpp.py',
        'role': 'profile download server (ES9+ authenticateClient / getBoundProfilePackage)',
    },
    MNO: {
        'label': 'MNO',
        'module': 'mno-server.py',
        'role': 'eligibility authority (zkRequest per download, registerCredential per device)',
    },
    PCA: {
        'label': 'PCA',
        'module': 'pca-server.py',
        'role': 'pseudonym certificate authority (certInitRequest, once per download)',
    },
}

# Per-server cost composition.  Each item is (op_name, multiplicity) -- how
# many times that server performs the op in a single transaction (e.g. the MNO
# emits three raw ECDSA signatures per zkRequest).
#
# SM-DP+ per download -------------------------------------------------------
# Baseline (non-ZK) transport crypto: euiccSignature1, EUM chain walk, and the
# smdpSignature2 the SM-DP+ produces for the BPP.
SMDP_BASELINE = [('base.verify_euicc_sig1', 1), ('base.chain_walk', 1), ('base.smdp_sign2', 1)]
# ZK additions inside authenticateClient (osmo-smdpp.py:826-867).
SMDP_ZK_ADDON = [('smdp.verify_sig_cred', 1), ('smdp.verify_sig_root', 1),
                 ('smdp.verify_auth_tok', 1), ('smdp.merkle_verify', 1),
                 ('smdp.token_bookkeeping', 1)]
# What ZK mode *stops* doing: the self-signed ZK eUICC cert has no EUM issuer,
# so osmo-smdpp.py:734 skips the chain walk (euiccSignature1 is still verified).
SMDP_ZK_SKIPPED = [('base.chain_walk', 1)]

# MNO -----------------------------------------------------------------------
# zkRequest, minus the Schnorr verify (measured in two variants below).
MNO_DOWNLOAD_CORE = [('mno.ecdsa_sign', 3), ('mno.accumulator_recompute', 1),
                     ('mno.accumulator_genproof', 1)]
MNO_ACCUMULATOR = [('mno.accumulator_recompute', 1), ('mno.accumulator_genproof', 1)]
MNO_ENROLL = [('mno.register_device_verify', 1), ('mno.register_blind_sig', 1)]

# PCA -----------------------------------------------------------------------
# certInitRequest, run once per download: verify the pk_U||EID binding
# signature, then issue (build + sign) the pseudonym certificate PCert_U.
PCA_DOWNLOAD = [('pca.binding_verify', 1), ('pca.build_pcert', 1)]
PCA_DOWNLOAD_STD = [('pca.binding_verify', 1), ('pca.build_std_cert', 1)]


def _ec_affine_add(pt, q):
    """Single affine P-256 point addition (used once per hazmat verify).

    Uses Python's built-in modular inverse pow(x, -1, p) (extended Euclid),
    which is far cheaper than the Fermat exponentiation in zk_utils._p256_add.
    """
    if pt is None:
        return q
    if q is None:
        return pt
    x1, y1 = pt
    x2, y2 = q
    if x1 == x2 and (y1 + y2) % _P256_P == 0:
        return None
    if x1 == x2 and y1 == y2:
        lam = (3 * x1 * x1 + _P256_A) * pow(2 * y1, -1, _P256_P) % _P256_P
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, _P256_P) % _P256_P
    x3 = (lam * lam - x1 - x2) % _P256_P
    y3 = (lam * (x1 - x3) - y1) % _P256_P
    return (x3, y3)


def schnorr_verify_hazmat(pk_bytes, msg, proof):
    """Schnorr proof verification with the two heavy scalar multiplications
    delegated to OpenSSL via `cryptography` hazmat, rather than the pure-Python
    big-integer loop in zk_utils.schnorr_verify_p256.

    Verifies  s*G == R + c*PK  by checking  X(s*G - R) == X(c*PK):
      * s*G   -- full point, computed by OpenSSL through derive_private_key().
      * c*PK  -- X-coordinate, computed by OpenSSL through an ECDH exchange
                 (the shared secret IS the X-coordinate of the product point).
      * one affine subtraction (s*G - R) is done in Python; the X-coordinate
        comparison admits the trivial +/- sign relaxation, which is fine for an
        honestly generated proof (and not exploitable without the secret).

    hazmat exposes no general EC point addition or arbitrary-point scalar
    multiplication, so this is the most native verification achievable with the
    `cryptography` library alone; it is a drop-in, ~100x faster replacement for
    the prototype verifier that the MNO could adopt.
    """
    if len(proof) != 97 or len(pk_bytes) != 65 or proof[0] != 0x04 or pk_bytes[0] != 0x04:
        return False
    rx = int.from_bytes(proof[1:33], 'big')
    ry = int.from_bytes(proof[33:65], 'big')
    s = int.from_bytes(proof[65:97], 'big')
    digest = hashes.Hash(hashes.SHA256())
    digest.update(msg)
    digest.update(proof[:65])
    c = int.from_bytes(digest.finalize(), 'big') % _P256_N
    if not (0 < s < _P256_N and 0 < c < _P256_N):
        return False
    s_g = ec.derive_private_key(s, _CURVE_P256).public_key().public_numbers()
    pk = ec.EllipticCurvePublicKey.from_encoded_point(_CURVE_P256, pk_bytes)
    cpk_x = int.from_bytes(
        ec.derive_private_key(c, _CURVE_P256).exchange(ec.ECDH(), pk), 'big')
    diff = _ec_affine_add((s_g.x, s_g.y), (rx, (_P256_P - ry) % _P256_P))  # s*G - R
    return diff is not None and diff[0] == cpk_x


# ---------------------------------------------------------------------------
# Timing harness
# ---------------------------------------------------------------------------
def summarize(samples_ns):
    """Reduce a list of per-call durations (ns) to summary statistics."""
    s = sorted(samples_ns)
    n = len(s)
    mean = sum(s) / n
    return {
        'count': n,
        'mean_ns': mean,
        'median_ns': float(statistics.median(s)),
        'stdev_ns': float(statistics.pstdev(s)) if n > 1 else 0.0,
        'min_ns': float(s[0]),
        'max_ns': float(s[-1]),
        'p95_ns': float(s[min(n - 1, int(0.95 * n))]),
        'p99_ns': float(s[min(n - 1, int(0.99 * n))]),
        'ops_per_sec': (1e9 / mean) if mean else 0.0,
    }


def bench(fn, iters, warmup):
    """Time `fn` (a zero-arg callable) `iters` times after `warmup` runs."""
    for _ in range(warmup):
        fn()
    pc = time.perf_counter_ns
    samples = [0] * iters
    for i in range(iters):
        t0 = pc()
        fn()
        samples[i] = pc() - t0
    return summarize(samples)


# ---------------------------------------------------------------------------
# Local copies of two trivial SM-DP+ helpers (osmo-smdpp.py is not importable
# because of its hyphenated filename; these are byte-for-byte equivalent).
# ---------------------------------------------------------------------------
def _utcnow():
    return datetime.datetime.now(datetime.timezone.utc)


def _decode_expiry(raw):
    return datetime.datetime.fromtimestamp(int(raw.decode('ascii')), tz=datetime.timezone.utc)


# ---------------------------------------------------------------------------
# Fixture construction (excluded from all timing)
# ---------------------------------------------------------------------------
def make_cert(subject_cn, issuer_priv, issuer_cn, subject_pub, hash_alg):
    """Build a minimal X.509 cert for the baseline EUM chain-walk fixture."""
    now = _utcnow()
    return (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn)]))
        .public_key(subject_pub)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .sign(issuer_priv, hash_alg)
    )


def build_fixtures(curve, accumulator_size):
    """Construct every key, signature, proof and certificate the benchmark
    needs.  Returns a dict of zero-arg callables ('ops') plus metadata.

    Curve policy (faithful to the servers):
      * SGP.22 transport crypto (euiccSignature1, EUM chain, smdpSigned2) uses
        the selected `curve` -- this mirrors `osmo-smdpp.py --brainpool`.
      * ZK-specific crypto (MNO credential signatures, the Schnorr proof, the
        PCA pseudonym cert, the user binding signature) is pinned to P-256,
        because mno-server.py / pca-server.py hard-code SECP256R1 regardless.
    """
    f = {}                     # ops: name -> callable
    meta = {}                  # human-readable notes / sanity values
    sha256 = hashes.SHA256()
    p256 = ec.SECP256R1()

    # ---- keys -------------------------------------------------------------
    sk_mno = ec.derive_private_key(int.from_bytes(os.urandom(32), 'big') % _P256_N or 1, p256)
    pk_mno = sk_mno.public_key()
    sk_pca = ec.generate_private_key(p256)
    sk_dp = ec.generate_private_key(curve)        # SM-DP+ DPpb signing key
    sk_euicc = ec.generate_private_key(curve)
    sk_eum = ec.generate_private_key(curve)
    sk_ci = ec.generate_private_key(curve)
    sk_device = ec.generate_private_key(p256)
    pk_device = sk_device.public_key()

    # user (eUICC ZK) key -- P-256, drives both the PCA cert and the Schnorr proof
    sk_u_int = int.from_bytes(os.urandom(32), 'big') % _P256_N or 1
    pk_u_pt = zk_utils._p256_mul(sk_u_int, _G)
    pk_u_bytes = b'\x04' + pk_u_pt[0].to_bytes(32, 'big') + pk_u_pt[1].to_bytes(32, 'big')
    pk_u_obj = ec.EllipticCurvePublicKey.from_encoded_point(p256, pk_u_bytes)

    # ---- ZK eligibility values (as produced by the MNO) -------------------
    h_pid = hash_fn(os.urandom(32))
    h_cert = hash_fn(os.urandom(220))             # SHA-256 of a cert-sized blob
    h_pid_hex = h_pid.hex()

    # Real Merkle accumulator with `accumulator_size` enrolled pseudonyms.
    # Built in O(N) (populate leaves, recompute root once) instead of N adds
    # (which would be O(N^2)).  This drives the MNO's per-download O(N)
    # accumulator work (recompute + generateProof) faithfully.
    acc = rsp.MerkleAccumulator()
    acc.leaves[h_pid_hex] = h_pid
    for _ in range(max(0, accumulator_size - 1)):
        leaf = hash_fn(os.urandom(32))
        acc.leaves[leaf.hex()] = leaf
    acc._compute_root()
    root_auth = bytes(acc.get_root())          # message that sig_root is signed over

    # Inclusion proof for the SM-DP+ verifyProof() check.  rsp.verifyProof()
    # hashes siblings in *sorted* order (min,max) -- and the repo's
    # generateProof() pairs by position, so multi-leaf proofs it emits do not
    # generally verify (production uses the single-leaf root==h_pid case).  We
    # therefore build a proof of depth ceil(log2 N) that IS valid under
    # verifyProof's own rule, so the op measures the true per-call cost of an
    # inclusion check at that depth.
    proof_depth = max(0, math.ceil(math.log2(accumulator_size))) if accumulator_size > 1 else 0
    pi_inc_list = []
    cur = h_pid
    for _ in range(proof_depth):
        sib = hash_fn(os.urandom(32))
        pi_inc_list.append(sib)
        cur = hash_fn(cur + sib) if cur < sib else hash_fn(sib + cur)
    merkle_root = cur if proof_depth else h_pid

    # The three raw 64-byte (r||s) MNO signatures the applet carries in BF38.
    def sign_raw(data):
        return ecdsa_der_to_tr03111(sk_mno.sign(data, ec.ECDSA(sha256)))

    msg_cred = h_pid + h_cert + FIXED_MNOID
    msg_root = root_auth
    msg_tok = h_pid + h_cert + FIXED_MNOID + FIXED_EXPIRY
    sig_cred = sign_raw(msg_cred)
    sig_root = sign_raw(msg_root)
    auth_tok = sign_raw(msg_tok)

    # ---- a valid Schnorr proof for schnorr_verify_p256 --------------------
    # statement is ~7 concatenated fields in the real BF42; size only affects
    # one SHA-256, so a representative-length blob is sufficient.
    stmt = os.urandom(323)
    k = int.from_bytes(os.urandom(32), 'big') % _P256_N or 1
    r_pt = zk_utils._p256_mul(k, _G)
    r_bytes = b'\x04' + r_pt[0].to_bytes(32, 'big') + r_pt[1].to_bytes(32, 'big')
    c_digest = hashes.Hash(sha256)
    c_digest.update(stmt)
    c_digest.update(r_bytes)
    c = int.from_bytes(c_digest.finalize(), 'big') % _P256_N
    s_val = (k + c * sk_u_int) % _P256_N
    schnorr_proof = r_bytes + s_val.to_bytes(32, 'big')   # 97 bytes: 04||Rx||Ry||s

    # ---- baseline SGP.22 transport fixtures -------------------------------
    euicc_signed1 = os.urandom(200)
    euicc_sig1 = ecdsa_der_to_tr03111(sk_euicc.sign(euicc_signed1, ec.ECDSA(sha256)))
    pk_euicc = sk_euicc.public_key()
    smdp_signed2 = os.urandom(64)

    ci_cert = make_cert('Test CI', sk_ci, 'Test CI', sk_ci.public_key(), sha256)
    eum_cert = make_cert('Test EUM', sk_ci, 'Test CI', sk_eum.public_key(), sha256)
    euicc_cert = make_cert('Test eUICC', sk_eum, 'Test EUM', pk_euicc, sha256)

    # ---- PCA / enrollment fixtures ----------------------------------------
    # binding signature is signed by the *user* key over pk_u || eid (pca-server.py)
    sk_u_obj = ec.derive_private_key(sk_u_int, p256)
    binding_sig = sk_u_obj.sign(pk_u_bytes + EID_BIN, ec.ECDSA(sha256))
    cred_binding_hash = hash_fn(os.urandom(32))
    eid_ascii = FIXED_TEST_EID.decode('ascii')

    blinded_challenge = os.urandom(32)
    device_auth_sig = sk_device.sign(blinded_challenge, ec.ECDSA(sha256))
    r_mno = int.from_bytes(os.urandom(32), 'big') % _P256_N or 1
    sk_mno_int = sk_mno.private_numbers().private_value

    # token-bookkeeping fixture: a populated spent-token set + a sample key
    spent = set(os.urandom(32).hex() for _ in range(1000))
    sample_key = auth_tok.hex()

    # =======================================================================
    # OPS -- each is exactly the call the corresponding server makes.
    # =======================================================================

    # --- SM-DP+ per-download ZK additions (osmo-smdpp.py authenticateClient)
    def verify_sig_cred():
        pk_mno.verify(ecdsa_tr03111_to_dss(sig_cred), msg_cred, ec.ECDSA(sha256))

    def verify_sig_root():
        pk_mno.verify(ecdsa_tr03111_to_dss(sig_root), msg_root, ec.ECDSA(sha256))

    def verify_auth_tok():
        pk_mno.verify(ecdsa_tr03111_to_dss(auth_tok), msg_tok, ec.ECDSA(sha256))

    def merkle_verify():
        if not rsp.MerkleAccumulator.verifyProof(h_pid_hex, pi_inc_list, merkle_root):
            raise AssertionError('verifyProof failed')

    def token_bookkeeping():
        dt = _decode_expiry(FIXED_EXPIRY)
        _ = _utcnow() > dt
        _ = sample_key in spent          # spent-token replay check (add is O(1) equiv.)

    # --- MNO per-download (mno-server.py zkRequest) ------------------------
    def schnorr_verify():
        if not schnorr_verify_p256(pk_u_bytes, stmt, schnorr_proof):
            raise AssertionError('schnorr_verify_p256 failed')

    def schnorr_verify_lib():
        if not schnorr_verify_hazmat(pk_u_bytes, stmt, schnorr_proof):
            raise AssertionError('schnorr_verify_hazmat failed')

    def mno_sign():
        ecdsa_der_to_tr03111(sk_mno.sign(msg_cred, ec.ECDSA(sha256)))

    def accumulator_recompute():
        acc._compute_root()              # work done inside each MNO accumulator add()

    def accumulator_genproof():
        acc.generateProof(h_pid_hex)

    # --- baseline SGP.22 transport (runs in both modes / non-ZK download) ---
    def verify_euicc_sig1():
        pk_euicc.verify(ecdsa_tr03111_to_dss(euicc_sig1), euicc_signed1, ec.ECDSA(sha256))

    def chain_walk():
        eum_cert.public_key().verify(
            euicc_cert.signature, euicc_cert.tbs_certificate_bytes,
            ec.ECDSA(euicc_cert.signature_hash_algorithm))
        ci_cert.public_key().verify(
            eum_cert.signature, eum_cert.tbs_certificate_bytes,
            ec.ECDSA(eum_cert.signature_hash_algorithm))

    def smdp_sign2():
        sk_dp.sign(smdp_signed2, ec.ECDSA(sha256))

    # --- PCA per-download (pca-server.py certInitRequest) ------------------
    def pca_binding_verify():
        pk_u_obj.verify(binding_sig, pk_u_bytes + EID_BIN, ec.ECDSA(sha256))

    def pca_build_pcert():
        _build_pcert_u(pk_u_bytes, sk_pca, eid_ascii, cred_binding_hash)

    def pca_build_std_cert():
        _build_std_cert_u(pk_u_bytes, sk_pca, eid_ascii)

    # --- MNO per-enrollment (mno-server.py registerCredential) -------------
    def register_device_verify():
        pk_device.verify(device_auth_sig, blinded_challenge, ec.ECDSA(sha256))

    def register_blind_sig():
        e_int = int.from_bytes(blinded_challenge, 'big')
        _ = (r_mno - e_int * sk_mno_int) % _P256_N

    # name -> (callable, server, phase).  `phase` is 'download', 'enroll' or
    # 'baseline' (transport crypto a non-ZK download pays too).
    f.update({
        # --- SM-DP+ -------------------------------------------------------
        'smdp.verify_sig_cred':      (verify_sig_cred, SMDP, 'download'),
        'smdp.verify_sig_root':      (verify_sig_root, SMDP, 'download'),
        'smdp.verify_auth_tok':      (verify_auth_tok, SMDP, 'download'),
        'smdp.merkle_verify':        (merkle_verify, SMDP, 'download'),
        'smdp.token_bookkeeping':    (token_bookkeeping, SMDP, 'download'),
        'base.verify_euicc_sig1':    (verify_euicc_sig1, SMDP, 'baseline'),
        'base.chain_walk':           (chain_walk, SMDP, 'baseline'),
        'base.smdp_sign2':           (smdp_sign2, SMDP, 'baseline'),
        # --- MNO ----------------------------------------------------------
        'mno.schnorr_verify':        (schnorr_verify, MNO, 'download'),
        'mno.schnorr_verify_hazmat': (schnorr_verify_lib, MNO, 'download'),
        'mno.ecdsa_sign':            (mno_sign, MNO, 'download'),
        'mno.accumulator_recompute': (accumulator_recompute, MNO, 'download'),
        'mno.accumulator_genproof':  (accumulator_genproof, MNO, 'download'),
        'mno.register_device_verify': (register_device_verify, MNO, 'enroll'),
        'mno.register_blind_sig':     (register_blind_sig, MNO, 'enroll'),
        # --- PCA ----------------------------------------------------------
        'pca.binding_verify':        (pca_binding_verify, PCA, 'download'),
        'pca.build_pcert':           (pca_build_pcert, PCA, 'download'),
        'pca.build_std_cert':        (pca_build_std_cert, PCA, 'download'),
    })

    meta.update({
        'accumulator_size': accumulator_size,
        'merkle_proof_depth': proof_depth,
        'single_leaf': root_auth == h_pid,
    })
    return f, meta


# ---------------------------------------------------------------------------
# Sanity gate -- every verification fixture must pass, else timing is garbage.
# ---------------------------------------------------------------------------
def sanity_check(ops):
    checks = [
        'smdp.verify_sig_cred', 'smdp.verify_sig_root', 'smdp.verify_auth_tok',
        'smdp.merkle_verify', 'mno.schnorr_verify', 'mno.schnorr_verify_hazmat',
        'base.verify_euicc_sig1', 'base.chain_walk', 'pca.binding_verify',
        'mno.register_device_verify',
    ]
    for name in checks:
        if name not in ops:            # server filtered out via --server
            continue
        fn = ops[name][0]
        try:
            fn()
        except Exception as exc:  # noqa: BLE001
            raise SystemExit(f'SANITY CHECK FAILED for {name}: {exc!r}\n'
                             'Fixtures are invalid; timing would be meaningless.')


# ---------------------------------------------------------------------------
# Per-op iteration policy: the pure-Python Schnorr verify and the O(N)
# accumulator ops are slow, so they get fewer iterations.
# ---------------------------------------------------------------------------
def iters_for(name, base_iters, base_warmup):
    if name == 'mno.schnorr_verify':
        return max(20, min(base_iters, 100)), max(2, min(base_warmup, 10))
    if name.startswith('mno.accumulator') or name.startswith('pca.build'):
        return max(50, min(base_iters, 500)), min(base_warmup, 50)
    return base_iters, base_warmup


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------
def fmt_ns(x):
    if x < 1e3:
        return f'{x:8.0f} ns'
    if x < 1e6:
        return f'{x / 1e3:8.2f} us'
    if x < 1e9:
        return f'{x / 1e6:8.3f} ms'
    return f'{x / 1e9:8.3f} s'


def fmt_per_n(seconds, n):
    total = seconds * n
    if total < 1e-3:
        return f'{total * 1e6:.1f} us'
    if total < 1.0:
        return f'{total * 1e3:.2f} ms'
    if total < 60:
        return f'{total:.2f} s'
    return f'{total / 60:.2f} min'


# ---------------------------------------------------------------------------
# Per-server cost composition
# ---------------------------------------------------------------------------
def compose_per_server(results, selected):
    """Total the measured op means into per-server, per-transaction costs.

    Returns {server: {metric: seconds}}.  Nothing is summed across servers:
    each role runs in its own process and is sized on its own hardware, so the
    SM-DP+, MNO and PCA figures stay separate.  HEADLINE (below) picks, per
    server, which of its metrics drives the throughput / core-count sizing.
    """
    def total(items):
        return sum(mult * results[n]['mean_ns'] for n, mult in items) / 1e9

    out = {}

    if SMDP in selected:
        baseline = total(SMDP_BASELINE)
        addon = total(SMDP_ZK_ADDON)
        skipped = total(SMDP_ZK_SKIPPED)
        out[SMDP] = {
            'download_baseline_non_zk': baseline,
            'download_zk_mode_total': baseline - skipped + addon,
            'download_zk_addon_gross': addon,
            'download_zk_addon_net': addon - skipped,
            'download_chain_walk_saved': skipped,
            'enrollment': 0.0,          # SM-DP+ takes no part in enrollment
        }

    if MNO in selected:
        core = total(MNO_DOWNLOAD_CORE)
        out[MNO] = {
            'download': core + total([('mno.schnorr_verify_hazmat', 1)]),
            'download_pure_python_schnorr': core + total([('mno.schnorr_verify', 1)]),
            'download_accumulator_oN': total(MNO_ACCUMULATOR),
            'enrollment': total(MNO_ENROLL),
        }

    if PCA in selected:
        out[PCA] = {
            'download': total(PCA_DOWNLOAD),
            'download_std_cert_variant': total(PCA_DOWNLOAD_STD),
            'enrollment': 0.0,          # a fresh PCert_U per download; nothing one-time
        }

    return out


# Which metric drives each server's throughput / core-count extrapolation.
HEADLINE = {
    SMDP: ('download_zk_addon_net', 'enrollment'),
    MNO:  ('download', 'enrollment'),
    PCA:  ('download', 'enrollment'),
}

# Per-server metric labels for the report, in print order.
METRIC_LABELS = {
    SMDP: [
        ('download_baseline_non_zk',  'Baseline download, non-ZK (SM-DP+ crypto only)'),
        ('download_zk_mode_total',    'ZK-mode download, total SM-DP+ crypto'),
        ('download_zk_addon_gross',   'ZK add-on, gross'),
        ('download_chain_walk_saved', '  minus EUM chain walk skipped in ZK mode'),
        ('download_zk_addon_net',     'ZK add-on, NET marginal cost per download'),
    ],
    MNO: [
        ('download',                     'Per download, zkRequest (OpenSSL/hazmat Schnorr)'),
        ('download_pure_python_schnorr', 'Per download, zkRequest (pure-Python Schnorr)'),
        ('download_accumulator_oN',      '  of which accumulator work, O(N)'),
        ('enrollment',                   'Per enrollment, registerCredential (one-time)'),
    ],
    PCA: [
        ('download',                  'Per download, certInitRequest (issues PCert_U)'),
        ('download_std_cert_variant', '  standard-cert variant (certInitRequestStd)'),
    ],
}


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main(argv):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('-i', '--iters', type=int, default=2000, help='timed iterations per op')
    ap.add_argument('-w', '--warmup', type=int, default=200, help='warmup iterations per op')
    ap.add_argument('-N', '--accumulator-size', type=int, default=1024,
                    help='number of enrolled pseudonyms in the Merkle accumulator')
    ap.add_argument('-c', '--curve', choices=['nist', 'brainpool'], default='nist',
                    help='curve for SGP.22 transport crypto (ZK ops stay P-256)')
    ap.add_argument('-s', '--server', action='append', choices=list(SERVER_ORDER),
                    help='measure only this server role (repeatable; default: all three)')
    ap.add_argument('--downloads-per-day', type=float, default=1_000_000,
                    help='target download volume for the per-server sizing example')
    ap.add_argument('--enrollments-per-day', type=float, default=None,
                    help='target enrollment volume (default: same as --downloads-per-day)')
    ap.add_argument('--json', metavar='PATH', help='write full results as JSON')
    ap.add_argument('--csv', metavar='PATH', help='write per-op stats as CSV')
    ap.add_argument('-q', '--quiet', action='store_true', help='suppress the stdout report')
    args = ap.parse_args(argv)

    if args.enrollments_per_day is None:
        args.enrollments_per_day = args.downloads_per_day
    selected = tuple(s for s in SERVER_ORDER if not args.server or s in args.server)

    curve = ec.SECP256R1() if args.curve == 'nist' else ec.BrainpoolP256R1()

    ops, meta = build_fixtures(curve, args.accumulator_size)
    ops = {n: v for n, v in ops.items() if v[1] in selected}
    sanity_check(ops)

    results = {}
    for name, (fn, server, phase) in ops.items():
        it, wu = iters_for(name, args.iters, args.warmup)
        stats = bench(fn, it, wu)
        stats['server'] = server
        stats['phase'] = phase
        results[name] = stats

    per_server = compose_per_server(results, selected)

    env = {
        'platform': platform.platform(),
        'processor': platform.processor() or platform.machine(),
        'python': platform.python_version(),
        'cryptography': __import__('cryptography').__version__,
        'curve_transport': args.curve,
        'curve_zk': 'nist-p256 (pinned by servers)',
        'iters': args.iters,
        'warmup': args.warmup,
        'servers_measured': list(selected),
        **meta,
    }

    payload = {'env': env, 'ops': results, 'per_server_seconds': per_server}

    if not args.quiet:
        print_report(payload, per_server, results, args, selected)

    if args.json:
        import json
        with open(args.json, 'w') as fh:
            json.dump(payload, fh, indent=2)
        print(f'\n[json]  wrote {args.json}')
    if args.csv:
        with open(args.csv, 'w', newline='') as fh:
            wr = csv.writer(fh)
            wr.writerow(['op', 'server', 'phase', 'count', 'mean_us', 'median_us',
                         'p95_us', 'p99_us', 'stdev_us', 'ops_per_sec'])
            for name, st in results.items():
                wr.writerow([name, st['server'], st['phase'], st['count'],
                             f"{st['mean_ns'] / 1e3:.3f}", f"{st['median_ns'] / 1e3:.3f}",
                             f"{st['p95_ns'] / 1e3:.3f}", f"{st['p99_ns'] / 1e3:.3f}",
                             f"{st['stdev_ns'] / 1e3:.3f}", f"{st['ops_per_sec']:.1f}"])
            wr.writerow([])
            wr.writerow(['server', 'metric', 'seconds', 'microseconds'])
            for server, metrics in payload['per_server_seconds'].items():
                for metric, sec in metrics.items():
                    wr.writerow([server, metric, f'{sec:.9f}', f'{sec * 1e6:.3f}'])
        print(f'[csv]   wrote {args.csv}')

    return 0


def print_scale(sec, per_day, unit, indent='      '):
    """Throughput / fleet-sizing lines for one per-transaction cost."""
    print(f'{indent}per {unit:<12}: {fmt_per_n(sec, 1)}')
    print(f'{indent}per 1,000       : {fmt_per_n(sec, 1_000)}')
    print(f'{indent}per 1,000,000   : {fmt_per_n(sec, 1_000_000)}')
    print(f'{indent}single-core rate: {1.0 / sec:,.0f} {unit}s/sec/core'
          f'  ≈ {86_400.0 / sec:,.0f} {unit}s/day/core')
    cores = per_day * sec / 86_400.0
    print(f'{indent}to sustain {per_day:,.0f} {unit}s/day: '
          f'{cores:.3g} CPU-core(s) ({math.ceil(cores)} core(s) rounded up)')


def print_server_section(idx, n, server, metrics, results, args):
    """One self-contained block per server: its ops, its totals, its sizing."""
    info = SERVERS[server]
    print()
    print('=' * 78)
    print(f"SERVER {idx}/{n} — {info['label']}  ({info['module']})")
    print(f"  role: {info['role']}")
    print('=' * 78)

    # --- per-op table, this server only ------------------------------------
    phases = [('download', 'per-download ZK work'),
              ('baseline', 'baseline SGP.22 transport (paid by ZK and non-ZK downloads)'),
              ('enroll', 'per-enrollment work (one-time per device)')]
    own = {nm: st for nm, st in results.items() if st['server'] == server}
    if own:
        print(f"{'operation':<34}{'mean':>12}{'median':>12}{'p95':>12}{'ops/s':>10}")
        print('-' * 78)
        for phase, title in phases:
            rows = [(nm, st) for nm, st in own.items() if st['phase'] == phase]
            if not rows:
                continue
            print(f'• {title}')
            for nm, st in rows:
                print(f"  {nm:<32}{fmt_ns(st['mean_ns']):>12}{fmt_ns(st['median_ns']):>12}"
                      f"{fmt_ns(st['p95_ns']):>12}{st['ops_per_sec']:>10,.0f}")
        print('-' * 78)

    # --- composed totals for this server -----------------------------------
    print(f"\n  {info['label']} per-transaction cost (sum of component means)")
    for key, lab in METRIC_LABELS[server]:
        if key not in metrics:
            continue
        print(f"  {lab:<56}{fmt_ns(metrics[key] * 1e9):>14}")

    # --- sizing, driven by this server's headline metrics -------------------
    dl_key, en_key = HEADLINE[server]
    dl = metrics.get(dl_key, 0.0)
    en = metrics.get(en_key, 0.0)
    if dl > 0:
        print(f"\n  at scale — {dict(METRIC_LABELS[server]).get(dl_key, dl_key)}")
        print_scale(dl, args.downloads_per_day, 'download')
    else:
        print('\n  at scale — not in the download path (0 s per download)')
    if en > 0:
        print(f"\n  at scale — {dict(METRIC_LABELS[server]).get(en_key, en_key)}")
        print_scale(en, args.enrollments_per_day, 'enrollment')
    else:
        print('  at scale — takes no part in enrollment (0 s per enrollment)')


def print_summary_table(per_server, args):
    """The three servers side by side, still never summed together."""
    print()
    print('=' * 78)
    print('PER-SERVER SUMMARY (single core, mean of component means)')
    print('=' * 78)
    print(f"{'server':<10}{'per download':>15}{'per enrollment':>16}"
          f"{'dl/sec/core':>14}{'cores @ target':>15}")
    print('-' * 78)
    for server in SERVER_ORDER:
        if server not in per_server:
            continue
        metrics = per_server[server]
        dl_key, en_key = HEADLINE[server]
        dl = metrics.get(dl_key, 0.0)
        en = metrics.get(en_key, 0.0)
        rate = f'{1.0 / dl:,.0f}' if dl > 0 else '—'
        cores = (f'{math.ceil(args.downloads_per_day * dl / 86_400.0)}' if dl > 0 else '—')
        print(f"{SERVERS[server]['label']:<10}"
              f"{(fmt_ns(dl * 1e9).strip() if dl > 0 else '—'):>15}"
              f"{(fmt_ns(en * 1e9).strip() if en > 0 else '—'):>16}"
              f"{rate:>14}{cores:>15}")
    print('-' * 78)
    print('  per download   = SM-DP+: net ZK add-on | MNO: full zkRequest crypto '
          '| PCA: certInitRequest')
    print(f'  cores @ target = to sustain {args.downloads_per_day:,.0f} downloads/day '
          f'on that server alone')
    print('  the three columns are NOT additive: separate processes, separate hosts.')


def print_report(payload, per_server, results, args, selected):
    env = payload['env']
    line = '=' * 78
    print(line)
    print('ZK-eSIM SERVER-SIDE OVERHEAD BENCHMARK  (measured per server role)')
    print(line)
    print(f"host        : {env['platform']}")
    print(f"cpu / python: {env['processor']}  |  Python {env['python']}  |  "
          f"cryptography {env['cryptography']}")
    print(f"params      : iters={env['iters']} warmup={env['warmup']} "
          f"transport-curve={env['curve_transport']}  zk-curve=P-256(pinned)")
    print(f"accumulator : {env['accumulator_size']} enrolled pseudonyms, "
          f"Merkle proof depth={env['merkle_proof_depth']} "
          f"({'single-leaf root==h_pid' if env['single_leaf'] else 'multi-leaf tree'})")
    print(f"targets     : {args.downloads_per_day:,.0f} downloads/day, "
          f"{args.enrollments_per_day:,.0f} enrollments/day")
    print(f"servers     : {', '.join(SERVERS[s]['label'] for s in selected)} "
          f"(timed and totalled separately)")
    print('fixtures valid ✓  (all signature / proof checks pass)')

    # --- one section per server -------------------------------------------
    for idx, server in enumerate([s for s in SERVER_ORDER if s in per_server], start=1):
        print_server_section(idx, len(per_server), server,
                             per_server[server], results, args)

    if len(per_server) > 1:
        print_summary_table(per_server, args)

    print('\nNOTES')
    print('-' * 78)
    print('* Each server is timed on its own: the SM-DP+, MNO and PCA totals are never')
    print('  summed, because they run as separate processes and are provisioned')
    print('  independently.  A single download touches all three, so their per-download')
    print('  figures are concurrent costs on three different hosts, not one serial')
    print('  latency budget.')
    print('* The PCA is a per-DOWNLOAD cost, not a one-time enrollment cost: CertInit')
    print('  runs before every download and mints a fresh PCert_U over a freshly')
    print('  derived sk_U.  That is what makes successive downloads unlinkable, so the')
    print('  pseudonym cert cannot be amortised across downloads.  Only the MNO Phase 0')
    print('  registerCredential is one-time per device.')
    print('* mno.schnorr_verify is the prototype PURE-PYTHON P-256 verifier (zk_utils),')
    print('  shown as a conservative upper bound.  mno.schnorr_verify_hazmat is a')
    print('  drop-in verifier that delegates both scalar multiplications to OpenSSL')
    print('  via cryptography hazmat (derive_private_key for s*G, ECDH for c*PK) --')
    print('  ~100x faster and the realistic figure for a deployed MNO.')
    print('* Merkle verifyProof is O(log N); the MNO accumulator recompute/genproof')
    print('  are O(N) -- the one component that grows with deployment size (a sparse/')
    print('  incremental Merkle tree would make these O(log N) too).')
    print('* TLS/HTTP/ASN.1/disk I/O are excluded by design: a non-ZK download pays')
    print('  them too, so they are not zkesim-specific overhead.')
    print('* "Firmware update" deployability is a client/applet property (the applet')
    print('  reuses P-256/ECDSA/SHA-256 already present in eUICCs) -- out of scope for')
    print('  this server-side benchmark.')
    print(line)


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:]))
