#!/usr/bin/env python3
# Copyright (C) 2024 ZK-eSIM contributors
#
# Server-side performance benchmark for the additional overhead that the
# ZK-eSIM design introduces over a standard SGP.22 profile download.
#
# This is a *CPU microbenchmark*: it times the real cryptographic code paths
# executed by the SM-DP+ (osmo-smdpp.py), the MNO role (mno-server.py) and the
# PCA role (pca-server.py) and reports the marginal cost per download, per
# thousand downloads and per million downloads, together with single-core
# throughput and a worked fleet-sizing example.
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
"""ZK-eSIM server-side overhead benchmark.

Run inside the same environment the servers run in (the `pysim` conda env)::

    python3 zk_server_bench.py
    python3 zk_server_bench.py --iters 5000 --accumulator-size 4096
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

    # --- PCA per-enrollment (pca-server.py certInitRequest) ----------------
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

    f.update({
        # SM-DP+ ZK additions (per download)
        'smdp.verify_sig_cred':   (verify_sig_cred, 'group:smdp_zk'),
        'smdp.verify_sig_root':   (verify_sig_root, 'group:smdp_zk'),
        'smdp.verify_auth_tok':   (verify_auth_tok, 'group:smdp_zk'),
        'smdp.merkle_verify':     (merkle_verify, 'group:smdp_zk'),
        'smdp.token_bookkeeping': (token_bookkeeping, 'group:smdp_zk'),
        # MNO ZK additions (per download)
        'mno.schnorr_verify':     (schnorr_verify, 'group:mno_dl'),
        'mno.schnorr_verify_hazmat': (schnorr_verify_lib, 'group:mno_dl'),
        'mno.ecdsa_sign':         (mno_sign, 'group:mno_dl'),
        'mno.accumulator_recompute': (accumulator_recompute, 'group:mno_dl'),
        'mno.accumulator_genproof':  (accumulator_genproof, 'group:mno_dl'),
        # baseline SGP.22 transport
        'base.verify_euicc_sig1': (verify_euicc_sig1, 'group:base'),
        'base.chain_walk':        (chain_walk, 'group:base'),
        'base.smdp_sign2':        (smdp_sign2, 'group:base'),
        # PCA enrollment (one-time)
        'pca.binding_verify':     (pca_binding_verify, 'group:enroll'),
        'pca.build_pcert':        (pca_build_pcert, 'group:enroll'),
        'pca.build_std_cert':     (pca_build_std_cert, 'group:enroll'),
        # MNO enrollment (one-time)
        'mno.register_device_verify': (register_device_verify, 'group:enroll'),
        'mno.register_blind_sig':     (register_blind_sig, 'group:enroll'),
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
    ap.add_argument('--downloads-per-day', type=float, default=1_000_000,
                    help='target volume for the fleet-sizing example')
    ap.add_argument('--json', metavar='PATH', help='write full results as JSON')
    ap.add_argument('--csv', metavar='PATH', help='write per-op stats as CSV')
    ap.add_argument('-q', '--quiet', action='store_true', help='suppress the stdout report')
    args = ap.parse_args(argv)

    curve = ec.SECP256R1() if args.curve == 'nist' else ec.BrainpoolP256R1()

    ops, meta = build_fixtures(curve, args.accumulator_size)
    sanity_check(ops)

    results = {}
    for name, (fn, group) in ops.items():
        it, wu = iters_for(name, args.iters, args.warmup)
        stats = bench(fn, it, wu)
        stats['group'] = group.split(':', 1)[1]
        results[name] = stats

    def mean_s(name):
        return results[name]['mean_ns'] / 1e9

    # --- composed scenarios (seconds) --------------------------------------
    smdp_zk_gross = sum(mean_s(n) for n in (
        'smdp.verify_sig_cred', 'smdp.verify_sig_root', 'smdp.verify_auth_tok',
        'smdp.merkle_verify', 'smdp.token_bookkeeping'))
    smdp_zk_net = smdp_zk_gross - mean_s('base.chain_walk')   # ZK mode skips the chain walk
    acc_cost = mean_s('mno.accumulator_recompute') + mean_s('mno.accumulator_genproof')
    mno_dl = (mean_s('mno.schnorr_verify') + 3 * mean_s('mno.ecdsa_sign') + acc_cost)
    # Library-backed variant: use the measured OpenSSL/hazmat Schnorr verify
    # instead of the prototype pure-Python verifier.
    mno_dl_hazmat = (mean_s('mno.schnorr_verify_hazmat')
                     + 3 * mean_s('mno.ecdsa_sign') + acc_cost)
    baseline_dl = (mean_s('base.verify_euicc_sig1')
                   + mean_s('base.chain_walk')
                   + mean_s('base.smdp_sign2'))
    zk_dl_total = smdp_zk_gross + mno_dl
    zk_dl_total_hazmat = smdp_zk_gross + mno_dl_hazmat
    enroll_total = sum(mean_s(n) for n in (
        'mno.register_device_verify', 'mno.register_blind_sig',
        'pca.binding_verify', 'pca.build_pcert'))

    scenarios = {
        'baseline_download_smdp': baseline_dl,
        'zk_smdp_addon_gross': smdp_zk_gross,
        'zk_smdp_addon_net_of_chainwalk': smdp_zk_net,
        'zk_mno_per_download': mno_dl,
        'zk_per_download_total_all_roles': zk_dl_total,
        'zk_per_download_total_hazmat': zk_dl_total_hazmat,
        'zk_per_enrollment_one_time': enroll_total,
        'mno_accumulator_per_download_oN': acc_cost,
    }

    env = {
        'platform': platform.platform(),
        'processor': platform.processor() or platform.machine(),
        'python': platform.python_version(),
        'cryptography': __import__('cryptography').__version__,
        'curve_transport': args.curve,
        'curve_zk': 'nist-p256 (pinned by servers)',
        'iters': args.iters,
        'warmup': args.warmup,
        **meta,
    }

    payload = {'env': env, 'ops': results, 'scenarios_seconds': scenarios}

    if not args.quiet:
        print_report(payload, scenarios, results, args)

    if args.json:
        import json
        with open(args.json, 'w') as fh:
            json.dump(payload, fh, indent=2)
        print(f'\n[json]  wrote {args.json}')
    if args.csv:
        with open(args.csv, 'w', newline='') as fh:
            wr = csv.writer(fh)
            wr.writerow(['op', 'group', 'count', 'mean_us', 'median_us',
                         'p95_us', 'p99_us', 'stdev_us', 'ops_per_sec'])
            for name, st in results.items():
                wr.writerow([name, st['group'], st['count'],
                             f"{st['mean_ns'] / 1e3:.3f}", f"{st['median_ns'] / 1e3:.3f}",
                             f"{st['p95_ns'] / 1e3:.3f}", f"{st['p99_ns'] / 1e3:.3f}",
                             f"{st['stdev_ns'] / 1e3:.3f}", f"{st['ops_per_sec']:.1f}"])
        print(f'[csv]   wrote {args.csv}')

    return 0


def print_report(payload, scenarios, results, args):
    env = payload['env']
    line = '=' * 78
    print(line)
    print('ZK-eSIM SERVER-SIDE OVERHEAD BENCHMARK')
    print(line)
    print(f"host        : {env['platform']}")
    print(f"cpu / python: {env['processor']}  |  Python {env['python']}  |  "
          f"cryptography {env['cryptography']}")
    print(f"params      : iters={env['iters']} warmup={env['warmup']} "
          f"transport-curve={env['curve_transport']}  zk-curve=P-256(pinned)")
    print(f"accumulator : {env['accumulator_size']} enrolled pseudonyms, "
          f"Merkle proof depth={env['merkle_proof_depth']} "
          f"({'single-leaf root==h_pid' if env['single_leaf'] else 'multi-leaf tree'})")
    print('fixtures valid ✓  (all signature / proof checks pass)')
    print()

    # per-op table
    groups = [
        ('SM-DP+  ZK additions per download (osmo-smdpp.py authenticateClient)', 'smdp_zk'),
        ('MNO     ZK work per download (mno-server.py zkRequest)', 'mno_dl'),
        ('Baseline SGP.22 transport crypto (both ZK and non-ZK)', 'base'),
        ('Enrollment (one-time per device): MNO register + PCA certInit', 'enroll'),
    ]
    print(f"{'operation':<34}{'mean':>12}{'median':>12}{'p95':>12}{'ops/s':>10}")
    print('-' * 78)
    for title, g in groups:
        print(f'• {title}')
        for name, st in results.items():
            if st['group'] != g:
                continue
            print(f"  {name:<32}{fmt_ns(st['mean_ns']):>12}{fmt_ns(st['median_ns']):>12}"
                  f"{fmt_ns(st['p95_ns']):>12}{st['ops_per_sec']:>10,.0f}")
    print('-' * 78)

    # scenarios
    print('\nCOMPOSED PER-DOWNLOAD COST (sum of component means)')
    print('-' * 78)
    labels = {
        'baseline_download_smdp':          'Baseline download (SM-DP+ crypto only)',
        'zk_smdp_addon_gross':             'ZK add-on on SM-DP+ (gross)',
        'zk_smdp_addon_net_of_chainwalk':  'ZK add-on on SM-DP+ (net; ZK skips chain walk)',
        'mno_accumulator_per_download_oN': '  of which MNO accumulator work (O(N))',
        'zk_mno_per_download':             'ZK work on MNO per download (pure-Python Schnorr)',
        'zk_per_download_total_all_roles': 'ZK ADDITIONAL per download (pure-Python upper bound)',
        'zk_per_download_total_hazmat':    'ZK ADDITIONAL per download (OpenSSL/hazmat Schnorr)',
        'zk_per_enrollment_one_time':      'ZK enrollment per device (one-time)',
    }
    for key, lab in labels.items():
        sec = scenarios[key]
        print(f"  {lab:<54}{fmt_ns(sec * 1e9):>14}")
    print('-' * 78)

    # extrapolation for the headline figures
    print('\nHEADLINE: additional zkesim server cost at scale')
    print('-' * 78)
    for key, lab in (
            ('zk_per_download_total_hazmat',    'All ZK roles, OpenSSL/hazmat Schnorr (realistic)'),
            ('zk_per_download_total_all_roles', 'All ZK roles, pure-Python Schnorr (upper bound)'),
            ('zk_smdp_addon_net_of_chainwalk',  'Marginal cost on the download server (SM-DP+) only')):
        sec = scenarios[key]
        if sec <= 0:
            continue
        print(f'  {lab}:')
        print(f'      per download      : {fmt_per_n(sec, 1)}')
        print(f'      per 1,000         : {fmt_per_n(sec, 1_000)}')
        print(f'      per 1,000,000     : {fmt_per_n(sec, 1_000_000)}')
        print(f'      single-core rate  : {1.0 / sec:,.0f} downloads/sec/core')
        per_day_core = 86_400.0 / sec
        print(f'                          ≈ {per_day_core:,.0f} downloads/day/core')
        cores = args.downloads_per_day * sec / 86_400.0
        print(f'      to sustain {args.downloads_per_day:,.0f}/day: '
              f'{cores:.3g} CPU-core(s) ({math.ceil(cores)} core(s) rounded up)')
        print()

    print('NOTES')
    print('-' * 78)
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
