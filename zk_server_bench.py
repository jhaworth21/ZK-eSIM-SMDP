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
import concurrent.futures
import csv
import datetime
import math
import os
import platform
import statistics
import sys
import threading
import time
import uuid

# Make `pySim` importable whether or not the package is pip-installed: the
# servers live in this same directory, so adding it to sys.path mirrors how
# they resolve `import pySim...` when launched from PYSIM_ROOT.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import psutil

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509.oid import NameOID

import pySim.esim.rsp as rsp

# Plotting lives in zk_plot.py so a recorded run can be re-drawn without
# re-measuring; importing it here keeps the inline --plot path and the
# standalone tool on exactly the same code and the same flags. zk_plot defers
# its matplotlib import, so this costs nothing on runs that do not plot.
from zk_plot import add_plot_args, plot_load  # noqa: E402
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
# Conventional-RSP baseline.  In a standard download the operator's entire
# provisioning role is the ES2+ DownloadOrder / ConfirmOrder exchange (paper
# Fig. 3, steps 4-9): it carries no provisioning-layer public-key crypto at
# all, being an authenticated backend TLS call, and TLS is excluded here under
# the same rule applied to every other role.  What remains genuinely in scope
# is minting the MatchingID and recording the ICCID <-> EID mapping.  The
# figure is therefore near-zero BY CONSTRUCTION, and that is the finding: on
# the MNO side essentially the whole ZK-eSIM cost is new work, unlike the
# SM-DP+ which already paid for signature and chain verification.
MNO_BASELINE = [('base.mno_matching_id', 1)]
# zkRequest, minus the Schnorr verify (measured in two variants below).
# Ordered to follow mno-server.py zk_request(): parse PCert_U and pull out
# pk_U, verify the proof, hash pid/cert, update the accumulator, then emit
# sigma_cred, sigma_root and T_i.
MNO_DOWNLOAD_CORE = [('mno.pcert_parse', 1), ('mno.hpid_hcert_hash', 1),
                     ('mno.ecdsa_sign', 3), ('mno.accumulator_recompute', 1),
                     ('mno.accumulator_genproof', 1)]
MNO_ACCUMULATOR = [('mno.accumulator_recompute', 1), ('mno.accumulator_genproof', 1)]
MNO_ENROLL = [('mno.register_device_verify', 1), ('mno.register_blind_sig', 1)]

# PCA -----------------------------------------------------------------------
# certInitRequest, run once per download: verify the pk_U||EID binding
# signature, then issue (build + sign) the pseudonym certificate PCert_U.
# certInitRequestStd is the same flow issuing a plain ECDSA cert with no ZK
# binding extension -- the within-PCA baseline, so the difference isolates
# what the pseudonym construction itself costs.  Note that conventional RSP
# has NO PCA at all, so measured against the deployed GSMA flow the entire
# PCA figure is new cost; the std-cert baseline answers the narrower question
# of what ZK-eSIM adds over simply issuing a short-lived certificate.
PCA_DOWNLOAD = [('pca.binding_verify', 1), ('pca.build_pcert', 1)]
PCA_DOWNLOAD_STD = [('pca.binding_verify', 1), ('pca.build_std_cert', 1)]


def _combine(*groups):
    """Merge (op, multiplicity) groups into one flat multiset.

    Negative multiplicities subtract, so "ZK-mode total = baseline - skipped +
    addon" can be expressed as a single op list.  Composing metrics this way,
    rather than doing arithmetic on already-summed totals, is what keeps the
    error propagation honest: an op appearing in two groups is netted down to
    one multiplicity instead of having its variance counted twice.
    """
    totals, order = {}, []
    for group in groups:
        for name, mult in group:
            if name not in totals:
                totals[name] = 0
                order.append(name)
            totals[name] += mult
    return [(n, totals[n]) for n in order if totals[n] != 0]


def _negate(group):
    return [(name, -mult) for name, mult in group]


# Derived compositions, as flat op lists (see _combine on why these are not
# computed by adding/subtracting totals).
SMDP_ZK_MODE_TOTAL = _combine(SMDP_BASELINE, _negate(SMDP_ZK_SKIPPED), SMDP_ZK_ADDON)
SMDP_ZK_ADDON_NET = _combine(SMDP_ZK_ADDON, _negate(SMDP_ZK_SKIPPED))
MNO_DOWNLOAD = _combine(MNO_DOWNLOAD_CORE, [('mno.schnorr_verify_hazmat', 1)])
MNO_DOWNLOAD_PY = _combine(MNO_DOWNLOAD_CORE, [('mno.schnorr_verify', 1)])
MNO_ZK_ADDON_NET = _combine(MNO_DOWNLOAD, _negate(MNO_BASELINE))
MNO_ZK_ADDON_NET_PY = _combine(MNO_DOWNLOAD_PY, _negate(MNO_BASELINE))
# binding_verify is common to both PCA flows, so _combine cancels it and the
# net figure isolates build_pcert - build_std_cert.
PCA_ZK_ADDON_NET = _combine(PCA_DOWNLOAD, _negate(PCA_DOWNLOAD_STD))


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
    """Reduce a list of per-call durations (ns) to summary statistics.

    Two different spreads are reported, because "±" can mean either:
      * `stdev_ns` -- sample standard deviation (Bessel-corrected).  The spread
        of a SINGLE execution; this is what the report prints as `± sd`.  It
        describes the workload and does not shrink with more iterations.
      * `sem_ns`   -- standard error of the mean, stdev/sqrt(n).  The
        uncertainty in the MEAN estimate itself, which does shrink as iterations
        increase.  Carried in the JSON/CSV for anyone quoting the mean.

    Note the sample (n-1) stdev is used rather than the population form: some
    ops run as few as 20 iterations (see iters_for), where the distinction is a
    couple of percent rather than negligible.
    """
    s = sorted(samples_ns)
    n = len(s)
    mean = sum(s) / n
    stdev = float(statistics.stdev(s)) if n > 1 else 0.0
    return {
        'count': n,
        'mean_ns': mean,
        'median_ns': float(statistics.median(s)),
        'stdev_ns': stdev,
        'sem_ns': (stdev / math.sqrt(n)) if n > 1 else 0.0,
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
    pid_raw = os.urandom(32)                      # per-session pseudonym, pre-hash
    h_pid = hash_fn(pid_raw)
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

    # A real PCert_U, so the MNO-side parse below works on the same DER the
    # PCA actually emits (mno-server.py re-parses the on-wire bytes rather
    # than trusting the decoded structure, which is what makes it a cost).
    pcert_der = _build_pcert_u(pk_u_bytes, sk_pca, eid_ascii, cred_binding_hash)
    binding_oid = x509.ObjectIdentifier('2.23.146.1.2.1.8')

    # Conventional-RSP operator state: the ICCID <-> EID table the MNO keeps
    # per order (paper Fig. 3, step 8 / step 21).  Pre-populated so the table
    # is already large, as an operator's would be: an empty dict grown one
    # order at a time makes CPython resize mid-measurement, and those rehash
    # spikes land in the timings as a spread several times the mean, which is
    # an artefact of the container rather than a cost of the protocol.  At
    # this size the insert stays well clear of the next resize threshold.
    conv_order_map = {f'mid-{i}': (f'894400000000000{i:04d}', FIXED_TEST_EID)
                      for i in range(50_000)}
    conv_iccid = '8944000000000000000'

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

    def mno_pcert_parse():
        # mno-server.py:239-250 -- load the on-wire DER, recover pk_U as an
        # uncompressed point for the proof check, and read the credential
        # binding extension.  NB: the deployed handler does NOT verify the
        # PCA's signature over PCert_U, so no chain verification is timed
        # here; see the note in print_report().
        cert = x509.load_der_x509_certificate(pcert_der)
        cert.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
        cert.extensions.get_extension_for_oid(binding_oid).value.value

    def mno_hpid_hcert_hash():
        # mno-server.py:259-265 -- Hpid = H'(pid), h_cert = H''(PCert_U), then
        # the L_auth replay check that rejects a repeated pseudonym.
        hp = hash_fn(pid_raw)
        hash_fn(pcert_der)
        _ = hp.hex() in acc.leaves

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

    def mno_matching_id():
        # Conventional RSP operator work per download: mint a fresh MatchingID
        # for the order and record ICCID <-> EID.  Deliberately trivial -- the
        # standard operator performs no provisioning-layer public-key crypto,
        # which is exactly what the ZK add-on is being measured against.
        mid = str(uuid.uuid4())
        conv_order_map[mid] = (conv_iccid, FIXED_TEST_EID)

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
        'mno.pcert_parse':           (mno_pcert_parse, MNO, 'download'),
        'mno.hpid_hcert_hash':       (mno_hpid_hcert_hash, MNO, 'download'),
        'mno.ecdsa_sign':            (mno_sign, MNO, 'download'),
        'base.mno_matching_id':      (mno_matching_id, MNO, 'baseline'),
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
        'mno.register_device_verify', 'mno.pcert_parse', 'mno.hpid_hcert_hash',
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
# Report width.  Wider than the usual 80 because every cost now carries a
# "± sd" term; the tables below are laid out against this.
W = 92


def _unit_ns(x):
    """Pick a display unit for a nanosecond quantity: (divisor, suffix, dp)."""
    if x < 1e3:
        return 1.0, 'ns', 0
    if x < 1e6:
        return 1e3, 'us', 2
    if x < 1e9:
        return 1e6, 'ms', 3
    return 1e9, 's', 3


def fmt_ns(x):
    div, unit, dp = _unit_ns(x)
    return f'{x / div:8.{dp}f} {unit}'


def _fmt_bytes(n, signed=False):
    sign = '+' if signed and n >= 0 else ('-' if n < 0 else '')
    n = abs(n)
    for unit, div in (('GB', 2**30), ('MB', 2**20), ('KB', 2**10)):
        if n >= div:
            return f'{sign}{n / div:.1f} {unit}'
    return f'{sign}{n:.0f} B'


def fmt_ns_pm(mean_ns, sd_ns):
    """`mean ± sd`, both rendered in the unit chosen for the mean."""
    div, unit, dp = _unit_ns(mean_ns)
    return f'{mean_ns / div:.{dp}f} ± {sd_ns / div:.{dp}f} {unit}'


def fmt_cost(cost):
    return fmt_ns_pm(cost['seconds'] * 1e9, cost['stdev_seconds'] * 1e9)


def fmt_per_n_pm(seconds, sd_seconds, n):
    """Cost of `n` independent transactions, with the spread propagated.

    The transactions are independent draws, so the total's sd grows as sqrt(n)
    while the total itself grows as n -- the relative spread therefore shrinks
    as the volume rises, which is why the per-million figure looks so much
    tighter than the per-transaction one.
    """
    total = seconds * n
    total_sd = sd_seconds * math.sqrt(n)
    if total < 1e-3:
        return f'{total * 1e6:.1f} ± {total_sd * 1e6:.1f} us'
    if total < 1.0:
        return f'{total * 1e3:.2f} ± {total_sd * 1e3:.2f} ms'
    if total < 60:
        return f'{total:.2f} ± {total_sd:.2f} s'
    return f'{total / 60:.2f} ± {total_sd / 60:.2f} min'


# ---------------------------------------------------------------------------
# Per-server cost composition
# ---------------------------------------------------------------------------
ZERO_COST = {'seconds': 0.0, 'stdev_seconds': 0.0, 'sem_seconds': 0.0}


def compose_per_server(results, selected):
    """Total the measured op stats into per-server, per-transaction costs.

    Returns {server: {metric: {'seconds', 'stdev_seconds', 'sem_seconds'}}}.
    Nothing is summed across servers: each role runs in its own process and is
    sized on its own hardware, so the SM-DP+, MNO and PCA figures stay separate.
    HEADLINE (below) picks, per server, which of its metrics drives the
    throughput / core-count sizing.

    Error propagation.  A transaction runs each op `mult` times; those runs are
    treated as independent, so variances add:

        sd(total)  = sqrt( sum |mult| * sd_op^2 )         spread of ONE transaction
        sem(total) = sqrt( sum mult^2 * sem_op^2 )        uncertainty of the MEAN

    Two consequences worth noting.  |mult| in the sd term (not mult^2) because
    the op is genuinely re-executed `mult` times per transaction, so the total
    is a sum of `mult` independent draws -- its sd grows as sqrt(mult), not
    mult.  And a SUBTRACTED term still adds variance: a difference of two
    independent measurements is no more precise than the measurements it is
    built from, so 'ZK add-on, net' carries the chain walk's noise too.
    """
    def total(items):
        mean = sum(mult * results[n]['mean_ns'] for n, mult in items) / 1e9
        var = sum(abs(mult) * results[n]['stdev_ns'] ** 2 for n, mult in items) / 1e18
        var_of_mean = sum(mult ** 2 * results[n]['sem_ns'] ** 2 for n, mult in items) / 1e18
        return {'seconds': mean,
                'stdev_seconds': math.sqrt(var),
                'sem_seconds': math.sqrt(var_of_mean)}

    out = {}

    if SMDP in selected:
        out[SMDP] = {
            'download_baseline_non_zk': total(SMDP_BASELINE),
            'download_zk_mode_total': total(SMDP_ZK_MODE_TOTAL),
            'download_zk_addon_gross': total(SMDP_ZK_ADDON),
            'download_zk_addon_net': total(SMDP_ZK_ADDON_NET),
            'download_chain_walk_saved': total(SMDP_ZK_SKIPPED),
            'enrollment': dict(ZERO_COST),   # SM-DP+ takes no part in enrollment
        }

    if MNO in selected:
        out[MNO] = {
            'download_baseline_non_zk': total(MNO_BASELINE),
            'download': total(MNO_DOWNLOAD),
            'download_zk_addon_net': total(MNO_ZK_ADDON_NET),
            'download_pure_python_schnorr': total(MNO_DOWNLOAD_PY),
            'download_zk_addon_net_pure_python': total(MNO_ZK_ADDON_NET_PY),
            'download_accumulator_oN': total(MNO_ACCUMULATOR),
            'enrollment': total(MNO_ENROLL),
        }

    if PCA in selected:
        out[PCA] = {
            'download_baseline_std_cert': total(PCA_DOWNLOAD_STD),
            'download': total(PCA_DOWNLOAD),
            'download_zk_addon_net': total(PCA_ZK_ADDON_NET),
            'enrollment': dict(ZERO_COST),   # fresh PCert_U per download; nothing one-time
        }

    return out


# ---------------------------------------------------------------------------
# Concurrency / load model
#
# The transaction each role executes when serving one request.  These must be
# all-positive op lists: they are *executed*, not merely summed, so a netted
# metric like 'ZK add-on' (which subtracts the skipped chain walk) cannot be
# used as a workload.  What a server actually runs per request is the full
# ZK-mode cost.
# ---------------------------------------------------------------------------
LOAD_TRANSACTION = {
    SMDP: ('ZK-mode download, full SM-DP+ crypto', SMDP_ZK_MODE_TOTAL),
    MNO:  ('zkRequest, hazmat Schnorr', MNO_DOWNLOAD),
    PCA:  ('certInitRequest, issues PCert_U', PCA_DOWNLOAD),
}

DEFAULT_WORKERS = os.cpu_count() or 1

# Minimum timed window per worker when auto-sizing --load-rounds.  A window of
# only a few ms is dominated by pool dispatch and OS scheduling rather than by
# the workload: measured on this testbed, the PCA appeared to reach only 2.7x
# on 8 processes with a ~1ms window and 7.3x with a ~250ms one, on identical
# code.  Short transactions therefore need proportionally more rounds.
MIN_LOAD_WINDOW_S = 0.25
MAX_LOAD_ROUNDS = 20_000


def _split_requests(total, workers):
    """Divide `total` requests as evenly as possible across `workers` slots.

    The remainder is spread one per worker rather than dumped on the last one:
    an unbalanced tail would leave workers idling while one finishes, which
    depresses throughput and inflates the all-busy overlap figure for reasons
    that have nothing to do with the workload.
    """
    if workers < 1:
        raise ValueError('workers must be >= 1')
    base, extra = divmod(max(0, total), workers)
    return [base + (1 if i < extra else 0) for i in range(workers)]

def _rss_bytes():
    """Current resident set size of this process."""
    return psutil.Process().memory_info().rss


def _proc_mem(proc):
    """(rss, pss) for one process, falling back to rss when PSS is unreadable.

    PSS divides each shared page by the number of processes mapping it, so
    summing PSS over a process tree gives total memory ONCE. Summing RSS
    double-counts every page the forked workers share with their parent --
    interpreter, loaded libraries, and any fixture built before the fork --
    which on this workload is roughly half of each worker's RSS.
    """
    try:
        info = proc.memory_full_info()
        return info.rss, getattr(info, 'pss', None) or info.uss
    except (psutil.AccessDenied, psutil.NoSuchProcess, AttributeError):
        try:
            rss = proc.memory_info().rss
            return rss, rss
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            return 0, 0


class _ResourceSampler:
    """Sample CPU and memory across this process AND its live children.

    psutil can read a running child's counters, which getrusage cannot:
    RUSAGE_CHILDREN only accounts for children already reaped, and a worker
    pool deliberately keeps its workers alive. That means the whole tree is
    measured from here, and workers no longer have to self-report.

    Memory is polled on a background thread so the figure is the peak reached
    during THIS window, rather than a high-water mark inherited from an earlier
    concurrency level. Sampling is syscall-bound and releases the GIL, so it
    does not meaningfully perturb thread-mode timings.
    """

    def __init__(self, interval=0.02):
        self.interval = interval
        self.proc = psutil.Process()
        self.peak_rss = 0
        self.peak_pss = 0
        self.peak_procs = 1
        self.cpu_seconds = 0.0
        self._cpu_start = {}
        self._cached_tree = None
        self._stop = threading.Event()
        self._thread = None

    def _tree(self, refresh=False):
        """Parent plus workers, cached.

        children(recursive=True) walks every process on the box, which at a
        20ms cadence costs more CPU than the workload being measured -- it
        showed up as the sampler apparently consuming half a core. The pool is
        fixed once the warm round has run, so the tree is resolved once and
        reused, and only re-scanned on demand.
        """
        if refresh or self._cached_tree is None:
            try:
                self._cached_tree = [self.proc] + self.proc.children(recursive=True)
            except psutil.NoSuchProcess:
                self._cached_tree = [self.proc]
        return self._cached_tree

    def _cpu_totals(self):
        # Refresh here rather than in the sampling loop: CPU is read only twice
        # (window start and end), so the expensive scan is paid twice, not
        # hundreds of times.
        out = {}
        for p in self._tree(refresh=True):
            try:
                t = p.cpu_times()
                out[p.pid] = t.user + t.system
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                continue
        return out

    def _sample_mem(self):
        tree = self._tree()
        rss = pss = 0
        for p in tree:
            r, s = _proc_mem(p)
            rss += r
            pss += s
        self.peak_rss = max(self.peak_rss, rss)
        self.peak_pss = max(self.peak_pss, pss)
        self.peak_procs = max(self.peak_procs, len(tree))

    def __enter__(self):
        self._cpu_start = self._cpu_totals()
        self._sample_mem()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        return self

    def _run(self):
        while not self._stop.wait(self.interval):
            self._sample_mem()

    def __exit__(self, *_exc):
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=1.0)
        self._sample_mem()
        end = self._cpu_totals()
        # Processes that appeared mid-window contribute their whole CPU time;
        # ones that vanished are simply absent from `end` and drop out.
        self.cpu_seconds = sum(v - self._cpu_start.get(pid, 0.0)
                               for pid, v in end.items())
        return False

# Per-process fixture set, populated by the ProcessPoolExecutor initializer.
_WORKER = {}


def _run_transaction(ops, spec):
    """Execute one request's worth of work for a role."""
    for name, mult in spec:
        fn = ops[name][0]
        for _ in range(mult):
            fn()


def _time_transactions(ops, spec, rounds):
    """Run `rounds` transactions back to back, returning per-request latencies."""
    pc = time.perf_counter_ns
    out = [0] * rounds
    for i in range(rounds):
        t0 = pc()
        _run_transaction(ops, spec)
        out[i] = pc() - t0
    return out


def _load_worker_init(curve_name, accumulator_size):
    curve = ec.SECP256R1() if curve_name == 'nist' else ec.BrainpoolP256R1()
    ops, _ = build_fixtures(curve, accumulator_size)
    _WORKER['ops'] = ops


def _load_worker_run(spec, rounds):
    """Run one worker's share of the load.

    CPU and memory are no longer self-reported: psutil lets the parent read
    live children, so the whole tree is sampled from one place. What the worker
    still has to supply is its own wall-clock span, since only it knows when it
    actually started and finished.
    """
    t0 = time.time()                      # absolute clock, comparable across processes
    lat = _time_transactions(_WORKER['ops'], spec, rounds)
    return {'lat': lat, 't0': t0, 't1': time.time()}


def _overlap_fraction(spans):
    """How much of a worker's runtime had EVERY other worker also running.

    spans is a list of (start, end) on a clock shared by all workers. Returns
    the width of the all-busy interval as a fraction of the mean worker
    runtime: 1.0 means the requests were genuinely processed at the same time
    for the whole window, 0.0 means they never once overlapped. This is the
    direct evidence that a mode is concurrent, rather than an inference drawn
    from throughput.
    """
    if len(spans) < 2:
        return None
    latest_start = max(s for s, _ in spans)
    earliest_end = min(e for _, e in spans)
    mean_span = sum(e - s for s, e in spans) / len(spans)
    if mean_span <= 0:
        return None
    return max(0.0, min(1.0, (earliest_end - latest_start) / mean_span))


def _summarize_load(latencies_ns, wall_s, concurrency, spec_serial_s, res):
    lat = sorted(latencies_ns)
    n = len(lat)
    mean = sum(lat) / n
    cpu_s = res['cpu_s']
    procs = max(1, res['processes'])
    return {
        'concurrency': concurrency,
        'requests': n,
        'wall_s': wall_s,
        'throughput_rps': n / wall_s if wall_s else 0.0,
        'lat_mean_ns': mean,
        'lat_p50_ns': float(statistics.median(lat)),
        'lat_p95_ns': float(lat[min(n - 1, int(0.95 * n))]),
        'lat_p99_ns': float(lat[min(n - 1, int(0.99 * n))]),
        'lat_max_ns': float(lat[-1]),
        'serial_service_s': spec_serial_s,
        # --- resources -----------------------------------------------------
        'cpu_seconds': cpu_s,
        # Cores' worth of CPU kept busy: >1 means genuine parallelism, ~1 means
        # one core saturated (a single reactor, or the GIL serialising threads).
        'cpu_cores_busy': (cpu_s / wall_s) if wall_s else 0.0,
        'cpu_ms_per_request': (cpu_s * 1e3 / n) if n else 0.0,
        'processes': procs,
        # RSS double-counts pages shared between forked workers; PSS is the
        # figure to size a deployment on. Both are reported so the gap between
        # them (i.e. how much is shared) stays visible.
        'rss_peak_total_bytes': res['rss_peak_total'],
        'pss_peak_total_bytes': res['pss_peak_total'],
        'pss_per_process_bytes': res['pss_peak_total'] / procs,
        'rss_growth_bytes': res['rss_growth'],
        'rss_baseline_bytes': res['rss_baseline'],
        # Measured, not assumed: fraction of a worker's runtime during which
        # every worker was simultaneously active.  None when the mode runs a
        # single worker and the question does not arise.
        'overlap_fraction': res.get('overlap'),
    }


def run_load(server, spec, workers, shares, curve_name, accumulator_size,
             serial_service_s):
    """Serve sum(shares) requests across `workers` worker processes.

    Process-based only, one worker per CPU core by default.  That is a
    deliberate choice and it is worth being clear about what it does and does
    not model: the deployed servers (osmo-smdpp.py, mno-server.py,
    pca-server.py) are Klein/Twisted apps whose handlers run inline on a single
    reactor thread, so as shipped they serve requests one at a time.  These
    figures are therefore the SCALE-OUT CEILING -- what the crypto costs when
    the same work is spread over N reactor processes -- not the throughput of
    the current single-process deployment.

    Threads are not offered because they do not help here: `cryptography`
    releases the GIL around OpenSSL EC operations, but the Merkle accumulator
    (a tight hashlib loop over small buffers) and the pure-Python Schnorr
    verifier hold it throughout, so a thread pool measured flat at ~1 core busy
    for the accumulator-dominated MNO.  Separate processes are the only shape
    that actually parallelises this workload.

    `shares` is the per-worker request count, one entry per worker, so
    sum(shares) is the total served.
    """
    spec = list(spec)
    # Taken before the pool exists, so memory attributable to serving is
    # separable from the parent process's floor.
    rss_baseline = _rss_bytes()

    with concurrent.futures.ProcessPoolExecutor(
            workers, initializer=_load_worker_init,
            initargs=(curve_name, accumulator_size)) as ex:
        # Warm round: forces every worker to spawn and build fixtures before
        # the clock starts, so process startup is not billed to throughput --
        # and so the sampler below sees the full tree from its first sample.
        list(ex.map(_load_worker_run, [spec] * workers, [1] * workers))
        rss_start = _rss_bytes()
        with _ResourceSampler() as sampler:
            t_start = time.perf_counter()
            chunks = list(ex.map(_load_worker_run, [spec] * workers, shares))
            wall = time.perf_counter() - t_start
        rss_end = _rss_bytes()
    # The sampler walks parent + workers, so the supervisor process is already
    # included -- a deployment pays for it too.
    res = {
        'cpu_s': sampler.cpu_seconds,
        'processes': sampler.peak_procs,
        'rss_peak_total': sampler.peak_rss,
        'pss_peak_total': sampler.peak_pss,
        'rss_growth': rss_end - rss_start,
        'rss_baseline': rss_baseline,
        'overlap': _overlap_fraction([(c['t0'], c['t1']) for c in chunks]),
    }
    return _summarize_load([x for c in chunks for x in c['lat']], wall,
                           workers, serial_service_s, res)



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
        ('download_baseline_non_zk',     'Baseline download, conventional RSP (ES2+ order only)'),
        ('download',                     'ZK-mode download, total zkRequest (hazmat Schnorr)'),
        ('download_zk_addon_net',        'ZK add-on, NET marginal cost per download'),
        ('download_pure_python_schnorr', 'ZK-mode download, total (pure-Python Schnorr)'),
        ('download_zk_addon_net_pure_python',
                                         '  ZK add-on, net (pure-Python Schnorr)'),
        ('download_accumulator_oN',      '  of which accumulator work, O(N)'),
        ('enrollment',                   'Per enrollment, registerCredential (one-time)'),
    ],
    PCA: [
        ('download_baseline_std_cert', 'Baseline download, std cert (certInitRequestStd)'),
        ('download',                   'ZK-mode download, certInitRequest (issues PCert_U)'),
        ('download_zk_addon_net',      'ZK add-on, NET marginal cost per download'),
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
    ap.add_argument('-R', '--requests', metavar='N[,N...]',
                    help='run a load test at each of these TOTAL request counts '
                         '(comma-separated, e.g. 1000,5000,20000). Each total is '
                         f'divided as evenly as possible across {DEFAULT_WORKERS} worker '
                         'processes, one per CPU core, which serve them in parallel.')
    ap.add_argument('--workers', type=int, default=DEFAULT_WORKERS,
                    help=f'worker processes sharing each request total '
                         f'(default: one per CPU core = {DEFAULT_WORKERS})')
    ap.add_argument('--plot', metavar='PATH',
                    help='chart peak memory and CPU against request count, one line '
                         'per role (requires --requests). The extension picks the '
                         'format. Recording --json instead lets zk_plot.py redraw '
                         'the same run later without re-measuring.')
    add_plot_args(ap)
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

    if args.plot and not args.requests:
        raise SystemExit('--plot charts results against request count, so it needs '
                         '--requests (e.g. -R 1000,5000,20000 --plot load.png)')
    if args.workers < 1:
        raise SystemExit('--workers must be >= 1')

    load = {}
    if args.requests:
        try:
            totals = sorted({int(x) for x in args.requests.split(',') if x.strip()})
        except ValueError:
            raise SystemExit(f'--requests: expected comma-separated integers, '
                             f'got {args.requests!r}')
        if not totals or totals[0] < 1:
            raise SystemExit('--requests: totals must be >= 1')
        if totals[0] < args.workers:
            raise SystemExit(f'--requests: smallest total ({totals[0]}) is fewer than '
                             f'the {args.workers} workers, so some would get no work. '
                             f'Raise the total or lower --workers.')
        env['request_totals'] = totals
        env['workers'] = args.workers
        env['concurrency_mode'] = 'process'
        for server in selected:
            label, spec = LOAD_TRANSACTION[server]
            # Serial reference: the same transaction as measured op-by-op in the
            # single-threaded pass above, so speedup is against a like-for-like
            # baseline rather than against the smallest-total row.
            serial = sum(mult * results[n]['mean_ns'] for n, mult in spec) / 1e9
            rows = []
            for total in totals:
                shares = _split_requests(total, args.workers)
                if not args.quiet:
                    print(f'[load] {SERVERS[server]["label"]}: {total:,} requests over '
                          f'{args.workers} workers ({min(shares)}-{max(shares)} each)...',
                          file=sys.stderr)
                row = run_load(server, spec, args.workers, shares, args.curve,
                               args.accumulator_size, serial)
                row['total_requests'] = total
                row['shares'] = shares
                # Per-worker window: what determines whether the timing is sound.
                row['window_s'] = max(shares) * serial
                rows.append(row)
            load[server] = {'transaction': label, 'levels': rows,
                            'workers': args.workers,
                            # recorded so zk_plot.py needs nothing from this module
                            'label': SERVERS[server]['label']}

    payload = {'env': env, 'ops': results, 'per_server_seconds': per_server,
               'load': load}

    if not args.quiet:
        print_report(payload, per_server, results, args, selected, load)

    if args.plot and load:
        if plot_load(load, args, args.plot):
            print(f'\n[plot]  wrote {args.plot} '
                  f'({args.plot_width:g}in wide, {args.plot_fontsize:g}pt base)')
            print(f'[plot]  include it UNSCALED so the type stays at '
                  f'{args.plot_fontsize:g}pt on the page:')
            print(f'[plot]    \\includegraphics[width={args.plot_width:g}in]'
                  f'{{{os.path.basename(args.plot)}}}')
            print(f'[plot]  (width=\\textwidth also works if \\textwidth is '
                  f'{args.plot_width:g}in. Scaling to a DIFFERENT width divides '
                  f'the type by the same factor.)')

    if args.json:
        import json
        with open(args.json, 'w') as fh:
            json.dump(payload, fh, indent=2)
        print(f'\n[json]  wrote {args.json}')
    if args.csv:
        with open(args.csv, 'w', newline='') as fh:
            wr = csv.writer(fh)
            wr.writerow(['op', 'server', 'phase', 'count', 'mean_us', 'median_us',
                         'p95_us', 'p99_us', 'stdev_us', 'sem_us', 'ops_per_sec'])
            for name, st in results.items():
                wr.writerow([name, st['server'], st['phase'], st['count'],
                             f"{st['mean_ns'] / 1e3:.3f}", f"{st['median_ns'] / 1e3:.3f}",
                             f"{st['p95_ns'] / 1e3:.3f}", f"{st['p99_ns'] / 1e3:.3f}",
                             f"{st['stdev_ns'] / 1e3:.3f}", f"{st['sem_ns'] / 1e3:.3f}",
                             f"{st['ops_per_sec']:.1f}"])
            wr.writerow([])
            wr.writerow(['server', 'metric', 'seconds', 'stdev_seconds', 'sem_seconds',
                         'microseconds', 'stdev_microseconds', 'sem_microseconds'])
            for server, metrics in payload['per_server_seconds'].items():
                for metric, cost in metrics.items():
                    sec, sd, sem = (cost['seconds'], cost['stdev_seconds'],
                                    cost['sem_seconds'])
                    wr.writerow([server, metric,
                                 f'{sec:.9f}', f'{sd:.9f}', f'{sem:.9f}',
                                 f'{sec * 1e6:.3f}', f'{sd * 1e6:.3f}', f'{sem * 1e6:.3f}'])
        print(f'[csv]   wrote {args.csv}')

    return 0


def print_scale(cost, per_day, unit, indent='      '):
    """Throughput / fleet-sizing lines for one per-transaction cost.

    The rate and core-count lines are deliberately quoted without a ±.  They
    follow from the mean alone: over a day's worth of transactions the per-call
    jitter averages out (that is exactly the sqrt(n) shrink above), so putting
    the single-call sd on a capacity figure would overstate the uncertainty.
    """
    sec, sd = cost['seconds'], cost['stdev_seconds']
    print(f'{indent}per {unit:<12}: {fmt_per_n_pm(sec, sd, 1)}')
    print(f'{indent}per 1,000       : {fmt_per_n_pm(sec, sd, 1_000)}')
    print(f'{indent}per 1,000,000   : {fmt_per_n_pm(sec, sd, 1_000_000)}')
    print(f'{indent}single-core rate: {1.0 / sec:,.0f} {unit}s/sec/core'
          f'  ≈ {86_400.0 / sec:,.0f} {unit}s/day/core')
    cores = per_day * sec / 86_400.0
    print(f'{indent}to sustain {per_day:,.0f} {unit}s/day: '
          f'{cores:.3g} CPU-core(s) ({math.ceil(cores)} core(s) rounded up)')


def print_server_section(idx, n, server, metrics, results, args):
    """One self-contained block per server: its ops, its totals, its sizing."""
    info = SERVERS[server]
    print()
    print('=' * W)
    print(f"SERVER {idx}/{n} — {info['label']}  ({info['module']})")
    print(f"  role: {info['role']}")
    print('=' * W)

    # --- per-op table, this server only ------------------------------------
    phases = [('download', 'per-download ZK work'),
              ('baseline', 'baseline SGP.22 transport (paid by ZK and non-ZK downloads)'),
              ('enroll', 'per-enrollment work (one-time per device)')]
    own = {nm: st for nm, st in results.items() if st['server'] == server}
    if own:
        print(f"{'operation':<34}{'mean ± sd':>24}{'median':>12}{'p95':>12}{'ops/s':>10}")
        print('-' * W)
        for phase, title in phases:
            rows = [(nm, st) for nm, st in own.items() if st['phase'] == phase]
            if not rows:
                continue
            print(f'• {title}')
            for nm, st in rows:
                print(f"  {nm:<32}{fmt_ns_pm(st['mean_ns'], st['stdev_ns']):>24}"
                      f"{fmt_ns(st['median_ns']):>12}"
                      f"{fmt_ns(st['p95_ns']):>12}{st['ops_per_sec']:>10,.0f}")
        print('-' * W)

    # --- composed totals for this server -----------------------------------
    print(f"\n  {info['label']} per-transaction cost "
          f"(sum of component means, ± propagated sd)")
    for key, lab in METRIC_LABELS[server]:
        if key not in metrics:
            continue
        print(f"  {lab:<56}{fmt_cost(metrics[key]):>26}")

    # --- sizing, driven by this server's headline metrics -------------------
    dl_key, en_key = HEADLINE[server]
    dl = metrics.get(dl_key, ZERO_COST)
    en = metrics.get(en_key, ZERO_COST)
    if dl['seconds'] > 0:
        print(f"\n  at scale — {dict(METRIC_LABELS[server]).get(dl_key, dl_key)}")
        print_scale(dl, args.downloads_per_day, 'download')
    else:
        print('\n  at scale — not in the download path (0 s per download)')
    if en['seconds'] > 0:
        print(f"\n  at scale — {dict(METRIC_LABELS[server]).get(en_key, en_key)}")
        print_scale(en, args.enrollments_per_day, 'enrollment')
    else:
        print('  at scale — takes no part in enrollment (0 s per enrollment)')


def print_summary_table(per_server, args):
    """The three servers side by side, still never summed together."""
    print()
    print('=' * W)
    print('PER-SERVER SUMMARY (single core, mean of component means ± propagated sd)')
    print('=' * W)
    print(f"{'server':<10}{'per download':>24}{'per enrollment':>24}"
          f"{'dl/sec/core':>14}{'cores @ target':>16}")
    print('-' * W)
    for server in SERVER_ORDER:
        if server not in per_server:
            continue
        metrics = per_server[server]
        dl_key, en_key = HEADLINE[server]
        dl = metrics.get(dl_key, ZERO_COST)
        en = metrics.get(en_key, ZERO_COST)
        dl_sec, en_sec = dl['seconds'], en['seconds']
        rate = f'{1.0 / dl_sec:,.0f}' if dl_sec > 0 else '—'
        cores = (f'{math.ceil(args.downloads_per_day * dl_sec / 86_400.0)}'
                 if dl_sec > 0 else '—')
        print(f"{SERVERS[server]['label']:<10}"
              f"{(fmt_cost(dl) if dl_sec > 0 else '—'):>24}"
              f"{(fmt_cost(en) if en_sec > 0 else '—'):>24}"
              f"{rate:>14}{cores:>16}")
    print('-' * W)
    print('  per download   = SM-DP+: net ZK add-on | MNO: full zkRequest crypto '
          '| PCA: certInitRequest')
    print('  each role\'s own conventional-RSP baseline and net add-on are in its section')
    print(f'  cores @ target = to sustain {args.downloads_per_day:,.0f} downloads/day '
          f'on that server alone')
    print('  the three columns are NOT additive: separate processes, separate hosts.')


def print_load_section(load, args):
    """Per-server behaviour as the total request count rises."""
    workers = args.workers
    how = ('one per CPU core' if workers == DEFAULT_WORKERS
           else f'on a {DEFAULT_WORKERS}-core host')
    print()
    print('=' * W)
    print(f'LOAD vs REQUEST COUNT  ({workers} worker processes, {how})')
    print('=' * W)
    print(f'  Each total is divided evenly across {workers} processes that serve it in')
    print('  parallel. These are SCALE-OUT figures: the shipped servers are Klein/Twisted')
    print('  apps running handlers inline on a single reactor thread, so this is the cost')
    print('  of the crypto spread over N reactors, not what one reactor delivers today.')

    for server in SERVER_ORDER:
        if server not in load:
            continue
        info = SERVERS[server]
        entry = load[server]
        print(f"\n  {info['label']}  —  {entry['transaction']}")
        print(f"  {'requests':>10}{'per worker':>12}{'wall':>11}{'throughput':>14}"
              f"{'lat p50':>12}{'lat p95':>12}{'lat max':>12}")
        print('  ' + '-' * (W - 4))
        for row in entry['levels']:
            sh = row['shares']
            per = f'{min(sh)}' if min(sh) == max(sh) else f'{min(sh)}-{max(sh)}'
            print(f"  {row['total_requests']:>10,}{per:>12}"
                  f"{row['wall_s']:>10.2f}s{row['throughput_rps']:>11,.0f}/s"
                  f"{fmt_ns(row['lat_p50_ns']):>12}{fmt_ns(row['lat_p95_ns']):>12}"
                  f"{fmt_ns(row['lat_max_ns']):>12}")
        print('  ' + '-' * (W - 4))

        # --- CPU / memory over the same sweep ------------------------------
        print(f"  {'requests':>10}{'cpu busy':>11}{'cpu total':>12}{'cpu/req':>11}"
              f"{'rss peak':>11}{'pss peak':>11}{'pss/proc':>11}{'all-busy':>10}")
        print('  ' + '-' * (W - 4))
        for row in entry['levels']:
            ov = row.get('overlap_fraction')
            print(f"  {row['total_requests']:>10,}"
                  f"{row['cpu_cores_busy']:>9.2f}x"
                  f"{row['cpu_seconds']:>11.2f}s"
                  f"{row['cpu_ms_per_request']:>9.3f}ms"
                  f"{_fmt_bytes(row['rss_peak_total_bytes']):>11}"
                  f"{_fmt_bytes(row['pss_peak_total_bytes']):>11}"
                  f"{_fmt_bytes(row['pss_per_process_bytes']):>11}"
                  f"{('—' if ov is None else f'{ov:.0%}'):>10}")
        print('  ' + '-' * (W - 4))
        srv = entry['levels'][0]['serial_service_s'] if entry['levels'] else 0.0
        base = entry['levels'][0]['rss_baseline_bytes'] if entry['levels'] else 0
        print(f"  single-request service time (op-by-op reference): "
              f"{fmt_ns(srv * 1e9).strip()}")
        print(f"  parent RSS floor before the pool was started: {_fmt_bytes(base)}")
        short = [r['total_requests'] for r in entry['levels']
                 if r['window_s'] < MIN_LOAD_WINDOW_S]
        if short:
            print(f"  [warn] totals {short} give each worker under "
                  f"{MIN_LOAD_WINDOW_S:.2g}s of work — pool dispatch and")
            print( "         scheduling jitter may dominate those rows; use larger totals")

    print()
    print('  cpu busy = CPU-seconds per wall-second, i.e. cores kept busy. It should sit')
    print(f'    near {workers} once the run is long enough to fill the pool; well below')
    print('    that means the workers are starved rather than the work being parallel.')
    print('  cpu total is the CPU-seconds the whole tree consumed and should scale')
    print('    LINEARLY with request count. cpu/req is that divided by requests and')
    print('    should stay FLAT — a rising value means added load is buying contention')
    print('    rather than throughput.')
    print('  rss peak vs pss peak: both are summed over parent + workers, but RSS counts')
    print('    every shared page once PER PROCESS, so summing it across forked workers')
    print('    double-counts the interpreter, the libraries and every fixture built')
    print('    before the fork. PSS divides each shared page by the number of processes')
    print('    mapping it, so it totals the memory ONCE. Size a deployment on pss peak;')
    print('    the gap to rss peak is what is being shared. Memory should stay FLAT as')
    print('    requests rise — a climb means per-request state is accumulating.')
    print("  all-busy is the measured share of each worker's runtime during which every")
    print('    worker was simultaneously active, from wall-clock spans the workers report')
    print('    themselves. Near 100% confirms the requests really were served in')
    print('    parallel, rather than the pool draining unevenly.')



def print_report(payload, per_server, results, args, selected, load=None):
    env = payload['env']
    line = '=' * W
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

    if load:
        print_load_section(load, args)
    print(line)


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:]))
