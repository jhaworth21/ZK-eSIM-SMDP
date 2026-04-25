#!/usr/bin/env bash
# Generate MNO TLS certificate (P-256 / NIST, self-signed for test use).
# Follows the same naming convention as DPtls/:
#   SK_MNO_TLS_NIST.pem   — private key
#   PK_MNO_TLS_NIST.pem   — public key
#   CERT_MNO_TLS_NIST.pem — certificate (PEM)
#   CERT_MNO_TLS_NIST.der — certificate (DER)
#
# Note: the SM-DP+ TLS certs (DPtls/) were taken from SGP.26 v3 test data and
# are CI-signed.  The MNO cert is self-signed because no CI private key is
# available in this repository; lpac disables peer verification (VERIFYPEER=0),
# so this is equivalent for local development.
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

echo "Generating MNO TLS private key (P-256)..."
openssl ecparam -name prime256v1 -genkey -noout \
    -out SK_MNO_TLS_NIST.pem

echo "Extracting MNO TLS public key..."
openssl ec -in SK_MNO_TLS_NIST.pem -pubout \
    -out PK_MNO_TLS_NIST.pem 2>/dev/null

echo "Generating self-signed MNO TLS certificate..."
openssl req -new -x509 \
    -key SK_MNO_TLS_NIST.pem \
    -out CERT_MNO_TLS_NIST.pem \
    -days 3650 \
    -sha256 \
    -config CERT_MNO_TLS.csr.cnf \
    -addext "keyUsage=critical,digitalSignature" \
    -addext "extendedKeyUsage=critical,serverAuth,clientAuth" \
    -addext "subjectAltName=DNS:testmno1.example.com,DNS:localhost" \
    -addext "subjectKeyIdentifier=hash"

echo "Converting to DER..."
openssl x509 -in CERT_MNO_TLS_NIST.pem -outform DER \
    -out CERT_MNO_TLS_NIST.der

echo "Done. Files written:"
ls -lh SK_MNO_TLS_NIST.pem PK_MNO_TLS_NIST.pem CERT_MNO_TLS_NIST.pem CERT_MNO_TLS_NIST.der
openssl x509 -in CERT_MNO_TLS_NIST.pem -noout \
    -subject -issuer -dates -fingerprint -sha256
