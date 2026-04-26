#!/usr/bin/env bash
# Generate PCA TLS certificate (P-256 / NIST, self-signed for local tests).
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

echo "Generating PCA TLS private key (P-256)..."
openssl ecparam -name prime256v1 -genkey -noout \
    -out SK_PCA_TLS_NIST.pem

echo "Extracting PCA TLS public key..."
openssl ec -in SK_PCA_TLS_NIST.pem -pubout \
    -out PK_PCA_TLS_NIST.pem 2>/dev/null

echo "Generating self-signed PCA TLS certificate..."
openssl req -new -x509 \
    -key SK_PCA_TLS_NIST.pem \
    -out CERT_PCA_TLS_NIST.pem \
    -days 3650 \
    -sha256 \
    -config CERT_PCA_TLS.csr.cnf \
    -addext "keyUsage=critical,digitalSignature" \
    -addext "extendedKeyUsage=critical,serverAuth" \
    -addext "subjectAltName=DNS:testpca1.example.com,DNS:localhost,IP:127.0.0.1" \
    -addext "subjectKeyIdentifier=hash"

echo "Converting to DER..."
openssl x509 -in CERT_PCA_TLS_NIST.pem -outform DER \
    -out CERT_PCA_TLS_NIST.der

echo "Done. Files written:"
ls -lh SK_PCA_TLS_NIST.pem PK_PCA_TLS_NIST.pem CERT_PCA_TLS_NIST.pem CERT_PCA_TLS_NIST.der
