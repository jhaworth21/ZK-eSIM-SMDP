#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

openssl ecparam -name prime256v1 -genkey -noout -out SK_MNO_TLS_NIST.pem
openssl ec -in SK_MNO_TLS_NIST.pem -pubout -out PK_MNO_TLS_NIST.pem
openssl req -new -key SK_MNO_TLS_NIST.pem -out CERT_MNO_TLS_NIST.csr -config CERT_MNO_TLS.csr.cnf
openssl x509 -req -days 3650 -in CERT_MNO_TLS_NIST.csr \
    -signkey SK_MNO_TLS_NIST.pem \
    -out CERT_MNO_TLS_NIST.pem \
    -extfile CERT_MNO_TLS.ext.cnf
openssl x509 -in CERT_MNO_TLS_NIST.pem -outform der -out CERT_MNO_TLS_NIST.der
rm -f CERT_MNO_TLS_NIST.csr
