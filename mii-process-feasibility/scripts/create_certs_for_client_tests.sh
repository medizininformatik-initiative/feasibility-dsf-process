#!/usr/bin/env bash

BASE_DIR="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
TARGET_DIR="${BASE_DIR}/../src/test/resources/de/medizininformatik_initiative/process/feasibility/client/certs"

mkdir -p "${TARGET_DIR}"

# Create a self signed CA
openssl req -x509 -sha256 -days 7 -nodes -newkey rsa:2048 -keyout ${TARGET_DIR}/ca_key.pem \
  -out ${TARGET_DIR}/ca.pem \
  -subj "/C=DE/ST=Berlin/L=Berlin/O=Foo/CN=Test Root CA"

# Convert certificate to PKCS12 format
openssl pkcs12 -export -out ${TARGET_DIR}/ca.p12 \
  -in  ${TARGET_DIR}/ca.pem \
  -inkey ${TARGET_DIR}/ca_key.pem \
  -passout pass:changeit

# Issue server certificate using said self signed CA
openssl req -nodes -sha256 -new -newkey rsa:2048 -keyout ${TARGET_DIR}/server_cert_key.pem \
  -out ${TARGET_DIR}/server_cert_csr.pem \
  -subj "/C=DE/ST=Berlin/L=Berlin/O=Bar/CN=localhost" \
  -addext "subjectAltName = DNS:localhost, DNS:proxy"

openssl x509 -req -days 7 -sha256 -in ${TARGET_DIR}/server_cert_csr.pem \
  -CA ${TARGET_DIR}/ca.pem \
  -CAkey ${TARGET_DIR}/ca_key.pem \
  -CAcreateserial \
  -copy_extensions copyall \
  -out ${TARGET_DIR}/server_cert.pem

# Server cert chain
cat ${TARGET_DIR}/server_cert.pem > ${TARGET_DIR}/server_cert_chain.pem
cat ${TARGET_DIR}/ca.pem >> ${TARGET_DIR}/server_cert_chain.pem

# Issue client certificate using said self signed CA
openssl req -nodes -sha256 -new -newkey rsa:2048 -keyout ${TARGET_DIR}/client_cert_key.pem \
  -out ${TARGET_DIR}/client_cert_csr.pem \
  -subj "/C=DE/ST=Berlin/L=Berlin/O=Bar/CN=test-client"

openssl x509 -req -days 7 -sha256 -in ${TARGET_DIR}/client_cert_csr.pem \
  -CA ${TARGET_DIR}/ca.pem \
  -CAkey ${TARGET_DIR}/ca_key.pem \
  -CAcreateserial \
  -out ${TARGET_DIR}/client_cert.pem

# Client Key Store
openssl pkcs12 -export -out ${TARGET_DIR}/client_key_store.p12 \
  -inkey ${TARGET_DIR}/client_cert_key.pem \
  -in ${TARGET_DIR}/client_cert.pem \
  -passout pass:changeit

## CLEANUP
rm -f ${BASE_DIR}/.srl
rm -f ${TARGET_DIR}/ca.srl
rm -f ${TARGET_DIR}/ca_key.pem
rm -f ${TARGET_DIR}/server_cert.pem
