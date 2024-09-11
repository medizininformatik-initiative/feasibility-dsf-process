#!/usr/bin/env sh
set -e

BASE_DIR="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"

mvn -f ../mii-process-feasibility/pom.xml clean package -DskipTests=true
mvn -f ../mii-process-feasibility-tools/mii-process-feasibility-test-data-generator/pom.xml clean package -DskipTests=true

# Create a self signed CA
openssl req -x509 -sha256 -days 365 -nodes -newkey rsa:2048 -keyout ${BASE_DIR}/secrets/dic_3_store_proxy_self_signed_ca_key.pem \
  -out ${BASE_DIR}/secrets/dic_3_store_proxy_self_signed_ca.pem \
  -subj "/C=DE/ST=Berlin/L=Berlin/O=Foo/CN=Foo Root CA"

# Convert certificate to PKCS12 format
# This is done using keytool instead of openssl since keytool adds a proprietary attribute that openssl does not.
# Without this attribute Java cannot properly process the resulting P12 file.
rm -f ${BASE_DIR}/secrets/dic_3_store_proxy_self_signed_ca.p12
keytool -genkeypair -alias tmp -storepass testpw -keyalg RSA \
  -keystore ${BASE_DIR}/secrets/dic_3_store_proxy_self_signed_ca.p12 \
  -dname "CN=tmp, OU=tmp, O=tmp, L=tmp, ST=tmp, C=tmp"
keytool -delete -alias tmp -storepass testpw \
  -keystore ${BASE_DIR}/secrets/dic_3_store_proxy_self_signed_ca.p12
keytool -importcert -file ${BASE_DIR}/secrets/dic_3_store_proxy_self_signed_ca.pem \
  -keystore ${BASE_DIR}/secrets/dic_3_store_proxy_self_signed_ca.p12 \
  -storepass testpw \
  -noprompt \
  -alias "CA"

# Issue certificate using said self signed CA
openssl req -nodes -sha256 -new -newkey rsa:2048 -keyout ${BASE_DIR}/secrets/dic_3_store_proxy_cert_key.pem \
  -out ${BASE_DIR}/secrets/dic_3_store_proxy_cert_csr.pem \
  -subj "/C=DE/ST=Berlin/L=Berlin/O=Bar/CN=dic-3-store-proxy"

openssl x509 -req -days 365 -sha256 -in ${BASE_DIR}/secrets/dic_3_store_proxy_cert_csr.pem \
  -CA ${BASE_DIR}/secrets/dic_3_store_proxy_self_signed_ca.pem \
  -CAkey ${BASE_DIR}/secrets/dic_3_store_proxy_self_signed_ca_key.pem \
  -CAcreateserial \
  -out ${BASE_DIR}/secrets/dic_3_store_proxy_cert.pem

rm -f ${BASE_DIR}/secrets/dic_3_store_proxy_self_signed_ca.srl

# Bundle Proxy Certificates
cat ${BASE_DIR}/secrets/dic_3_store_proxy_cert.pem > ${BASE_DIR}/secrets/dic_3_store_proxy_cert_bundle.pem
cat ${BASE_DIR}/secrets/dic_3_store_proxy_self_signed_ca.pem >> ${BASE_DIR}/secrets/dic_3_store_proxy_cert_bundle.pem

