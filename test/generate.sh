#!/bin/bash -ex


# generate ssl key and self signed certificate
openssl req -nodes -newkey rsa:2048 -keyout ssl.key -out ssl.csr -subj "/C=US/O=Test/CN=nginx-sxg.test"
openssl x509 -req -days 365 -signkey ssl.key < ssl.csr > ssl.crt
rm ssl.csr

# generate sxg key and self signed certificate
generate_sxg_key_pair() {
  KEYNAME=${1}
  openssl ecparam -out ${KEYNAME}.key -name prime256v1 -genkey
  openssl req -new -sha256 -key ${KEYNAME}.key -out ${KEYNAME}.csr -subj '/C=US/O=Test/CN=nginx-sxg.test'
  openssl x509 -req -days 90 -in ${KEYNAME}.csr -signkey ${KEYNAME}.key -out ${KEYNAME}.crt \
    -extfile <(echo -e "1.3.6.1.4.1.11129.2.1.22 = ASN1:NULL\nsubjectAltName=DNS:nginx-sxg.test")
  rm ${KEYNAME}.csr
}
generate_sxg_key_pair "sxg"
generate_sxg_key_pair "sxg1"
generate_sxg_key_pair "sxg2"
generate_sxg_key_pair "sxg3"
