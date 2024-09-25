#!/bin/sh

openssl req \
    -nodes \
    -newkey rsa:2048 \
    -keyout ./signer.key \
    -out ./signer.csr \
    -subj '/C=FR/ST=PACA/L=Nice/O=super-secure-organisation/OU=certifier-1/UID=truc/CN='"$1" \
    -addext 'subjectAltName=DNS:super-cool-domain.org'

openssl req \
    -x509 \
    -nodes \
    -newkey rsa:2048 \
    -keyout ./issuer.key \
    -out ./issuer.crt \
    -subj '/C=FR/ST=PACA/L=Nice/O=super-secure-organisation/OU=certifier-1/UID=truc/CN='"$1-issuer" \
    -addext 'subjectAltName=DNS:super-cool-domain.org'

openssl x509 -req \
    -in signer.csr \
    -days 365 \
    -CA issuer.crt \
    -CAkey issuer.key \
    -CAcreateserial \
    -out signer.crt