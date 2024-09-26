#!/bin/sh

openssl req \
    -x509 \
    -nodes \
    -days 365 \
    -newkey rsa:2048 \
    -keyout ./sign.key \
    -out ./sign.crt \
    -subj '/C=FR/ST=PACA/L=Nice/O=super-secure-organisation/OU=certifier-1/UID=truc/CN='"$1" \
    -addext 'subjectAltName=DNS:super-cool-domain.org'