#!/bin/sh
# Generate a self-signed cert for local testing. NOT for production.
set -e
mkdir -p tls
openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout tls/key.pem -out tls/cert.pem \
    -days 365 -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost"
echo "wrote tls/cert.pem and tls/key.pem"
