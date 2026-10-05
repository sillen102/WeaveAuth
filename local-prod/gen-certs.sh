#!/usr/bin/env bash
# Throwaway CA + one server cert for the local-prod stack. Never use these anywhere real.
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p certs && cd certs
# A trusted CA's key must never stay on disk; refuse to reuse one.
[ -f ca.key ] && { echo "certs/ holds a CA key; rm -rf certs and re-run"; exit 1; }
[ -f server.crt ] && { echo "certs/ exists; delete it to regenerate"; exit 0; }
# The CA gets trusted in a browser: without its key nobody can issue another cert from it,
# so it goes whether the script finishes or dies on the way.
trap 'rm -f ca.key server.csr server.ext ca.srl' EXIT

# CA extensions set explicitly: whether `req -x509` adds them depends on the local openssl.cnf.
# Name-constrained to the stack's own names, so trusting it can't vouch for any other site.
openssl req -x509 -newkey rsa:2048 -nodes -days 365 -subj "/CN=WeaveAuth local-prod CA" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "nameConstraints=critical,permitted;DNS:localhost,permitted;DNS:mail" \
  -keyout ca.key -out ca.crt
openssl req -newkey rsa:2048 -nodes -subj "/CN=login.localhost" -keyout server.key -out server.csr
cat > server.ext <<'EXT'
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:login.localhost, DNS:bff.localhost, DNS:mail
EXT
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 365 \
  -extfile server.ext -out server.crt
# ponytail: world-readable so Caddy and Mailpit can read it whatever uid they run as; test keys only.
chmod 644 server.key
echo "Done. Trust certs/ca.crt in your browser to skip the warning."
