#!/usr/bin/env bash
# gen-certs.sh — Generate mTLS CA, server, and client certificates for clawkeyring.
# Usage: ./scripts/gen-certs.sh [output-dir]
#
# Output:
#   <output-dir>/ca.crt        — CA certificate
#   <output-dir>/ca.key        — CA private key (keep secret!)
#   <output-dir>/server.crt    — server certificate
#   <output-dir>/server.key    — server private key
#   <output-dir>/client.crt    — client certificate
#   <output-dir>/client.key    — client private key

set -euo pipefail

OUT="${1:-~/.clawkeyring/certs}"
OUT="${OUT/#\~/$HOME}"

mkdir -p "$OUT"
chmod 700 "$OUT"

echo "Generating mTLS certificates in $OUT"

# ---- CA ----
openssl genrsa -out "$OUT/ca.key" 4096
chmod 600 "$OUT/ca.key"

openssl req -new -x509 -days 3650 -key "$OUT/ca.key" \
  -subj "/CN=ClawKeyring CA/O=ClawInfra/C=AU" \
  -out "$OUT/ca.crt"

echo "✓ CA certificate: $OUT/ca.crt"

# ---- Server ----
openssl genrsa -out "$OUT/server.key" 4096
chmod 600 "$OUT/server.key"

openssl req -new -key "$OUT/server.key" \
  -subj "/CN=clawkeyring-server/O=ClawInfra/C=AU" \
  -out "$OUT/server.csr"

openssl x509 -req -days 365 \
  -in "$OUT/server.csr" \
  -CA "$OUT/ca.crt" -CAkey "$OUT/ca.key" -CAcreateserial \
  -extfile <(printf "subjectAltName=IP:127.0.0.1,DNS:localhost") \
  -out "$OUT/server.crt"

rm "$OUT/server.csr"
echo "✓ Server certificate: $OUT/server.crt"

# ---- Client ----
openssl genrsa -out "$OUT/client.key" 4096
chmod 600 "$OUT/client.key"

openssl req -new -key "$OUT/client.key" \
  -subj "/CN=clawkeyring-client/O=ClawInfra/C=AU" \
  -out "$OUT/client.csr"

openssl x509 -req -days 365 \
  -in "$OUT/client.csr" \
  -CA "$OUT/ca.crt" -CAkey "$OUT/ca.key" -CAcreateserial \
  -out "$OUT/client.crt"

rm "$OUT/client.csr"
echo "✓ Client certificate: $OUT/client.crt"

echo ""
echo "mTLS certificates generated successfully."
echo ""
echo "Use with:"
echo "  clawkeyring serve --cert $OUT/server.crt --key $OUT/server.key --ca $OUT/ca.crt"
