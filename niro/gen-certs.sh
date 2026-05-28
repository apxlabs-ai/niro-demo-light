#!/usr/bin/env bash
# Generate the self-signed CA, server cert, and per-user client certs
# for the mTLS endpoint (port 8443).
#
# All certs are committed to niro/certs/ — they are demo-only, non-secret
# credentials for local testing. Same pattern as gen-credentials.sh
# committing plaintext passwords.
#
# Rerun any time you want fresh certs (e.g. after expiry).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="$SCRIPT_DIR/certs"
mkdir -p "$OUT"

# ---------------------------------------------------------------------------
# CA
# ---------------------------------------------------------------------------
openssl genrsa -out "$OUT/ca.key" 2048 2>/dev/null
openssl req -new -x509 -days 3650 -key "$OUT/ca.key" -out "$OUT/ca.crt" \
  -subj "/CN=niro-demo-CA/O=niro-demo" 2>/dev/null
echo "→ CA: $OUT/ca.crt"

# ---------------------------------------------------------------------------
# Server cert (SAN=localhost so curl --cacert ca.crt trusts it)
# ---------------------------------------------------------------------------
openssl genrsa -out "$OUT/server.key" 2048 2>/dev/null
openssl req -new -key "$OUT/server.key" -out "$OUT/server.csr" \
  -subj "/CN=localhost/O=niro-demo" 2>/dev/null
openssl x509 -req -days 3650 -in "$OUT/server.csr" -CA "$OUT/ca.crt" \
  -CAkey "$OUT/ca.key" -CAcreateserial -out "$OUT/server.crt" \
  -extfile <(printf "subjectAltName=DNS:localhost,IP:127.0.0.1") 2>/dev/null
rm "$OUT/server.csr"
echo "→ server: $OUT/server.crt"

# ---------------------------------------------------------------------------
# Client certs — one per demo user; CN = user email
# ---------------------------------------------------------------------------
_client_cert() {
  local name="$1" cn="$2"
  openssl genrsa -out "$OUT/client-${name}.key" 2048 2>/dev/null
  openssl req -new -key "$OUT/client-${name}.key" -out "$OUT/client-${name}.csr" \
    -subj "/CN=${cn}/O=niro-demo" 2>/dev/null
  openssl x509 -req -days 3650 -in "$OUT/client-${name}.csr" \
    -CA "$OUT/ca.crt" -CAkey "$OUT/ca.key" -CAcreateserial \
    -out "$OUT/client-${name}.crt" 2>/dev/null
  rm "$OUT/client-${name}.csr"
  echo "→ client cert for ${cn}: $OUT/client-${name}.crt"
}

_client_cert "alex"  "alex@customer.test"
_client_cert "blair" "blair@customer.test"
_client_cert "agent" "agent@helpdesk.test"

echo "→ all certs written to $OUT"
echo "→ run niro/gen-credentials.sh to embed PEM blocks in credentials.yaml"
