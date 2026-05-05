#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERT_DIR="${1:-$SCRIPT_DIR/certs}"
DOMAIN="${2:-beta.local}"

mkdir -p "$CERT_DIR"

if ! command -v mkcert >/dev/null 2>&1; then
  cat >&2 <<'EOF'
mkcert is not installed.
Install it on macOS with:
  brew install mkcert
  mkcert -install
EOF
  exit 1
fi

mkcert -key-file "$CERT_DIR/${DOMAIN}.key" -cert-file "$CERT_DIR/${DOMAIN}.crt" "$DOMAIN" localhost 127.0.0.1

echo "Created TLS certs in: $CERT_DIR"
echo "Use docker compose up -d in the https/ directory to start the reverse proxy."

