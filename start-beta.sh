#!/usr/bin/env bash
set -euo pipefail

ROOT="/Users/itst/Desktop/BetaInvestments"
PHP_DIR="$ROOT/php-backend"
HTTPS_DIR="$PHP_DIR/https"
CERT_DIR="$HTTPS_DIR/certs"

MYSQL_CONTAINER="beta-mysql"
PHP_IMAGE="beta-php-mysql"
PHP_CONTAINER="beta-php"
PROXY_CONTAINER="beta-nginx"
NETWORK="beta-net"
DB_NAME="beta_investments"
DB_PASS="rootpass123"
APP_SESSION_NAME="beta_investments_session"
APP_HTTPS_HOST="beta.local"

cd "$PHP_DIR"

docker network create "$NETWORK" >/dev/null 2>&1 || true

if ! docker ps --format '{{.Names}}' | grep -qx "$MYSQL_CONTAINER"; then
  docker rm -f "$MYSQL_CONTAINER" >/dev/null 2>&1 || true
  docker run -d \
    --name "$MYSQL_CONTAINER" \
    --network "$NETWORK" \
    -e MYSQL_ROOT_PASSWORD="$DB_PASS" \
    -e MYSQL_DATABASE="$DB_NAME" \
    -v /tmp/beta-investments/mysql-data:/var/lib/mysql \
    mysql:8.0 >/dev/null
fi

for i in {1..30}; do
  if docker exec "$MYSQL_CONTAINER" mysqladmin -uroot -p"$DB_PASS" ping --silent >/dev/null 2>&1; then
    break
  fi
  sleep 2
done

docker exec -i "$MYSQL_CONTAINER" mysql -uroot -p"$DB_PASS" "$DB_NAME" < schema.sql
if [ -f "20260505_add_numeric_enc_columns.sql" ]; then
  docker exec -i "$MYSQL_CONTAINER" mysql -uroot -p"$DB_PASS" "$DB_NAME" < 20260505_add_numeric_enc_columns.sql
fi

if ! docker image inspect "$PHP_IMAGE" >/dev/null 2>&1; then
  docker build -t "$PHP_IMAGE" -<<'EOF2'
FROM php:8.3-cli
RUN docker-php-ext-install pdo_mysql
WORKDIR /app
CMD ["php", "-S", "0.0.0.0:8080"]
EOF2
fi

APP_CRYPTO_KEY="${APP_CRYPTO_KEY:-$(openssl rand -base64 32)}"

docker rm -f "$PHP_CONTAINER" >/dev/null 2>&1 || true
docker run -d \
  --name "$PHP_CONTAINER" \
  --network "$NETWORK" \
  -p 8080:8080 \
  -v "$PHP_DIR":/app \
  -w /app \
  -e DB_HOST="$MYSQL_CONTAINER" \
  -e DB_PORT=3306 \
  -e DB_NAME="$DB_NAME" \
  -e DB_USER=root \
  -e DB_PASS="$DB_PASS" \
  -e APP_CRYPTO_KEY="$APP_CRYPTO_KEY" \
  -e APP_SESSION_NAME="$APP_SESSION_NAME" \
  -e APP_HTTPS_HOST="$APP_HTTPS_HOST" \
  "$PHP_IMAGE" php -S 0.0.0.0:8080 >/dev/null

if ! command -v mkcert >/dev/null 2>&1; then
  echo "mkcert not found. Install it first:"
  echo "  brew install mkcert"
  echo "  mkcert -install"
  exit 1
fi

mkdir -p "$CERT_DIR"
if [ ! -f "$CERT_DIR/beta.local.crt" ] || [ ! -f "$CERT_DIR/beta.local.key" ]; then
  mkcert -key-file "$CERT_DIR/beta.local.key" -cert-file "$CERT_DIR/beta.local.crt" beta.local localhost 127.0.0.1
fi

cd "$HTTPS_DIR"
docker compose up -d

echo "Open: https://beta.local/login.php"
