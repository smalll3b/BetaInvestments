# HTTPS reverse proxy (Scheme A)

This folder contains a small Nginx reverse-proxy setup that terminates TLS and forwards traffic to the PHP demo running on `http://host.docker.internal:8080`.

## What it does

- Redirects `http://beta.local` to `https://beta.local`
- Terminates HTTPS with a local certificate
- Proxies traffic to the PHP server
- Adds HSTS and common security headers
- Preserves `X-Forwarded-Proto: https` so the PHP app can detect secure requests

## Files

- `nginx.conf` - Nginx reverse-proxy + TLS config
- `docker-compose.yml` - starts the proxy container
- `generate-cert.sh` - helper to create a local certificate with `mkcert`

## Setup

1. Install `mkcert` and create a local CA once:

```bash
brew install mkcert
mkcert -install
```

2. Generate the certificate files:

```bash
bash generate-cert.sh
```

This creates:
- `certs/beta.local.crt`
- `certs/beta.local.key`

3. Make sure your PHP app is already running on port 8080.

4. Start the proxy:

```bash
docker compose up -d
```

5. Open:

- `https://beta.local/login.php`

## Notes for the PHP container

Set these environment variables when you start the PHP container so redirects and secure cookies behave correctly behind the proxy:

```bash
-e APP_HTTPS_HOST=beta.local
-e APP_SESSION_NAME=beta_investments_session
```

The app already checks `X-Forwarded-Proto`, so requests coming through this reverse proxy are treated as HTTPS.

