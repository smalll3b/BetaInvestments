# Beta Investments - Secure PHP Stock Trading Demo

This folder contains a small PHP + MySQL demo built for a security-focused coursework presentation.

## Files

- `db_config.php` - PDO connection, session hardening, CSRF, encryption, TOTP helpers.
- `login.php` - secure registration and login flow with optional TOTP 2FA.
- `trade.php` - authenticated trading page with buy/sell logic and ownership checks.
- `schema.sql` - MySQL schema and sample stock data.

## Setup

1. Create the database and tables:

```bash
mysql -u root -p < schema.sql
```

If you already have an existing database, apply the encrypted shadow-column migration first:

```bash
mysql -u root -p beta_investments < 20260505_add_numeric_enc_columns.sql
```

2. Configure environment variables for the PHP app:

```bash
export DB_HOST=127.0.0.1
export DB_PORT=3306
export DB_NAME=beta_investments
export DB_USER=root
export DB_PASS='your-password'
export APP_CRYPTO_KEY="$(openssl rand -base64 32)"
export APP_SESSION_NAME=beta_investments_session
```

3. Put the `php-backend/` folder under your web server document root or point Apache/Nginx to it.

4. Open `login.php`, register a user, then sign in and use `trade.php`.

## Optional: HTTPS/TLS reverse proxy (Scheme A)

If you want to demonstrate `in-transit` protection, use the Nginx reverse proxy in `https/`:

```bash
cd https
bash generate-cert.sh
docker compose up -d
```

Then open `https://beta.local/login.php`.

When starting the PHP container, set `APP_HTTPS_HOST=beta.local` so the app knows which HTTPS host to redirect to when a request is not already secure.

## Security features demonstrated

- `password_hash()` and `password_verify()` for adaptive password hashing.
- Optional TOTP-based 2FA for stronger authentication.
- AES-256-GCM encryption for sensitive fields at rest.
- Encrypted shadow columns for monetary values so sensitive numbers are stored twice: as DECIMAL for arithmetic and as AES-256-GCM ciphertext for at-rest protection.
- PDO prepared statements to resist SQL injection.
- CSRF tokens on all POST actions.
- `htmlspecialchars()` output escaping to prevent XSS.
- Session cookie hardening and session ID regeneration to reduce fixation/hijacking risk.
- Transactional trade updates to keep balances and holdings consistent.
- HTTPS/TLS reverse proxy support for protecting data in transit.

## Notes for your coursework demo

- If your MySQL edition supports transparent database encryption (TDE), mention that as the preferred database-layer control.
- If TDE is not available, this demo already encrypts sensitive application fields using AES-256-GCM.
- The application deliberately uses generic login errors to reduce user enumeration.
- Audit logging is included to support incident response and accountability.

