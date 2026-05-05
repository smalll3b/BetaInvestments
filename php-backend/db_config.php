<?php
declare(strict_types=1);

/**
 * Beta Investments - shared security and database bootstrap.
 *
 * This file centralises the security controls used by the demo application:
 * - PDO with prepared statements for SQL injection resistance.
 * - Session hardening to reduce session hijacking risk.
 * - CSRF token generation/verification for state-changing requests.
 * - HTML escaping helpers for XSS prevention.
 * - AES-256-GCM field encryption for sensitive data at rest.
 * - TOTP helpers for an optional second factor.
 */

date_default_timezone_set('Europe/London');

// In a teaching/demo environment, errors are useful. In production, log instead.
ini_set('display_errors', '1');
error_reporting(E_ALL);

/**
 * Start a hardened session once per request.
 *
 * The security flags below are important because PHP sessions are often
 * targeted by cookie theft or fixation attacks:
 * - HttpOnly: blocks JavaScript access to the session cookie.
 * - Secure: only sends the cookie over HTTPS.
 * - SameSite=Lax: helps reduce CSRF risk for normal navigation.
 * - session_regenerate_id(): called after authentication to prevent fixation.
 */
function start_secure_session(): void
{
    if (session_status() === PHP_SESSION_ACTIVE) {
        return;
    }

    $https = is_https_request();

    if (PHP_SAPI !== 'cli' && !$https && getenv('APP_REQUIRE_HTTPS') !== '0') {
        $canonicalHost = canonical_https_host();
        $requestUri = $_SERVER['REQUEST_URI'] ?? '/';
        header('Location: https://' . $canonicalHost . $requestUri, true, 301);
        exit;
    }

    session_name(getenv('APP_SESSION_NAME') ?: 'beta_investments_session');
    session_set_cookie_params([
        'lifetime' => 0,
        'path' => '/',
        'domain' => '',
        'secure' => $https,
        'httponly' => true,
        'samesite' => 'Lax',
    ]);

    session_start();
}

/**
 * Determine whether the current request arrived over HTTPS, including a TLS
 * reverse-proxy termination that forwards X-Forwarded-Proto.
 */
function is_https_request(): bool
{
    $https = (!empty($_SERVER['HTTPS']) && strtolower((string) $_SERVER['HTTPS']) !== 'off')
        || (($_SERVER['SERVER_PORT'] ?? null) === '443');

    $forwardedProto = strtolower(trim((string) ($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '')));
    $forwardedSsl = strtolower(trim((string) ($_SERVER['HTTP_X_FORWARDED_SSL'] ?? '')));

    return $https || $forwardedProto === 'https' || $forwardedSsl === 'on';
}

/**
 * Build the canonical host used when redirecting HTTP traffic to HTTPS.
 */
function canonical_https_host(): string
{
    $host = getenv('APP_HTTPS_HOST');
    if (!is_string($host) || trim($host) === '') {
        $host = (string) ($_SERVER['HTTP_HOST'] ?? 'localhost');
    }

    $host = trim($host);
    $host = preg_replace('/:\d+$/', '', $host) ?? $host;
    return $host !== '' ? $host : 'localhost';
}

start_secure_session();

/**
 * Escape HTML output to stop user-supplied content becoming executable script.
 */
function e(?string $value): string
{
    return htmlspecialchars($value ?? '', ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

/**
 * Create a CSRF token for the current session.
 *
 * The token is stored server-side in the session and also embedded in forms.
 * A successful POST must present the same token, which makes forged requests
 * from another site much harder.
 */
function csrf_token(): string
{
    if (empty($_SESSION['_csrf_token']) || !is_string($_SESSION['_csrf_token'])) {
        $_SESSION['_csrf_token'] = bin2hex(random_bytes(32));
    }

    return $_SESSION['_csrf_token'];
}

/**
 * Verify a submitted CSRF token.
 */
function verify_csrf_token(?string $token): bool
{
    return is_string($token)
        && isset($_SESSION['_csrf_token'])
        && is_string($_SESSION['_csrf_token'])
        && hash_equals($_SESSION['_csrf_token'], $token);
}

/**
 * Basic request helper.
 */
function is_post(): bool
{
    return ($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST';
}

/**
 * Redirect and stop execution.
 */
function redirect(string $location): void
{
    header('Location: ' . $location);
    exit;
}

/**
 * Return the current authenticated user ID from the session.
 */
function current_user_id(): ?int
{
    return isset($_SESSION['user_id']) ? (int) $_SESSION['user_id'] : null;
}

/**
 * Protect routes that require authentication.
 */
function require_auth(): void
{
    if (current_user_id() === null) {
        redirect('login.php');
    }
}

/**
 * Generate a stable application secret key from the environment.
 *
 * For AES-256 we need exactly 32 bytes of key material. The safest approach is
 * to supply a random base64 string through APP_CRYPTO_KEY.
 */
function crypto_key(): string
{
    $raw = getenv('APP_CRYPTO_KEY');
    if ($raw === false || $raw === '') {
        throw new RuntimeException('APP_CRYPTO_KEY is not configured.');
    }

    // Allow both raw text and base64-encoded values for convenience.
    $decoded = base64_decode($raw, true);
    $key = $decoded !== false ? $decoded : $raw;

    if (strlen($key) !== 32) {
        $key = hash('sha256', $key, true);
    }

    return $key;
}

/**
 * Encrypt a sensitive field using AES-256-GCM.
 *
 * GCM gives confidentiality + integrity: if the ciphertext is altered, decryption
 * will fail instead of silently returning corrupted plaintext.
 */
function encrypt_sensitive_value(string $plaintext): string
{
    $iv = random_bytes(12); // Recommended IV length for GCM.
    $tag = '';
    $ciphertext = openssl_encrypt(
        $plaintext,
        'aes-256-gcm',
        crypto_key(),
        OPENSSL_RAW_DATA,
        $iv,
        $tag
    );

    if ($ciphertext === false) {
        throw new RuntimeException('Unable to encrypt sensitive data.');
    }

    // Versioned payload makes future migrations easier.
    return 'v1:' . base64_encode($iv . $tag . $ciphertext);
}

/**
 * Decrypt a value previously stored by encrypt_sensitive_value().
 */
function decrypt_sensitive_value(?string $payload): ?string
{
    if ($payload === null || $payload === '') {
        return null;
    }

    if (!str_starts_with($payload, 'v1:')) {
        // If legacy plaintext data exists, return it as-is so the demo still runs.
        return $payload;
    }

    $raw = base64_decode(substr($payload, 3), true);
    if ($raw === false || strlen($raw) < 28) {
        return null;
    }

    $iv = substr($raw, 0, 12);
    $tag = substr($raw, 12, 16);
    $ciphertext = substr($raw, 28);

    $plaintext = openssl_decrypt(
        $ciphertext,
        'aes-256-gcm',
        crypto_key(),
        OPENSSL_RAW_DATA,
        $iv,
        $tag
    );

    return $plaintext === false ? null : $plaintext;
}

/**
 * Normalize a numeric value to a fixed-scale decimal string.
 *
 * This keeps the encrypted payload stable and avoids scientific notation.
 */
function normalize_decimal_string(mixed $value, int $scale = 2): ?string
{
    if ($value === null || $scale < 0) {
        return null;
    }

    if (!is_int($value) && !is_float($value) && !is_string($value)) {
        return null;
    }

    $stringValue = is_string($value) ? trim($value) : (string) $value;
    if ($stringValue === '' || !preg_match('/^-?\d+(?:\.\d+)?$/', $stringValue)) {
        return null;
    }

    $negative = str_starts_with($stringValue, '-');
    if ($negative) {
        $stringValue = substr($stringValue, 1);
    }

    [$integerPart, $fractionalPart] = array_pad(explode('.', $stringValue, 2), 2, '');
    $integerPart = ltrim($integerPart, '0');
    if ($integerPart === '') {
        $integerPart = '0';
    }

    $fractionalPart = substr(str_pad($fractionalPart, $scale, '0'), 0, $scale);
    $normalized = $scale > 0 ? $integerPart . '.' . $fractionalPart : $integerPart;
    $isZero = $integerPart === '0' && trim($fractionalPart, '0') === '';

    return ($negative && !$isZero ? '-' : '') . $normalized;
}

/**
 * Encrypt a numeric value after canonicalizing it to a decimal string.
 */
function encrypt_numeric_value(mixed $value, int $scale = 2): ?string
{
    $normalized = normalize_decimal_string($value, $scale);
    if ($normalized === null) {
        return null;
    }

    return encrypt_sensitive_value($normalized);
}

/**
 * Decrypt a numeric payload back into a canonical decimal string.
 */
function decrypt_numeric_value(?string $payload, int $scale = 2): ?string
{
    $plaintext = decrypt_sensitive_value($payload);
    if ($plaintext === null) {
        return null;
    }

    return normalize_decimal_string($plaintext, $scale);
}

/**
 * Convenience helper when a float is specifically needed in application logic.
 */
function decrypt_numeric_float_value(?string $payload, int $scale = 2): ?float
{
    $normalized = decrypt_numeric_value($payload, $scale);
    return $normalized === null ? null : (float) $normalized;
}

/**
 * Base32 encoding is useful for TOTP secrets because authenticator apps expect it.
 */
function base32_encode_bytes(string $data): string
{
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $binary = '';
    foreach (str_split($data) as $char) {
        $binary .= str_pad(decbin(ord($char)), 8, '0', STR_PAD_LEFT);
    }

    $output = '';
    foreach (str_split($binary, 5) as $chunk) {
        if (strlen($chunk) < 5) {
            $chunk = str_pad($chunk, 5, '0', STR_PAD_RIGHT);
        }
        $output .= $alphabet[bindec($chunk)];
    }

    return rtrim(str_split($output, 8) ? $output : '', '=');
}

/**
 * Generate a fresh TOTP secret.
 */
function generate_totp_secret(int $bytes = 20): string
{
    return base32_encode_bytes(random_bytes($bytes));
}

/**
 * Decode a Base32 string into raw bytes.
 */
function base32_decode_string(string $input): string
{
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $input = strtoupper(preg_replace('/[^A-Z2-7]/', '', $input) ?? '');

    $binary = '';
    foreach (str_split($input) as $char) {
        $position = strpos($alphabet, $char);
        if ($position === false) {
            continue;
        }
        $binary .= str_pad(decbin($position), 5, '0', STR_PAD_LEFT);
    }

    $bytes = '';
    foreach (str_split($binary, 8) as $chunk) {
        if (strlen($chunk) === 8) {
            $bytes .= chr(bindec($chunk));
        }
    }

    return $bytes;
}

/**
 * Verify a 6-digit TOTP code.
 *
 * This is intentionally self-contained so the demo does not depend on a third
 * party library. The current window is 30 seconds, which matches common apps
 * such as Google Authenticator or Microsoft Authenticator.
 */
function verify_totp_code(string $base32Secret, string $code, int $window = 1): bool
{
    $code = preg_replace('/\D/', '', $code) ?? '';
    if (strlen($code) !== 6) {
        return false;
    }

    $secret = base32_decode_string($base32Secret);
    if ($secret === '') {
        return false;
    }

    $timeSlice = (int) floor(time() / 30);
    for ($i = -$window; $i <= $window; $i++) {
        $counter = $timeSlice + $i;
        $binaryCounter = pack('N*', 0) . pack('N*', $counter);
        $hash = hash_hmac('sha1', $binaryCounter, $secret, true);
        $offset = ord(substr($hash, -1)) & 0x0F;
        $part = substr($hash, $offset, 4);
        $value = unpack('N', $part)[1] & 0x7FFFFFFF;
        $otp = str_pad((string) ($value % 1000000), 6, '0', STR_PAD_LEFT);

        if (hash_equals($otp, $code)) {
            return true;
        }
    }

    return false;
}

/**
 * Send a security event to the audit log if the table exists.
 *
 * Logging authentication and trade activity helps with incident response and is
 * a good talking point in a security demonstration.
 */
function audit_event(PDO $pdo, ?int $userId, string $eventType, string $details): void
{
    try {
        $stmt = $pdo->prepare(
            'INSERT INTO audit_logs (user_id, event_type, event_detail, ip_address, created_at)
             VALUES (:user_id, :event_type, :event_detail, :ip_address, NOW())'
        );
        $stmt->execute([
            ':user_id' => $userId,
            ':event_type' => $eventType,
            ':event_detail' => $details,
            ':ip_address' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
        ]);
    } catch (Throwable $e) {
        // The demo should continue even if auditing is unavailable.
    }
}

/**
 * Create the PDO connection with safe defaults.
 */
function db(): PDO
{
    static $pdo = null;

    if ($pdo instanceof PDO) {
        return $pdo;
    }

    $host = getenv('DB_HOST') ?: '127.0.0.1';
    $port = getenv('DB_PORT') ?: '3306';
    $name = getenv('DB_NAME') ?: 'beta_investments';
    $user = getenv('DB_USER') ?: 'root';
    $pass = getenv('DB_PASS') ?: '';
    $charset = 'utf8mb4';

    $dsn = sprintf('mysql:host=%s;port=%s;dbname=%s;charset=%s', $host, $port, $name, $charset);

    $pdo = new PDO($dsn, $user, $pass, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES => false,
    ]);

    return $pdo;
}

/**
 * Helper for safe integer validation.
 */
function positive_int_or_null(mixed $value): ?int
{
    if (!is_string($value) && !is_int($value)) {
        return null;
    }

    if (filter_var($value, FILTER_VALIDATE_INT) === false) {
        return null;
    }

    $int = (int) $value;
    return $int > 0 ? $int : null;
}

/**
 * Simple symbol whitelist to keep stock codes predictable.
 */
function normalize_symbol(string $symbol): string
{
    $symbol = strtoupper(trim($symbol));
    return preg_replace('/[^A-Z0-9.\-]/', '', $symbol) ?? '';
}

