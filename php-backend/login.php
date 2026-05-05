<?php
declare(strict_types=1);

require_once __DIR__ . '/db_config.php';

$pdo = db();
$message = '';
$success = '';
$twoFactorSecretVisible = null;
$twoFactorUriVisible = null;

/**
 * Small helper to reduce repeated validation code.
 */
function register_input_error(string $text): string
{
    return trim($text);
}

if (is_post()) {
    if (!verify_csrf_token($_POST['csrf_token'] ?? null)) {
        $message = 'Invalid CSRF token. Please refresh the page and try again.';
    } else {
        $action = $_POST['action'] ?? '';

        try {
            if ($action === 'register') {
                // Registration is included so the demo covers password hashing from end to end.
                $username = strtolower(trim((string) ($_POST['username'] ?? '')));
                $email = strtolower(trim((string) ($_POST['email'] ?? '')));
                $password = (string) ($_POST['password'] ?? '');
                $confirm = (string) ($_POST['confirm_password'] ?? '');
                $enable2fa = isset($_POST['enable_2fa']) && $_POST['enable_2fa'] === '1';

                if (!preg_match('/^[a-z0-9_.-]{3,50}$/', $username)) {
                    throw new RuntimeException('Username must be 3-50 characters and use only letters, numbers, dot, underscore, or dash.');
                }

                if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
                    throw new RuntimeException('Please enter a valid email address.');
                }

                if (strlen($password) < 12) {
                    throw new RuntimeException('Password must be at least 12 characters long.');
                }

                if (!hash_equals($password, $confirm)) {
                    throw new RuntimeException('Password confirmation does not match.');
                }

                $exists = $pdo->prepare('SELECT id FROM users WHERE username = :username OR email = :email LIMIT 1');
                $exists->execute([':username' => $username, ':email' => $email]);
                if ($exists->fetch()) {
                    throw new RuntimeException('An account with that username or email already exists.');
                }

                // password_hash automatically selects a strong adaptive algorithm.
                $passwordHash = password_hash($password, PASSWORD_DEFAULT);
                if ($passwordHash === false) {
                    throw new RuntimeException('Password hashing failed.');
                }

                // 2FA is optional but strongly recommended for the course demo.
                $totpSecret = null;
                if ($enable2fa) {
                    $totpSecret = generate_totp_secret();
                }

                $stmt = $pdo->prepare(
                    'INSERT INTO users (username, email, password_hash, role, cash_balance, cash_balance_enc, two_factor_enabled, totp_secret_enc, failed_login_attempts, locked_until, created_at, updated_at)
                     VALUES (:username, :email, :password_hash, :role, :cash_balance, :cash_balance_enc, :two_factor_enabled, :totp_secret_enc, 0, NULL, NOW(), NOW())'
                );
                $startingBalance = '100000.00';
                $stmt->execute([
                    ':username' => $username,
                    ':email' => $email,
                    ':password_hash' => $passwordHash,
                    ':role' => 'user',
                    ':cash_balance' => $startingBalance,
                    ':cash_balance_enc' => encrypt_numeric_value($startingBalance),
                    ':two_factor_enabled' => $enable2fa ? 1 : 0,
                    ':totp_secret_enc' => $totpSecret ? encrypt_sensitive_value($totpSecret) : null,
                ]);

                if ($enable2fa && $totpSecret !== null) {
                    $issuer = rawurlencode('Beta Investments');
                    $label = rawurlencode('Beta Investments:' . $username);
                    $twoFactorSecretVisible = $totpSecret;
                    $twoFactorUriVisible = "otpauth://totp/{$label}?secret={$totpSecret}&issuer={$issuer}";
                }

                $success = 'Registration successful. You can now sign in using the new account.';
                audit_event($pdo, null, 'register', 'New user registered: ' . $username);
            }

            if ($action === 'login') {
                // Login attempts are intentionally generic to avoid user enumeration.
                $identifier = strtolower(trim((string) ($_POST['identifier'] ?? '')));
                $password = (string) ($_POST['password'] ?? '');
                $totpCode = trim((string) ($_POST['totp_code'] ?? ''));

                audit_event($pdo, null, 'login_attempt', 'Login attempt submitted for identifier: ' . ($identifier !== '' ? $identifier : '[empty]'));

                if ($identifier === '' || $password === '') {
                    throw new RuntimeException('Login failed.');
                }

                $stmt = $pdo->prepare(
                    'SELECT id, username, email, password_hash, role, two_factor_enabled, totp_secret_enc, failed_login_attempts, locked_until
                     FROM users
                     WHERE username = :identifier_username OR email = :identifier_email
                     LIMIT 1'
                );
                $stmt->execute([
                    ':identifier_username' => $identifier,
                    ':identifier_email' => $identifier,
                ]);
                $user = $stmt->fetch();

                if (!$user) {
                    throw new RuntimeException('Login failed.');
                }

                if (!empty($user['locked_until']) && strtotime((string) $user['locked_until']) > time()) {
                    throw new RuntimeException('Account is temporarily locked. Please try again later.');
                }

                if (!password_verify($password, (string) $user['password_hash'])) {
                    $attempts = ((int) $user['failed_login_attempts']) + 1;
                    $lockedUntil = $attempts >= 5 ? date('Y-m-d H:i:s', time() + 15 * 60) : null;

                    $update = $pdo->prepare(
                        'UPDATE users
                         SET failed_login_attempts = :attempts,
                             locked_until = :locked_until,
                             updated_at = NOW()
                         WHERE id = :id'
                    );
                    $update->execute([
                        ':attempts' => $attempts,
                        ':locked_until' => $lockedUntil,
                        ':id' => (int) $user['id'],
                    ]);

                    audit_event($pdo, (int) $user['id'], 'login_failed', 'Invalid password');
                    throw new RuntimeException('Login failed.');
                }

                if ((int) $user['two_factor_enabled'] === 1) {
                    $secret = decrypt_sensitive_value($user['totp_secret_enc'] ?? null);
                    if ($secret === null || !verify_totp_code($secret, $totpCode)) {
                        $attempts = ((int) $user['failed_login_attempts']) + 1;
                        $lockedUntil = $attempts >= 5 ? date('Y-m-d H:i:s', time() + 15 * 60) : null;

                        $update = $pdo->prepare(
                            'UPDATE users
                             SET failed_login_attempts = :attempts,
                                 locked_until = :locked_until,
                                 updated_at = NOW()
                             WHERE id = :id'
                        );
                        $update->execute([
                            ':attempts' => $attempts,
                            ':locked_until' => $lockedUntil,
                            ':id' => (int) $user['id'],
                        ]);

                        audit_event($pdo, (int) $user['id'], 'login_failed_2fa', 'Invalid TOTP code');
                        throw new RuntimeException('Login failed.');
                    }
                }

                // Reset lockout state after a valid login.
                $reset = $pdo->prepare(
                    'UPDATE users
                     SET failed_login_attempts = 0,
                         locked_until = NULL,
                         updated_at = NOW()
                     WHERE id = :id'
                );
                $reset->execute([':id' => (int) $user['id']]);

                // Session fixation protection: create a new session ID after authentication.
                session_regenerate_id(true);
                $_SESSION['authenticated'] = true;
                $_SESSION['user_id'] = (int) $user['id'];
                $_SESSION['username'] = (string) $user['username'];
                $_SESSION['role'] = (string) $user['role'];
                $_SESSION['second_factor_completed'] = true;
                $_SESSION['login_time'] = time();

                audit_event($pdo, (int) $user['id'], 'login_success', 'User authenticated successfully');
                redirect('trade.php');
            }
        } catch (Throwable $exception) {
            $message = $exception->getMessage();
        }
    }
}

?><!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Beta Investments - Secure Login</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 2rem; line-height: 1.5; background: #f6f7fb; }
        .wrap { max-width: 980px; margin: 0 auto; }
        .card { background: #fff; border: 1px solid #d9dee7; border-radius: 12px; padding: 1.25rem; margin-bottom: 1.25rem; box-shadow: 0 2px 10px rgba(0,0,0,.04); }
        .grid { display: grid; gap: 1rem; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); }
        label { display: block; font-weight: 700; margin-bottom: .35rem; }
        input[type="text"], input[type="email"], input[type="password"] { width: 100%; padding: .75rem; border: 1px solid #b9c1cf; border-radius: 8px; box-sizing: border-box; }
        button { padding: .75rem 1rem; border: 0; border-radius: 8px; background: #1d4ed8; color: white; font-weight: 700; cursor: pointer; }
        button:hover { background: #1e40af; }
        .msg { padding: .9rem 1rem; border-radius: 8px; margin-bottom: 1rem; }
        .error { background: #fee2e2; color: #991b1b; }
        .ok { background: #dcfce7; color: #166534; }
        .hint { font-size: .95rem; color: #475569; }
        code, pre { background: #f1f5f9; padding: .2rem .4rem; border-radius: 6px; }
    </style>
</head>
<body>
<div class="wrap">
    <div class="card">
        <h1>Beta Investments Secure Authentication</h1>
        <p class="hint">This page demonstrates strong password handling, optional TOTP 2FA, CSRF protection, and session hardening for the VT6005CEM Security coursework.</p>
        <p><strong>Current CSRF token:</strong> <code><?= e(csrf_token()) ?></code></p>
    </div>

    <?php if ($message !== ''): ?>
        <div class="msg error"><?= e($message) ?></div>
    <?php endif; ?>

    <?php if ($success !== ''): ?>
        <div class="msg ok">
            <?= e($success) ?>
            <?php if ($twoFactorSecretVisible !== null): ?>
                <hr>
                <p><strong>2FA secret:</strong> <code><?= e($twoFactorSecretVisible) ?></code></p>
                <p><strong>otpauth URI:</strong></p>
                <pre><?= e($twoFactorUriVisible ?? '') ?></pre>
                <p class="hint">Import the secret into an authenticator app. In a real deployment, display this once and encourage the user to enroll immediately.</p>
            <?php endif; ?>
        </div>
    <?php endif; ?>

    <div class="grid">
        <div class="card">
            <h2>Register</h2>
            <form method="post" action="">
                <input type="hidden" name="csrf_token" value="<?= e(csrf_token()) ?>">
                <input type="hidden" name="action" value="register">

                <label for="reg_username">Username</label>
                <input id="reg_username" name="username" type="text" required maxlength="50" placeholder="e.g. analyst_01">

                <label for="reg_email">Email</label>
                <input id="reg_email" name="email" type="email" required maxlength="255" placeholder="name@example.com">

                <label for="reg_password">Password</label>
                <input id="reg_password" name="password" type="password" required minlength="12">

                <label for="reg_confirm">Confirm Password</label>
                <input id="reg_confirm" name="confirm_password" type="password" required minlength="12">

                <p>
                    <label>
                        <input type="checkbox" name="enable_2fa" value="1">
                        Enable TOTP 2FA at registration
                    </label>
                </p>

                <button type="submit">Create Account</button>
            </form>
        </div>

        <div class="card">
            <h2>Login</h2>
            <form method="post" action="">
                <input type="hidden" name="csrf_token" value="<?= e(csrf_token()) ?>">
                <input type="hidden" name="action" value="login">

                <label for="login_identifier">Username or Email</label>
                <input id="login_identifier" name="identifier" type="text" required maxlength="255">

                <label for="login_password">Password</label>
                <input id="login_password" name="password" type="password" required>

                <label for="login_totp">TOTP Code</label>
                <input id="login_totp" name="totp_code" type="text" inputmode="numeric" maxlength="6" placeholder="Required only if 2FA is enabled">

                <p class="hint">The code is validated only when the account has 2FA enabled. Keeping the same form makes the demo easy to present.</p>

                <button type="submit">Sign In</button>
            </form>
        </div>
    </div>

    <div class="card">
        <h2>Security controls demonstrated</h2>
        <ul>
            <li><strong>password_hash / password_verify</strong> for adaptive password hashing.</li>
            <li><strong>AES-256-GCM</strong> field encryption for the stored TOTP secret.</li>
            <li><strong>Prepared statements</strong> everywhere to block SQL injection.</li>
            <li><strong>CSRF tokens</strong> on all state-changing forms.</li>
            <li><strong>Session hardening</strong> and regeneration to reduce fixation risk.</li>
            <li><strong>Generic login failures</strong> to reduce user enumeration.</li>
            <li><strong>Account lockout</strong> after repeated failed logins.</li>
        </ul>
    </div>
</div>
</body>
</html>


