<?php
declare(strict_types=1);

require_once __DIR__ . '/db_config.php';

require_auth();

$pdo = db();
$userId = current_user_id();
$message = '';
$success = '';

if (isset($_GET['logout']) && $_GET['logout'] === '1') {
    // Clear the session to terminate the authenticated state cleanly.
    $_SESSION = [];
    if (ini_get('session.use_cookies')) {
        $params = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000, $params['path'], $params['domain'], $params['secure'], $params['httponly']);
    }
    session_destroy();
    redirect('login.php');
}

// Load the current account so the demo can show available cash and demonstrate row-level ownership checks.
$accountStmt = $pdo->prepare('SELECT id, username, role, cash_balance FROM users WHERE id = :id LIMIT 1');
$accountStmt->execute([':id' => $userId]);
$account = $accountStmt->fetch();

if (!$account) {
    // If the session survives but the user row was removed, force re-authentication.
    $_SESSION = [];
    session_destroy();
    redirect('login.php');
}

if (is_post()) {
    if (!verify_csrf_token($_POST['csrf_token'] ?? null)) {
        $message = 'Invalid CSRF token. Please refresh the page and try again.';
    } else {
        $tradeType = strtolower(trim((string) ($_POST['trade_type'] ?? '')));
        $symbol = normalize_symbol((string) ($_POST['symbol'] ?? ''));
        $quantity = positive_int_or_null($_POST['quantity'] ?? null);

        try {
            if (!in_array($tradeType, ['buy', 'sell'], true)) {
                throw new RuntimeException('Please choose buy or sell.');
            }

            if ($symbol === '') {
                throw new RuntimeException('Please choose a valid stock symbol.');
            }

            if ($quantity === null || $quantity > 100000) {
                throw new RuntimeException('Quantity must be a positive number and within the allowed limit.');
            }

            $pdo->beginTransaction();

            // Lock the stock row for the duration of the trade to keep the price consistent inside the transaction.
            $stockStmt = $pdo->prepare('SELECT symbol, company_name, current_price FROM stocks WHERE symbol = :symbol LIMIT 1 FOR UPDATE');
            $stockStmt->execute([':symbol' => $symbol]);
            $stock = $stockStmt->fetch();

            if (!$stock) {
                throw new RuntimeException('Unknown stock symbol.');
            }

            $price = (float) $stock['current_price'];
            $total = round($price * $quantity, 2);

            $userStmt = $pdo->prepare('SELECT id, cash_balance FROM users WHERE id = :id FOR UPDATE');
            $userStmt->execute([':id' => $userId]);
            $lockedUser = $userStmt->fetch();

            if (!$lockedUser) {
                throw new RuntimeException('Account not found.');
            }

            if ($tradeType === 'buy') {
                $cashBalance = (float) $lockedUser['cash_balance'];
                if ($cashBalance < $total) {
                    throw new RuntimeException('Insufficient cash balance for this trade.');
                }

                // Deduct the simulated cash balance after validating affordability.
                $balanceUpdate = $pdo->prepare('UPDATE users SET cash_balance = cash_balance - :total, updated_at = NOW() WHERE id = :id');
                $balanceUpdate->execute([':total' => $total, ':id' => $userId]);

                // Upsert the owned quantity so the portfolio reflects the simulated position.
                $holdingStmt = $pdo->prepare(
                    'SELECT quantity FROM user_portfolio WHERE user_id = :user_id AND symbol = :symbol FOR UPDATE'
                );
                $holdingStmt->execute([':user_id' => $userId, ':symbol' => $symbol]);
                $holding = $holdingStmt->fetch();

                if ($holding) {
                    $updateHolding = $pdo->prepare(
                        'UPDATE user_portfolio SET quantity = quantity + :quantity, updated_at = NOW() WHERE user_id = :user_id AND symbol = :symbol'
                    );
                    $updateHolding->execute([':quantity' => $quantity, ':user_id' => $userId, ':symbol' => $symbol]);
                } else {
                    $insertHolding = $pdo->prepare(
                        'INSERT INTO user_portfolio (user_id, symbol, quantity, created_at, updated_at) VALUES (:user_id, :symbol, :quantity, NOW(), NOW())'
                    );
                    $insertHolding->execute([':user_id' => $userId, ':symbol' => $symbol, ':quantity' => $quantity]);
                }
            } else {
                // Selling is restricted to positions the current user actually owns.
                $holdingStmt = $pdo->prepare(
                    'SELECT quantity FROM user_portfolio WHERE user_id = :user_id AND symbol = :symbol FOR UPDATE'
                );
                $holdingStmt->execute([':user_id' => $userId, ':symbol' => $symbol]);
                $holding = $holdingStmt->fetch();

                $owned = $holding ? (int) $holding['quantity'] : 0;
                if ($owned < $quantity) {
                    throw new RuntimeException('You do not own enough shares to sell this quantity.');
                }

                $balanceUpdate = $pdo->prepare('UPDATE users SET cash_balance = cash_balance + :total, updated_at = NOW() WHERE id = :id');
                $balanceUpdate->execute([':total' => $total, ':id' => $userId]);

                if ($owned === $quantity) {
                    $deleteHolding = $pdo->prepare('DELETE FROM user_portfolio WHERE user_id = :user_id AND symbol = :symbol');
                    $deleteHolding->execute([':user_id' => $userId, ':symbol' => $symbol]);
                } else {
                    $reduceHolding = $pdo->prepare(
                        'UPDATE user_portfolio SET quantity = quantity - :quantity, updated_at = NOW() WHERE user_id = :user_id AND symbol = :symbol'
                    );
                    $reduceHolding->execute([':quantity' => $quantity, ':user_id' => $userId, ':symbol' => $symbol]);
                }
            }

            $tradeStmt = $pdo->prepare(
                'INSERT INTO trades (user_id, symbol, trade_type, quantity, price, total_amount, status, created_at)
                 VALUES (:user_id, :symbol, :trade_type, :quantity, :price, :total_amount, :status, NOW())'
            );
            $tradeStmt->execute([
                ':user_id' => $userId,
                ':symbol' => $symbol,
                ':trade_type' => $tradeType,
                ':quantity' => $quantity,
                ':price' => $price,
                ':total_amount' => $total,
                ':status' => 'filled',
            ]);

            $pdo->commit();
            audit_event($pdo, $userId, 'trade_' . $tradeType, sprintf('%s %d %s at %.2f', strtoupper($tradeType), $quantity, $symbol, $price));
            $success = sprintf('%s order executed: %d %s at £%.2f each (total £%.2f).', ucfirst($tradeType), $quantity, $symbol, $price, $total);

            // Refresh the account snapshot so the page shows the new balance after a successful trade.
            $accountStmt->execute([':id' => $userId]);
            $account = $accountStmt->fetch();
        } catch (Throwable $exception) {
            if ($pdo->inTransaction()) {
                $pdo->rollBack();
            }
            $message = $exception->getMessage();
            audit_event($pdo, $userId, 'trade_failed', $message);
        }
    }
}

$stockList = $pdo->query('SELECT symbol, company_name, current_price, updated_at FROM stocks ORDER BY symbol ASC')->fetchAll();

$portfolioStmt = $pdo->prepare(
    'SELECT p.symbol, p.quantity, s.company_name, s.current_price, ROUND(p.quantity * s.current_price, 2) AS market_value
     FROM user_portfolio p
     INNER JOIN stocks s ON s.symbol = p.symbol
     WHERE p.user_id = :user_id
     ORDER BY p.symbol ASC'
);
$portfolioStmt->execute([':user_id' => $userId]);
$portfolio = $portfolioStmt->fetchAll();

$tradeHistoryStmt = $pdo->prepare(
    'SELECT symbol, trade_type, quantity, price, total_amount, status, created_at
     FROM trades
     WHERE user_id = :user_id
     ORDER BY created_at DESC
     LIMIT 10'
);
$tradeHistoryStmt->execute([':user_id' => $userId]);
$recentTrades = $tradeHistoryStmt->fetchAll();

?><!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Beta Investments - Trading Desk</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 2rem; line-height: 1.5; background: #f8fafc; }
        .wrap { max-width: 1200px; margin: 0 auto; }
        .card { background: #fff; border: 1px solid #d9dee7; border-radius: 12px; padding: 1.1rem; margin-bottom: 1.2rem; box-shadow: 0 2px 10px rgba(0,0,0,.04); }
        .grid { display: grid; gap: 1rem; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); }
        table { width: 100%; border-collapse: collapse; }
        th, td { text-align: left; border-bottom: 1px solid #e2e8f0; padding: .65rem .45rem; }
        th { background: #eff6ff; }
        label { display: block; font-weight: 700; margin-bottom: .35rem; }
        input[type="text"], input[type="number"], select { width: 100%; padding: .75rem; border: 1px solid #b9c1cf; border-radius: 8px; box-sizing: border-box; }
        button { padding: .75rem 1rem; border: 0; border-radius: 8px; background: #0f766e; color: white; font-weight: 700; cursor: pointer; }
        button:hover { background: #115e59; }
        .btn-secondary { background: #475569; }
        .btn-secondary:hover { background: #334155; }
        .msg { padding: .9rem 1rem; border-radius: 8px; margin-bottom: 1rem; }
        .error { background: #fee2e2; color: #991b1b; }
        .ok { background: #dcfce7; color: #166534; }
        .hint { color: #475569; font-size: .95rem; }
        .right { text-align: right; }
        a { color: #1d4ed8; }
    </style>
</head>
<body>
<div class="wrap">
    <div class="card">
        <h1>Beta Investments Trading Desk</h1>
        <p class="hint">Authenticated user: <strong><?= e((string) $account['username']) ?></strong> | Role: <strong><?= e((string) $account['role']) ?></strong> | Cash balance: <strong>£<?= number_format((float) $account['cash_balance'], 2) ?></strong></p>
        <p><a href="?logout=1">Logout</a></p>
    </div>

    <?php if ($message !== ''): ?>
        <div class="msg error"><?= e($message) ?></div>
    <?php endif; ?>

    <?php if ($success !== ''): ?>
        <div class="msg ok"><?= e($success) ?></div>
    <?php endif; ?>

    <div class="grid">
        <div class="card">
            <h2>Place simulated trade</h2>
            <form method="post" action="">
                <input type="hidden" name="csrf_token" value="<?= e(csrf_token()) ?>">

                <label for="symbol">Stock Symbol</label>
                <select id="symbol" name="symbol" required>
                    <option value="">Select a stock</option>
                    <?php foreach ($stockList as $stock): ?>
                        <option value="<?= e((string) $stock['symbol']) ?>"><?= e((string) $stock['symbol']) ?> - <?= e((string) $stock['company_name']) ?></option>
                    <?php endforeach; ?>
                </select>

                <label for="trade_type">Trade Type</label>
                <select id="trade_type" name="trade_type" required>
                    <option value="buy">Buy</option>
                    <option value="sell">Sell</option>
                </select>

                <label for="quantity">Quantity</label>
                <input id="quantity" name="quantity" type="number" min="1" max="100000" required>

                <p class="hint">The server validates ownership, balance, symbol, and quantity before committing the transaction.</p>
                <button type="submit">Execute Trade</button>
            </form>
        </div>

        <div class="card">
            <h2>Available market prices</h2>
            <table>
                <thead>
                <tr>
                    <th>Symbol</th>
                    <th>Company</th>
                    <th class="right">Price</th>
                    <th>Updated</th>
                </tr>
                </thead>
                <tbody>
                <?php foreach ($stockList as $stock): ?>
                    <tr>
                        <td><?= e((string) $stock['symbol']) ?></td>
                        <td><?= e((string) $stock['company_name']) ?></td>
                        <td class="right">£<?= number_format((float) $stock['current_price'], 2) ?></td>
                        <td><?= e((string) $stock['updated_at']) ?></td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    </div>

    <div class="card">
        <h2>Your simulated portfolio</h2>
        <table>
            <thead>
            <tr>
                <th>Symbol</th>
                <th>Company</th>
                <th class="right">Quantity</th>
                <th class="right">Current Price</th>
                <th class="right">Market Value</th>
            </tr>
            </thead>
            <tbody>
            <?php if ($portfolio === []): ?>
                <tr><td colspan="5">No holdings yet.</td></tr>
            <?php else: ?>
                <?php foreach ($portfolio as $row): ?>
                    <tr>
                        <td><?= e((string) $row['symbol']) ?></td>
                        <td><?= e((string) $row['company_name']) ?></td>
                        <td class="right"><?= (int) $row['quantity'] ?></td>
                        <td class="right">£<?= number_format((float) $row['current_price'], 2) ?></td>
                        <td class="right">£<?= number_format((float) $row['market_value'], 2) ?></td>
                    </tr>
                <?php endforeach; ?>
            <?php endif; ?>
            </tbody>
        </table>
    </div>

    <div class="card">
        <h2>Recent trade history</h2>
        <table>
            <thead>
            <tr>
                <th>Date</th>
                <th>Symbol</th>
                <th>Type</th>
                <th class="right">Qty</th>
                <th class="right">Price</th>
                <th class="right">Total</th>
                <th>Status</th>
            </tr>
            </thead>
            <tbody>
            <?php if ($recentTrades === []): ?>
                <tr><td colspan="7">No trades yet.</td></tr>
            <?php else: ?>
                <?php foreach ($recentTrades as $row): ?>
                    <tr>
                        <td><?= e((string) $row['created_at']) ?></td>
                        <td><?= e((string) $row['symbol']) ?></td>
                        <td><?= e(strtoupper((string) $row['trade_type'])) ?></td>
                        <td class="right"><?= (int) $row['quantity'] ?></td>
                        <td class="right">£<?= number_format((float) $row['price'], 2) ?></td>
                        <td class="right">£<?= number_format((float) $row['total_amount'], 2) ?></td>
                        <td><?= e((string) $row['status']) ?></td>
                    </tr>
                <?php endforeach; ?>
            <?php endif; ?>
            </tbody>
        </table>
    </div>

    <div class="card">
        <h2>Security notes for the demonstration</h2>
        <ul>
            <li>Only the authenticated user ID from the session is used in portfolio and trade queries.</li>
            <li>Trade execution runs inside a database transaction so balance and holdings stay consistent.</li>
            <li>Prepared statements prevent SQL injection.</li>
            <li>CSRF tokens stop cross-site request forgery on buy/sell actions.</li>
            <li>All output is escaped before rendering to prevent XSS.</li>
        </ul>
    </div>
</div>
</body>
</html>

