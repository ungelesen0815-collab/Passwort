<?php
require_once __DIR__ . '/session.php';
require_once 'db.php';
require_once 'vendor/autoload.php';
require_once 'csrf.php';
require_once 'auth_utils.php';

use RobThree\Auth\TwoFactorAuth;

if (!isset($_SESSION['user_id'])) {
    header('Location: login.php');
    exit;
}

try {
    $user = get_user_by_id($pdo, $_SESSION['user_id']);
} catch (\PDOException $e) {
    error_log("Database error in mfa_setup.php: " . $e->getMessage());
    die('A database error occurred. Please contact the administrator.');
}

$tfa = new TwoFactorAuth(new \RobThree\Auth\Providers\Qr\EndroidQrCodeProvider(), 'My App');

$error = '';
$success = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    try {
        verify_csrf_token($_POST['csrf_token'] ?? null);
    } catch (Exception $e) {
        $error = 'Invalid CSRF token. Please refresh the page and try again.';
    }

    if (!$error) {
        if (isset($_POST['disable_mfa'])) {
            $password = (string)($_POST['password'] ?? '');
            $ip_address = get_client_ip();
            $user_identifier = 'user:' . $user['username'];
            $current_time = time();

            if (is_rate_limited($pdo, [$ip_address, $user_identifier], $current_time)) {
                $error = 'Too many failed attempts. Please try again later.';
            } elseif ($password === '' || strlen($password) > 72) {
                $error = 'Password is required to disable MFA.';
            } elseif (!password_verify($password, $user['password'])) {
                $error = 'Incorrect password. MFA was not disabled.';
                increment_login_attempts($pdo, $ip_address, $current_time);
                increment_login_attempts($pdo, $user_identifier, $current_time);
            } else {
                clear_login_attempts($pdo, $user_identifier);
                try {
                    $stmt = $pdo->prepare('UPDATE users SET mfa_enabled = 0, mfa_secret = NULL WHERE id = ?');
                    $stmt->execute([$_SESSION['user_id']]);
                    $success = 'MFA disabled.';
                    $user['mfa_enabled'] = 0;
                } catch (\PDOException $e) {
                    error_log("Database error in mfa_setup.php (disable): " . $e->getMessage());
                    $error = 'A database error occurred.';
                }
            }
        } elseif (isset($_POST['verify_mfa'])) {
            $code = (string)($_POST['mfa_code'] ?? '');
            $secret = $_SESSION['temp_mfa_secret'] ?? '';
            $ip_address = get_client_ip();
            $user_identifier = 'user:' . $user['username'];
            $current_time = time();

            if (is_rate_limited($pdo, [$ip_address, $user_identifier], $current_time)) {
                $error = 'Too many failed attempts. Please try again later.';
            } elseif ($secret !== '' && $tfa->verifyCode($secret, $code)) {
                clear_login_attempts($pdo, $user_identifier);
                $storedSecret = encrypt_mfa_secret($secret);
                try {
                    $stmt = $pdo->prepare('UPDATE users SET mfa_enabled = 1, mfa_secret = ? WHERE id = ?');
                    $stmt->execute([$storedSecret, $_SESSION['user_id']]);
                    $success = 'MFA successfully enabled.';
                    $user['mfa_enabled'] = 1;
                    unset($_SESSION['temp_mfa_secret']);
                } catch (\PDOException $e) {
                    error_log("Database error in mfa_setup.php (enable): " . $e->getMessage());
                    $error = 'A database error occurred.';
                }
            } else {
                increment_login_attempts($pdo, $ip_address, $current_time);
                increment_login_attempts($pdo, $user_identifier, $current_time);
                $error = 'Invalid code. Try again.';
            }
        }
    }
}

$qrCodeUrl = '';
if (!$user['mfa_enabled']) {
    if (!isset($_SESSION['temp_mfa_secret'])) {
        $_SESSION['temp_mfa_secret'] = $tfa->createSecret();
    }
    $qrCodeUrl = $tfa->getQRCodeImageAsDataUri($user['username'], $_SESSION['temp_mfa_secret']);
}

$pageTitle = 'MFA Setup';
require_once 'header.php';
?>
<?php require_once 'navbar.php'; ?>
<div class="container">
    <div class="row justify-content-center">
        <div class="col-md-6">
            <div class="card">
                <div class="card-header">
                    <h4>Multi-Factor Authentication</h4>
                </div>
                <div class="card-body">
                    <?php if ($success): ?>
                        <div class="alert alert-success"><?= htmlspecialchars($success) ?></div>
                    <?php endif; ?>
                    <?php if ($error): ?>
                        <div class="alert alert-danger"><?= htmlspecialchars($error) ?></div>
                    <?php endif; ?>

                    <?php if ($user['mfa_enabled']): ?>
                        <p>MFA is currently <strong>enabled</strong>.</p>
                        <form method="post">
                            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
                            <div class="mb-3">
                                <label for="password" class="form-label">Confirm Password</label>
                                <input type="password" class="form-control" id="password" name="password" required>
                            </div>
                            <button type="submit" name="disable_mfa" class="btn btn-danger">Disable MFA</button>
                        </form>
                    <?php else: ?>
                        <p>Scan the QR code below with your Authenticator app (like Google Authenticator or Authy).</p>
                        <div class="text-center mb-3">
                            <img src="<?= $qrCodeUrl ?>" alt="QR Code">
                        </div>
                        <p class="text-center">Secret: <?= htmlspecialchars($_SESSION['temp_mfa_secret']) ?></p>
                        <form method="post">
                            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
                            <div class="mb-3">
                                <label for="mfa_code" class="form-label">Enter verification code</label>
                                <input type="text" class="form-control" id="mfa_code" name="mfa_code" required>
                            </div>
                            <button type="submit" name="verify_mfa" class="btn btn-primary">Verify and Enable</button>
                        </form>
                    <?php endif; ?>
                </div>
            </div>
            <div class="mt-3">
                <a href="index.php" class="btn btn-secondary">Back to Dashboard</a>
            </div>
        </div>
    </div>
</div>

<?php require_once 'footer.php'; ?>