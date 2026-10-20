<?php
require_once __DIR__ . '/session.php';
require_once 'db.php';
require_once 'vendor/autoload.php';
require_once 'csrf.php';
require_once 'auth_utils.php';

if (!isset($_SESSION['pending_user_id'])) {
    header('Location: login.php');
    exit;
}

$error = '';
try {
    $user = get_user_by_id($pdo, $_SESSION['pending_user_id']);
} catch (\PDOException $e) {
    error_log("Database error in mfa_verify.php: " . $e->getMessage());
    die('A database error occurred. Please contact the administrator.');
}

if (!$user || !$user['mfa_enabled']) {
    header('Location: login.php');
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    try {
        verify_csrf_token($_POST['csrf_token'] ?? null);
    } catch (Exception $e) {
        $error = $e->getMessage();
    }

    if (!$error) {
        // Cast code to string to prevent array injection errors
        $code = (string)($_POST['mfa_code'] ?? '');

        $ip_address = get_client_ip();
        $user_identifier = 'user:' . $user['id'];
        $current_time = time();

        try {
            $identifiers = [$ip_address, $user_identifier];

            if (is_rate_limited($pdo, $identifiers, $current_time)) {
                unset($_SESSION['pending_user_id']);
                header('Location: login.php?error=too_many_attempts');
                exit;
            }

            $tfa = new \RobThree\Auth\TwoFactorAuth(new \RobThree\Auth\Providers\Qr\EndroidQrCodeProvider(), 'My App');

            if ($tfa->verifyCode($user['mfa_secret'], $code)) {
                session_regenerate_id(true);

                $_SESSION['user_id'] = $user['id'];
                $_SESSION['username'] = $user['username'];
                $_SESSION['role'] = $user['role'];
                unset($_SESSION['pending_user_id']);
                header('Location: index.php');
                exit;
            } else {
                $ip_attempts = increment_login_attempts($pdo, $ip_address, $current_time);
                $user_attempts = increment_login_attempts($pdo, $user_identifier, $current_time);

                if ($ip_attempts >= 5 || $user_attempts >= 5) {
                    unset($_SESSION['pending_user_id']);
                    header('Location: login.php?error=too_many_attempts');
                    exit;
                }
                $error = 'Invalid verification code.';
            }
        } catch (\PDOException $e) {
            error_log("Database error in mfa_verify.php: " . $e->getMessage());
            $error = 'A database error occurred. Please contact the administrator.';
        }
    }
}

$pageTitle = 'MFA Verification';
require_once 'header.php';
?>
<div class="container mt-5">
    <div class="row justify-content-center">
        <div class="col-md-6">
            <div class="card">
                <div class="card-header text-center">
                    <h4>MFA Verification</h4>
                </div>
                <div class="card-body">
                    <?php if ($error): ?>
                        <div class="alert alert-danger"><?= htmlspecialchars($error) ?></div>
                    <?php endif; ?>
                    <form method="post" action="mfa_verify.php">
                        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token'] ?? '') ?>">
                        <div class="mb-3">
                            <label for="mfa_code" class="form-label">Authentication Code</label>
                            <input type="text" class="form-control" id="mfa_code" name="mfa_code" required autofocus autocomplete="off">
                        </div>
                        <button type="submit" class="btn btn-primary w-100">Verify</button>
                    </form>
                    <div class="mt-3 text-center">
                        <a href="login.php">Cancel</a>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>

<?php require_once 'footer.php'; ?>