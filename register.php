<?php
require_once __DIR__ . '/session.php';
require_once 'db.php';
require_once 'csrf.php';
require_once 'auth_utils.php';
require_once 'RegistrationService.php';

$error = '';

$allowRegistrationEnv = $_ENV['ALLOW_REGISTRATION'] ?? getenv('ALLOW_REGISTRATION');
$allowRegistration = ($allowRegistrationEnv === null || $allowRegistrationEnv === '')
    ? true
    : (filter_var($allowRegistrationEnv, FILTER_VALIDATE_BOOLEAN, FILTER_NULL_ON_FAILURE) ?? true);

$configuredInviteCode = trim((string)($_ENV['REGISTRATION_INVITE_CODE'] ?? getenv('REGISTRATION_INVITE_CODE') ?: ''));

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $error = validate_csrf_token($_POST['csrf_token'] ?? null) ?? '';

    if (!$error && !$allowRegistration) {
        $submittedInviteCode = trim((string)($_POST['invite_code'] ?? ''));
        if ($configuredInviteCode === '' || !hash_equals($configuredInviteCode, $submittedInviteCode)) {
            $error = 'Die öffentliche Registrierung ist derzeit deaktiviert.';
        }
    }

    if (!$error) {
        $ip_address = 'reg:' . get_client_ip();
        $current_time = time();
        $rateLimited = false;

        try {
            $rateLimited = is_rate_limited($pdo, [$ip_address], $current_time);
        } catch (\Throwable $e) {
            $rateLimited = false;
        }

        if ($rateLimited) {
            $error = 'Too many registration attempts. Please try again later.';
        } else {
            $username = trim((string)($_POST['username'] ?? ''));
            $password = (string)($_POST['password'] ?? '');

            ensure_user_feature_columns($pdo);
            $registrationService = new RegistrationService($pdo);
            $result = $registrationService->register($username, $password);

            if ($result['success']) {
                header('Location: login.php');
                exit;
            } else {
                try {
                    increment_login_attempts($pdo, $ip_address, $current_time);
                } catch (\Throwable $e) {
                    // Ignore rate-limit logging errors
                }
                $error = $result['error'];
            }
        }
    }
}

$pageTitle = 'Register';
require_once 'header.php';
?>
<div class="container mt-5">
    <div class="row justify-content-center">
        <div class="col-md-6">
            <div class="card">
                <div class="card-header text-center">
                    <h4>Register</h4>
                </div>
                <div class="card-body">
                    <?php if ($error): ?>
                        <div class="alert alert-danger"><?= htmlspecialchars($error) ?></div>
                    <?php endif; ?>
                    <?php if (!$allowRegistration && $configuredInviteCode === ''): ?>
                        <div class="alert alert-warning text-center">
                            <strong>Registrierung deaktiviert</strong><br>
                            Die Registrierung neuer Konten ist derzeit deaktiviert. Bitte wenden Sie sich an den Administrator.
                        </div>
                        <div class="mt-3 text-center">
                            <a href="login.php" class="btn btn-outline-secondary w-100">Zurück zum Login</a>
                        </div>
                    <?php else: ?>
                        <form method="post" action="register.php">
                            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token'] ?? '') ?>">
                            <?php if (!$allowRegistration && $configuredInviteCode !== ''): ?>
                            <div class="mb-3">
                                <label for="invite_code" class="form-label">Einladungscode</label>
                                <input type="text" class="form-control" id="invite_code" name="invite_code" placeholder="Einladungscode eingeben" required>
                            </div>
                            <?php endif; ?>
                            <div class="mb-3">
                                <label for="username" class="form-label">Username</label>
                                <input type="text" class="form-control" id="username" name="username" required>
                            </div>
                            <div class="mb-3">
                                <label for="password" class="form-label">Password</label>
                                <input type="password" class="form-control" id="password" name="password" required>
                            </div>
                            <button type="submit" class="btn btn-primary w-100">Register</button>
                        </form>
                        <div class="mt-3 text-center">
                            <a href="login.php">Already have an account? Login</a>
                        </div>
                    <?php endif; ?>
                </div>
            </div>
        </div>
    </div>
</div>

<?php require_once 'footer.php'; ?>