<?php
require_once __DIR__ . '/session.php';
try {
    require_once 'db.php';
} catch (\Throwable $e) {
    // DB connection failed or env not configured; handled during runtime requests
}
require_once 'csrf.php';
require_once 'auth_utils.php';

const DUMMY_PASSWORD_HASH = '$2y$10$af7Ut8Qngg0SM0anMdogOuJo6W11NYi66eyUFz93j3oHgjnzvntea';

$error = '';

function check_login_rate_limit(PDO $pdo, string $ip_address, string $username, int $current_time): ?string {
    $user_identifier = 'user:' . $username;
    $identifiers = [$ip_address, $user_identifier];

    if (is_rate_limited($pdo, $identifiers, $current_time)) {
        return 'Too many failed login attempts. Please try again later.';
    }

    return null;
}

function authenticate_user(PDO $pdo, string $username, string $password): ?array {
    $username_len = strlen($username);
    $password_len = strlen($password);

    if ($username_len === 0 || $password_len === 0 || $username_len > 250 || $password_len > 72) {
        return null;
    }

    $stmt = $pdo->prepare('SELECT * FROM users WHERE username = ?');
    $stmt->execute([$username]);
    $user = $stmt->fetch();

    // Dummy hash to prevent timing attacks for non-existent users
    $hash_to_verify = $user ? $user['password'] : DUMMY_PASSWORD_HASH;

    $valid_password = password_verify($password, $hash_to_verify);

    if ($user && $valid_password) {
        return $user;
    }

    return null;
}

function handle_authenticated_session(array $user, ?callable $redirectHandler = null): void {
    if (session_status() !== PHP_SESSION_ACTIVE) {
        session_start();
    }

    session_regenerate_id(true);

    if (!empty($user['mfa_enabled'])) {
        $_SESSION['pending_user_id'] = $user['id'];
        $location = 'mfa_verify.php';
    } else {
        $_SESSION['user_id'] = $user['id'];
        $_SESSION['username'] = $user['username'];
        $_SESSION['role'] = $user['role'];
        $location = 'index.php';
    }

    if ($redirectHandler !== null) {
        $redirectHandler($location);
    } else {
        header('Location: ' . $location);
        exit();
    }
}

function handle_login_request(PDO $pdo): ?string {
    $username = trim((string)($_POST['username'] ?? ''));
    $password = (string)($_POST['password'] ?? '');

    $username_len = strlen($username);
    $password_len = strlen($password);

    if ($username_len === 0 || $password_len === 0) {
        return 'Username and password are required.';
    }

    if ($username_len > 250 || $password_len > 72) {
        return 'Invalid credentials.';
    }

    $ip_address = get_client_ip();
    $current_time = time();

    $rate_limit_error = check_login_rate_limit($pdo, $ip_address, $username, $current_time);
    if ($rate_limit_error !== null) {
        return $rate_limit_error;
    }

    $user = authenticate_user($pdo, $username, $password);
    if ($user !== null) {
        if (empty($user['mfa_enabled'])) {
            clear_login_attempts($pdo, 'user:' . $username);
        }
        handle_authenticated_session($user);
    }

    $user_identifier = 'user:' . $username;
    increment_login_attempts($pdo, $ip_address, $current_time);
    increment_login_attempts($pdo, $user_identifier, $current_time);

    return 'Invalid credentials.';
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    try {
        verify_csrf_token($_POST['csrf_token'] ?? null);
    } catch (Exception $e) {
        $error = 'Invalid CSRF token. Please refresh the page and try again.';
    }

    if (!$error) {
        try {
            $error = handle_login_request($pdo) ?? '';
        } catch (\PDOException $e) {
            error_log("Database error in login.php: " . $e->getMessage());
            $error = 'A database error occurred. Please contact the administrator.';
        }
    }
}

$pageTitle = 'Login';
require_once 'header.php';
?>
<div class="container mt-5">
    <div class="row justify-content-center">
        <div class="col-md-6">
            <div class="card">
                <div class="card-header text-center">
                    <h4>Login</h4>
                </div>
                <div class="card-body">
                    <?php if ($error): ?>
                        <div class="alert alert-danger"><?= htmlspecialchars($error) ?></div>
                    <?php endif; ?>
                    <!-- Note: the form ensures credentials are submitted over the current protocol, ideally HTTPS -->
                    <form method="post" action="login.php">
                        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token'] ?? '') ?>">
                        <div class="mb-3">
                            <label for="username" class="form-label">Username</label>
                            <input type="text" class="form-control" id="username" name="username" required>
                        </div>
                        <div class="mb-3">
                            <label for="password" class="form-label">Password</label>
                            <input type="password" class="form-control" id="password" name="password" required>
                        </div>
                        <button type="submit" class="btn btn-primary w-100">Login</button>
                    </form>
                    <div class="mt-3 text-center">
                        <a href="register.php">Don't have an account? Register</a>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>

<?php require_once 'footer.php'; ?>