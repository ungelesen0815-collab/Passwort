<?php
require_once __DIR__ . '/session.php';
require_once 'db.php';
require_once 'csrf.php';
require_once 'RegistrationService.php';

$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $error = validate_csrf_token($_POST['csrf_token'] ?? null) ?? '';

    if (!$error) {
        $username = trim((string)($_POST['username'] ?? ''));
    $password = (string)($_POST['password'] ?? '');

        $registrationService = new RegistrationService($pdo);
        $result = $registrationService->register($username, $password);

        if ($result['success']) {
            header('Location: login.php');
            exit;
        } else {
            $error = $result['error'];
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
                    <form method="post" action="register.php">
                        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token'] ?? '') ?>">
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
                </div>
            </div>
        </div>
    </div>
</div>

<?php require_once 'footer.php'; ?>