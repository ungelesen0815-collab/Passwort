<?php
require_once __DIR__ . '/session.php';
require_once 'csrf.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    die('Invalid request method.');
}

try {
    verify_csrf_token($_POST['csrf_token'] ?? null);
} catch (Exception $e) {
    die('Invalid CSRF token.');
}

$_SESSION = array();
session_unset();
session_destroy();

if (ini_get("session.use_cookies")) {
    $params = session_get_cookie_params();
    setcookie(session_name(), '', [
        'expires' => time() - 42000,
        'path' => $params["path"],
        'domain' => $params["domain"],
        'secure' => $params["secure"],
        'httponly' => $params["httponly"],
        'samesite' => $params["samesite"] ?? 'Strict',
    ]);
}

if (session_status() !== PHP_SESSION_ACTIVE) {
    session_start();
}
session_regenerate_id(true);
if (function_exists('rotate_csrf_token')) {
    rotate_csrf_token();
} else {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

header('Location: login.php');
exit;
