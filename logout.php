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

header('Location: login.php');
exit;
