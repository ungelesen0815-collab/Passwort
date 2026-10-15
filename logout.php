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
    setcookie(session_name(), '', time() - 42000,
        $params["path"], $params["domain"],
        $params["secure"], $params["httponly"]
    );
}
setcookie(session_name(), '', time() - 3600, '/');

header('Location: login.php');
exit;
