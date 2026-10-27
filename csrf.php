<?php

if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

function verify_csrf_token($token) {
    if (!isset($token) || !is_string($token) || !hash_equals((string)$_SESSION['csrf_token'], (string)$token)) {
        throw new Exception('Invalid CSRF token.');
    }
}

function validate_csrf_token($token): ?string {
    try {
        verify_csrf_token($token);
        return null;
    } catch (Exception $e) {
        return 'Invalid CSRF token. Please refresh the page and try again.';
    }
}
