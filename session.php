<?php
// Enforce secure session configurations
if (session_status() !== PHP_SESSION_ACTIVE && !headers_sent()) {
    @ini_set('session.use_strict_mode', 1);
    @ini_set('session.cookie_httponly', 1);
    @ini_set('session.cookie_secure', 1);
    @ini_set('session.cookie_samesite', 'Strict');
}

// Defense-in-depth headers
if (!headers_sent()) {
    header('X-Frame-Options: DENY');
    header('X-Content-Type-Options: nosniff');
    header("Content-Security-Policy: default-src 'self'; connect-src 'self' https://cdn.jsdelivr.net; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; img-src 'self' data:; font-src 'self' data:; form-action 'self'; base-uri 'self';");
    header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
    header('Referrer-Policy: strict-origin-when-cross-origin');
    header('Permissions-Policy: geolocation=(), microphone=(), camera=()');
    header('Cross-Origin-Opener-Policy: same-origin');
    header('Cross-Origin-Resource-Policy: same-origin');
}

if (session_status() !== PHP_SESSION_ACTIVE) {
    @session_start();
}

$now = time();
$inactivityTimeout = 1800;  // 30 minutes inactivity timeout
$absoluteTimeout = 28800;   // 8 hours absolute session limit
$regenerationInterval = 1800; // 30 minutes periodic session ID regeneration

$isAuthenticated = !empty($_SESSION['user_id']) || !empty($_SESSION['username']);

if ($isAuthenticated) {
    // Prevent browser from caching authenticated private pages
    if (!headers_sent()) {
        header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
        header('Pragma: no-cache');
    }

    // Check inactivity timeout (30 minutes)
    if (isset($_SESSION['last_activity']) && ($now - (int)$_SESSION['last_activity'] > $inactivityTimeout)) {
        $_SESSION = [];
        if (ini_get("session.use_cookies") && !headers_sent()) {
            $params = session_get_cookie_params();
            @setcookie(session_name(), '', time() - 42000, $params["path"], $params["domain"], $params["secure"], $params["httponly"]);
        }
        if (session_status() === PHP_SESSION_ACTIVE) {
            @session_destroy();
        }
        if (session_status() !== PHP_SESSION_ACTIVE && !headers_sent()) {
            @session_start();
        }
        $isAuthenticated = false;
    }
    // Check absolute session lifetime (8 hours)
    elseif (isset($_SESSION['session_created_at']) && ($now - (int)$_SESSION['session_created_at'] > $absoluteTimeout)) {
        $_SESSION = [];
        if (ini_get("session.use_cookies") && !headers_sent()) {
            $params = session_get_cookie_params();
            @setcookie(session_name(), '', time() - 42000, $params["path"], $params["domain"], $params["secure"], $params["httponly"]);
        }
        if (session_status() === PHP_SESSION_ACTIVE) {
            @session_destroy();
        }
        if (session_status() !== PHP_SESSION_ACTIVE && !headers_sent()) {
            @session_start();
        }
        $isAuthenticated = false;
    } else {
        if (!isset($_SESSION['session_created_at'])) {
            $_SESSION['session_created_at'] = $now;
        }

        // Periodic session ID regeneration
        if (!isset($_SESSION['last_regeneration'])) {
            $_SESSION['last_regeneration'] = $now;
        } elseif ($now - (int)$_SESSION['last_regeneration'] > $regenerationInterval) {
            if (!headers_sent()) {
                @session_regenerate_id(true);
            }
            $_SESSION['last_regeneration'] = $now;
        }
    }
}

if ($isAuthenticated) {
    $_SESSION['last_activity'] = $now;
}

