<?php

class PhpIniTest
{
    public static function run(): void
    {
        echo "Running php.ini hardening tests...\n";

        $iniPath = __DIR__ . '/../php.ini';
        if (!file_exists($iniPath)) {
            throw new Exception("php.ini does not exist at: $iniPath");
        }

        $parsed = parse_ini_file($iniPath, true, INI_SCANNER_TYPED);
        if ($parsed === false) {
            throw new Exception("Failed to parse php.ini syntax");
        }

        // 1. Verify Security Directives
        $phpSection = $parsed['PHP'] ?? $parsed;
        if (!empty($phpSection['expose_php'])) {
            throw new Exception("expose_php must be Off");
        }

        if (!empty($phpSection['display_errors'])) {
            throw new Exception("display_errors must be Off");
        }

        if (!empty($phpSection['allow_url_include'])) {
            throw new Exception("allow_url_include must be Off");
        }

        // 2. Verify Session Directives
        $sessionSection = $parsed['Session'] ?? [];
        if (($sessionSection['session.cookie_httponly'] ?? null) !== '1' && ($sessionSection['session.cookie_httponly'] ?? null) !== 1) {
            throw new Exception("session.cookie_httponly must be enabled");
        }

        if (($sessionSection['session.cookie_samesite'] ?? null) !== 'Strict') {
            throw new Exception("session.cookie_samesite must be Strict");
        }

        if (($sessionSection['session.use_strict_mode'] ?? null) !== '1' && ($sessionSection['session.use_strict_mode'] ?? null) !== 1) {
            throw new Exception("session.use_strict_mode must be enabled");
        }

        // 3. Verify Function Blacklisting (Principle of Least Privilege)
        $disableFunctionsStr = $phpSection['disable_functions'] ?? '';
        $disabledList = array_filter(array_map('trim', explode(',', $disableFunctionsStr)));

        if (count($disabledList) < 1000) {
            throw new Exception("disable_functions must contain all unneeded functions (expected > 1000, got " . count($disabledList) . ")");
        }

        $criticalDangerous = [
            'exec', 'passthru', 'shell_exec', 'system',
            'proc_open', 'proc_close', 'proc_terminate', 'proc_get_status', 'proc_nice',
            'popen', 'pclose', 'show_source', 'highlight_file', 'phpinfo', 'dl',
            'pcntl_exec', 'posix_kill'
        ];

        foreach ($criticalDangerous as $fn) {
            if (!in_array($fn, $disabledList, true)) {
                throw new Exception("Critical dangerous function '$fn' is NOT locked in disable_functions!");
            }
        }

        // 4. Verify Whitelist integrity (application functions must NOT be disabled)
        $mustBeAllowed = [
            'strlen', 'count', 'implode', 'explode', 'sprintf', 'htmlspecialchars',
            'password_hash', 'password_verify', 'hash', 'hash_hmac', 'openssl_encrypt',
            'openssl_decrypt', 'random_bytes', 'json_encode', 'json_decode',
            'session_start', 'session_status', 'header', 'file_get_contents',
            'file_put_contents', 'is_uploaded_file', 'move_uploaded_file', 'curl_init',
            'imagecreatefromstring', 'imagepng', 'spl_autoload_register'
        ];

        foreach ($mustBeAllowed as $allowed) {
            if (in_array($allowed, $disabledList, true)) {
                throw new Exception("Required application function '$allowed' was incorrectly disabled!");
            }
        }

        echo "All php.ini hardening tests passed successfully! (" . count($disabledList) . " functions locked)\n";
    }
}

if (php_sapi_name() === 'cli' && realpath($argv[0]) === realpath(__FILE__)) {
    PhpIniTest::run();
}
