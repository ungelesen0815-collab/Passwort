<?php

class SecurityTestMockPdo extends PDO
{
    public $stmt;
    public function __construct() {}
    #[\ReturnTypeWillChange]
    public function prepare(string $query, array $options = []): object
    {
        return $this->stmt;
    }
}

class SecurityEnhancementsTest
{
    public static function run(): void
    {
        echo "Running SecurityEnhancementsTest...\n";

        // 1. Test root .htaccess rules
        $rootHtaccess = file_get_contents(__DIR__ . '/../.htaccess');
        assert(str_contains($rootHtaccess, 'Options -Indexes'), 'Root .htaccess must have Options -Indexes');
        assert(str_contains($rootHtaccess, 'db.php') || str_contains($rootHtaccess, 'db|session'), 'Root .htaccess must block internal PHP files');
        assert(str_contains($rootHtaccess, 'session'), 'Root .htaccess must mention session');
        assert(str_contains($rootHtaccess, 'csrf'), 'Root .htaccess must mention csrf');
        assert(str_contains($rootHtaccess, 'auth_utils'), 'Root .htaccess must mention auth_utils');
        assert(str_contains($rootHtaccess, 'RegistrationService'), 'Root .htaccess must mention RegistrationService');
        assert(str_contains($rootHtaccess, 'migrate'), 'Root .htaccess must mention migrate');
        assert(str_contains($rootHtaccess, 'create_admin'), 'Root .htaccess must mention create_admin');
        echo "✓ Root .htaccess rules verified\n";

        // 2. Test uploads/.htaccess rules
        $uploadHtaccessPath = __DIR__ . '/../uploads/.htaccess';
        assert(file_exists($uploadHtaccessPath), 'uploads/.htaccess must exist');
        $uploadHtaccess = file_get_contents($uploadHtaccessPath);
        assert(str_contains($uploadHtaccess, 'Options -Indexes'), 'uploads/.htaccess must have Options -Indexes');
        assert(str_contains($uploadHtaccess, 'Require all denied'), 'uploads/.htaccess must deny script execution');
        assert(str_contains($uploadHtaccess, 'FilesMatch'), 'uploads/.htaccess must use FilesMatch');
        echo "✓ uploads/.htaccess rules verified\n";

        // 3. Test session.php security headers
        $sessionContent = file_get_contents(__DIR__ . '/../session.php');
        assert(str_contains($sessionContent, 'Cross-Origin-Opener-Policy: same-origin'), 'session.php must set COOP');
        assert(str_contains($sessionContent, 'Cross-Origin-Resource-Policy: same-origin'), 'session.php must set CORP');
        assert(str_contains($sessionContent, "form-action 'self'"), 'CSP must include form-action self');
        assert(str_contains($sessionContent, "base-uri 'self'"), 'CSP must include base-uri self');
        assert(str_contains($sessionContent, 'Cache-Control: no-store'), 'session.php must set Cache-Control for authenticated sessions');
        echo "✓ session.php security headers verified\n";

        // 4. Test session timeout and inactivity
        if (session_status() === PHP_SESSION_NONE) {
            @session_start();
        }
        $_SESSION = [
            'user_id' => 42,
            'username' => 'testuser',
            'last_activity' => time() - 2000 // 2000 seconds ago (> 1800s timeout)
        ];
        require __DIR__ . '/../session.php';
        assert(empty($_SESSION['username']), 'Expired session due to inactivity should clear username');
        assert(empty($_SESSION['user_id']), 'Expired session due to inactivity should clear user_id');
        echo "✓ Session inactivity timeout verified\n";

        // 5. Test CSRF rotation
        require_once __DIR__ . '/../csrf.php';
        $oldToken = $_SESSION['csrf_token'] ?? '';
        $newToken = rotate_csrf_token();
        assert(!empty($newToken), 'Rotated CSRF token must not be empty');
        assert($newToken !== $oldToken, 'Rotated CSRF token must differ from old token');
        echo "✓ CSRF token rotation verified\n";

        // 6. Test RegistrationService password hashing and common password protection
        require_once __DIR__ . '/../RegistrationService.php';
        $mockPdo = new SecurityTestMockPdo();
        $mockPdo->stmt = new class {
            public $params;
            public function execute(?array $params = null): bool {
                $this->params = $params;
                return true;
            }
        };
        $service = new RegistrationService($mockPdo);

        // Common password check
        $commonResult = $service->register('testuser1', 'password');
        assert($commonResult['success'] === false, 'Registration must fail for common password "password"');
        assert(str_contains($commonResult['error'], 'common'), 'Error message must note common password');

        $commonResult2 = $service->register('testuser2', '12345678');
        assert($commonResult2['success'] === false, 'Registration must fail for common password "12345678"');

        // Strong password check & hashing algorithm
        $strongResult = $service->register('testuser3', 'SecurePassw0rd!#2026');
        assert($strongResult['success'] === true, 'Registration must succeed for strong password');

        $savedHash = $mockPdo->stmt->params[1] ?? '';
        if (defined('PASSWORD_ARGON2ID')) {
            assert(str_starts_with($savedHash, '$argon2id$'), 'Password must be hashed with Argon2id when supported');
        } else {
            assert(str_starts_with($savedHash, '$2y$'), 'Password must be hashed with bcrypt when Argon2id is not present');
        }
        echo "✓ RegistrationService password hashing & common password rejection verified\n";

        // 7. Test MFA Secret encryption & decryption
        require_once __DIR__ . '/../auth_utils.php';
        $_ENV['APP_ENCRYPTION_KEY'] = 'my_super_secret_app_key_32bytes_long!';
        $rawMfaSecret = 'JBSWY3DPEHPK3PXP';
        $encryptedSecret = encrypt_mfa_secret($rawMfaSecret);
        assert(str_starts_with($encryptedSecret, 'enc:v1:'), 'Encrypted MFA secret must have enc:v1: prefix');
        assert($encryptedSecret !== $rawMfaSecret, 'Encrypted secret must not be in plaintext');

        $decryptedSecret = decrypt_mfa_secret($encryptedSecret);
        assert($decryptedSecret === $rawMfaSecret, 'Decrypted secret must match original secret');

        // Legacy unencrypted secret backwards-compatibility
        assert(decrypt_mfa_secret('LEGACYSECRET') === 'LEGACYSECRET', 'Legacy unencrypted secrets must pass through transparently');
        echo "✓ MFA Secret AES-256-GCM encryption verified\n";

        // 8. Test ALLOW_REGISTRATION logic
        $registerPhpContent = file_get_contents(__DIR__ . '/../register.php');
        assert(str_contains($registerPhpContent, 'ALLOW_REGISTRATION'), 'register.php must check ALLOW_REGISTRATION');
        assert(str_contains($registerPhpContent, 'REGISTRATION_INVITE_CODE'), 'register.php must support invite code');
        echo "✓ ALLOW_REGISTRATION and invite code logic in register.php verified\n";

        echo "\nAll SecurityEnhancementsTest checks PASSED!\n";
    }
}

if (php_sapi_name() === 'cli' && realpath($argv[0]) === realpath(__FILE__)) {
    SecurityEnhancementsTest::run();
}
