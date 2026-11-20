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

        // 9. Test batch migration of plaintext MFA secrets
        $existingEncrypted = encrypt_mfa_secret('ALREADYENCRYPTED');
        $mfaMigrationPdo = new class($existingEncrypted) extends PDO {
            public array $rows;
            public array $updates = [];
            public function __construct(string $existingEncrypted) {
                $this->rows = [
                    ['id' => 1, 'mfa_secret' => 'LEGACYPLAINTEXT1'],
                    ['id' => 2, 'mfa_secret' => $existingEncrypted],
                    ['id' => 3, 'mfa_secret' => 'LEGACYPLAINTEXT2'],
                ];
            }
            #[\ReturnTypeWillChange]
            public function query(string $query, ?int $fetchMode = null, mixed ...$fetchModeArgs): object {
                $rows = $this->rows;
                return new class($rows) {
                    private array $rows;
                    public function __construct(array $rows) { $this->rows = $rows; }
                    public function fetchAll(int $mode = PDO::FETCH_ASSOC): array { return $this->rows; }
                };
            }
            #[\ReturnTypeWillChange]
            public function prepare(string $query, array $options = []): object {
                $pdoRef = $this;
                return new class($pdoRef) {
                    private $pdoRef;
                    public function __construct($pdoRef) { $this->pdoRef = $pdoRef; }
                    public function execute(?array $params = null): bool {
                        $this->pdoRef->updates[$params[1]] = $params[0];
                        return true;
                    }
                };
            }
        };
        $migratedCount = migrate_plaintext_mfa_secrets($mfaMigrationPdo);
        assert($migratedCount === 2, "Expected 2 plaintext MFA secrets migrated, got $migratedCount");
        assert(isset($mfaMigrationPdo->updates[1]) && is_mfa_secret_encrypted($mfaMigrationPdo->updates[1]), 'User 1 MFA secret must be encrypted');
        assert(decrypt_mfa_secret($mfaMigrationPdo->updates[1]) === 'LEGACYPLAINTEXT1', 'User 1 decrypted secret must match');
        assert(!isset($mfaMigrationPdo->updates[2]), 'Already encrypted User 2 MFA secret must not be re-encrypted');
        assert(isset($mfaMigrationPdo->updates[3]) && decrypt_mfa_secret($mfaMigrationPdo->updates[3]) === 'LEGACYPLAINTEXT2', 'User 3 decrypted secret must match');
        echo "✓ Batch migration of plaintext MFA secrets verified\n";

        // 10. Test transparent password rehashing on login (bcrypt -> Argon2id)
        $_SERVER['REQUEST_METHOD'] = 'GET';
        ob_start();
        require_once __DIR__ . '/../login.php';
        ob_end_clean();

        $legacyPassword = 'LegacyUserPass!2026';
        $legacyBcryptHash = password_hash($legacyPassword, PASSWORD_BCRYPT);
        $loginMockPdo = new class($legacyBcryptHash) extends PDO {
            public string $legacyHash;
            public ?array $updatedPasswordParams = null;
            public function __construct(string $legacyHash) { $this->legacyHash = $legacyHash; }
            #[\ReturnTypeWillChange]
            public function prepare(string $query, array $options = []): object {
                $pdoRef = $this;
                if (stripos($query, 'SELECT') === 0) {
                    return new class($pdoRef) {
                        private $pdoRef;
                        public function __construct($pdoRef) { $this->pdoRef = $pdoRef; }
                        public function execute(?array $params = null): bool { return true; }
                        public function fetch(): array {
                            return [
                                'id' => 99,
                                'username' => 'legacyuser',
                                'password' => $this->pdoRef->legacyHash,
                                'role' => 'user',
                                'mfa_enabled' => 0,
                            ];
                        }
                    };
                }
                return new class($pdoRef) {
                    private $pdoRef;
                    public function __construct($pdoRef) { $this->pdoRef = $pdoRef; }
                    public function execute(?array $params = null): bool {
                        $this->pdoRef->updatedPasswordParams = $params;
                        return true;
                    }
                };
            }
        };

        $authenticatedUser = authenticate_user($loginMockPdo, 'legacyuser', $legacyPassword);
        assert($authenticatedUser !== null, 'Legacy bcrypt user must authenticate successfully');
        if (defined('PASSWORD_ARGON2ID')) {
            assert($loginMockPdo->updatedPasswordParams !== null, 'Legacy bcrypt hash must be updated in DB on login');
            assert(str_starts_with($loginMockPdo->updatedPasswordParams[0], '$argon2id$'), 'Rehashed password must use Argon2id');
            assert($loginMockPdo->updatedPasswordParams[1] === 99, 'Rehash update must target the authenticated user ID');
            assert(password_verify($legacyPassword, $loginMockPdo->updatedPasswordParams[0]), 'New Argon2id hash must verify against the user password');
        }
        echo "✓ Transparent password rehashing on login verified\n";

        // 11. Test migrate.php and mfa_verify.php migration hooks
        $migratePhpContent = file_get_contents(__DIR__ . '/../migrate.php');
        assert(str_contains($migratePhpContent, 'migrate_plaintext_mfa_secrets'), 'migrate.php must invoke migrate_plaintext_mfa_secrets');
        $mfaVerifyContent = file_get_contents(__DIR__ . '/../mfa_verify.php');
        assert(str_contains($mfaVerifyContent, 'is_mfa_secret_encrypted'), 'mfa_verify.php must auto-encrypt legacy plaintext MFA secrets');
        echo "✓ migrate.php & mfa_verify.php migration hooks verified\n";

        echo "\nAll SecurityEnhancementsTest checks PASSED!\n";
    }
}

if (php_sapi_name() === 'cli' && realpath($argv[0]) === realpath(__FILE__)) {
    SecurityEnhancementsTest::run();
}
