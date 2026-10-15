<?php

use PHPUnit\Framework\TestCase;

// Mark db.php as required to prevent mfa_verify.php from overwriting $pdo
$_SERVER['REQUEST_METHOD'] = 'GET';
ob_start();
require_once __DIR__ . '/../db.php';
ob_end_clean();

class MfaVerifyTest extends TestCase
{
    private PDO $pdo;
    private string $validSecret;

    protected function setUp(): void
    {
        if (session_status() === PHP_SESSION_NONE) {
            @session_start();
        }
        $_SESSION = [];
        $_SERVER['REQUEST_METHOD'] = 'GET';
        $_POST = [];
        $_SERVER['REMOTE_ADDR'] = '127.0.0.1';

        $host = $_ENV['DB_HOST'] ?? getenv('DB_HOST') ?: '127.0.0.1';
        $dbname = $_ENV['DB_NAME'] ?? getenv('DB_NAME') ?: 'app_db';
        $user = $_ENV['DB_USER'] ?? getenv('DB_USER') ?: 'app_user';
        $pass = $_ENV['DB_PASS'] ?? getenv('DB_PASS') ?: 'app_password';

        $this->pdo = new PDO("mysql:host=$host;dbname=$dbname;charset=utf8mb4", $user, $pass, [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        ]);

        $this->pdo->exec("DROP TRIGGER IF EXISTS trigger_fail_login_attempts");
        $this->pdo->exec("DELETE FROM users");
        $this->pdo->exec("DELETE FROM login_attempts");

        $tfa = new \RobThree\Auth\TwoFactorAuth(new \RobThree\Auth\Providers\Qr\EndroidQrCodeProvider(), 'My App');
        $this->validSecret = $tfa->createSecret();
    }

    protected function tearDown(): void
    {
        $_SESSION = [];
        $_POST = [];
        if ($this->pdo) {
            $this->pdo->exec("DROP TRIGGER IF EXISTS trigger_fail_login_attempts");
            $this->pdo->exec("DELETE FROM users");
            $this->pdo->exec("DELETE FROM login_attempts");
        }
    }

    private function executeMfaVerify(): array
    {
        $pdo = $this->pdo;
        $GLOBALS['pdo'] = $this->pdo;

        $oldDisplayErrors = ini_get('display_errors');
        $oldLogErrors = ini_get('log_errors');
        $oldErrorLog = ini_get('error_log');

        ini_set('display_errors', '0');
        ini_set('log_errors', '1');
        ini_set('error_log', sys_get_temp_dir() . '/php_test_errors.log');

        ob_start();
        @include __DIR__ . '/../mfa_verify.php';
        $output = ob_get_clean();

        ini_set('display_errors', $oldDisplayErrors);
        ini_set('log_errors', $oldLogErrors);
        ini_set('error_log', $oldErrorLog);

        return [
            'output' => $output,
            'error'  => $error ?? '',
            'user'   => $user ?? null,
        ];
    }

    public function testDbExceptionDuringRateLimitingSetsError(): void
    {
        $stmt = $this->pdo->prepare("INSERT INTO users (username, password, role, mfa_enabled, mfa_secret) VALUES ('testuser', 'hash', 'user', 1, ?)");
        $stmt->execute([$this->validSecret]);
        $userId = (int)$this->pdo->lastInsertId();

        // Temporarily rename login_attempts table to simulate table missing error during rate limiting query
        $this->pdo->exec("RENAME TABLE login_attempts TO login_attempts_temp");

        $_SESSION['pending_user_id'] = $userId;
        $_SESSION['csrf_token'] = 'valid_csrf';
        $_SERVER['REQUEST_METHOD'] = 'POST';
        $_POST = [
            'csrf_token' => 'valid_csrf',
            'mfa_code'   => '123456',
        ];

        try {
            $res = $this->executeMfaVerify();

            $this->assertEquals('A database error occurred. Please contact the administrator.', $res['error']);
            $this->assertStringContainsString('A database error occurred. Please contact the administrator.', $res['output']);
        } finally {
            $this->pdo->exec("RENAME TABLE login_attempts_temp TO login_attempts");
        }
    }

    public function testDbExceptionDuringIncrementAttemptsSetsError(): void
    {
        $stmt = $this->pdo->prepare("INSERT INTO users (username, password, role, mfa_enabled, mfa_secret) VALUES ('testuser', 'hash', 'user', 1, ?)");
        $stmt->execute([$this->validSecret]);
        $userId = (int)$this->pdo->lastInsertId();

        // Trigger on login_attempts to force PDOException when inserting attempts
        $this->pdo->exec("CREATE TRIGGER trigger_fail_login_attempts BEFORE INSERT ON login_attempts FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Simulated DB error'");

        $_SESSION['pending_user_id'] = $userId;
        $_SESSION['csrf_token'] = 'valid_csrf';
        $_SERVER['REQUEST_METHOD'] = 'POST';
        $_POST = [
            'csrf_token' => 'valid_csrf',
            'mfa_code'   => '000000',
        ];

        $res = $this->executeMfaVerify();

        $this->assertEquals('A database error occurred. Please contact the administrator.', $res['error']);
        $this->assertStringContainsString('A database error occurred. Please contact the administrator.', $res['output']);
    }

    public function testMfaVerifyWithInvalidCodeSetsErrorAndIncrementsAttempts(): void
    {
        $stmt = $this->pdo->prepare("INSERT INTO users (username, password, role, mfa_enabled, mfa_secret) VALUES ('testuser', 'hash', 'user', 1, ?)");
        $stmt->execute([$this->validSecret]);
        $userId = (int)$this->pdo->lastInsertId();

        $_SESSION['pending_user_id'] = $userId;
        $_SESSION['csrf_token'] = 'valid_csrf';
        $_SERVER['REQUEST_METHOD'] = 'POST';
        $_POST = [
            'csrf_token' => 'valid_csrf',
            'mfa_code'   => '000000',
        ];

        $res = $this->executeMfaVerify();

        $this->assertEquals('Invalid verification code.', $res['error']);
        $this->assertStringContainsString('Invalid verification code.', $res['output']);

        // Verify attempts incremented in database
        $stmt = $this->pdo->prepare("SELECT attempts FROM login_attempts WHERE ip_address = ?");
        $stmt->execute(['127.0.0.1']);
        $row = $stmt->fetch();
        $this->assertEquals(1, (int)$row['attempts']);
    }

    public function testDbExceptionDuringUserFetchTerminatesWithErrorMessage(): void
    {
        $this->pdo->exec("RENAME TABLE users TO users_temp");

        try {
            $code = sprintf('
                session_start();
                $_SESSION["pending_user_id"] = 1;
                $_SERVER["REQUEST_METHOD"] = "GET";
                ini_set("display_errors", "0");
                ini_set("log_errors", "1");
                ini_set("error_log", sys_get_temp_dir() . "/php_test_errors.log");
                require %s;
            ', var_export(__DIR__ . "/../mfa_verify.php", true));

            $env = array_merge($_ENV, [
                "DB_HOST" => $_ENV["DB_HOST"] ?? getenv("DB_HOST") ?: "127.0.0.1",
                "DB_NAME" => $_ENV["DB_NAME"] ?? getenv("DB_NAME") ?: "app_db",
                "DB_USER" => $_ENV["DB_USER"] ?? getenv("DB_USER") ?: "app_user",
                "DB_PASS" => $_ENV["DB_PASS"] ?? getenv("DB_PASS") ?: "app_password",
            ]);

            $cmd = sprintf("%s -d variables_order=EGPCS -r %s 2>&1", escapeshellarg(PHP_BINARY), escapeshellarg($code));

            $descriptors = [
                0 => ["pipe", "r"],
                1 => ["pipe", "w"],
                2 => ["pipe", "w"],
            ];

            $process = proc_open($cmd, $descriptors, $pipes, __DIR__ . "/..", $env);
            $stdout = stream_get_contents($pipes[1]);
            fclose($pipes[0]);
            fclose($pipes[1]);
            fclose($pipes[2]);
            proc_close($process);

            $this->assertStringContainsString("A database error occurred. Please contact the administrator.", $stdout);
        } finally {
            $this->pdo->exec("RENAME TABLE users_temp TO users");
        }
    }
}
