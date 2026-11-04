<?php

use PHPUnit\Framework\TestCase;

class MfaSetupTest extends TestCase
{
    private PDO $pdo;

    protected function setUp(): void
    {
        if (session_status() === PHP_SESSION_NONE) {
            @session_start();
        }
        $_SESSION = [];
        $this->pdo = new PDO('sqlite::memory:');
        $this->pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $this->pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);

        $this->pdo->exec("CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username VARCHAR(50) NOT NULL UNIQUE,
            password VARCHAR(255) NOT NULL,
            mfa_enabled TINYINT(1) DEFAULT 0,
            mfa_secret VARCHAR(255) DEFAULT NULL
        )");

        $this->pdo->exec("CREATE TABLE login_attempts (
            ip_address VARCHAR(255) PRIMARY KEY,
            attempts INT NOT NULL DEFAULT 0,
            last_attempt INT NOT NULL
        )");
    }

    private function executeMfaSetup(): array
    {
        $pdo = $this->pdo;
        $GLOBALS['pdo'] = $this->pdo;
        if (session_status() !== PHP_SESSION_ACTIVE) { session_start(); }

        $oldDisplayErrors = ini_get('display_errors');
        $oldLogErrors = ini_get('log_errors');
        $oldErrorLog = ini_get('error_log');

        ini_set('display_errors', '0');
        ini_set('log_errors', '1');
        ini_set('error_log', sys_get_temp_dir() . '/php_test_errors.log');

        ob_start();
        // Keep a copy of session vars so session_start doesn't wipe them if session.php calls it
        $tempSession = $_SESSION;
        session_write_close();
        session_start();
        $_SESSION = $tempSession;

        try {
            @include __DIR__ . '/../mfa_setup.php';
        } catch (\Throwable $e) {}
        $output = ob_get_clean();

        ini_set('display_errors', $oldDisplayErrors);
        ini_set('log_errors', $oldLogErrors);
        ini_set('error_log', $oldErrorLog);

        return [
            'output'  => $output,
            'error'   => $error ?? '',
            'success' => $success ?? '',
            'user'    => $user ?? null,
        ];
    }

    public function testPasswordIsRequiredToDisableMfa(): void
    {
        $hashedPassword = password_hash('Secret123!', PASSWORD_BCRYPT);
        $stmt = $this->pdo->prepare('INSERT INTO users (username, password, mfa_enabled, mfa_secret) VALUES (?, ?, 1, ?)');
        $stmt->execute(['testuser', $hashedPassword, 'SECRET123']);
        $userId = (int)$this->pdo->lastInsertId();

        $_SESSION['user_id'] = $userId;
        $_SESSION['csrf_token'] = 'valid_csrf';
        $_SERVER['REQUEST_METHOD'] = 'POST';
        $_POST = [
            'csrf_token' => 'valid_csrf',
            'disable_mfa' => '1',
            'password' => ''
        ];

        $res = $this->executeMfaSetup();

        $this->assertEquals('Password is required to disable MFA.', $res['error']);

        $stmt = $this->pdo->prepare('SELECT mfa_enabled, mfa_secret FROM users WHERE id = ?');
        $stmt->execute([$userId]);
        $updatedUser = $stmt->fetch();
        $this->assertEquals(1, $updatedUser['mfa_enabled']);
        $this->assertEquals('SECRET123', $updatedUser['mfa_secret']);
    }

    public function testIncorrectPasswordIncrementsRateLimit(): void
    {
        $hashedPassword = password_hash('Secret123!', PASSWORD_BCRYPT);
        $stmt = $this->pdo->prepare('INSERT INTO users (username, password, mfa_enabled, mfa_secret) VALUES (?, ?, 1, ?)');
        $stmt->execute(['testuser', $hashedPassword, 'SECRET123']);
        $userId = (int)$this->pdo->lastInsertId();

        $_SESSION['user_id'] = $userId;
        $_SESSION['csrf_token'] = 'valid_csrf';
        $_SERVER['REQUEST_METHOD'] = 'POST';
        $_POST = [
            'csrf_token' => 'valid_csrf',
            'disable_mfa' => '1',
            'password' => 'WrongPassword!'
        ];

        $this->executeMfaSetup();

        $stmt = $this->pdo->prepare('SELECT attempts FROM login_attempts WHERE ip_address = ?');
        $stmt->execute(['user:testuser']);
        $attempts = $stmt->fetchColumn();
        $this->assertEquals(1, $attempts);
    }

    public function testDisableMfaIsRateLimited(): void
    {
        $hashedPassword = password_hash('Secret123!', PASSWORD_BCRYPT);
        $stmt = $this->pdo->prepare('INSERT INTO users (username, password, mfa_enabled, mfa_secret) VALUES (?, ?, 1, ?)');
        $stmt->execute(['testuser', $hashedPassword, 'SECRET123']);
        $userId = (int)$this->pdo->lastInsertId();

        $_SESSION['user_id'] = $userId;
        $_SESSION['csrf_token'] = 'valid_csrf';
        $_SERVER['REQUEST_METHOD'] = 'POST';
        $_POST = [
            'csrf_token' => 'valid_csrf',
            'disable_mfa' => '1',
            'password' => 'WrongPassword!'
        ];

        // Simulate 5 failed attempts
        for ($i = 0; $i < 5; $i++) {
            $this->executeMfaSetup();
        }

        // 6th attempt should be rate limited, even with correct password
        $_POST['password'] = 'Secret123!';
        $res = $this->executeMfaSetup();

        $this->assertEquals('Too many failed attempts. Please try again later.', $res['error']);

        $stmt = $this->pdo->prepare('SELECT mfa_enabled FROM users WHERE id = ?');
        $stmt->execute([$userId]);
        $this->assertEquals(1, $stmt->fetchColumn());
    }

    public function testIncorrectPasswordFailsToDisableMfa(): void
    {
        $hashedPassword = password_hash('Secret123!', PASSWORD_BCRYPT);
        $stmt = $this->pdo->prepare('INSERT INTO users (username, password, mfa_enabled, mfa_secret) VALUES (?, ?, 1, ?)');
        $stmt->execute(['testuser', $hashedPassword, 'SECRET123']);
        $userId = (int)$this->pdo->lastInsertId();

        $_SESSION['user_id'] = $userId;
        $_SESSION['csrf_token'] = 'valid_csrf';
        $_SERVER['REQUEST_METHOD'] = 'POST';
        $_POST = [
            'csrf_token' => 'valid_csrf',
            'disable_mfa' => '1',
            'password' => 'WrongPassword!'
        ];

        $res = $this->executeMfaSetup();

        $this->assertEquals('Incorrect password. MFA was not disabled.', $res['error']);

        $stmt = $this->pdo->prepare('SELECT mfa_enabled, mfa_secret FROM users WHERE id = ?');
        $stmt->execute([$userId]);
        $updatedUser = $stmt->fetch();
        $this->assertEquals(1, $updatedUser['mfa_enabled']);
        $this->assertEquals('SECRET123', $updatedUser['mfa_secret']);
    }

    public function testCorrectPasswordSuccessfullyDisablesMfa(): void
    {
        $hashedPassword = password_hash('Secret123!', PASSWORD_BCRYPT);
        $stmt = $this->pdo->prepare('INSERT INTO users (username, password, mfa_enabled, mfa_secret) VALUES (?, ?, 1, ?)');
        $stmt->execute(['testuser', $hashedPassword, 'SECRET123']);
        $userId = (int)$this->pdo->lastInsertId();

        $_SESSION['user_id'] = $userId;
        $_SESSION['csrf_token'] = 'valid_csrf';
        $_SERVER['REQUEST_METHOD'] = 'POST';
        $_POST = [
            'csrf_token' => 'valid_csrf',
            'disable_mfa' => '1',
            'password' => 'Secret123!'
        ];

        $res = $this->executeMfaSetup();

        $this->assertEmpty($res['error']);
        $this->assertEquals('MFA disabled.', $res['success']);

        $stmt = $this->pdo->prepare('SELECT mfa_enabled, mfa_secret FROM users WHERE id = ?');
        $stmt->execute([$userId]);
        $updatedUser = $stmt->fetch();
        $this->assertEquals(0, $updatedUser['mfa_enabled']);
        $this->assertNull($updatedUser['mfa_secret']);
    }

    public function testVerifyMfaWithValidCodeSuccessfullyEnablesMfa(): void
    {
        $hashedPassword = password_hash('Secret123!', PASSWORD_BCRYPT);
        $stmt = $this->pdo->prepare('INSERT INTO users (username, password, mfa_enabled, mfa_secret) VALUES (?, ?, 0, NULL)');
        $stmt->execute(['testuser', $hashedPassword]);
        $userId = (int)$this->pdo->lastInsertId();

        $tfa = new \RobThree\Auth\TwoFactorAuth(new \RobThree\Auth\Providers\Qr\EndroidQrCodeProvider(), 'My App');
        $secret = $tfa->createSecret();
        $code = $tfa->getCode($secret);

        $_SESSION['user_id'] = $userId;
        $_SESSION['csrf_token'] = 'valid_csrf';
        $_SESSION['temp_mfa_secret'] = $secret;
        $_SERVER['REQUEST_METHOD'] = 'POST';
        $_POST = [
            'csrf_token' => 'valid_csrf',
            'verify_mfa' => '1',
            'mfa_code'   => $code
        ];

        $res = $this->executeMfaSetup();

        $this->assertEmpty($res['error']);
        $this->assertEquals('MFA successfully enabled.', $res['success']);
        $this->assertArrayNotHasKey('temp_mfa_secret', $_SESSION);

        $stmt = $this->pdo->prepare('SELECT mfa_enabled, mfa_secret FROM users WHERE id = ?');
        $stmt->execute([$userId]);
        $updatedUser = $stmt->fetch();
        $this->assertEquals(1, $updatedUser['mfa_enabled']);
        $this->assertEquals($secret, $updatedUser['mfa_secret']);
    }

    public function testVerifyMfaWithInvalidCodeFailsToEnableMfa(): void
    {
        $hashedPassword = password_hash('Secret123!', PASSWORD_BCRYPT);
        $stmt = $this->pdo->prepare('INSERT INTO users (username, password, mfa_enabled, mfa_secret) VALUES (?, ?, 0, NULL)');
        $stmt->execute(['testuser', $hashedPassword]);
        $userId = (int)$this->pdo->lastInsertId();

        $tfa = new \RobThree\Auth\TwoFactorAuth(new \RobThree\Auth\Providers\Qr\EndroidQrCodeProvider(), 'My App');
        $secret = $tfa->createSecret();

        $_SESSION['user_id'] = $userId;
        $_SESSION['csrf_token'] = 'valid_csrf';
        $_SESSION['temp_mfa_secret'] = $secret;
        $_SERVER['REQUEST_METHOD'] = 'POST';
        $_POST = [
            'csrf_token' => 'valid_csrf',
            'verify_mfa' => '1',
            'mfa_code'   => '000000'
        ];

        $res = $this->executeMfaSetup();

        $this->assertEquals('Invalid code. Try again.', $res['error']);
        $this->assertEmpty($res['success']);
        $this->assertEquals($secret, $_SESSION['temp_mfa_secret']);

        $stmt = $this->pdo->prepare('SELECT mfa_enabled, mfa_secret FROM users WHERE id = ?');
        $stmt->execute([$userId]);
        $updatedUser = $stmt->fetch();
        $this->assertEquals(0, $updatedUser['mfa_enabled']);
        $this->assertNull($updatedUser['mfa_secret']);
    }
}
