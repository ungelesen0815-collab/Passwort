<?php

use PHPUnit\Framework\TestCase;

$_ENV['DB_HOST'] = $_SERVER['DB_HOST'] ?? '127.0.0.1';
$_ENV['DB_NAME'] = $_SERVER['DB_NAME'] ?? 'test_db';
$_ENV['DB_USER'] = $_SERVER['DB_USER'] ?? 'test_user';
$_ENV['DB_PASS'] = $_SERVER['DB_PASS'] ?? 'test_pass';

$_SERVER['REQUEST_METHOD'] = 'GET';

require_once __DIR__ . '/../session.php';
require_once __DIR__ . '/../csrf.php';
require_once __DIR__ . '/../auth_utils.php';

if (!defined('DUMMY_PASSWORD_HASH')) {
    define('DUMMY_PASSWORD_HASH', '$2y$10$af7Ut8Qngg0SM0anMdogOuJo6W11NYi66eyUFz93j3oHgjnzvntea');
}

$oldDisplayErrors = ini_get('display_errors');
$oldLogErrors = ini_get('log_errors');
$oldErrorLog = ini_get('error_log');

ini_set('display_errors', '0');
ini_set('log_errors', '1');
ini_set('error_log', sys_get_temp_dir() . '/php_test_errors.log');

try {
    ob_start();
    require_once __DIR__ . '/../login.php';
    ob_end_clean();
} catch (\Throwable $e) {
    ob_end_clean();
}

ini_set('display_errors', $oldDisplayErrors);
ini_set('log_errors', $oldLogErrors);
ini_set('error_log', $oldErrorLog);
ini_set('display_errors', '0');
ini_set('log_errors', '1');
ini_set('error_log', sys_get_temp_dir() . '/php_test_errors.log');
ob_start();
require_once __DIR__ . '/../login.php';
ob_end_clean();

require_once __DIR__ . '/../auth_utils.php';
require_once __DIR__ . '/../csrf.php';

if (!defined('DUMMY_PASSWORD_HASH')) {
    define('DUMMY_PASSWORD_HASH', '$2y$10$af7Ut8Qngg0SM0anMdogOuJo6W11NYi66eyUFz93j3oHgjnzvntea');
}

try {
    ob_start();
    require_once __DIR__ . '/../login.php';
    ob_end_clean();
} catch (Throwable $e) {
    ob_end_clean();
}

class LoginTest extends TestCase
{
    private PDO $pdo;

    protected function setUp(): void
    {
        $_POST = [];
        $_SERVER['REMOTE_ADDR'] = '127.0.0.1';
        unset($_SERVER['HTTP_X_FORWARDED_FOR'], $_SERVER['HTTP_CLIENT_IP'], $_ENV['TRUSTED_PROXIES']);

        $this->pdo = new PDO('sqlite::memory:');
        $this->pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $this->pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);

        $this->pdo->exec("CREATE TABLE login_attempts (
            ip_address VARCHAR(255) PRIMARY KEY,
            attempts INT NOT NULL,
            last_attempt INT NOT NULL
        )");

        $this->pdo->exec("CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username VARCHAR(255) UNIQUE NOT NULL,
            password VARCHAR(255) NOT NULL,
            role VARCHAR(50) NOT NULL DEFAULT 'user',
            mfa_secret VARCHAR(255) DEFAULT NULL,
            mfa_enabled INTEGER DEFAULT 0,
            full_name VARCHAR(255) DEFAULT NULL,
            personal_details TEXT DEFAULT NULL,
            profile_picture VARCHAR(255) DEFAULT NULL
        )");
    }

    protected function tearDown(): void
    {
        $_POST = [];
    }

    public function testAuthenticateUserReturnsNullOnEmptyUsername(): void
    {
        $this->assertNull(authenticate_user($this->pdo, '', 'password123'));
    }

    public function testAuthenticateUserReturnsNullOnEmptyPassword(): void
    {
        $this->assertNull(authenticate_user($this->pdo, 'john_doe', ''));
    }

    public function testAuthenticateUserReturnsNullOnPasswordExceeding72Bytes(): void
    {
        $this->assertNull(authenticate_user($this->pdo, 'john_doe', str_repeat('a', 73)));
    }

    public function testAuthenticateUserReturnsNullOnUsernameExceeding250Bytes(): void
    {
        $this->assertNull(authenticate_user($this->pdo, str_repeat('a', 251), 'password123'));
    }

    public function testHandleLoginRequestReturnsRequiredOnEmptyFields(): void
    {
        $_POST['username'] = '';
        $_POST['password'] = 'password123';
        $this->assertEquals('Username and password are required.', handle_login_request($this->pdo));

        $_POST['username'] = 'john';
        $_POST['password'] = '';
        $this->assertEquals('Username and password are required.', handle_login_request($this->pdo));
    }

    public function testHandleLoginRequestReturnsInvalidCredentialsOnLongUsername(): void
    {
        $_POST['username'] = str_repeat('a', 251);
        $_POST['password'] = 'password123';
        $this->assertEquals('Invalid credentials.', handle_login_request($this->pdo));
    }

    public function testAuthenticateUserReturnsNullForNonExistentUser(): void
    {
        $this->assertNull(authenticate_user($this->pdo, 'non_existent_user', 'password123'));
    }

    public function testAuthenticateUserReturnsNullForIncorrectPassword(): void
    {
        $hash = password_hash('correct_password', PASSWORD_BCRYPT);
        $stmt = $this->pdo->prepare('INSERT INTO users (username, password) VALUES (?, ?)');
        $stmt->execute(['test_user', $hash]);

        $this->assertNull(authenticate_user($this->pdo, 'test_user', 'wrong_password'));
    }

    public function testAuthenticateUserReturnsUserArrayForValidCredentials(): void
    {
        $hash = password_hash('correct_password', PASSWORD_BCRYPT);
        $stmt = $this->pdo->prepare('INSERT INTO users (username, password) VALUES (?, ?)');
        $stmt->execute(['valid_user', $hash]);

        $result = authenticate_user($this->pdo, 'valid_user', 'correct_password');
        $this->assertIsArray($result);
        $this->assertEquals('valid_user', $result['username']);
    }

    public function testAuthenticateUserWithMockEmptyResult(): void
    {
        $stmt = $this->createMock(\PDOStatement::class);
        $stmt->expects($this->once())->method('execute')->with(['test_user']);
        $stmt->expects($this->once())->method('fetch')->willReturn(false);

        $pdo = $this->createMock(\PDO::class);
        $pdo->expects($this->once())->method('prepare')->willReturn($stmt);

        $this->assertNull(authenticate_user($pdo, 'test_user', 'password123'));
    }

    public function testAuthenticateUserWithMockWrongPassword(): void
    {
        $stmt = $this->createMock(\PDOStatement::class);
        $stmt->expects($this->once())->method('execute')->with(['test_user']);
        $stmt->expects($this->once())->method('fetch')->willReturn([
            'id' => 1,
            'username' => 'test_user',
            'password' => password_hash('correct_password', PASSWORD_BCRYPT),
            'password_hash' => password_hash('correct_password', PASSWORD_BCRYPT),
            'mfa_secret' => null
        ]);

        $pdo = $this->createMock(\PDO::class);
        $pdo->expects($this->once())->method('prepare')->willReturn($stmt);

        $this->assertNull(authenticate_user($pdo, 'test_user', 'wrong_password'));
    }

    public function testAuthenticateUserWithMockRightPassword(): void
    {
        $stmt = $this->createMock(\PDOStatement::class);
        $stmt->expects($this->once())->method('execute')->with(['test_user']);
        $stmt->expects($this->once())->method('fetch')->willReturn([
            'id' => 1,
            'username' => 'test_user',
            'password' => password_hash('correct_password', PASSWORD_BCRYPT),
            'password_hash' => password_hash('correct_password', PASSWORD_BCRYPT),
            'mfa_secret' => null
        ]);

        $pdo = $this->createMock(\PDO::class);
        $pdo->expects($this->once())->method('prepare')->willReturn($stmt);

        $result = authenticate_user($pdo, 'test_user', 'correct_password');
        $this->assertIsArray($result);
        $this->assertEquals('test_user', $result['username']);
    }

    public function testCheckLoginRateLimitReturnsNullWhenNotRateLimited(): void
    {
        $now = time();
        $this->assertNull(check_login_rate_limit($this->pdo, '127.0.0.1', 'john_doe', $now));

        // Also test with attempts below threshold using distinct identifiers
        $stmt = $this->pdo->prepare('INSERT INTO login_attempts (ip_address, attempts, last_attempt) VALUES (?, ?, ?)');
        $stmt->execute(['10.0.0.1', 4, $now]);
        $stmt->execute(['user:jane_doe', 4, $now]);

        $this->assertNull(check_login_rate_limit($this->pdo, '10.0.0.1', 'jane_doe', $now));
    }

    public function testCheckLoginRateLimitReturnsErrorWhenIpRateLimited(): void
    {
        $now = time();
        $stmt = $this->pdo->prepare('INSERT INTO login_attempts (ip_address, attempts, last_attempt) VALUES (?, ?, ?)');
        $stmt->execute(['127.0.0.1', 5, $now]);

        $result = check_login_rate_limit($this->pdo, '127.0.0.1', 'john_doe', $now);
        $this->assertEquals('Too many failed login attempts. Please try again later.', $result);
    }

    public function testCheckLoginRateLimitReturnsErrorWhenUserRateLimited(): void
    {
        $now = time();
        $stmt = $this->pdo->prepare('INSERT INTO login_attempts (ip_address, attempts, last_attempt) VALUES (?, ?, ?)');
        $stmt->execute(['user:john_doe', 5, $now]);

        $result = check_login_rate_limit($this->pdo, '127.0.0.1', 'john_doe', $now);
        $this->assertEquals('Too many failed login attempts. Please try again later.', $result);
    }

    public function testCheckLoginRateLimitReturnsNullWhenAttemptsExpired(): void
    {
        $now = time();
        $old_time = $now - 301;
        $stmt = $this->pdo->prepare('INSERT INTO login_attempts (ip_address, attempts, last_attempt) VALUES (?, ?, ?)');
        $stmt->execute(['127.0.0.1', 5, $old_time]);
        $stmt->execute(['user:john_doe', 5, $old_time]);

        $result = check_login_rate_limit($this->pdo, '127.0.0.1', 'john_doe', $now);
        $this->assertNull($result);
    }

    public function testHandleAuthenticatedSessionStartsSessionIfNoneActive(): void
    {
        if (session_status() === PHP_SESSION_ACTIVE) {
            session_write_close();
        }

        $user = [
            'id' => 999,
            'username' => 'test_session',
            'role' => 'user',
            'mfa_enabled' => 0
        ];

        $redirectedTo = null;
        handle_authenticated_session($user, function (string $location) use (&$redirectedTo) {
            $redirectedTo = $location;
        });

        $this->assertEquals(PHP_SESSION_ACTIVE, session_status());
        $this->assertEquals(999, $_SESSION['user_id']);
        $this->assertEquals('index.php', $redirectedTo);
    }

    public function testHandleAuthenticatedSessionWithMfaEnabledSetsPendingUserIdAndRedirectsToMfaVerify(): void
    {
        if (session_status() === PHP_SESSION_NONE) {
            @session_start();
        }
        $_SESSION = [];

        $user = [
            'id' => 101,
            'username' => 'mfa_user',
            'role' => 'user',
            'mfa_enabled' => 1
        ];

        $redirectedTo = null;
        handle_authenticated_session($user, function (string $location) use (&$redirectedTo) {
            $redirectedTo = $location;
        });

        $this->assertEquals(101, $_SESSION['pending_user_id'] ?? null);
        $this->assertArrayNotHasKey('user_id', $_SESSION);
        $this->assertArrayNotHasKey('username', $_SESSION);
        $this->assertArrayNotHasKey('role', $_SESSION);
        $this->assertEquals('mfa_verify.php', $redirectedTo);
    }

    public function testHandleAuthenticatedSessionWithMfaDisabledSetsSessionVariablesAndRedirectsToIndex(): void
    {
        if (session_status() === PHP_SESSION_NONE) {
            @session_start();
        }
        $_SESSION = [];

        $user = [
            'id' => 202,
            'username' => 'regular_user',
            'role' => 'admin',
            'mfa_enabled' => 0
        ];

        $redirectedTo = null;
        handle_authenticated_session($user, function (string $location) use (&$redirectedTo) {
            $redirectedTo = $location;
        });

        $this->assertEquals(202, $_SESSION['user_id'] ?? null);
        $this->assertEquals('regular_user', $_SESSION['username'] ?? null);
        $this->assertEquals('admin', $_SESSION['role'] ?? null);
        $this->assertArrayNotHasKey('pending_user_id', $_SESSION);
        $this->assertEquals('index.php', $redirectedTo);
    }

    public function testHandleAuthenticatedSessionDefaultHandlerExits(): void
    {
        $code = sprintf('
            session_start();
            $_ENV["DB_HOST"] = "127.0.0.1";
            $_ENV["DB_NAME"] = "test";
            $_ENV["DB_USER"] = "test";
            $_ENV["DB_PASS"] = "test";
            ini_set("display_errors", "0");
            ini_set("log_errors", "1");
            ini_set("error_log", sys_get_temp_dir() . "/php_test_errors.log");

            try {
                ob_start();
                require %s;
                ob_end_clean();
            } catch (\Throwable $e) {
                ob_end_clean();
            }

            $user = ["id" => 303, "username" => "default_user", "role" => "user", "mfa_enabled" => 0];
            handle_authenticated_session($user);
            echo "SHOULD_NOT_BE_REACHED";
        ', var_export(__DIR__ . '/../login.php', true));

        $descriptors = [
            0 => ['pipe', 'r'],
            1 => ['pipe', 'w'],
            2 => ['pipe', 'w'],
        ];

        $cmd = sprintf('%s -d variables_order=EGPCS -r %s', escapeshellarg(PHP_BINARY), escapeshellarg($code));
        $process = proc_open($cmd, $descriptors, $pipes);
        $stdout = stream_get_contents($pipes[1]);
        fclose($pipes[0]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        $returnCode = proc_close($process);

        $this->assertEquals(0, $returnCode);
        $this->assertStringNotContainsString('SHOULD_NOT_BE_REACHED', $stdout);
    }

    public function testLoginPostWithInvalidCsrfTokenRendersErrorMessage(): void
    {
        $code = sprintf('
            $_SERVER["REQUEST_METHOD"] = "POST";
            $_POST = ["csrf_token" => "invalid_csrf_token_value", "username" => "testuser", "password" => "password123"];
            $_ENV["DB_HOST"] = "127.0.0.1";
            $_ENV["DB_NAME"] = "test";
            $_ENV["DB_USER"] = "test";
            $_ENV["DB_PASS"] = "test";
            ini_set("display_errors", "0");
            ini_set("log_errors", "1");
            ini_set("error_log", sys_get_temp_dir() . "/php_test_errors.log");

            ob_start();
            require %s;
            $output = ob_get_clean();

            echo $output;
        ', var_export(__DIR__ . '/../login.php', true));

        $descriptors = [
            0 => ['pipe', 'r'],
            1 => ['pipe', 'w'],
            2 => ['pipe', 'w'],
        ];

        $cmd = sprintf('%s -d variables_order=EGPCS -r %s', escapeshellarg(PHP_BINARY), escapeshellarg($code));
        $process = proc_open($cmd, $descriptors, $pipes);
        $stdout = stream_get_contents($pipes[1]);
        fclose($pipes[0]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        $returnCode = proc_close($process);

        $this->assertEquals(0, $returnCode);
        $this->assertStringContainsString('Invalid CSRF token. Please refresh the page and try again.', $stdout);
    }

    public function testLoginPostWithMissingCsrfTokenRendersErrorMessage(): void
    {
        $code = sprintf('
            $_SERVER["REQUEST_METHOD"] = "POST";
            $_POST = ["username" => "testuser", "password" => "password123"];
            $_ENV["DB_HOST"] = "127.0.0.1";
            $_ENV["DB_NAME"] = "test";
            $_ENV["DB_USER"] = "test";
            $_ENV["DB_PASS"] = "test";
            ini_set("display_errors", "0");
            ini_set("log_errors", "1");
            ini_set("error_log", sys_get_temp_dir() . "/php_test_errors.log");

            ob_start();
            require %s;
            $output = ob_get_clean();

            echo $output;
        ', var_export(__DIR__ . '/../login.php', true));

        $descriptors = [
            0 => ['pipe', 'r'],
            1 => ['pipe', 'w'],
            2 => ['pipe', 'w'],
        ];

        $cmd = sprintf('%s -d variables_order=EGPCS -r %s', escapeshellarg(PHP_BINARY), escapeshellarg($code));
        $process = proc_open($cmd, $descriptors, $pipes);
        $stdout = stream_get_contents($pipes[1]);
        fclose($pipes[0]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        $returnCode = proc_close($process);

        $this->assertEquals(0, $returnCode);
        $this->assertStringContainsString('Invalid CSRF token. Please refresh the page and try again.', $stdout);
    }

    public function testHandleLoginRequestReturnsErrorOnEmptyUsername(): void
    {
        $_POST['username'] = '';
        $_POST['password'] = 'password123';

        $result = handle_login_request($this->pdo);
        $this->assertEquals('Username and password are required.', $result);
    }

    public function testHandleLoginRequestReturnsErrorOnLongUsername(): void
    {
        $_POST['username'] = str_repeat('a', 251);
        $_POST['password'] = 'password123';

        $result = handle_login_request($this->pdo);
        $this->assertEquals('Invalid credentials.', $result);
    }

    public function testHandleLoginRequestReturnsErrorOnLongPassword(): void
    {
        $_POST['username'] = 'john_doe';
        $_POST['password'] = str_repeat('a', 73);

        $result = handle_login_request($this->pdo);
        $this->assertEquals('Invalid credentials.', $result);
    }

    public function testHandleLoginRequestReturnsErrorOnEmptyPassword(): void
    {
        $_POST['username'] = 'john_doe';
        $_POST['password'] = '';

        $result = handle_login_request($this->pdo);
        $this->assertEquals('Username and password are required.', $result);
    }

    public function testHandleLoginRequestReturnsErrorOnMissingBoth(): void
    {
        $_POST = [];

        $result = handle_login_request($this->pdo);
        $this->assertEquals('Username and password are required.', $result);
    }

    public function testHandleLoginRequestReturnsErrorOnWhitespaceUsername(): void
    {
        $_POST['username'] = '   ';
        $_POST['password'] = 'password123';

        $result = handle_login_request($this->pdo);
        $this->assertEquals('Username and password are required.', $result);
    }

    public function testHandleLoginRequestReturnsErrorWhenRateLimited(): void
    {
        $now = time();
        $stmt = $this->pdo->prepare('INSERT INTO login_attempts (ip_address, attempts, last_attempt) VALUES (?, ?, ?)');
        $stmt->execute(['127.0.0.1', 5, $now]);

        $_POST['username'] = 'john_doe';
        $_POST['password'] = 'password123';

        $result = handle_login_request($this->pdo);
        $this->assertEquals('Too many failed login attempts. Please try again later.', $result);
    }

    public function testHandleLoginRequestReturnsInvalidCredentialsForNonExistentUser(): void
    {
        $_POST['username'] = 'non_existent_user';
        $_POST['password'] = 'password123';

        $result = handle_login_request($this->pdo);
        $this->assertEquals('Invalid credentials.', $result);

        $stmt = $this->pdo->prepare('SELECT attempts FROM login_attempts WHERE ip_address = ?');
        $stmt->execute(['127.0.0.1']);
        $this->assertEquals(1, (int)$stmt->fetchColumn());

        $stmt->execute(['user:non_existent_user']);
        $this->assertEquals(1, (int)$stmt->fetchColumn());
    }

    public function testHandleLoginRequestReturnsInvalidCredentialsForWrongPassword(): void
    {
        $hash = password_hash('correct_password', PASSWORD_BCRYPT);
        $stmt = $this->pdo->prepare('INSERT INTO users (username, password) VALUES (?, ?)');
        $stmt->execute(['valid_user', $hash]);

        $_POST['username'] = 'valid_user';
        $_POST['password'] = 'wrong_password';

        $result = handle_login_request($this->pdo);
        $this->assertEquals('Invalid credentials.', $result);

        $stmt = $this->pdo->prepare('SELECT attempts FROM login_attempts WHERE ip_address = ?');
        $stmt->execute(['127.0.0.1']);
        $this->assertEquals(1, (int)$stmt->fetchColumn());

        $stmt->execute(['user:valid_user']);
        $this->assertEquals(1, (int)$stmt->fetchColumn());
    }

    public function testHandleLoginRequestDoesNotIncrementAttemptsOnMissingFields(): void
    {
        $_POST['username'] = '';
        $_POST['password'] = 'password123';

        handle_login_request($this->pdo);

        $stmt = $this->pdo->query('SELECT COUNT(*) FROM login_attempts');
        $this->assertEquals(0, (int)$stmt->fetchColumn());
    }

    public function testLoginWithInvalidCsrfTokenDisplaysErrorMessage(): void
    {
        $code = sprintf('
            session_start();
            $_SERVER["REQUEST_METHOD"] = "POST";
            $_POST = ["csrf_token" => "invalid_token_value", "username" => "testuser", "password" => "password123"];
            $_SERVER["REMOTE_ADDR"] = "127.0.0.1";
            $_ENV["DB_HOST"] = "127.0.0.1";
            $_ENV["DB_NAME"] = "test";
            $_ENV["DB_USER"] = "test";
            $_ENV["DB_PASS"] = "test";
            ini_set("display_errors", "0");
            ini_set("log_errors", "1");
            ini_set("error_log", sys_get_temp_dir() . "/php_test_errors.log");

            require %s;
        ', var_export(__DIR__ . '/../login.php', true));

        $cmd = sprintf('%s -d variables_order=EGPCS -r %s', escapeshellarg(PHP_BINARY), escapeshellarg($code));
        $output = [];
        exec($cmd, $output);
        $result = implode("\n", $output);

        $this->assertStringContainsString('Invalid CSRF token. Please refresh the page and try again.', $result);
    }

    public function testLoginWithMissingCsrfTokenDisplaysErrorMessage(): void
    {
        $code = sprintf('
            session_start();
            $_SERVER["REQUEST_METHOD"] = "POST";
            $_POST = ["username" => "testuser", "password" => "password123"];
            $_SERVER["REMOTE_ADDR"] = "127.0.0.1";
            $_ENV["DB_HOST"] = "127.0.0.1";
            $_ENV["DB_NAME"] = "test";
            $_ENV["DB_USER"] = "test";
            $_ENV["DB_PASS"] = "test";
            ini_set("display_errors", "0");
            ini_set("log_errors", "1");
            ini_set("error_log", sys_get_temp_dir() . "/php_test_errors.log");

            require %s;
        ', var_export(__DIR__ . '/../login.php', true));

        $cmd = sprintf('%s -d variables_order=EGPCS -r %s', escapeshellarg(PHP_BINARY), escapeshellarg($code));
        $output = [];
        exec($cmd, $output);
        $result = implode("\n", $output);

        $this->assertStringContainsString('Invalid CSRF token. Please refresh the page and try again.', $result);
    }

    public function testLoginPostWithDatabaseErrorDisplaysErrorMessage(): void
    {
        $code = sprintf('
            require_once %s;
            require_once %s;

            $_SESSION["csrf_token"] = $_SESSION["csrf_token"] ?? "valid_token";
            $_SERVER["REQUEST_METHOD"] = "POST";
            $_POST = ["csrf_token" => $_SESSION["csrf_token"], "username" => "testuser", "password" => "password123"];
            $_SERVER["REMOTE_ADDR"] = "127.0.0.1";
            $_ENV["DB_HOST"] = "127.0.0.1";
            $_ENV["DB_NAME"] = "test";
            $_ENV["DB_USER"] = "test";
            $_ENV["DB_PASS"] = "test";
            ini_set("display_errors", "0");
            ini_set("log_errors", "1");
            ini_set("error_log", sys_get_temp_dir() . "/php_test_errors.log");

            $pdo = new PDO("sqlite::memory:");
            $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

            ob_start();
            require %s;
            $output = ob_get_clean();

            echo $output;
        ',
            var_export(__DIR__ . '/../session.php', true),
            var_export(__DIR__ . '/../csrf.php', true),
            var_export(__DIR__ . '/../login.php', true)
        );

        $cmd = sprintf('%s -d variables_order=EGPCS -r %s', escapeshellarg(PHP_BINARY), escapeshellarg($code));
        $output = [];
        exec($cmd, $output);
        $result = implode("\n", $output);

        $this->assertStringContainsString('A database error occurred. Please contact the administrator.', $result);
    }
}
