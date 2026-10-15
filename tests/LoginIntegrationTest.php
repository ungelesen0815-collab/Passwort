<?php
namespace Tests;

use PHPUnit\Framework\TestCase;
use GuzzleHttp\Client;
use GuzzleHttp\Cookie\CookieJar;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use PDO;

class TestCookieJar extends CookieJar {
    public function extractCookies(RequestInterface $request, ResponseInterface $response): void {
        parent::extractCookies($request, $response);
        foreach ($this->getIterator() as $cookie) {
            // Strip Secure flag so Guzzle sends the cookie over HTTP for our local test
            $cookie->setSecure(false);
        }
    }
}

class LoginIntegrationTest extends TestCase
{
    private static $pdo;
    private static $serverPid;
    private static $envBackup;

    public static function setUpBeforeClass(): void
    {
        // Setup isolated DB for testing
        $host = '127.0.0.1';
        $user = 'test_user';
        $pass = 'test_pass';

        $pdoRoot = new PDO("mysql:host=$host;charset=utf8mb4", $user, $pass, [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        ]);

        // Generate a random DB name to prevent collisions and avoid dropping real data
        $dbName = 'test_app_db_' . time() . '_' . rand(1000, 9999);
        $pdoRoot->exec("CREATE DATABASE `$dbName`");

        $dsn = "mysql:host=$host;dbname=$dbName;charset=utf8mb4";
        self::$pdo = new PDO($dsn, $user, $pass, [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        ]);

        self::$pdo->exec("CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(255) UNIQUE NOT NULL,
            password VARCHAR(255) NOT NULL,
            role ENUM('admin', 'user') NOT NULL DEFAULT 'user',
            mfa_secret VARCHAR(255) DEFAULT NULL,
            mfa_enabled TINYINT(1) DEFAULT 0
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;");

        self::$pdo->exec("CREATE TABLE IF NOT EXISTS login_attempts (
            id INT AUTO_INCREMENT PRIMARY KEY,
            ip_address VARCHAR(45) UNIQUE NOT NULL,
            attempts INT NOT NULL DEFAULT 1,
            last_attempt INT NOT NULL
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;");

        // Setup temporary .env file for the tested application
        $envPath = __DIR__ . '/../.env';
        if (file_exists($envPath)) {
            self::$envBackup = file_get_contents($envPath);
        }

        $testEnv = "DB_HOST=$host\nDB_NAME=$dbName\nDB_USER=$user\nDB_PASS=$pass\n";
        file_put_contents($envPath, $testEnv);

        $cmd = sprintf('php -d display_errors=1 -S 127.0.0.1:8000 -t %s >/dev/null 2>&1 & echo $!', escapeshellarg(__DIR__ . '/../'));
        self::$serverPid = exec($cmd);
        sleep(1); // allow time for the server to spin up
    }

    public static function tearDownAfterClass(): void
    {
        if (self::$serverPid) {
            exec('kill ' . self::$serverPid);
        }

        // Drop the test database
        if (self::$pdo) {
            $dbName = self::$pdo->query("SELECT DATABASE()")->fetchColumn();
            self::$pdo->exec("DROP DATABASE IF EXISTS `$dbName`");
        }

        // Restore .env file
        $envPath = __DIR__ . '/../.env';
        if (self::$envBackup !== null) {
            file_put_contents($envPath, self::$envBackup);
        } else {
            @unlink($envPath);
        }
    }

    protected function setUp(): void
    {
        self::$pdo->exec('TRUNCATE TABLE users');
        self::$pdo->exec('TRUNCATE TABLE login_attempts');

        $stmt = self::$pdo->prepare('INSERT INTO users (username, password, role, mfa_enabled) VALUES (?, ?, ?, ?)');
        $stmt->execute(['testuser', password_hash('password123', PASSWORD_BCRYPT), 'user', 0]);
        $stmt->execute(['mfauser', password_hash('password123', PASSWORD_BCRYPT), 'user', 1]);
    }

    private function getCsrfToken($client)
    {
        $response = $client->get('/login.php');
        $body = (string) $response->getBody();
        if (preg_match('/name="csrf_token" value="([^"]+)"/', $body, $matches)) {
            return $matches[1];
        }
        return '';
    }

    public function testSuccessfulLogin()
    {
        $jar = new TestCookieJar();
        $client = new Client([
            'base_uri' => 'http://127.0.0.1:8000',
            'cookies' => $jar,
            'allow_redirects' => false
        ]);

        $csrfToken = $this->getCsrfToken($client);

        $response = $client->post('/login.php', [
            'form_params' => [
                'csrf_token' => $csrfToken,
                'username' => 'testuser',
                'password' => 'password123'
            ]
        ]);

        $this->assertEquals(302, $response->getStatusCode());
        $this->assertEquals('index.php', $response->getHeaderLine('Location'));
    }

    public function testInvalidCredentials()
    {
        $jar = new TestCookieJar();
        $client = new Client([
            'base_uri' => 'http://127.0.0.1:8000',
            'cookies' => $jar,
            'allow_redirects' => false
        ]);

        $csrfToken = $this->getCsrfToken($client);

        $response = $client->post('/login.php', [
            'form_params' => [
                'csrf_token' => $csrfToken,
                'username' => 'testuser',
                'password' => 'wrongpass'
            ]
        ]);

        $this->assertEquals(200, $response->getStatusCode());
        $body = (string) $response->getBody();
        $this->assertStringContainsString('Invalid credentials.', $body);
    }

    public function testRateLimiting()
    {
        $jar = new TestCookieJar();
        $client = new Client([
            'base_uri' => 'http://127.0.0.1:8000',
            'cookies' => $jar,
            'allow_redirects' => false
        ]);

        $csrfToken = $this->getCsrfToken($client);

        for ($i = 0; $i < 5; $i++) {
            $client->post('/login.php', [
                'form_params' => [
                    'csrf_token' => $csrfToken,
                    'username' => 'testuser',
                    'password' => 'wrongpass'
                ]
            ]);
        }

        $response = $client->post('/login.php', [
            'form_params' => [
                'csrf_token' => $csrfToken,
                'username' => 'testuser',
                'password' => 'wrongpass'
            ]
        ]);

        $this->assertEquals(200, $response->getStatusCode());
        $body = (string) $response->getBody();
        $this->assertStringContainsString('Too many failed login attempts.', $body);

        // Even with correct credentials, the rate limit is evaluated before authentication,
        // so it should still be rate limited.
        $response = $client->post('/login.php', [
            'form_params' => [
                'csrf_token' => $csrfToken,
                'username' => 'testuser',
                'password' => 'password123'
            ]
        ]);
        $this->assertEquals(200, $response->getStatusCode());
        $body = (string) $response->getBody();
        $this->assertStringContainsString('Too many failed login attempts.', $body);

        // Simulate wait to bypass rate limit
        self::$pdo->exec("UPDATE login_attempts SET last_attempt = 0");

        // Now authentication should succeed, and because the time expired, attempts will naturally reset to 0 *before* evaluating login success.
        $response = $client->post('/login.php', [
            'form_params' => [
                'csrf_token' => $csrfToken,
                'username' => 'testuser',
                'password' => 'password123'
            ]
        ]);
        $this->assertEquals(302, $response->getStatusCode());
        $this->assertEquals('index.php', $response->getHeaderLine('Location'));

        // Assert that the login attempts tracking rows were cleared after a successful login
        $stmt = self::$pdo->query('SELECT COUNT(*) FROM login_attempts');
        $count = $stmt->fetchColumn();
        $this->assertEquals(0, $count, 'Login attempts tracking rows should be cleared upon successful login');
    }

    public function testSuccessfulLoginClearsAttempts()
    {
        $jar = new TestCookieJar();
        $client = new Client([
            'base_uri' => 'http://127.0.0.1:8000',
            'cookies' => $jar,
            'allow_redirects' => false
        ]);

        $csrfToken = $this->getCsrfToken($client);

        // Make 3 failed attempts
        for ($i = 0; $i < 3; $i++) {
            $client->post('/login.php', [
                'form_params' => [
                    'csrf_token' => $csrfToken,
                    'username' => 'testuser',
                    'password' => 'wrongpass'
                ]
            ]);
        }

        $stmt = self::$pdo->prepare('SELECT attempts FROM login_attempts WHERE ip_address = ?');
        $stmt->execute(['127.0.0.1']);
        $this->assertEquals(3, $stmt->fetchColumn(), 'Failed attempts should be incremented to 3');

        // Successful login
        $response = $client->post('/login.php', [
            'form_params' => [
                'csrf_token' => $csrfToken,
                'username' => 'testuser',
                'password' => 'password123'
            ]
        ]);
        $this->assertEquals(302, $response->getStatusCode());

        // Verify attempts are cleared after successful login
        $stmt->execute(['127.0.0.1']);
        $this->assertFalse($stmt->fetchColumn(), 'Attempts for IP should be cleared on successful login');

        $stmt->execute(['user:testuser']);
        $this->assertFalse($stmt->fetchColumn(), 'Attempts for user should be cleared on successful login');
    }

    public function testSuccessfulLoginDoesNotIncrementAttempts()
    {
        $jar = new TestCookieJar();
        $client = new Client([
            'base_uri' => 'http://127.0.0.1:8000',
            'cookies' => $jar,
            'allow_redirects' => false
        ]);

        $csrfToken = $this->getCsrfToken($client);

        $response = $client->post('/login.php', [
            'form_params' => [
                'csrf_token' => $csrfToken,
                'username' => 'testuser',
                'password' => 'password123'
            ]
        ]);
        $this->assertEquals(302, $response->getStatusCode());

        $stmt = self::$pdo->query('SELECT COUNT(*) FROM login_attempts');
        $this->assertEquals(0, $stmt->fetchColumn(), 'Successful login should not create attempt records');
    }

    public function testMfaRedirect()
    {
        $jar = new TestCookieJar();
        $client = new Client([
            'base_uri' => 'http://127.0.0.1:8000',
            'cookies' => $jar,
            'allow_redirects' => false
        ]);

        $csrfToken = $this->getCsrfToken($client);

        $response = $client->post('/login.php', [
            'form_params' => [
                'csrf_token' => $csrfToken,
                'username' => 'mfauser',
                'password' => 'password123'
            ]
        ]);

        $this->assertEquals(302, $response->getStatusCode());
        $this->assertEquals('mfa_verify.php', $response->getHeaderLine('Location'));
    }

    public function testPasswordTooLong()
    {
        $jar = new TestCookieJar();
        $client = new Client([
            'base_uri' => 'http://127.0.0.1:8000',
            'cookies' => $jar,
            'allow_redirects' => false
        ]);

        $csrfToken = $this->getCsrfToken($client);

        $oversizedPassword = str_repeat('a', 73); // More than 72 characters

        $response = $client->post('/login.php', [
            'form_params' => [
                'csrf_token' => $csrfToken,
                'username' => 'testuser',
                'password' => $oversizedPassword
            ]
        ]);

        $this->assertEquals(200, $response->getStatusCode());
        $body = (string) $response->getBody();
        $this->assertStringContainsString('Invalid credentials.', $body);
    }

    public function testMissingFields()
    {
        $jar = new TestCookieJar();
        $client = new Client([
            'base_uri' => 'http://127.0.0.1:8000',
            'cookies' => $jar,
            'allow_redirects' => false
        ]);

        $csrfToken = $this->getCsrfToken($client);

        $response = $client->post('/login.php', [
            'form_params' => [
                'csrf_token' => $csrfToken,
                'username' => '',
                'password' => ''
            ]
        ]);

        $this->assertEquals(200, $response->getStatusCode());
        $body = (string) $response->getBody();
        $this->assertStringContainsString('Username and password are required.', $body);
    }
    public function testMissingCsrfToken()
    {
        $jar = new TestCookieJar();
        $client = new Client([
            'base_uri' => 'http://127.0.0.1:8000',
            'cookies' => $jar,
            'allow_redirects' => false
        ]);

        $this->getCsrfToken($client);

        $response = $client->post('/login.php', [
            'http_errors' => false,
            'form_params' => [
                'username' => 'testuser',
                'password' => 'password123'
            ]
        ]);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertStringContainsString('Invalid CSRF token', (string)$response->getBody());
    }

    public function testMissingTableGracefulError()
    {
        $jar = new TestCookieJar();
        $client = new Client([
            'base_uri' => 'http://127.0.0.1:8000',
            'cookies' => $jar,
            'allow_redirects' => false
        ]);

        $csrfToken = $this->getCsrfToken($client);

        // Temporarily drop the table to simulate missing table error
        self::$pdo->exec('DROP TABLE IF EXISTS login_attempts');

        $response = $client->post('/login.php', [
            'http_errors' => false,
            'form_params' => [
                'csrf_token' => $csrfToken,
                'username' => 'testuser',
                'password' => 'password123'
            ]
        ]);

        $this->assertEquals(200, $response->getStatusCode());
        $body = (string) $response->getBody();
        $this->assertStringContainsString('A database error occurred. Please contact the administrator.', $body);

        // Recreate the table to restore the state for other tests or tear down
        self::$pdo->exec("CREATE TABLE IF NOT EXISTS login_attempts (
            id INT AUTO_INCREMENT PRIMARY KEY,
            ip_address VARCHAR(45) UNIQUE NOT NULL,
            attempts INT NOT NULL DEFAULT 1,
            last_attempt INT NOT NULL
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;");
    }

    public function testMfaRateLimit()
    {
        $jar = new TestCookieJar();
        $client = new Client([
            'base_uri' => 'http://127.0.0.1:8000',
            'cookies' => $jar,
            'allow_redirects' => false
        ]);

        $csrfToken = $this->getCsrfToken($client);

        for ($i = 0; $i < 3; $i++) {
            $client->post('/login.php', [
                'form_params' => [
                    'csrf_token' => $csrfToken,
                    'username' => 'testuser',
                    'password' => 'wrongpass'
                ]
            ]);
        }

        self::$pdo->exec("UPDATE users SET mfa_secret = 'AABBCCDDEE', mfa_enabled = 1 WHERE username = 'mfauser'");

        $csrfToken = $this->getCsrfToken($client);

        $response = $client->post('/login.php', [
            'form_params' => [
                'csrf_token' => $csrfToken,
                'username' => 'mfauser',
                'password' => 'password123'
            ]
        ]);

        $this->assertEquals(302, $response->getStatusCode());
        $this->assertEquals('mfa_verify.php', $response->getHeaderLine('Location'));

        $response = $client->get('/mfa_verify.php');
        $mfaBody = (string) $response->getBody();
        preg_match('/name="csrf_token" value="([^"]+)"/', $mfaBody, $matches);
        $mfaCsrfToken = $matches[1] ?? '';

        for ($i = 1; $i <= 5; $i++) {
            $response = $client->post('/mfa_verify.php', [
                'form_params' => [
                    'csrf_token' => $mfaCsrfToken,
                    'mfa_code' => '00000' . $i
                ]
            ]);
        }

        // The 6th attempt should fail due to rate limit and redirect to login
        $response = $client->post('/mfa_verify.php', [
            'form_params' => [
                'csrf_token' => $mfaCsrfToken,
                'mfa_code' => '000006'
            ]
        ]);

        $this->assertEquals(302, $response->getStatusCode());
        $this->assertEquals('login.php', $response->getHeaderLine('Location'));

        // Assert that the attempts were not reset to 0 after successful login
        $stmt = self::$pdo->prepare('SELECT attempts FROM login_attempts WHERE ip_address = ?');
        $stmt->execute(['127.0.0.1']);
        $attempts = $stmt->fetchColumn();
        $this->assertGreaterThanOrEqual(5, $attempts, 'Attempts should be greater than or equal to 5 due to failures');
    }

    public function testLogoutClearsSessionCookie()
    {
        $jar = new TestCookieJar();
        $client = new Client([
            'base_uri' => 'http://127.0.0.1:8000',
            'cookies' => $jar,
            'http_errors' => false,
            'allow_redirects' => false // Keep this false so we can inspect cookies/headers before redirect
        ]);

        // 1. Get login page to get CSRF
        $response = $client->get('/login.php');
        $body = (string)$response->getBody();
        preg_match('/name="csrf_token" value="([^"]+)"/', $body, $matches);
        $this->assertNotEmpty($matches, 'CSRF token not found');
        $csrfToken = $matches[1];

        // 2. Perform login
        $response = $client->post('/login.php', [
            'form_params' => [
                'csrf_token' => $csrfToken,
                'username' => 'testuser',
                'password' => 'password123'
            ]
        ]);
        $this->assertEquals(302, $response->getStatusCode());

        // 3. Get index page to get CSRF for logout
        $response = $client->get('/index.php');
        $body = (string)$response->getBody();
        preg_match('/action="logout.php".*?name="csrf_token" value="([^"]+)"/s', $body, $matches);
        $this->assertNotEmpty($matches, 'CSRF token for logout not found');
        $logoutCsrfToken = $matches[1];

        // 4. Perform logout
        $response = $client->post('/logout.php', [
            'form_params' => [
                'csrf_token' => $logoutCsrfToken
            ]
        ]);

        $this->assertEquals(302, $response->getStatusCode());

        $setCookieHeaders = $response->getHeader('Set-Cookie');
        $phpsessidCleared = false;
        foreach ($setCookieHeaders as $header) {
            if (strpos($header, 'PHPSESSID=deleted') !== false || (strpos($header, 'PHPSESSID=') !== false && strpos($header, 'expires=') !== false && strpos(strtolower($header), '1970') !== false)) {
                $phpsessidCleared = true;
                break;
            }
        }

        $this->assertTrue($phpsessidCleared, 'Session cookie (PHPSESSID) should be cleared upon logout');
    }

    public function testLogoutMissingCsrfToken()
    {
        $jar = new TestCookieJar();
        $client = new Client([
            'base_uri' => 'http://127.0.0.1:8000',
            'cookies' => $jar,
            'http_errors' => false,
            'allow_redirects' => false
        ]);

        $response = $client->post('/logout.php', [
            'form_params' => []
        ]);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertStringContainsString('Invalid CSRF token.', (string)$response->getBody());
    }

    public function testLogoutInvalidCsrfToken()
    {
        $jar = new TestCookieJar();
        $client = new Client([
            'base_uri' => 'http://127.0.0.1:8000',
            'cookies' => $jar,
            'http_errors' => false,
            'allow_redirects' => false
        ]);

        $response = $client->post('/logout.php', [
            'form_params' => [
                'csrf_token' => 'invalid_csrf_token_value'
            ]
        ]);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertStringContainsString('Invalid CSRF token.', (string)$response->getBody());
    }

    public function testLogoutInvalidRequestMethod()
    {
        $jar = new TestCookieJar();
        $client = new Client([
            'base_uri' => 'http://127.0.0.1:8000',
            'cookies' => $jar,
            'http_errors' => false,
            'allow_redirects' => false
        ]);

        $response = $client->get('/logout.php');

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertStringContainsString('Invalid request method.', (string)$response->getBody());
    }

    public function testLoginRateLimitingBlocksIpRotation()
    {
        $jar = new TestCookieJar();
        $client = new Client([
            'base_uri' => 'http://127.0.0.1:8000',
            'cookies' => $jar,
            'http_errors' => false,
            'allow_redirects' => false
        ]);

        $csrfToken = $this->getCsrfToken($client);

        for ($i = 0; $i < 5; $i++) {
            $client->post('/login.php', [
                'form_params' => [
                    'csrf_token' => $csrfToken,
                    'username' => 'testuser',
                    'password' => 'wrongpass'
                ]
            ]);
        }

        // Simulate IP rotation by resetting the IP's login_attempts entry to 0 while user's remains 5
        self::$pdo->exec("DELETE FROM login_attempts WHERE ip_address = '127.0.0.1'");

        // Attempting login again should still be blocked due to user rate limit
        $response = $client->post('/login.php', [
            'form_params' => [
                'csrf_token' => $csrfToken,
                'username' => 'testuser',
                'password' => 'password123'
            ]
        ]);

        $this->assertEquals(200, $response->getStatusCode());
        $body = (string) $response->getBody();
        $this->assertStringContainsString('Too many failed login attempts. Please try again later.', $body);
    }

    public function testMfaRateLimitingBlocksIpRotation()
    {
        self::$pdo->exec("UPDATE users SET mfa_secret = 'AABBCCDDEE' WHERE username = 'mfauser'");

        $jar = new TestCookieJar();
        $client = new Client([
            'base_uri' => 'http://127.0.0.1:8000',
            'cookies' => $jar,
            'http_errors' => false,
            'allow_redirects' => false
        ]);

        $csrfToken = $this->getCsrfToken($client);

        $response = $client->post('/login.php', [
            'form_params' => [
                'csrf_token' => $csrfToken,
                'username' => 'mfauser',
                'password' => 'password123'
            ]
        ]);

        $this->assertEquals(302, $response->getStatusCode());
        $this->assertEquals('mfa_verify.php', $response->getHeaderLine('Location'));

        $response = $client->get('/mfa_verify.php');
        $mfaBody = (string) $response->getBody();
        preg_match('/name="csrf_token" value="([^"]+)"/', $mfaBody, $matches);
        $mfaCsrfToken = $matches[1] ?? '';

        for ($i = 1; $i <= 5; $i++) {
            $client->post('/mfa_verify.php', [
                'form_params' => [
                    'csrf_token' => $mfaCsrfToken,
                    'mfa_code' => '00000' . $i
                ]
            ]);
        }

        // Simulate IP rotation by resetting the IP's login_attempts entry to 0 while user's remains 5
        self::$pdo->exec("DELETE FROM login_attempts WHERE ip_address = '127.0.0.1'");

        // Attempting MFA verification again should still be blocked due to user rate limit
        $response = $client->post('/mfa_verify.php', [
            'form_params' => [
                'csrf_token' => $mfaCsrfToken,
                'mfa_code' => '000006'
            ]
        ]);

        $this->assertEquals(302, $response->getStatusCode());
        $this->assertEquals('login.php', $response->getHeaderLine('Location'));
    }

    public function testMfaVerifyInvalidCsrfToken()
    {
        self::$pdo->exec("UPDATE users SET mfa_secret = 'AABBCCDDEE' WHERE username = 'mfauser'");

        $jar = new TestCookieJar();
        $client = new Client([
            'base_uri' => 'http://127.0.0.1:8000',
            'cookies' => $jar,
            'http_errors' => false,
            'allow_redirects' => false
        ]);

        $csrfToken = $this->getCsrfToken($client);

        $response = $client->post('/login.php', [
            'form_params' => [
                'csrf_token' => $csrfToken,
                'username' => 'mfauser',
                'password' => 'password123'
            ]
        ]);

        $this->assertEquals(302, $response->getStatusCode());
        $this->assertEquals('mfa_verify.php', $response->getHeaderLine('Location'));

        $response = $client->post('/mfa_verify.php', [
            'form_params' => [
                'csrf_token' => 'invalid_csrf_token',
                'mfa_code' => '123456'
            ]
        ]);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertStringContainsString('Invalid CSRF token.', (string)$response->getBody());
    }

    public function testMfaVerifyMissingCsrfToken()
    {
        self::$pdo->exec("UPDATE users SET mfa_secret = 'AABBCCDDEE' WHERE username = 'mfauser'");

        $jar = new TestCookieJar();
        $client = new Client([
            'base_uri' => 'http://127.0.0.1:8000',
            'cookies' => $jar,
            'http_errors' => false,
            'allow_redirects' => false
        ]);

        $csrfToken = $this->getCsrfToken($client);

        $response = $client->post('/login.php', [
            'form_params' => [
                'csrf_token' => $csrfToken,
                'username' => 'mfauser',
                'password' => 'password123'
            ]
        ]);

        $this->assertEquals(302, $response->getStatusCode());
        $this->assertEquals('mfa_verify.php', $response->getHeaderLine('Location'));

        $response = $client->post('/mfa_verify.php', [
            'form_params' => [
                'mfa_code' => '123456'
            ]
        ]);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertStringContainsString('Invalid CSRF token.', (string)$response->getBody());
    }
}
