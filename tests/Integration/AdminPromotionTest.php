<?php
namespace Tests\Integration;

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
            $cookie->setSecure(false);
        }
    }
}

class AdminPromotionTest extends TestCase
{
    private static $pdo;
    private static $serverPid;
    private static $envBackup;

    public static function setUpBeforeClass(): void
    {
        $host = '127.0.0.1';
        $user = 'test_user';
        $pass = 'test_pass';

        $pdoRoot = new PDO("mysql:host=$host;charset=utf8mb4", $user, $pass, [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        ]);

        $dbName = 'test_admin_db_' . time() . '_' . rand(1000, 9999);
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

        $envPath = __DIR__ . '/../../.env';
        if (file_exists($envPath)) {
            self::$envBackup = file_get_contents($envPath);
        }

        $testEnv = "DB_HOST=$host\nDB_NAME=$dbName\nDB_USER=$user\nDB_PASS=$pass\n";
        file_put_contents($envPath, $testEnv);

        $cmd = sprintf('php -d display_errors=1 -S 127.0.0.1:8000 -t %s >/dev/null 2>&1 & echo $!', escapeshellarg(__DIR__ . '/../../'));
        self::$serverPid = exec($cmd);
        sleep(1);
    }

    public static function tearDownAfterClass(): void
    {
        if (self::$serverPid) {
            exec('kill ' . self::$serverPid);
        }

        if (self::$pdo) {
            $dbName = self::$pdo->query("SELECT DATABASE()")->fetchColumn();
            self::$pdo->exec("DROP DATABASE IF EXISTS `$dbName`");
        }

        $envPath = __DIR__ . '/../../.env';
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
        $stmt->execute(['adminuser', password_hash('password123', PASSWORD_BCRYPT), 'admin', 0]);
        $stmt->execute(['regularuser', password_hash('password123', PASSWORD_BCRYPT), 'user', 0]);
    }

    private function getLoginCsrfToken($client)
    {
        $response = $client->get('/login.php');
        $body = (string) $response->getBody();
        if (preg_match('/name="csrf_token" value="([^"]+)"/', $body, $matches)) {
            return $matches[1];
        }
        return '';
    }

    private function loginAsAdmin($client)
    {
        $csrfToken = $this->getLoginCsrfToken($client);
        $client->post('/login.php', [
            'form_params' => [
                'csrf_token' => $csrfToken,
                'username' => 'adminuser',
                'password' => 'password123'
            ]
        ]);
    }

    private function getAdminCsrfToken($client)
    {
        $response = $client->get('/admin.php');
        $body = (string) $response->getBody();
        if (preg_match('/name="csrf_token" value="([^"]+)"/', $body, $matches)) {
            return $matches[1];
        }
        return '';
    }

    public function testAdminCanPromoteUserToAdmin()
    {
        $jar = new TestCookieJar();
        $client = new Client([
            'base_uri' => 'http://127.0.0.1:8000',
            'cookies' => $jar,
            'allow_redirects' => false
        ]);

        $this->loginAsAdmin($client);
        $adminCsrfToken = $this->getAdminCsrfToken($client);

        $stmt = self::$pdo->prepare('SELECT id FROM users WHERE username = ?');
        $stmt->execute(['regularuser']);
        $regularUserId = $stmt->fetchColumn();

        $response = $client->post('/admin.php', [
            'form_params' => [
                'csrf_token' => $adminCsrfToken,
                'promote_id' => $regularUserId
            ]
        ]);

        $this->assertEquals(200, $response->getStatusCode());
        $body = (string) $response->getBody();
        $this->assertStringContainsString('User promoted to admin successfully.', $body);

        $stmt = self::$pdo->prepare('SELECT role FROM users WHERE id = ?');
        $stmt->execute([$regularUserId]);
        $role = $stmt->fetchColumn();
        $this->assertEquals('admin', $role);
    }

    public function testPromoteNonExistentOrAlreadyAdminUser()
    {
        $jar = new TestCookieJar();
        $client = new Client([
            'base_uri' => 'http://127.0.0.1:8000',
            'cookies' => $jar,
            'allow_redirects' => false
        ]);

        $this->loginAsAdmin($client);
        $adminCsrfToken = $this->getAdminCsrfToken($client);

        // Attempting to promote already-admin user
        $stmt = self::$pdo->prepare('SELECT id FROM users WHERE username = ?');
        $stmt->execute(['adminuser']);
        $adminUserId = $stmt->fetchColumn();

        $response = $client->post('/admin.php', [
            'form_params' => [
                'csrf_token' => $adminCsrfToken,
                'promote_id' => $adminUserId
            ]
        ]);

        $this->assertEquals(200, $response->getStatusCode());
        $body = (string) $response->getBody();
        $this->assertStringContainsString('Failed to promote user. User may already be an admin or does not exist.', $body);

        // Attempting to promote non-existent user ID
        $response = $client->post('/admin.php', [
            'form_params' => [
                'csrf_token' => $adminCsrfToken,
                'promote_id' => 999999
            ]
        ]);

        $this->assertEquals(200, $response->getStatusCode());
        $body = (string) $response->getBody();
        $this->assertStringContainsString('Failed to promote user. User may already be an admin or does not exist.', $body);
    }

    public function testPromoteWithInvalidCsrfToken()
    {
        $jar = new TestCookieJar();
        $client = new Client([
            'base_uri' => 'http://127.0.0.1:8000',
            'cookies' => $jar,
            'allow_redirects' => false
        ]);

        $this->loginAsAdmin($client);

        $response = $client->post('/admin.php', [
            'form_params' => [
                'csrf_token' => 'invalid_csrf_token',
                'promote_id' => 2
            ]
        ]);

        $this->assertEquals(200, $response->getStatusCode());
        $body = (string) $response->getBody();
        $this->assertStringContainsString('Invalid CSRF token. Please refresh the page and try again.', $body);
    }

    public function testNonAdminAccessRedirected()
    {
        $jar = new TestCookieJar();
        $client = new Client([
            'base_uri' => 'http://127.0.0.1:8000',
            'cookies' => $jar,
            'allow_redirects' => false
        ]);

        // Login as regular user (non-admin)
        $csrfToken = $this->getLoginCsrfToken($client);
        $client->post('/login.php', [
            'form_params' => [
                'csrf_token' => $csrfToken,
                'username' => 'regularuser',
                'password' => 'password123'
            ]
        ]);

        // Attempt to access admin.php
        $response = $client->get('/admin.php');
        $this->assertEquals(302, $response->getStatusCode());
        $this->assertEquals('index.php', $response->getHeaderLine('Location'));
    }

    public function testPromoteUserDatabaseError()
    {
        $jar = new TestCookieJar();
        $client = new Client([
            'base_uri' => 'http://127.0.0.1:8000',
            'cookies' => $jar,
            'allow_redirects' => false
        ]);

        $this->loginAsAdmin($client);
        $adminCsrfToken = $this->getAdminCsrfToken($client);

        $stmt = self::$pdo->prepare('SELECT id FROM users WHERE username = ?');
        $stmt->execute(['regularuser']);
        $regularUserId = $stmt->fetchColumn();

        self::$pdo->exec("CREATE TRIGGER fail_update BEFORE UPDATE ON users FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Simulated update failure'");

        try {
            $response = $client->post('/admin.php', [
                'form_params' => [
                    'csrf_token' => $adminCsrfToken,
                    'promote_id' => $regularUserId
                ]
            ]);

            $this->assertEquals(200, $response->getStatusCode());
            $body = (string) $response->getBody();
            $this->assertStringContainsString('Database error occurred while promoting user.', $body);
        } finally {
            self::$pdo->exec("DROP TRIGGER IF EXISTS fail_update");
        }
    }

    public function testAdminPageHandlesFetchDatabaseErrorGracefully()
    {
        $jar = new TestCookieJar();
        $client = new Client([
            'base_uri' => 'http://127.0.0.1:8000',
            'cookies' => $jar,
            'allow_redirects' => false
        ]);

        $this->loginAsAdmin($client);

        self::$pdo->exec("RENAME TABLE users TO users_hidden");

        try {
            $response = $client->get('/admin.php');
            $this->assertEquals(200, $response->getStatusCode());
            $body = (string) $response->getBody();
            $this->assertStringContainsString('A database error occurred. Please contact the administrator.', $body);
            $this->assertStringContainsString('Admin Panel', $body);
        } finally {
            self::$pdo->exec("RENAME TABLE users_hidden TO users");
        }
    }
}
