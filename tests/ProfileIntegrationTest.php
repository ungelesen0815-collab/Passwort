<?php
namespace Tests;

use PHPUnit\Framework\TestCase;
use GuzzleHttp\Client;
use GuzzleHttp\Cookie\CookieJar;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use PDO;

class TestCookieJarForProfile extends CookieJar {
    public function extractCookies(RequestInterface $request, ResponseInterface $response): void {
        parent::extractCookies($request, $response);
        foreach ($this->getIterator() as $cookie) {
            $cookie->setSecure(false);
        }
    }
}

class ProfileIntegrationTest extends TestCase
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

        $dbName = 'test_profile_db_' . time() . '_' . rand(1000, 9999);
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
            mfa_enabled TINYINT(1) DEFAULT 0,
            full_name VARCHAR(255) DEFAULT NULL,
            personal_details TEXT DEFAULT NULL,
            profile_picture VARCHAR(255) DEFAULT NULL
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;");

        self::$pdo->exec("CREATE TABLE IF NOT EXISTS login_attempts (
            ip_address VARCHAR(45) PRIMARY KEY,
            attempts INT NOT NULL DEFAULT 0,
            last_attempt INT NOT NULL
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;");

        $envPath = __DIR__ . '/../.env';
        if (file_exists($envPath)) {
            self::$envBackup = file_get_contents($envPath);
        }

        $testEnv = "DB_HOST=$host\nDB_NAME=$dbName\nDB_USER=$user\nDB_PASS=$pass\n";
        file_put_contents($envPath, $testEnv);

        $cmd = sprintf('php -d display_errors=1 -d upload_max_filesize=10M -d post_max_size=10M -S 127.0.0.1:8001 -t %s >/dev/null 2>&1 & echo $!', escapeshellarg(__DIR__ . '/../'));
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

        $stmt = self::$pdo->prepare('INSERT INTO users (username, password, role, mfa_enabled, full_name, personal_details, profile_picture) VALUES (?, ?, ?, ?, ?, ?, ?)');
        $stmt->execute(['testuser', password_hash('password123', PASSWORD_BCRYPT), 'user', 0, 'Initial Name', 'Initial Details', null]);
    }

    private function getAuthenticatedClient(): array
    {
        $jar = new TestCookieJarForProfile();
        $client = new Client([
            'base_uri' => 'http://127.0.0.1:8001',
            'cookies' => $jar,
            'allow_redirects' => false,
            'http_errors' => false
        ]);

        $response = $client->get('/login.php');
        $body = (string) $response->getBody();
        preg_match('/name="csrf_token" value="([^"]+)"/', $body, $matches);
        $loginCsrf = $matches[1] ?? '';

        $client->post('/login.php', [
            'form_params' => [
                'csrf_token' => $loginCsrf,
                'username' => 'testuser',
                'password' => 'password123'
            ]
        ]);

        $response = $client->get('/profile.php');
        $body = (string) $response->getBody();
        preg_match('/name="csrf_token" value="([^"]+)"/', $body, $matches);
        $profileCsrf = $matches[1] ?? '';

        return [$client, $profileCsrf];
    }

    public function testUnauthenticatedAccessRedirectsToLogin(): void
    {
        $jar = new TestCookieJarForProfile();
        $client = new Client([
            'base_uri' => 'http://127.0.0.1:8001',
            'cookies' => $jar,
            'allow_redirects' => false,
            'http_errors' => false
        ]);

        $response = $client->get('/profile.php');
        $this->assertEquals(302, $response->getStatusCode());
        $this->assertEquals('login.php', $response->getHeaderLine('Location'));
    }

    public function testSuccessfulProfileUpdate(): void
    {
        [$client, $csrfToken] = $this->getAuthenticatedClient();

        $response = $client->post('/profile.php', [
            'form_params' => [
                'csrf_token' => $csrfToken,
                'full_name' => 'John Doe',
                'personal_details' => 'Software Engineer'
            ]
        ]);

        $this->assertEquals(200, $response->getStatusCode());
        $body = (string) $response->getBody();
        $this->assertStringContainsString('Profile updated successfully.', $body);

        $stmt = self::$pdo->prepare('SELECT full_name, personal_details FROM users WHERE username = ?');
        $stmt->execute(['testuser']);
        $user = $stmt->fetch();
        $this->assertEquals('John Doe', $user['full_name']);
        $this->assertEquals('Software Engineer', $user['personal_details']);
    }

    public function testFullNameExceeds255Characters(): void
    {
        [$client, $csrfToken] = $this->getAuthenticatedClient();

        $longName = str_repeat('A', 256);

        $response = $client->post('/profile.php', [
            'form_params' => [
                'csrf_token' => $csrfToken,
                'full_name' => $longName,
                'personal_details' => 'Details'
            ]
        ]);

        $this->assertEquals(200, $response->getStatusCode());
        $body = (string) $response->getBody();
        $this->assertStringContainsString('Full name must not exceed 255 characters.', $body);
    }

    public function testInvalidProfilePictureFileType(): void
    {
        [$client, $csrfToken] = $this->getAuthenticatedClient();

        $response = $client->post('/profile.php', [
            'multipart' => [
                ['name' => 'csrf_token', 'contents' => $csrfToken],
                ['name' => 'full_name', 'contents' => 'John Doe'],
                ['name' => 'personal_details', 'contents' => 'Details'],
                [
                    'name' => 'profile_picture',
                    'contents' => 'Plain text content',
                    'filename' => 'test.txt',
                    'headers' => ['Content-Type' => 'text/plain']
                ]
            ]
        ]);

        $this->assertEquals(200, $response->getStatusCode());
        $body = (string) $response->getBody();
        $this->assertStringContainsString('Invalid file type. Only JPG, PNG, and WEBP are allowed.', $body);
    }

    public function testOversizedProfilePictureUpload(): void
    {
        [$client, $csrfToken] = $this->getAuthenticatedClient();

        // 1x1 transparent PNG header + padding to make it > 2MB (approx 2.1MB)
        $pngHeader = "\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\nIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01\r\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82";
        $largeData = $pngHeader . str_repeat('0', (2 * 1024 * 1024) + 100);

        $response = $client->post('/profile.php', [
            'multipart' => [
                ['name' => 'csrf_token', 'contents' => $csrfToken],
                ['name' => 'full_name', 'contents' => 'John Doe'],
                ['name' => 'personal_details', 'contents' => 'Details'],
                [
                    'name' => 'profile_picture',
                    'contents' => $largeData,
                    'filename' => 'large.png',
                    'headers' => ['Content-Type' => 'image/png']
                ]
            ]
        ]);

        $this->assertEquals(200, $response->getStatusCode());
        $body = (string) $response->getBody();
        $this->assertStringContainsString('File size exceeds 2MB limit.', $body);
    }

    public function testSuccessfulProfilePictureUpload(): void
    {
        [$client, $csrfToken] = $this->getAuthenticatedClient();

        // 1x1 pixel PNG image binary
        $validPng = "\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\nIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01\r\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82";

        $response = $client->post('/profile.php', [
            'multipart' => [
                ['name' => 'csrf_token', 'contents' => $csrfToken],
                ['name' => 'full_name', 'contents' => 'Jane Doe'],
                ['name' => 'personal_details', 'contents' => 'Updated details'],
                [
                    'name' => 'profile_picture',
                    'contents' => $validPng,
                    'filename' => 'avatar.png',
                    'headers' => ['Content-Type' => 'image/png']
                ]
            ]
        ]);

        $this->assertEquals(200, $response->getStatusCode());
        $body = (string) $response->getBody();
        $this->assertStringContainsString('Profile updated successfully.', $body);

        $stmt = self::$pdo->prepare('SELECT profile_picture FROM users WHERE username = ?');
        $stmt->execute(['testuser']);
        $picturePath = $stmt->fetchColumn();

        $this->assertNotEmpty($picturePath);
        $fullPath = __DIR__ . '/../' . $picturePath;
        $this->assertFileExists($fullPath);

        // Cleanup created test upload file
        if (file_exists($fullPath)) {
            unlink($fullPath);
        }
    }

    public function testCorruptedOrPolyglotImageUploadFails(): void
    {
        [$client, $csrfToken] = $this->getAuthenticatedClient();

        // Fake image header with embedded malicious PHP payload
        $fakePolyglot = "GIF89a;<?php echo 'hacked'; ?>";

        $response = $client->post('/profile.php', [
            'multipart' => [
                ['name' => 'csrf_token', 'contents' => $csrfToken],
                ['name' => 'full_name', 'contents' => 'John Doe'],
                ['name' => 'personal_details', 'contents' => 'Details'],
                [
                    'name' => 'profile_picture',
                    'contents' => $fakePolyglot,
                    'filename' => 'polyglot.png',
                    'headers' => ['Content-Type' => 'image/png']
                ]
            ]
        ]);

        $this->assertEquals(200, $response->getStatusCode());
        $body = (string) $response->getBody();
        $this->assertStringContainsString('Invalid file type.', $body);
    }

    public function testMissingTableErrorDuringProfileUpdate(): void
    {
        [$client, $csrfToken] = $this->getAuthenticatedClient();

        self::$pdo->exec("CREATE TRIGGER fail_profile_update BEFORE UPDATE ON users FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Simulated DB Error'");

        try {
            $response = $client->post('/profile.php', [
                'form_params' => [
                    'csrf_token' => $csrfToken,
                    'full_name' => 'John Doe',
                    'personal_details' => 'Software Engineer'
                ]
            ]);

            $this->assertEquals(200, $response->getStatusCode());
            $body = (string) $response->getBody();
            $this->assertStringContainsString('A database error occurred while updating your profile. Please check your input.', $body);
        } finally {
            self::$pdo->exec('DROP TRIGGER IF EXISTS fail_profile_update');
        }
    }
}
