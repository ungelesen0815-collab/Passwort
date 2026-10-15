<?php

use PHPUnit\Framework\TestCase;

class CreateAdminTest extends TestCase
{
    private static ?PDO $pdo = null;
    private static $serverPid = null;
    private static int $serverPort = 8999;
    private static string $dbHost = '127.0.0.1';
    private static string $dbName = 'app_db';
    private static string $dbUser = 'app_user';
    private static string $dbPass = 'app_password';

    public static function setUpBeforeClass(): void
    {
        $envFile = __DIR__ . '/../.env';
        if (!file_exists($envFile) && file_exists(__DIR__ . '/../.env.example')) {
            copy(__DIR__ . '/../.env.example', $envFile);
        }

        if (file_exists($envFile)) {
            $envContents = parse_ini_file($envFile);
            if (is_array($envContents)) {
                self::$dbHost = $envContents['DB_HOST'] ?? self::$dbHost;
                self::$dbName = $envContents['DB_NAME'] ?? self::$dbName;
                self::$dbUser = $envContents['DB_USER'] ?? self::$dbUser;
                self::$dbPass = $envContents['DB_PASS'] ?? self::$dbPass;
            }
        }

        try {
            $dsn = sprintf('mysql:host=%s;dbname=%s;charset=utf8mb4', self::$dbHost, self::$dbName);
            self::$pdo = new PDO($dsn, self::$dbUser, self::$dbPass, [
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
        } catch (\PDOException $e) {
            self::$pdo = null;
        }

        // Spin up a local PHP server to test non-CLI SAPI execution
        $cmd = sprintf(
            '%s -S 127.0.0.1:%d -t %s >/dev/null 2>&1 & echo $!',
            escapeshellarg(PHP_BINARY),
            self::$serverPort,
            escapeshellarg(__DIR__ . '/../')
        );
        self::$serverPid = exec($cmd);
        usleep(200000); // 200ms pause for server startup
    }

    public static function tearDownAfterClass(): void
    {
        if (self::$serverPid) {
            exec('kill ' . self::$serverPid . ' 2>/dev/null');
        }
    }

    protected function setUp(): void
    {
        if (self::$pdo) {
            self::$pdo->exec("DELETE FROM users WHERE username LIKE 'test_admin%'");
        }
    }

    protected function tearDown(): void
    {
        if (self::$pdo) {
            self::$pdo->exec("DELETE FROM users WHERE username LIKE 'test_admin%'");
        }
    }

    private function runScript(array $args, array $envOverrides = []): array
    {
        $cmd = sprintf(
            '%s -d variables_order=EGPCS %s',
            escapeshellarg(PHP_BINARY),
            escapeshellarg(__DIR__ . '/../create_admin.php')
        );
        foreach ($args as $arg) {
            $cmd .= ' ' . escapeshellarg($arg);
        }
        $cmd .= ' 2>&1';

        $descriptors = [
            0 => ["pipe", "r"],
            1 => ["pipe", "w"],
            2 => ["pipe", "w"]
        ];

        $defaultEnv = [
            'DB_HOST' => self::$dbHost,
            'DB_NAME' => self::$dbName,
            'DB_USER' => self::$dbUser,
            'DB_PASS' => self::$dbPass,
        ];

        $env = array_merge(getenv(), $_ENV, $defaultEnv, $envOverrides);
        $process = proc_open($cmd, $descriptors, $pipes, __DIR__ . '/..', $env);

        if (is_resource($process)) {
            fclose($pipes[0]);
            $output = stream_get_contents($pipes[1]);
            $output .= stream_get_contents($pipes[2]);
            fclose($pipes[1]);
            fclose($pipes[2]);
            $returnCode = proc_close($process);

            return [
                'returnCode' => $returnCode,
                'output' => trim($output),
            ];
        }

        return ['returnCode' => -1, 'output' => 'Proc open failed'];
    }

    public function testNonCliExecutionIsBlocked(): void
    {
        $client = new GuzzleHttp\Client(['http_errors' => false]);
        $url = sprintf('http://127.0.0.1:%d/create_admin.php', self::$serverPort);
        $response = $client->get($url);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertStringContainsString('This script can only be run from the command line.', (string) $response->getBody());
    }

    public function testMissingArgumentsShowsUsage(): void
    {
        // 0 extra args ($argc = 1)
        $res = $this->runScript([]);
        $this->assertEquals(1, $res['returnCode']);
        $this->assertStringContainsString('Usage: php create_admin.php <username> <password>', $res['output']);

        // 1 extra arg ($argc = 2)
        $res = $this->runScript(['test_admin_user']);
        $this->assertEquals(1, $res['returnCode']);
        $this->assertStringContainsString('Usage: php create_admin.php <username> <password>', $res['output']);

        // 3 extra args ($argc = 4)
        $res = $this->runScript(['test_admin_user', 'password123', 'extra_arg']);
        $this->assertEquals(1, $res['returnCode']);
        $this->assertStringContainsString('Usage: php create_admin.php <username> <password>', $res['output']);
    }

    public function testEmptyUsernameOrPasswordFails(): void
    {
        // Empty username
        $res = $this->runScript(['', 'password123']);
        $this->assertEquals(1, $res['returnCode']);
        $this->assertStringContainsString('Username and password are required.', $res['output']);

        // Whitespace username (trimmed to empty)
        $res = $this->runScript(['   ', 'password123']);
        $this->assertEquals(1, $res['returnCode']);
        $this->assertStringContainsString('Username and password are required.', $res['output']);

        // Empty password
        $res = $this->runScript(['test_admin_user', '']);
        $this->assertEquals(1, $res['returnCode']);
        $this->assertStringContainsString('Username and password are required.', $res['output']);
    }

    public function testPasswordLengthValidation(): void
    {
        // Password too short (< 8 chars)
        $res = $this->runScript(['test_admin_user', 'short']);
        $this->assertEquals(1, $res['returnCode']);
        $this->assertStringContainsString('Password must be between 8 and 72 characters.', $res['output']);

        // Password too long (> 72 chars)
        $oversizedPassword = str_repeat('a', 73);
        $res = $this->runScript(['test_admin_user', $oversizedPassword]);
        $this->assertEquals(1, $res['returnCode']);
        $this->assertStringContainsString('Password must be between 8 and 72 characters.', $res['output']);
    }

    public function testSuccessfulAdminUserCreation(): void
    {
        if (self::$pdo === null) {
            $this->markTestSkipped('Database connection is not available.');
        }

        $username = 'test_admin_success';
        $password = 'validPassword123';

        $res = $this->runScript([$username, $password]);

        $this->assertEquals(0, $res['returnCode']);
        $this->assertStringContainsString("Admin user '{$username}' created successfully.", $res['output']);

        // Verify database record
        $stmt = self::$pdo->prepare("SELECT * FROM users WHERE username = ?");
        $stmt->execute([$username]);
        $user = $stmt->fetch();

        $this->assertNotFalse($user, 'Created admin user should exist in database.');
        $this->assertEquals($username, $user['username']);
        $this->assertEquals('admin', $user['role']);
        $this->assertTrue(password_verify($password, $user['password']), 'Password hash should match.');
    }

    public function testDuplicateUsernameError(): void
    {
        if (self::$pdo === null) {
            $this->markTestSkipped('Database connection is not available.');
        }

        $username = 'test_admin_dup';
        $password = 'validPassword123';

        // First creation succeeds
        $res1 = $this->runScript([$username, $password]);
        $this->assertEquals(0, $res1['returnCode']);

        // Second creation with same username fails
        $res2 = $this->runScript([$username, $password]);
        $this->assertEquals(1, $res2['returnCode']);
        $this->assertStringContainsString("Error: Username '{$username}' already exists.", $res2['output']);
    }

    public function testDatabaseErrorHandling(): void
    {
        // Run with an invalid DB_NAME to trigger a database error during execution
        $res = $this->runScript(['test_admin_err', 'validPassword123'], [
            'DB_NAME' => 'non_existent_db_12345'
        ]);

        $this->assertNotEquals(0, $res['returnCode']);
        $this->assertTrue(
            str_contains(strtolower($res['output']), 'error') ||
            str_contains(strtolower($res['output']), 'exception'),
            'Output should indicate a database error'
        );
    }

    private function runScriptWithMockPdo(array $args, int $exceptionCode, string $exceptionMessage): array
    {
        $scriptPath = realpath(__DIR__ . '/../create_admin.php');
        $argsExport = var_export(array_merge(['create_admin.php'], $args), true);
        $scriptPathExport = var_export($scriptPath, true);

        $runnerCode = "<?php
class MockStatement {
    private \$code;
    private \$msg;
    public function __construct(\$code, \$msg) {
        \$this->code = \$code;
        \$this->msg = \$msg;
    }
    public function execute(\$params) {
        throw new \\PDOException(\$this->msg, \$this->code);
    }
}
class MockPDO {
    private \$code;
    private \$msg;
    public function __construct(\$code, \$msg) {
        \$this->code = \$code;
        \$this->msg = \$msg;
    }
    public function prepare(\$sql) {
        return new MockStatement(\$this->code, \$this->msg);
    }
}
\$pdo = new MockPDO({$exceptionCode}, " . var_export($exceptionMessage, true) . ");
\$argv = {$argsExport};
\$argc = count(\$argv);

\$scriptContent = file_get_contents({$scriptPathExport});
\$scriptContent = str_replace(\"require_once __DIR__ . '/db.php';\", \"// db.php overridden\", \$scriptContent);
\$scriptContent = preg_replace(\"/^<\\?php/\", \"\", \$scriptContent);
eval(\$scriptContent);
";

        $tmpFile = tempnam(sys_get_temp_dir(), 'test_mock_pdo_');
        file_put_contents($tmpFile, $runnerCode);

        exec(PHP_BINARY . ' ' . escapeshellarg($tmpFile) . ' 2>&1', $output, $returnCode);
        @unlink($tmpFile);

        return [
            'returnCode' => $returnCode,
            'output' => trim(implode("\n", $output)),
        ];
    }

    public function testDbIntegrityViolationErrorPathMocked(): void
    {
        $username = 'existing_admin_user';
        $res = $this->runScriptWithMockPdo([$username, 'validPassword123'], 23000, "Duplicate entry '{$username}' for key 'users.username'");

        $this->assertEquals(1, $res['returnCode']);
        $this->assertEquals("Error: Username '{$username}' already exists.", $res['output']);
    }

    public function testGeneralDatabaseErrorPathMocked(): void
    {
        $username = 'err_admin_user';
        $res = $this->runScriptWithMockPdo([$username, 'validPassword123'], 50000, "General database query failure");

        $this->assertEquals(1, $res['returnCode']);
        $this->assertEquals("Error creating admin user: General database query failure", $res['output']);
    }
}
