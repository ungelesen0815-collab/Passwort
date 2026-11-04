<?php

use PHPUnit\Framework\TestCase;

class MigrateTest extends TestCase
{
    private static string $host = '127.0.0.1';
    private static string $user = 'test_user';
    private static string $pass = 'test_pass';
    private static ?PDO $pdoRoot = null;

    public static function setUpBeforeClass(): void
    {
        try {
            self::$pdoRoot = new PDO("mysql:host=" . self::$host . ";charset=utf8mb4", self::$user, self::$pass, [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            ]);
        } catch (\PDOException $e) {
            self::$pdoRoot = null;
        }
    }

    private function createIsolatedDb(): string
    {
        if (!self::$pdoRoot) {
            $this->markTestSkipped('Database server is not running or accessible in this environment.');
        }

        $dbName = 'test_mig_db_' . time() . '_' . rand(1000, 9999);
        self::$pdoRoot->exec("CREATE DATABASE `$dbName`");

        return $dbName;
    }

    private function dropIsolatedDb(string $dbName): void
    {
        if (self::$pdoRoot) {
            self::$pdoRoot->exec("DROP DATABASE IF EXISTS `$dbName`");
        }
    }

    private function getDbConnection(string $dbName): PDO
    {
        return new PDO("mysql:host=" . self::$host . ";dbname=$dbName;charset=utf8mb4", self::$user, self::$pass, [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        ]);
    }

    private function runMigrateScript(array $envVars): array
    {
        $tmpDir = sys_get_temp_dir() . '/mig_test_' . uniqid();
        mkdir($tmpDir);
        copy(__DIR__ . '/../migrate.php', $tmpDir . '/migrate.php');
        copy(__DIR__ . '/../db.php', $tmpDir . '/db.php');
        symlink(__DIR__ . '/../vendor', $tmpDir . '/vendor');

        $envLines = [];
        foreach ($envVars as $key => $val) {
            $envLines[] = "$key=$val";
        }
        file_put_contents($tmpDir . '/.env', implode("\n", $envLines) . "\n");

        $cmd = sprintf('php %s 2>&1', escapeshellarg($tmpDir . '/migrate.php'));
        exec($cmd, $output, $returnCode);

        // Cleanup temporary directory
        unlink($tmpDir . '/migrate.php');
        unlink($tmpDir . '/db.php');
        unlink($tmpDir . '/.env');
        unlink($tmpDir . '/vendor');
        rmdir($tmpDir);

        return [
            'returnCode' => $returnCode,
            'output'     => implode("\n", $output),
        ];
    }

    public function testFreshMigrationCreatesTablesAndColumns(): void
    {
        $dbName = $this->createIsolatedDb();

        try {
            $res = $this->runMigrateScript([
                'DB_HOST' => self::$host,
                'DB_NAME' => $dbName,
                'DB_USER' => self::$user,
                'DB_PASS' => self::$pass,
            ]);

            $this->assertEquals(0, $res['returnCode'], "Migration script output: " . $res['output']);
            $this->assertStringContainsString("Migration completed successfully: 'users', 'login_attempts', 'vaults', 'vault_items', and 'crypt_shares' tables are ready.", $res['output']);

            $pdo = $this->getDbConnection($dbName);

            // Verify users table and columns
            $stmt = $pdo->query("SHOW COLUMNS FROM users");
            $columns = $stmt->fetchAll(PDO::FETCH_COLUMN);

            $expectedColumns = [
                'id', 'username', 'password', 'role',
                'mfa_secret', 'mfa_enabled', 'full_name',
                'personal_details', 'profile_picture'
            ];

            foreach ($expectedColumns as $col) {
                $this->assertContains($col, $columns, "Column '$col' should exist in 'users' table.");
            }

            // Verify login_attempts table
            $stmt = $pdo->query("SHOW COLUMNS FROM login_attempts");
            $loginColumns = $stmt->fetchAll(PDO::FETCH_COLUMN);
            $this->assertContains('ip_address', $loginColumns);
            $this->assertContains('attempts', $loginColumns);
            $this->assertContains('last_attempt', $loginColumns);
        } finally {
            $this->dropIsolatedDb($dbName);
        }
    }

    public function testIncrementalMigrationAddsMissingColumns(): void
    {
        $dbName = $this->createIsolatedDb();

        try {
            $pdo = $this->getDbConnection($dbName);

            // Create partial users table without full_name, personal_details, profile_picture
            $pdo->exec("CREATE TABLE users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(255) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                role ENUM('admin', 'user') NOT NULL DEFAULT 'user',
                mfa_secret VARCHAR(255) DEFAULT NULL,
                mfa_enabled TINYINT(1) DEFAULT 0
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;");

            // Verify initial columns do not have full_name, personal_details, profile_picture
            $stmt = $pdo->query("SHOW COLUMNS FROM users");
            $initialColumns = $stmt->fetchAll(PDO::FETCH_COLUMN);
            $this->assertNotContains('full_name', $initialColumns);
            $this->assertNotContains('personal_details', $initialColumns);
            $this->assertNotContains('profile_picture', $initialColumns);

            // Run migration script
            $res = $this->runMigrateScript([
                'DB_HOST' => self::$host,
                'DB_NAME' => $dbName,
                'DB_USER' => self::$user,
                'DB_PASS' => self::$pass,
            ]);

            $this->assertEquals(0, $res['returnCode'], "Migration script output: " . $res['output']);
            $this->assertStringContainsString("Migration completed successfully: 'users', 'login_attempts', 'vaults', 'vault_items', and 'crypt_shares' tables are ready.", $res['output']);

            // Verify missing columns were added
            $stmt = $pdo->query("SHOW COLUMNS FROM users");
            $updatedColumns = $stmt->fetchAll(PDO::FETCH_COLUMN);
            $this->assertContains('full_name', $updatedColumns);
            $this->assertContains('personal_details', $updatedColumns);
            $this->assertContains('profile_picture', $updatedColumns);
        } finally {
            $this->dropIsolatedDb($dbName);
        }
    }

    public function testIdempotency(): void
    {
        $dbName = $this->createIsolatedDb();

        try {
            $env = [
                'DB_HOST' => self::$host,
                'DB_NAME' => $dbName,
                'DB_USER' => self::$user,
                'DB_PASS' => self::$pass,
            ];

            // First run
            $res1 = $this->runMigrateScript($env);
            $this->assertEquals(0, $res1['returnCode']);

            // Second run
            $res2 = $this->runMigrateScript($env);
            $this->assertEquals(0, $res2['returnCode']);
            $this->assertStringContainsString("Migration completed successfully: 'users', 'login_attempts', 'vaults', 'vault_items', and 'crypt_shares' tables are ready.", $res2['output']);
        } finally {
            $this->dropIsolatedDb($dbName);
        }
    }

    public function testMigrationFailureOnDatabaseError(): void
    {
        $res = $this->runMigrateScript([
            'DB_HOST' => self::$host,
            'DB_NAME' => 'non_existent_db_xyz_123',
            'DB_USER' => self::$user,
            'DB_PASS' => 'invalid_pass',
        ]);

        $this->assertNotEquals(0, $res['returnCode']);
        $this->assertStringContainsString('Database connection failed', $res['output']);
    }
}
