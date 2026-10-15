<?php

use PHPUnit\Framework\TestCase;

class DbTest extends TestCase
{
    private function runDbScriptWithEnv(array $envVars): array
    {
        $envExport = var_export($envVars, true);
        $code = sprintf('
            $dir = sys_get_temp_dir() . "/db_test_" . uniqid();
            mkdir($dir);
            copy(%s, $dir . "/db.php");
            symlink(%s, $dir . "/vendor");
            $_ENV = %s;
            try {
                require $dir . "/db.php";
            } finally {
                if (file_exists($dir . "/db.php")) unlink($dir . "/db.php");
                if (is_link($dir . "/vendor")) unlink($dir . "/vendor");
                if (is_dir($dir)) rmdir($dir);
            }
        ', var_export(__DIR__ . '/../db.php', true), var_export(__DIR__ . '/../vendor', true), $envExport);

        $cmd = sprintf('%s -r %s 2>&1', escapeshellarg(PHP_BINARY), escapeshellarg($code));
        exec($cmd, $output, $returnCode);

        return [
            'returnCode' => $returnCode,
            'output'     => implode("\n", $output),
        ];
    }

    public function testMissingDbHostThrowsRuntimeException(): void
    {
        $res = $this->runDbScriptWithEnv([]);

        $this->assertNotEquals(0, $res['returnCode']);
        $this->assertStringContainsString('Database host (DB_HOST) must be set in the environment.', $res['output']);
    }

    public function testMissingDbNameThrowsRuntimeException(): void
    {
        $res = $this->runDbScriptWithEnv([
            'DB_HOST' => '127.0.0.1',
        ]);

        $this->assertNotEquals(0, $res['returnCode']);
        $this->assertStringContainsString('Database name (DB_NAME) must be set in the environment.', $res['output']);
    }

    public function testMissingDbUserThrowsRuntimeException(): void
    {
        $res = $this->runDbScriptWithEnv([
            'DB_HOST' => '127.0.0.1',
            'DB_NAME' => 'app_db',
        ]);

        $this->assertNotEquals(0, $res['returnCode']);
        $this->assertStringContainsString('Database user (DB_USER) must be set in the environment.', $res['output']);
    }

    public function testMissingDbPassThrowsRuntimeException(): void
    {
        $res = $this->runDbScriptWithEnv([
            'DB_HOST' => '127.0.0.1',
            'DB_NAME' => 'app_db',
            'DB_USER' => 'app_user',
        ]);

        $this->assertNotEquals(0, $res['returnCode']);
        $this->assertStringContainsString('Database password (DB_PASS) must be set in the environment.', $res['output']);
    }

    public function testFailedDbConnectionThrowsExceptionAndLogsError(): void
    {
        $res = $this->runDbScriptWithEnv([
            'DB_HOST' => '127.0.0.1',
            'DB_NAME' => 'app_db',
            'DB_USER' => 'app_user',
            'DB_PASS' => 'invalid_password_123',
        ]);

        $this->assertNotEquals(0, $res['returnCode']);
        $this->assertStringContainsString('A database error occurred. Please contact the administrator.', $res['output']);
        $this->assertStringContainsString('Database connection failed', $res['output']);
    }

    public function testSuccessfulDbConnectionCreatesPdoInstance(): void
    {
        $originalEnv = $_ENV;
        $_ENV = [
            'DB_HOST' => '127.0.0.1',
            'DB_NAME' => 'app_db',
            'DB_USER' => 'app_user',
            'DB_PASS' => 'app_password',
        ];

        try {
            require __DIR__ . '/../db.php';
        } catch (Exception $e) {
            $this->markTestSkipped('Database server is not running or accessible in this environment: ' . $e->getMessage());
        } finally {
            $_ENV = $originalEnv;
        }

        $this->assertInstanceOf(PDO::class, $pdo);
        $this->assertEquals(PDO::ERRMODE_EXCEPTION, $pdo->getAttribute(PDO::ATTR_ERRMODE));
        $this->assertEquals(PDO::FETCH_ASSOC, $pdo->getAttribute(PDO::ATTR_DEFAULT_FETCH_MODE));
        $this->assertEquals(0, $pdo->getAttribute(PDO::ATTR_EMULATE_PREPARES));
    }
}
