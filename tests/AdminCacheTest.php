<?php
use PHPUnit\Framework\TestCase;

class AdminCacheTest extends TestCase
{
    private string $cacheDir;
    private string $cacheFile;

    protected function setUp(): void
    {
        $this->cacheDir = __DIR__ . '/../cache';
        $this->cacheFile = $this->cacheDir . '/admin_user_count.cache';

        if (file_exists($this->cacheFile)) {
            @unlink($this->cacheFile);
        }
    }

    protected function tearDown(): void
    {
        if (file_exists($this->cacheFile)) {
            @unlink($this->cacheFile);
        }
    }

    public function testAdminPhpDoesNotUseSysGetTempDirForCache(): void
    {
        $adminPhp = file_get_contents(__DIR__ . '/../admin.php');

        $this->assertStringNotContainsString("sys_get_temp_dir() . '/admin_user_count.cache'", $adminPhp);
        $this->assertStringContainsString("__DIR__ . '/cache'", $adminPhp);
        $this->assertStringContainsString("Require all denied", $adminPhp);
        $this->assertStringContainsString(".htaccess", $adminPhp);
    }

    public function testAdminPhpDoesNotHaveToctouInCacheDirCreation(): void
    {
        $adminPhp = file_get_contents(__DIR__ . '/../admin.php');

        $this->assertStringNotContainsString("if (!is_dir(\$cacheDir)) {\n        @mkdir(\$cacheDir", $adminPhp);
        $this->assertStringContainsString("@mkdir(\$cacheDir, 0750, true);", $adminPhp);
    }

    public function testCacheDirectoryCreationAndFilePlacement(): void
    {
        @mkdir($this->cacheDir, 0750, true);
        $this->assertTrue(is_dir($this->cacheDir));

        file_put_contents($this->cacheFile, "42");

        $this->assertFileExists($this->cacheFile);
        $this->assertEquals("42", file_get_contents($this->cacheFile));
    }
}
