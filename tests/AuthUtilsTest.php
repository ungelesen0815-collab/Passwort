<?php

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../auth_utils.php';

class AuthUtilsTest extends TestCase
{
    private PDO $pdo;

    protected function setUp(): void
    {
        $this->pdo = new PDO('sqlite::memory:');
        $this->pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $this->pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);

        $this->pdo->exec("CREATE TABLE login_attempts (
            ip_address VARCHAR(255) PRIMARY KEY,
            attempts INT NOT NULL,
            last_attempt INT NOT NULL
        )");
    }

    public function testIsRateLimitedReturnsFalseWhenNoAttempts(): void
    {
        $now = time();
        $this->assertFalse(is_rate_limited($this->pdo, ['127.0.0.1', 'user:1'], $now));
    }

    public function testIsRateLimitedReturnsFalseWhenAttemptsBelowThreshold(): void
    {
        $now = time();
        $stmt = $this->pdo->prepare('INSERT INTO login_attempts (ip_address, attempts, last_attempt) VALUES (?, ?, ?)');
        $stmt->execute(['127.0.0.1', 4, $now]);

        $this->assertFalse(is_rate_limited($this->pdo, ['127.0.0.1', 'user:1'], $now));
    }

    public function testIsRateLimitedReturnsTrueWhenSingleIdentifierReachesThreshold(): void
    {
        $now = time();
        $stmt = $this->pdo->prepare('INSERT INTO login_attempts (ip_address, attempts, last_attempt) VALUES (?, ?, ?)');
        $stmt->execute(['user:1', 5, $now]);

        $this->assertTrue(is_rate_limited($this->pdo, ['127.0.0.1', 'user:1'], $now));
    }

    public function testIsRateLimitedCustomMaxAttempts(): void
    {
        $now = time();
        $stmt = $this->pdo->prepare('INSERT INTO login_attempts (ip_address, attempts, last_attempt) VALUES (?, ?, ?)');
        $stmt->execute(['127.0.0.1', 3, $now]);

        $this->assertFalse(is_rate_limited($this->pdo, ['127.0.0.1'], $now, 5));
        $this->assertTrue(is_rate_limited($this->pdo, ['127.0.0.1'], $now, 3));
    }

    public function testIsRateLimitedWithEmptyIdentifiers(): void
    {
        $now = time();
        $this->assertFalse(is_rate_limited($this->pdo, [], $now));
    }

    public function testIsRateLimitedResetsExpiredAttemptsInBatch(): void
    {
        $now = time();
        $old_time = $now - 301;
        $stmt = $this->pdo->prepare('INSERT INTO login_attempts (ip_address, attempts, last_attempt) VALUES (?, ?, ?)');
        $stmt->execute(['127.0.0.1', 5, $old_time]);
        $stmt->execute(['user:1', 2, $now]);

        $this->assertFalse(is_rate_limited($this->pdo, ['127.0.0.1', 'user:1'], $now));

        // Confirm 127.0.0.1 attempts reset to 0 in DB
        $stmt = $this->pdo->prepare('SELECT attempts FROM login_attempts WHERE ip_address = ?');
        $stmt->execute(['127.0.0.1']);
        $this->assertEquals(0, (int)$stmt->fetchColumn());
    }

    public function testGetClientIp(): void
    {
        $_SERVER['REMOTE_ADDR'] = '192.168.1.1';
        unset($_SERVER['HTTP_X_FORWARDED_FOR'], $_SERVER['HTTP_CLIENT_IP'], $_ENV['TRUSTED_PROXIES']);
        putenv('TRUSTED_PROXIES=');

        // Without trusted proxies configured, header spoofing is ignored and REMOTE_ADDR is returned
        $_SERVER['HTTP_X_FORWARDED_FOR'] = '203.0.113.195';
        $this->assertEquals('192.168.1.1', get_client_ip());

        // When REMOTE_ADDR is a trusted proxy, forwarded header is traversed right-to-left
        // to get the true client IP (70.41.3.18) rather than spoofed left-most header (203.0.113.195)
        $_ENV['TRUSTED_PROXIES'] = '192.168.1.1, 10.0.0.1';
        $_SERVER['HTTP_X_FORWARDED_FOR'] = '203.0.113.195, 70.41.3.18, 10.0.0.1';
        $this->assertEquals('70.41.3.18', get_client_ip());

        // Break chain on invalid IP, fallback to remote address or last untrusted valid IP
        // Here the right-most is invalid, so it breaks and returns REMOTE_ADDR since we traverse backwards and find invalid before trusted proxy chain breaks.
        $_SERVER['HTTP_X_FORWARDED_FOR'] = '203.0.113.195, invalid_ip';
        $this->assertEquals('192.168.1.1', get_client_ip());

        // When REMOTE_ADDR is untrusted despite TRUSTED_PROXIES being set, return REMOTE_ADDR
        $_SERVER['REMOTE_ADDR'] = '10.0.0.99';
        $this->assertEquals('10.0.0.99', get_client_ip());

        unset($_ENV['TRUSTED_PROXIES']);
        putenv('TRUSTED_PROXIES=');
    }

    public function testGetClientIpHandlesEmptyEntriesInTrustedProxies(): void
    {
        $_SERVER['REMOTE_ADDR'] = '192.168.1.1';
        $_ENV['TRUSTED_PROXIES'] = '192.168.1.1, , 10.0.0.1';
        $_SERVER['HTTP_X_FORWARDED_FOR'] = '203.0.113.10, 10.0.0.1';

        $this->assertEquals('203.0.113.10', get_client_ip());

        unset($_ENV['TRUSTED_PROXIES'], $_SERVER['HTTP_X_FORWARDED_FOR']);
    }

    public function testGetClientIpReturnsRemoteAddrWhenXForwardedForIsNonString(): void
    {
        $_SERVER['REMOTE_ADDR'] = '192.168.1.1';
        $_ENV['TRUSTED_PROXIES'] = '192.168.1.1';
        $_SERVER['HTTP_X_FORWARDED_FOR'] = ['spoofed_array'];

        $this->assertEquals('192.168.1.1', get_client_ip());

        unset($_ENV['TRUSTED_PROXIES'], $_SERVER['HTTP_X_FORWARDED_FOR']);
    }

    public function testClearLoginAttemptsRemovesRecords(): void
    {
        $now = time();
        $stmt = $this->pdo->prepare('INSERT INTO login_attempts (ip_address, attempts, last_attempt) VALUES (?, ?, ?)');
        $stmt->execute(['127.0.0.1', 1, $now]);

        clear_login_attempts($this->pdo, '127.0.0.1');

        $stmt = $this->pdo->prepare('SELECT COUNT(*) FROM login_attempts WHERE ip_address = ?');
        $stmt->execute(['127.0.0.1']);
        $this->assertEquals(0, (int)$stmt->fetchColumn());
    }

    public function testGetUserByIdReturnsUserArrayWhenFound(): void
    {
        $this->pdo->exec("CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username VARCHAR(255) NOT NULL
        )");
        $this->pdo->exec("INSERT INTO users (id, username) VALUES (1, 'john_doe')");

        $user = get_user_by_id($this->pdo, 1);
        $this->assertIsArray($user);
        $this->assertEquals('john_doe', $user['username']);
    }

    public function testGetUserByIdReturnsFalseWhenNotFound(): void
    {
        $this->pdo->exec("CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username VARCHAR(255) NOT NULL
        )");

        $user = get_user_by_id($this->pdo, 999);
        $this->assertFalse($user);
    }

    public function testIncrementLoginAttemptsCreatesNewRecordOnFirstAttempt(): void
    {
        $now = time();
        $attempts = increment_login_attempts($this->pdo, '127.0.0.1', $now);

        $this->assertEquals(1, $attempts);
        $stmt = $this->pdo->prepare('SELECT attempts FROM login_attempts WHERE ip_address = ?'); $stmt->execute(['127.0.0.1']); $this->assertEquals(1, $stmt->fetchColumn());
    }

    public function testIncrementLoginAttemptsIncrementsCountWithinWindow(): void
    {
        $now = time();
        $attempts1 = increment_login_attempts($this->pdo, '127.0.0.1', $now);
        $attempts2 = increment_login_attempts($this->pdo, '127.0.0.1', $now + 10);
        $attempts3 = increment_login_attempts($this->pdo, '127.0.0.1', $now + 20);

        $this->assertEquals(1, $attempts1);
        $this->assertEquals(2, $attempts2);
        $this->assertEquals(3, $attempts3);
        $stmt = $this->pdo->prepare('SELECT attempts FROM login_attempts WHERE ip_address = ?'); $stmt->execute(['127.0.0.1']); $this->assertEquals(3, $stmt->fetchColumn());
    }

    public function testIncrementLoginAttemptsResetsCountAfterWindowExpiry(): void
    {
        $now = time();
        increment_login_attempts($this->pdo, '127.0.0.1', $now);
        increment_login_attempts($this->pdo, '127.0.0.1', $now + 10);

        $later = $now + 10 + 301;
        $attempts = increment_login_attempts($this->pdo, '127.0.0.1', $later);

        $this->assertEquals(1, $attempts);
        $stmt = $this->pdo->prepare('SELECT attempts FROM login_attempts WHERE ip_address = ?'); $stmt->execute(['127.0.0.1']); $this->assertEquals(1, $stmt->fetchColumn());
    }

    public function testIncrementLoginAttemptsTracksIdentifiersIndependently(): void
    {
        $now = time();
        $ipAttempts1 = increment_login_attempts($this->pdo, '127.0.0.1', $now);
        $userAttempts1 = increment_login_attempts($this->pdo, 'user:john', $now);
        $ipAttempts2 = increment_login_attempts($this->pdo, '127.0.0.1', $now + 1);

        $this->assertEquals(1, $ipAttempts1);
        $this->assertEquals(1, $userAttempts1);
        $this->assertEquals(2, $ipAttempts2);
    }

    public function testExistingUsersKeepAllFeaturesAndNewUsersOnlyGetPasswordGenerator(): void
    {
        $this->pdo->exec("CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username VARCHAR(255) NOT NULL,
            role VARCHAR(50) NOT NULL DEFAULT 'user'
        )");
        $this->pdo->exec("INSERT INTO users (id, username, role) VALUES (1, 'existing_user', 'user')");

        // Run automatic column migration
        ensure_user_feature_columns($this->pdo);

        // Existing user keeps all features (1, 1, 1)
        $existingPerms = get_user_permissions($this->pdo, 1, 'user');
        $this->assertTrue($existingPerms['password_generator']);
        $this->assertTrue($existingPerms['vault']);
        $this->assertTrue($existingPerms['crypt_share']);

        // New user inserted after migration only gets Password Generator (1, 0, 0)
        $this->pdo->exec("INSERT INTO users (id, username, role) VALUES (2, 'new_user', 'user')");
        $newPerms = get_user_permissions($this->pdo, 2, 'user');
        $this->assertTrue($newPerms['password_generator']);
        $this->assertFalse($newPerms['vault']);
        $this->assertFalse($newPerms['crypt_share']);

        // Admin can toggle features for the user
        $stmt = $this->pdo->prepare("UPDATE users SET can_use_password_generator = 1, can_use_vault = 1, can_use_crypt_share = 0 WHERE id = ?");
        $stmt->execute([2]);

        $this->assertTrue(user_has_feature($this->pdo, 2, 'password_generator', 'user'));
        $this->assertTrue(user_has_feature($this->pdo, 2, 'vault', 'user'));
        $this->assertFalse(user_has_feature($this->pdo, 2, 'crypt_share', 'user'));

        // Admin role always has all features
        $this->assertTrue(user_has_feature($this->pdo, 2, 'crypt_share', 'admin'));
    }
}
