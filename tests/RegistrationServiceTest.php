<?php

use PHPUnit\Framework\TestCase;

ini_set('display_errors', '0');
ini_set('log_errors', '1');
ini_set('error_log', sys_get_temp_dir() . '/php_test_errors.log');

require_once __DIR__ . '/../RegistrationService.php';

class RegistrationServiceTest extends TestCase
{
    private PDO $pdo;
    private RegistrationService $service;

    protected function setUp(): void
    {
        ini_set('display_errors', '0');
        ini_set('log_errors', '1');
        ini_set('error_log', sys_get_temp_dir() . '/php_test_errors.log');

        $this->pdo = new PDO('sqlite::memory:');
        $this->pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $this->pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);

        $this->pdo->exec("CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username VARCHAR(255) UNIQUE NOT NULL,
            password VARCHAR(255) NOT NULL,
            role VARCHAR(50) NOT NULL DEFAULT 'user'
        )");

        $this->service = new RegistrationService($this->pdo);
    }

    public function testRegisterSuccess(): void
    {
        $result = $this->service->register('test_user', 'password123');

        $this->assertTrue($result['success']);
        $this->assertEquals('', $result['error']);

        $stmt = $this->pdo->prepare('SELECT * FROM users WHERE username = ?');
        $stmt->execute(['test_user']);
        $user = $stmt->fetch();

        $this->assertNotFalse($user);
        $this->assertEquals('test_user', $user['username']);
        $this->assertEquals('user', $user['role']);
        $this->assertTrue(password_verify('password123', $user['password']));
    }

    public function testRegisterTrimsUsername(): void
    {
        $result = $this->service->register('  trimmed_user  ', 'password123');

        $this->assertTrue($result['success']);
        $this->assertEquals('', $result['error']);

        $stmt = $this->pdo->prepare('SELECT * FROM users WHERE username = ?');
        $stmt->execute(['trimmed_user']);
        $user = $stmt->fetch();

        $this->assertNotFalse($user);
        $this->assertEquals('trimmed_user', $user['username']);
    }

    public function testRegisterEmptyUsername(): void
    {
        $result = $this->service->register('', 'password123');

        $this->assertFalse($result['success']);
        $this->assertEquals('Username and password are required.', $result['error']);
    }

    public function testRegisterEmptyPassword(): void
    {
        $result = $this->service->register('validuser', '');

        $this->assertFalse($result['success']);
        $this->assertEquals('Username and password are required.', $result['error']);
    }

    public function testRegisterBothEmpty(): void
    {
        $result = $this->service->register('', '');

        $this->assertFalse($result['success']);
        $this->assertEquals('Username and password are required.', $result['error']);
    }

    public function testRegisterWhitespaceUsername(): void
    {
        $result = $this->service->register('   ', 'password123');

        $this->assertFalse($result['success']);
        $this->assertEquals('Username and password are required.', $result['error']);
    }

    public function testRegisterUsernameTooShort(): void
    {
        $result = $this->service->register('ab', 'password123');

        $this->assertFalse($result['success']);
        $this->assertEquals('Username must be 3-50 characters and contain only letters, numbers, and underscores.', $result['error']);
    }

    public function testRegisterUsernameTooLong(): void
    {
        $longUsername = str_repeat('a', 51);
        $result = $this->service->register($longUsername, 'password123');

        $this->assertFalse($result['success']);
        $this->assertEquals('Username must be 3-50 characters and contain only letters, numbers, and underscores.', $result['error']);
    }

    public function testRegisterUsernameInvalidChars(): void
    {
        $invalidUsernames = ['user@name', 'user name', 'user-name', 'user!'];

        foreach ($invalidUsernames as $username) {
            $result = $this->service->register($username, 'password123');

            $this->assertFalse($result['success']);
            $this->assertEquals('Username must be 3-50 characters and contain only letters, numbers, and underscores.', $result['error']);
        }
    }

    public function testRegisterUsernameBoundaryLengths(): void
    {
        $minUsername = 'abc'; // 3 chars
        $resultMin = $this->service->register($minUsername, 'password123');
        $this->assertTrue($resultMin['success']);

        $maxUsername = str_repeat('z', 50); // 50 chars
        $resultMax = $this->service->register($maxUsername, 'password123');
        $this->assertTrue($resultMax['success']);
    }

    public function testRegisterPasswordTooShort(): void
    {
        $result = $this->service->register('validuser', 'pass123'); // 7 chars

        $this->assertFalse($result['success']);
        $this->assertEquals('Password must be between 8 and 72 characters.', $result['error']);
    }

    public function testRegisterPasswordTooLong(): void
    {
        $longPassword = str_repeat('a', 73);
        $result = $this->service->register('validuser', $longPassword);

        $this->assertFalse($result['success']);
        $this->assertEquals('Password must be between 8 and 72 characters.', $result['error']);
    }

    public function testRegisterPasswordBoundaryLengths(): void
    {
        $minPassword = str_repeat('a', 8);
        $resultMin = $this->service->register('user_min_pass', $minPassword);
        $this->assertTrue($resultMin['success']);

        $maxPassword = str_repeat('b', 72);
        $resultMax = $this->service->register('user_max_pass', $maxPassword);
        $this->assertTrue($resultMax['success']);
    }

    public function testRegisterDuplicateUsername(): void
    {
        $first = $this->service->register('unique_user', 'password123');
        $this->assertTrue($first['success']);

        $second = $this->service->register('unique_user', 'password123');
        $this->assertFalse($second['success']);
        $this->assertEquals('Registration failed.', $second['error']);
    }

    public function testRegisterGenericDatabaseError(): void
    {
        ini_set('display_errors', '0');
        ini_set('log_errors', '1');
        ini_set('error_log', sys_get_temp_dir() . '/php_test_errors.log');

        $emptyPdo = new PDO('sqlite::memory:');
        $emptyPdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $serviceWithBadDb = new RegistrationService($emptyPdo);

        $result = $serviceWithBadDb->register('validuser', 'password123');

        $this->assertFalse($result['success']);
        $this->assertEquals('Registration failed.', $result['error']);
    }
}
