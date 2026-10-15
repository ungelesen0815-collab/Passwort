<?php

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../../RegistrationService.php';

class RegistrationServiceTest extends TestCase {
    private \PDO $pdo;
    private RegistrationService $service;

    protected function setUp(): void {
        // Use an in-memory SQLite database for integration testing
        $this->pdo = new \PDO('sqlite::memory:');
        $this->pdo->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);

        // Create the users table schema as expected by the application
        $this->pdo->exec('CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL
        )');

        $this->service = new RegistrationService($this->pdo);
    }

    public function testAllRegisteredUsersAreNormalUsers() {
        $result1 = $this->service->register('first_user', 'password123');
        $result2 = $this->service->register('second_user', 'password123');

        $this->assertTrue($result1['success']);
        $this->assertTrue($result2['success']);

        $stmt1 = $this->pdo->query('SELECT role FROM users WHERE username = "first_user"');
        $this->assertEquals('user', $stmt1->fetchColumn());

        $stmt2 = $this->pdo->query('SELECT role FROM users WHERE username = "second_user"');
        $this->assertEquals('user', $stmt2->fetchColumn());
    }

    public function testUsernameValidation() {
        // Too short
        $result = $this->service->register('ab', 'password123');
        $this->assertFalse($result['success']);
        $this->assertEquals('Username must be 3-50 characters and contain only letters, numbers, and underscores.', $result['error']);

        // Invalid characters
        $result = $this->service->register('user!name', 'password123');
        $this->assertFalse($result['success']);
        $this->assertEquals('Username must be 3-50 characters and contain only letters, numbers, and underscores.', $result['error']);

        // Too long
        $longUsername = str_repeat('a', 51);
        $result = $this->service->register($longUsername, 'password123');
        $this->assertFalse($result['success']);
        $this->assertEquals('Username must be 3-50 characters and contain only letters, numbers, and underscores.', $result['error']);
    }

    public function testCannotRegisterDuplicateUsername() {
        $this->service->register('testuser', 'password123');

        $result = $this->service->register('testuser', 'anotherpass123');

        $this->assertFalse($result['success']);
        $this->assertEquals('Registration failed.', $result['error']);
    }

    public function testPasswordLengthValidation() {
        // Too short
        $result = $this->service->register('user1', 'short');
        $this->assertFalse($result['success']);
        $this->assertEquals('Password must be between 8 and 72 characters.', $result['error']);

        // Too long (73 chars)
        $longPass = str_repeat('a', 73);
        $result = $this->service->register('user2', $longPass);
        $this->assertFalse($result['success']);
        $this->assertEquals('Password must be between 8 and 72 characters.', $result['error']);
    }

    public function testEmptyUsernameOrPassword() {
        $result = $this->service->register('', 'password123');
        $this->assertFalse($result['success']);
        $this->assertEquals('Username and password are required.', $result['error']);

        $result = $this->service->register('user', '');
        $this->assertFalse($result['success']);
        $this->assertEquals('Username and password are required.', $result['error']);
    }

    public function testUsernameIsTrimmed() {
        $result = $this->service->register(' spaced_user ', 'password123');

        $this->assertTrue($result['success']);

        $stmt = $this->pdo->query('SELECT username FROM users WHERE username = "spaced_user"');
        $this->assertEquals('spaced_user', $stmt->fetchColumn());
    }

    public function testGeneralDatabaseError() {
        $this->expectOutputRegex('/.*/');
        // Drop the table to trigger a general PDOException (not an integrity constraint violation)
        $this->pdo->exec('DROP TABLE users');

        $result = $this->service->register('testuser', 'password123');

        $this->assertFalse($result['success']);
        $this->assertEquals('Registration failed.', $result['error']);
    }

    public function testDbIntegrityViolationWithMock() {
        $pdoMock = $this->createStub(\PDO::class);
        $stmtMock = $this->createStub(\PDOStatement::class);

        $pdoMock->method('prepare')->willReturn($stmtMock);
        $stmtMock->method('execute')->willThrowException(new \PDOException('Integrity constraint violation', 23000));

        $service = new RegistrationService($pdoMock);
        $result = $service->register('newuser', 'password123');

        $this->assertFalse($result['success']);
        $this->assertEquals('Registration failed.', $result['error']);
    }

    public function testUsernameBoundaryLengths(): void {
        // Test minimum valid username length (3 chars)
        $resultMin = $this->service->register('usr', 'password123');
        $this->assertTrue($resultMin['success']);

        // Test maximum valid username length (50 chars)
        $maxUsername = str_repeat('a', 50);
        $resultMax = $this->service->register($maxUsername, 'password123');
        $this->assertTrue($resultMax['success']);
    }

    public function testPasswordBoundaryLengths(): void {
        // Test minimum valid password length (8 chars)
        $resultMin = $this->service->register('user_p8', 'pass1234');
        $this->assertTrue($resultMin['success']);

        // Test maximum valid password length (72 chars)
        $maxPassword = str_repeat('p', 72);
        $resultMax = $this->service->register('user_p72', $maxPassword);
        $this->assertTrue($resultMax['success']);
    }

    public function testWhitespaceOnlyUsernameReturnsRequiredError(): void {
        $result = $this->service->register('   ', 'password123');
        $this->assertFalse($result['success']);
        $this->assertEquals('Username and password are required.', $result['error']);
    }

    public function testPasswordIsHashedInDatabase(): void {
        $password = 'secret_password_123';
        $result = $this->service->register('hash_user', $password);
        $this->assertTrue($result['success']);

        $stmt = $this->pdo->prepare('SELECT password FROM users WHERE username = ?');
        $stmt->execute(['hash_user']);
        $storedHash = $stmt->fetchColumn();

        $this->assertNotEquals($password, $storedHash);
        $this->assertTrue(password_verify($password, $storedHash));
    }
}
