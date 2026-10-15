<?php

use PHPUnit\Framework\TestCase;

class CsrfTest extends TestCase
{
    protected function setUp(): void
    {
        // Start session if not started
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }

        // Ensure $_SESSION is reset before each test
        $_SESSION = [];

        // Since require_once only executes once, if we call it again it won't do anything,
        // and if $_SESSION['csrf_token'] was unset, it won't be regenerated.
        // So we need to manually generate it if it's missing just like csrf.php does.
        if (empty($_SESSION['csrf_token'])) {
            $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        }

        // Include the file containing the function we want to test
        require_once __DIR__ . '/../csrf.php';
    }

    public function testVerifyCsrfTokenWithValidToken()
    {
        // Arrange
        $validToken = $_SESSION['csrf_token']; // csrf.php auto-generates this if empty

        // Act & Assert
        // We expect no exception to be thrown
        try {
            verify_csrf_token($validToken);
            $this->assertTrue(true); // If we reach here, it passed
        } catch (Exception $e) {
            $this->fail("Exception was thrown unexpectedly: " . $e->getMessage());
        }
    }

    public function testVerifyCsrfTokenWithInvalidTokenThrowsException()
    {
        // Arrange
        $invalidToken = 'invalid_token_string';

        // Assert
        $this->expectException(Exception::class);
        $this->expectExceptionMessage('Invalid CSRF token.');

        // Act
        verify_csrf_token($invalidToken);
    }

    public function testVerifyCsrfTokenWithMissingTokenThrowsException()
    {
        // Assert
        $this->expectException(Exception::class);
        $this->expectExceptionMessage('Invalid CSRF token.');

        // Act
        verify_csrf_token(null);
    }

    public function testVerifyCsrfTokenWithNonStringTokenThrowsException()
    {
        // Arrange
        $nonStringToken = ['this', 'is', 'an', 'array'];

        // Assert
        $this->expectException(Exception::class);
        $this->expectExceptionMessage('Invalid CSRF token.');

        // Act
        verify_csrf_token($nonStringToken);
    }

    public function testValidateCsrfTokenWithValidTokenReturnsNull()
    {
        $validToken = $_SESSION['csrf_token'];
        $this->assertNull(validate_csrf_token($validToken));
    }

    public function testValidateCsrfTokenWithInvalidTokenReturnsErrorMessage()
    {
        $result = validate_csrf_token('invalid_token');
        $this->assertEquals('Invalid CSRF token. Please refresh the page and try again.', $result);
    }
}
