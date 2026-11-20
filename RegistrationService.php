<?php

class RegistrationService {
    public const COMMON_PASSWORDS = [
        'password', 'passwort', '12345678', '123456789', '1234567890',
        'qwertyui', 'asdfghjk', '11111111', 'admin1234', 'welcome123'
    ];

    private \PDO $pdo;

    public function __construct(\PDO $pdo) {
        $this->pdo = $pdo;
    }

    public function register(string $username, string $password): array {
        $username = trim($username);

        if ($username === '' || $password === '') {
            return ['success' => false, 'error' => 'Username and password are required.'];
        }

        if (!preg_match('/^[a-zA-Z0-9_]{3,50}$/', $username)) {
            return ['success' => false, 'error' => 'Username must be 3-50 characters and contain only letters, numbers, and underscores.'];
        }

        $passwordLen = strlen($password);
        if ($passwordLen < 8 || $passwordLen > 72) {
            return ['success' => false, 'error' => 'Password must be between 8 and 72 characters.'];
        }

        if (in_array(strtolower($password), self::COMMON_PASSWORDS, true)) {
            return ['success' => false, 'error' => 'This password is too common and easily guessed. Please choose a stronger password.'];
        }

        $role = 'user';

        $algo = defined('PASSWORD_ARGON2ID') ? PASSWORD_ARGON2ID : PASSWORD_DEFAULT;
        $hashedPassword = password_hash($password, $algo);

        try {
            $stmt = $this->pdo->prepare('INSERT INTO users (username, password, role) VALUES (?, ?, ?)');
            $stmt->execute([$username, $hashedPassword, $role]);

            $cacheFile = __DIR__ . '/cache/admin_user_count.cache';
            if (file_exists($cacheFile)) {
                @unlink($cacheFile);
            }

            return ['success' => true, 'error' => ''];
        } catch (\PDOException $e) {
            if ($e->getCode() == 23000) { // Integrity constraint violation
                return ['success' => false, 'error' => 'Registration failed.'];
            } else {
                error_log("Database error in RegistrationService: " . $e->getMessage());
                return ['success' => false, 'error' => 'Registration failed.'];
            }
        }
    }
}
