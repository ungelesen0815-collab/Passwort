<?php

if (php_sapi_name() !== 'cli') {
    exit("This script can only be run from the command line.\n");
}

if ($argc !== 3) {
    echo "Usage: php create_admin.php <username> <password>\n";
    exit(1);
}

$username = trim($argv[1]);
$password = $argv[2];

if ($username === '' || $password === '') {
    echo "Username and password are required.\n";
    exit(1);
}

if (strlen($password) < 8 || strlen($password) > 72) {
    echo "Password must be between 8 and 72 characters.\n";
    exit(1);
}

require_once __DIR__ . '/db.php';

$hashedPassword = password_hash($password, PASSWORD_DEFAULT);

try {
    $stmt = $pdo->prepare("INSERT INTO users (username, password, role) VALUES (?, ?, 'admin')");
    $stmt->execute([$username, $hashedPassword]);
    echo "Admin user '{$username}' created successfully.\n";
} catch (\PDOException $e) {
    if ($e->getCode() == 23000) {
        echo "Error: Username '{$username}' already exists.\n";
    } else {
        echo "Error creating admin user: " . $e->getMessage() . "\n";
    }
    exit(1);
}
