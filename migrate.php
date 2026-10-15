<?php
if (php_sapi_name() !== 'cli') {
    die("This script can only be run from the command line.\n");
}

require_once __DIR__ . '/db.php';

try {
    $pdo->exec("CREATE TABLE IF NOT EXISTS users (
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

    // Add columns if they do not exist for existing users tables
    $columns = [
        "full_name VARCHAR(255) DEFAULT NULL",
        "personal_details TEXT DEFAULT NULL",
        "profile_picture VARCHAR(255) DEFAULT NULL"
    ];

    $stmt = $pdo->query("SHOW COLUMNS FROM users");
    $existingColumns = $stmt->fetchAll(PDO::FETCH_COLUMN);
    $existingColumnsMap = array_flip($existingColumns);

    $missingColumns = [];
    foreach ($columns as $columnDef) {
        $colName = explode(' ', trim($columnDef))[0];
        if (!isset($existingColumnsMap[$colName])) {
            $missingColumns[] = "ADD COLUMN $columnDef";
        }
    }

    if (!empty($missingColumns)) {
        $pdo->exec("ALTER TABLE users " . implode(', ', $missingColumns));
    }

    $pdo->exec("CREATE TABLE IF NOT EXISTS login_attempts (
        ip_address VARCHAR(255) PRIMARY KEY,
        attempts INT NOT NULL DEFAULT 0,
        last_attempt INT NOT NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;");

    try {
        $pdo->exec("ALTER TABLE login_attempts MODIFY ip_address VARCHAR(255)");
    } catch (\PDOException $e) {
        error_log("Database error migrating login_attempts schema: " . $e->getMessage());
    }

    echo "Migration completed successfully: 'users' and 'login_attempts' tables are ready.\n";
} catch (\PDOException $e) {
    echo "Migration failed: " . $e->getMessage() . "\n";
    exit(1);
}
