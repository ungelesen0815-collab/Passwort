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
        profile_picture VARCHAR(255) DEFAULT NULL,
        can_use_password_generator TINYINT(1) NOT NULL DEFAULT 1,
        can_use_vault TINYINT(1) NOT NULL DEFAULT 0,
        can_use_crypt_share TINYINT(1) NOT NULL DEFAULT 0,
        can_use_secure_notes TINYINT(1) NOT NULL DEFAULT 0
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;");

    // Add columns if they do not exist for existing users tables
    $columns = [
        "full_name VARCHAR(255) DEFAULT NULL",
        "personal_details TEXT DEFAULT NULL",
        "profile_picture VARCHAR(255) DEFAULT NULL",
        "can_use_password_generator TINYINT(1) NOT NULL DEFAULT 1",
        "can_use_vault TINYINT(1) NOT NULL DEFAULT 0",
        "can_use_crypt_share TINYINT(1) NOT NULL DEFAULT 0",
        "can_use_secure_notes TINYINT(1) NOT NULL DEFAULT 0"
    ];

    $stmt = $pdo->query("SHOW COLUMNS FROM users");
    $existingColumns = $stmt->fetchAll(PDO::FETCH_COLUMN);
    $existingColumnsMap = array_flip($existingColumns);

    $hadFeatureColumns = isset($existingColumnsMap['can_use_password_generator'])
        && isset($existingColumnsMap['can_use_vault'])
        && isset($existingColumnsMap['can_use_crypt_share']);
    $hadSecureNotesColumn = isset($existingColumnsMap['can_use_secure_notes']);

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

    if (!$hadFeatureColumns) {
        // Existing users keep all features when migrating
        $pdo->exec("UPDATE users SET can_use_password_generator = 1, can_use_vault = 1, can_use_crypt_share = 1, can_use_secure_notes = 1");
    } elseif (!$hadSecureNotesColumn) {
        // Existing users get the newly added Secure Notes feature enabled
        $pdo->exec("UPDATE users SET can_use_secure_notes = 1");
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

    $pdo->exec("CREATE TABLE IF NOT EXISTS vaults (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        name VARCHAR(255) NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;");

    $pdo->exec("CREATE TABLE IF NOT EXISTS vault_items (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        item_type ENUM('password', 'keyfile', 'certificate') NOT NULL,
        title VARCHAR(255) NOT NULL,
        category VARCHAR(100) NOT NULL DEFAULT '',
        is_favorite TINYINT(1) NOT NULL DEFAULT 0,
        encrypted_data LONGTEXT NOT NULL,
        iv VARCHAR(255) NOT NULL,
        salt VARCHAR(255) NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;");

    // Check if category and is_favorite exist in vault_items
    $stmtVaultCols = $pdo->query("SHOW COLUMNS FROM vault_items");
    $existingVaultCols = array_flip($stmtVaultCols->fetchAll(PDO::FETCH_COLUMN));
    if (!isset($existingVaultCols['category'])) {
        $pdo->exec("ALTER TABLE vault_items ADD COLUMN category VARCHAR(100) NOT NULL DEFAULT '' AFTER title");
    }
    if (!isset($existingVaultCols['is_favorite'])) {
        $pdo->exec("ALTER TABLE vault_items ADD COLUMN is_favorite TINYINT(1) NOT NULL DEFAULT 0 AFTER category");
    }

    $pdo->exec("CREATE TABLE IF NOT EXISTS vault_item_history (
        id INT AUTO_INCREMENT PRIMARY KEY,
        vault_item_id INT NOT NULL,
        user_id INT NOT NULL,
        encrypted_data LONGTEXT NOT NULL,
        iv VARCHAR(255) NOT NULL,
        salt VARCHAR(255) NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (vault_item_id) REFERENCES vault_items(id) ON DELETE CASCADE,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;");

    // Check if vault_id exists in vault_items
    $stmt = $pdo->query("SHOW COLUMNS FROM vault_items LIKE 'vault_id'");
    $hasVaultId = $stmt->fetch();

    if (!$hasVaultId) {
        // Create default vault for all users who have items or just existing users
        $pdo->exec("INSERT INTO vaults (user_id, name) SELECT id, 'Default Vault' FROM users");

        // Add vault_id to this user's existing vault_items
        // Temporarily we can't do this easily before column exists, so let's add column first allowing null, then update, then modify to not null
        $pdo->exec("ALTER TABLE vault_items ADD COLUMN vault_id INT NULL");

        // Update vault_items with newly created default vaults
        $pdo->exec("
            UPDATE vault_items vi
            INNER JOIN vaults v ON vi.user_id = v.user_id AND v.name = 'Default Vault'
            SET vi.vault_id = v.id
            WHERE vi.vault_id IS NULL
        ");

        // Any orphaned items?
        // Let's create a generic vault for them if they exist but their user somehow doesn't have a default vault
        // First find items with null vault_id
        $orphanedStmt = $pdo->query("SELECT DISTINCT user_id FROM vault_items WHERE vault_id IS NULL");
        $orphanedUsers = $orphanedStmt->fetchAll(PDO::FETCH_ASSOC);
        foreach ($orphanedUsers as $orphan) {
            $userId = $orphan['user_id'];
            $insertVaultStmt = $pdo->prepare("INSERT INTO vaults (user_id, name) VALUES (?, 'Default Vault')");
            $insertVaultStmt->execute([$userId]);
            $vaultId = $pdo->lastInsertId();

            $updateStmt = $pdo->prepare("UPDATE vault_items SET vault_id = ? WHERE user_id = ? AND vault_id IS NULL");
            $updateStmt->execute([$vaultId, $userId]);
        }

        // Now set vault_id to NOT NULL
        // First delete any that STILL have null just to be safe (should be none)
        $pdo->exec("DELETE FROM vault_items WHERE vault_id IS NULL");
        $pdo->exec("ALTER TABLE vault_items MODIFY COLUMN vault_id INT NOT NULL");

        // Add foreign key constraint
        $pdo->exec("ALTER TABLE vault_items ADD CONSTRAINT fk_vault_id FOREIGN KEY (vault_id) REFERENCES vaults(id) ON DELETE CASCADE");
    }

    $pdo->exec("CREATE TABLE IF NOT EXISTS crypt_shares (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        file_name VARCHAR(255) NOT NULL,
        encrypted_data LONGTEXT NOT NULL,
        iv VARCHAR(255) NOT NULL,
        salt VARCHAR(255) NOT NULL,
        access_token VARCHAR(255) UNIQUE NOT NULL,
        pin_hash VARCHAR(255) DEFAULT NULL,
        max_views INT NOT NULL DEFAULT 1,
        view_count INT NOT NULL DEFAULT 0,
        expires_at DATETIME NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;");

    // Check if pin_hash, max_views, view_count exist in crypt_shares
    $stmtShareCols = $pdo->query("SHOW COLUMNS FROM crypt_shares");
    $existingShareCols = array_flip($stmtShareCols->fetchAll(PDO::FETCH_COLUMN));
    if (!isset($existingShareCols['pin_hash'])) {
        $pdo->exec("ALTER TABLE crypt_shares ADD COLUMN pin_hash VARCHAR(255) DEFAULT NULL AFTER access_token");
    }
    if (!isset($existingShareCols['max_views'])) {
        $pdo->exec("ALTER TABLE crypt_shares ADD COLUMN max_views INT NOT NULL DEFAULT 1 AFTER pin_hash");
    }
    if (!isset($existingShareCols['view_count'])) {
        $pdo->exec("ALTER TABLE crypt_shares ADD COLUMN view_count INT NOT NULL DEFAULT 0 AFTER max_views");
    }

    $pdo->exec("CREATE TABLE IF NOT EXISTS secure_notes (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        note_type VARCHAR(50) NOT NULL DEFAULT 'note',
        title VARCHAR(255) NOT NULL,
        encrypted_data LONGTEXT NOT NULL,
        iv VARCHAR(255) NOT NULL,
        salt VARCHAR(255) NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;");

    echo "Migration completed successfully: 'users', 'login_attempts', 'vaults', 'vault_items', and 'crypt_shares' tables are ready.\n";
} catch (\PDOException $e) {
    echo "Migration failed: " . $e->getMessage() . "\n";
    exit(1);
}
