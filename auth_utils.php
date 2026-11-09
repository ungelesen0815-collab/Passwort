<?php

function get_client_ip(): string {
    $remote_addr = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';

    $trusted_proxies_env = $_ENV['TRUSTED_PROXIES'] ?? getenv('TRUSTED_PROXIES') ?: '';
    if (empty($trusted_proxies_env)) {
        return $remote_addr;
    }

    static $cached_env = null;
    static $trusted_proxies_map = [];

    if ($cached_env !== $trusted_proxies_env) {
        $cached_env = $trusted_proxies_env;
        $trusted_proxies = array_filter(array_map('trim', explode(',', $trusted_proxies_env)), fn($ip) => $ip !== '');
        $trusted_proxies_map = array_flip($trusted_proxies);
    }

    if (!isset($trusted_proxies_map[$remote_addr])) {
        return $remote_addr;
    }

    if (!empty($_SERVER['HTTP_X_FORWARDED_FOR']) && is_string($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $raw_ips = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
        for ($i = count($raw_ips) - 1; $i >= 0; $i--) {
            $ip = trim($raw_ips[$i]);
            if ($ip === '') {
                continue;
            }
            if (isset($trusted_proxies_map[$ip])) {
                continue;
            }
            if (filter_var($ip, FILTER_VALIDATE_IP)) {
                return $ip;
            }
            return $remote_addr;
        }
    }

    return $remote_addr;
}

function increment_login_attempts(PDO $pdo, string $identifier, int $current_time): int {
    if ($pdo->getAttribute(PDO::ATTR_DRIVER_NAME) === 'sqlite') {
        $stmt = $pdo->prepare('INSERT INTO login_attempts (ip_address, attempts, last_attempt) VALUES (?, 1, ?) ON CONFLICT(ip_address) DO UPDATE SET attempts = CASE WHEN ? - last_attempt > 300 THEN 1 ELSE attempts + 1 END, last_attempt = ? RETURNING attempts');
        $stmt->execute([$identifier, $current_time, $current_time, $current_time]);
        return (int)$stmt->fetchColumn();
    }

    $stmt = $pdo->prepare('INSERT INTO login_attempts (ip_address, attempts, last_attempt) VALUES (?, LAST_INSERT_ID(1), ?) ON DUPLICATE KEY UPDATE attempts = LAST_INSERT_ID(IF(? - last_attempt > 300, 1, attempts + 1)), last_attempt = ?');
    $stmt->execute([$identifier, $current_time, $current_time, $current_time]);

    return (int)$pdo->lastInsertId();
}

function is_rate_limited(PDO $pdo, array $identifiers, int $current_time, int $max_attempts = 5): bool {
    if (empty($identifiers)) {
        return false;
    }

    $unique_identifiers = array_values(array_unique($identifiers));

    $placeholders = implode(',', array_fill(0, count($unique_identifiers), '?'));
    $cutoff = $current_time - 300;

    $update_params = array_merge([$current_time], $unique_identifiers, [$cutoff]);
    $update_stmt = $pdo->prepare("UPDATE login_attempts SET attempts = 0, last_attempt = ? WHERE ip_address IN ($placeholders) AND last_attempt < ?");
    $update_stmt->execute($update_params);

    $select_params = array_merge($unique_identifiers, [$max_attempts]);
    $select_stmt = $pdo->prepare("SELECT 1 FROM login_attempts WHERE ip_address IN ($placeholders) AND attempts >= ? LIMIT 1");
    $select_stmt->execute($select_params);

    return (bool)$select_stmt->fetchColumn();
}

function clear_login_attempts(PDO $pdo, string $identifier): void {
    $stmt = $pdo->prepare('DELETE FROM login_attempts WHERE ip_address = ?');
    $stmt->execute([$identifier]);
}

function get_user_by_id(PDO $pdo, int|string $id): array|false {
    $stmt = $pdo->prepare('SELECT * FROM users WHERE id = ?');
    $stmt->execute([$id]);
    return $stmt->fetch();
}

function ensure_user_feature_columns(PDO $pdo): void {
    static $checkedPdo = null;
    if ($checkedPdo === $pdo) {
        return;
    }

    try {
        $driver = $pdo->getAttribute(PDO::ATTR_DRIVER_NAME);
        if ($driver === 'sqlite') {
            $stmt = $pdo->query("PRAGMA table_info(users)");
            $cols = $stmt ? $stmt->fetchAll(PDO::FETCH_ASSOC) : [];
            if (empty($cols)) {
                return;
            }
            $existing = array_column($cols, 'name');
        } else {
            $stmt = $pdo->query("SHOW COLUMNS FROM users");
            $existing = $stmt ? $stmt->fetchAll(PDO::FETCH_COLUMN) : [];
        }

        $existingMap = array_flip($existing);
        $addedBaseFeatures = false;
        $addedSecureNotes = false;
        $addedTotp = false;
        $addedAudit = false;

        if (!isset($existingMap['can_use_password_generator'])) {
            $pdo->exec("ALTER TABLE users ADD COLUMN can_use_password_generator TINYINT(1) NOT NULL DEFAULT 1");
            $addedBaseFeatures = true;
        }
        if (!isset($existingMap['can_use_vault'])) {
            $pdo->exec("ALTER TABLE users ADD COLUMN can_use_vault TINYINT(1) NOT NULL DEFAULT 0");
            $addedBaseFeatures = true;
        }
        if (!isset($existingMap['can_use_crypt_share'])) {
            $pdo->exec("ALTER TABLE users ADD COLUMN can_use_crypt_share TINYINT(1) NOT NULL DEFAULT 0");
            $addedBaseFeatures = true;
        }
        if (!isset($existingMap['can_use_secure_notes'])) {
            $pdo->exec("ALTER TABLE users ADD COLUMN can_use_secure_notes TINYINT(1) NOT NULL DEFAULT 0");
            $addedSecureNotes = true;
        }
        if (!isset($existingMap['can_use_totp'])) {
            $pdo->exec("ALTER TABLE users ADD COLUMN can_use_totp TINYINT(1) NOT NULL DEFAULT 0");
            $addedTotp = true;
        }
        if (!isset($existingMap['can_use_security_audit'])) {
            $pdo->exec("ALTER TABLE users ADD COLUMN can_use_security_audit TINYINT(1) NOT NULL DEFAULT 0");
            $addedAudit = true;
        }

        if ($addedBaseFeatures) {
            // Existing users retain all features
            $pdo->exec("UPDATE users SET can_use_password_generator = 1, can_use_vault = 1, can_use_crypt_share = 1, can_use_secure_notes = 1, can_use_totp = 1, can_use_security_audit = 1");
        } else {
            if ($addedSecureNotes) {
                $pdo->exec("UPDATE users SET can_use_secure_notes = 1");
            }
            if ($addedTotp) {
                $pdo->exec("UPDATE users SET can_use_totp = 1");
            }
            if ($addedAudit) {
                $pdo->exec("UPDATE users SET can_use_security_audit = 1");
            }
        }

        $checkedPdo = $pdo;
    } catch (\Throwable $e) {
        // Ignore if table does not exist yet or cannot be altered
    }
}

function ensure_secure_notes_table(PDO $pdo): void {
    static $checkedNotesPdo = null;
    if ($checkedNotesPdo === $pdo) {
        return;
    }

    try {
        $driver = $pdo->getAttribute(PDO::ATTR_DRIVER_NAME);
        if ($driver === 'sqlite') {
            $pdo->exec("CREATE TABLE IF NOT EXISTS secure_notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                note_type VARCHAR(50) NOT NULL DEFAULT 'note',
                title VARCHAR(255) NOT NULL,
                encrypted_data TEXT NOT NULL,
                iv VARCHAR(255) NOT NULL,
                salt VARCHAR(255) NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )");
        } else {
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
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
        }
        $checkedNotesPdo = $pdo;
    } catch (\Throwable $e) {
        // Ignore if table cannot be created automatically
    }
}

function ensure_vault_enhancements_schema(PDO $pdo): void {
    static $checkedVaultPdo = null;
    if ($checkedVaultPdo === $pdo) {
        return;
    }

    try {
        $driver = $pdo->getAttribute(PDO::ATTR_DRIVER_NAME);
        if ($driver === 'sqlite') {
            $stmt = $pdo->query("PRAGMA table_info(vault_items)");
            $cols = $stmt ? $stmt->fetchAll(PDO::FETCH_ASSOC) : [];
            if (!empty($cols)) {
                $existing = array_flip(array_column($cols, 'name'));
                if (!isset($existing['category'])) {
                    $pdo->exec("ALTER TABLE vault_items ADD COLUMN category VARCHAR(100) NOT NULL DEFAULT ''");
                }
                if (!isset($existing['is_favorite'])) {
                    $pdo->exec("ALTER TABLE vault_items ADD COLUMN is_favorite TINYINT(1) NOT NULL DEFAULT 0");
                }
            }

            $pdo->exec("CREATE TABLE IF NOT EXISTS vault_item_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                vault_item_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                encrypted_data TEXT NOT NULL,
                iv VARCHAR(255) NOT NULL,
                salt VARCHAR(255) NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (vault_item_id) REFERENCES vault_items(id) ON DELETE CASCADE,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )");
        } else {
            $stmt = $pdo->query("SHOW COLUMNS FROM vault_items");
            $cols = $stmt ? $stmt->fetchAll(PDO::FETCH_COLUMN) : [];
            if (!empty($cols)) {
                $existing = array_flip($cols);
                if (!isset($existing['category'])) {
                    $pdo->exec("ALTER TABLE vault_items ADD COLUMN category VARCHAR(100) NOT NULL DEFAULT '' AFTER title");
                }
                if (!isset($existing['is_favorite'])) {
                    $pdo->exec("ALTER TABLE vault_items ADD COLUMN is_favorite TINYINT(1) NOT NULL DEFAULT 0 AFTER category");
                }
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
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
        }
        $checkedVaultPdo = $pdo;
    } catch (\Throwable $e) {
        // Ignore if table does not exist yet or cannot be altered automatically
    }
}

function ensure_crypt_shares_enhancements_schema(PDO $pdo): void {
    static $checkedSharesPdo = null;
    if ($checkedSharesPdo === $pdo) {
        return;
    }

    try {
        $driver = $pdo->getAttribute(PDO::ATTR_DRIVER_NAME);
        if ($driver === 'sqlite') {
            $stmt = $pdo->query("PRAGMA table_info(crypt_shares)");
            $cols = $stmt ? $stmt->fetchAll(PDO::FETCH_ASSOC) : [];
            if (!empty($cols)) {
                $existing = array_flip(array_column($cols, 'name'));
                if (!isset($existing['pin_hash'])) {
                    $pdo->exec("ALTER TABLE crypt_shares ADD COLUMN pin_hash VARCHAR(255) DEFAULT NULL");
                }
                if (!isset($existing['max_views'])) {
                    $pdo->exec("ALTER TABLE crypt_shares ADD COLUMN max_views INT NOT NULL DEFAULT 1");
                }
                if (!isset($existing['view_count'])) {
                    $pdo->exec("ALTER TABLE crypt_shares ADD COLUMN view_count INT NOT NULL DEFAULT 0");
                }
            }
        } else {
            $stmt = $pdo->query("SHOW COLUMNS FROM crypt_shares");
            $cols = $stmt ? $stmt->fetchAll(PDO::FETCH_COLUMN) : [];
            if (!empty($cols)) {
                $existing = array_flip($cols);
                if (!isset($existing['pin_hash'])) {
                    $pdo->exec("ALTER TABLE crypt_shares ADD COLUMN pin_hash VARCHAR(255) DEFAULT NULL AFTER access_token");
                }
                if (!isset($existing['max_views'])) {
                    $pdo->exec("ALTER TABLE crypt_shares ADD COLUMN max_views INT NOT NULL DEFAULT 1 AFTER pin_hash");
                }
                if (!isset($existing['view_count'])) {
                    $pdo->exec("ALTER TABLE crypt_shares ADD COLUMN view_count INT NOT NULL DEFAULT 0 AFTER max_views");
                }
            }
        }
        $checkedSharesPdo = $pdo;
    } catch (\Throwable $e) {
        // Ignore if table does not exist yet or cannot be altered automatically
    }
}

function generate_qr_svg_data_uri(string $content, int $size = 200): string {
    if ($content === '') {
        return '';
    }

    try {
        if (!class_exists(\BaconQrCode\Writer::class)) {
            $autoloadPath = __DIR__ . '/vendor/autoload.php';
            if (file_exists($autoloadPath)) {
                require_once $autoloadPath;
            }
        }

        if (class_exists(\BaconQrCode\Writer::class) && class_exists(\BaconQrCode\Renderer\ImageRenderer::class)) {
            $renderer = new \BaconQrCode\Renderer\ImageRenderer(
                new \BaconQrCode\Renderer\RendererStyle\RendererStyle($size, 2),
                new \BaconQrCode\Renderer\Image\SvgImageBackEnd()
            );
            $writer = new \BaconQrCode\Writer($renderer);
            $svg = $writer->writeString($content);
            return 'data:image/svg+xml;base64,' . base64_encode($svg);
        }
    } catch (\Throwable $e) {
        error_log("QR Code generation error: " . $e->getMessage());
    }

    return '';
}

function ensure_totp_entries_table(PDO $pdo): void {
    static $checkedTotpPdo = null;
    if ($checkedTotpPdo === $pdo) {
        return;
    }

    try {
        $driver = $pdo->getAttribute(PDO::ATTR_DRIVER_NAME);
        if ($driver === 'sqlite') {
            $pdo->exec("CREATE TABLE IF NOT EXISTS totp_entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                issuer VARCHAR(255) NOT NULL DEFAULT '',
                account_name VARCHAR(255) NOT NULL,
                category VARCHAR(100) NOT NULL DEFAULT '',
                encrypted_data TEXT NOT NULL,
                iv VARCHAR(255) NOT NULL,
                salt VARCHAR(255) NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )");
        } else {
            $pdo->exec("CREATE TABLE IF NOT EXISTS totp_entries (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                issuer VARCHAR(255) NOT NULL DEFAULT '',
                account_name VARCHAR(255) NOT NULL,
                category VARCHAR(100) NOT NULL DEFAULT '',
                encrypted_data LONGTEXT NOT NULL,
                iv VARCHAR(255) NOT NULL,
                salt VARCHAR(255) NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
        }
        $checkedTotpPdo = $pdo;
    } catch (\Throwable $e) {
        // Ignore if table cannot be created automatically
    }
}

function extract_permissions_from_user_row(array $user): array {
    if (($user['role'] ?? 'user') === 'admin') {
        return [
            'password_generator' => true,
            'vault' => true,
            'crypt_share' => true,
            'secure_notes' => true,
            'totp' => true,
            'security_audit' => true,
        ];
    }

    return [
        'password_generator' => array_key_exists('can_use_password_generator', $user) ? !empty($user['can_use_password_generator']) : true,
        'vault' => array_key_exists('can_use_vault', $user) ? !empty($user['can_use_vault']) : true,
        'crypt_share' => array_key_exists('can_use_crypt_share', $user) ? !empty($user['can_use_crypt_share']) : true,
        'secure_notes' => array_key_exists('can_use_secure_notes', $user) ? !empty($user['can_use_secure_notes']) : true,
        'totp' => array_key_exists('can_use_totp', $user) ? !empty($user['can_use_totp']) : true,
        'security_audit' => array_key_exists('can_use_security_audit', $user) ? !empty($user['can_use_security_audit']) : true,
    ];
}

function get_user_permissions(PDO $pdo, int|string $userId, string $role = 'user'): array {
    if ($role === 'admin') {
        $perms = [
            'password_generator' => true,
            'vault' => true,
            'crypt_share' => true,
            'secure_notes' => true,
            'totp' => true,
            'security_audit' => true,
        ];
        $_SESSION['permissions'] = $perms;
        return $perms;
    }

    try {
        ensure_user_feature_columns($pdo);
        $user = get_user_by_id($pdo, $userId);
        if (is_array($user)) {
            $perms = extract_permissions_from_user_row($user);
            $_SESSION['permissions'] = $perms;
            return $perms;
        }
    } catch (\Throwable $e) {
        // Fallback to session permissions or default on DB error
    }

    return $_SESSION['permissions'] ?? [
        'password_generator' => true,
        'vault' => true,
        'crypt_share' => true,
        'secure_notes' => true,
        'totp' => true,
        'security_audit' => true,
    ];
}

function user_has_feature(PDO $pdo, int|string $userId, string $feature, string $role = 'user'): bool {
    $perms = get_user_permissions($pdo, $userId, $role);
    return !empty($perms[$feature]);
}

function get_mfa_encryption_key(): ?string {
    $rawKey = $_ENV['MFA_ENCRYPTION_KEY'] ?? getenv('MFA_ENCRYPTION_KEY') ?: '';
    if (!is_string($rawKey) || trim($rawKey) === '') {
        return null;
    }
    return hash('sha256', trim($rawKey), true);
}

function encrypt_mfa_secret(string $secret): string {
    $key = get_mfa_encryption_key();
    if ($key === null || $secret === '') {
        return $secret;
    }

    $iv = random_bytes(12);
    $tag = '';
    $ciphertext = openssl_encrypt($secret, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag, '', 16);
    if ($ciphertext === false) {
        return $secret;
    }

    return 'enc:v1:' . base64_encode($iv . $tag . $ciphertext);
}

function decrypt_mfa_secret(?string $storedSecret): string {
    if (!is_string($storedSecret) || $storedSecret === '') {
        return '';
    }

    if (!str_starts_with($storedSecret, 'enc:v1:')) {
        return $storedSecret;
    }

    $key = get_mfa_encryption_key();
    if ($key === null) {
        throw new RuntimeException('MFA_ENCRYPTION_KEY is required to decrypt stored MFA secret.');
    }

    $decoded = base64_decode(substr($storedSecret, 7), true);
    if ($decoded === false || strlen($decoded) <= 28) {
        throw new RuntimeException('Invalid encrypted MFA secret payload.');
    }

    $iv = substr($decoded, 0, 12);
    $tag = substr($decoded, 12, 16);
    $ciphertext = substr($decoded, 28);

    $plaintext = openssl_decrypt($ciphertext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);
    if ($plaintext === false) {
        throw new RuntimeException('Failed to decrypt MFA secret.');
    }

    return $plaintext;
}
