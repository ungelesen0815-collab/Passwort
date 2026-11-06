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
        $addedAny = false;

        if (!isset($existingMap['can_use_password_generator'])) {
            $pdo->exec("ALTER TABLE users ADD COLUMN can_use_password_generator TINYINT(1) NOT NULL DEFAULT 1");
            $addedAny = true;
        }
        if (!isset($existingMap['can_use_vault'])) {
            $pdo->exec("ALTER TABLE users ADD COLUMN can_use_vault TINYINT(1) NOT NULL DEFAULT 0");
            $addedAny = true;
        }
        if (!isset($existingMap['can_use_crypt_share'])) {
            $pdo->exec("ALTER TABLE users ADD COLUMN can_use_crypt_share TINYINT(1) NOT NULL DEFAULT 0");
            $addedAny = true;
        }

        if ($addedAny) {
            // Existing users retain all features
            $pdo->exec("UPDATE users SET can_use_password_generator = 1, can_use_vault = 1, can_use_crypt_share = 1");
        }

        $checkedPdo = $pdo;
    } catch (\Throwable $e) {
        // Ignore if table does not exist yet or cannot be altered
    }
}

function extract_permissions_from_user_row(array $user): array {
    if (($user['role'] ?? 'user') === 'admin') {
        return [
            'password_generator' => true,
            'vault' => true,
            'crypt_share' => true,
        ];
    }

    return [
        'password_generator' => array_key_exists('can_use_password_generator', $user) ? !empty($user['can_use_password_generator']) : true,
        'vault' => array_key_exists('can_use_vault', $user) ? !empty($user['can_use_vault']) : true,
        'crypt_share' => array_key_exists('can_use_crypt_share', $user) ? !empty($user['can_use_crypt_share']) : true,
    ];
}

function get_user_permissions(PDO $pdo, int|string $userId, string $role = 'user'): array {
    if ($role === 'admin') {
        $perms = [
            'password_generator' => true,
            'vault' => true,
            'crypt_share' => true,
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
