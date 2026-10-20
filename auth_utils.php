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

    $driver = $pdo->getAttribute(PDO::ATTR_DRIVER_NAME);
    if ($driver === 'sqlite') {
        $stmt = $pdo->prepare('INSERT INTO login_attempts (ip_address, attempts, last_attempt) VALUES (?, 1, ?) ON CONFLICT(ip_address) DO UPDATE SET attempts = CASE WHEN ? - last_attempt > 300 THEN 1 ELSE attempts + 1 END, last_attempt = ?');
        $stmt->execute([$identifier, $current_time, $current_time, $current_time]);
    } else {
        $stmt = $pdo->prepare('INSERT INTO login_attempts (ip_address, attempts, last_attempt) VALUES (?, LAST_INSERT_ID(1), ?) ON DUPLICATE KEY UPDATE attempts = LAST_INSERT_ID(IF(? - last_attempt > 300, 1, attempts + 1)), last_attempt = ?');
        $stmt->execute([$identifier, $current_time, $current_time, $current_time]);
    }

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
