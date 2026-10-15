<?php
require_once __DIR__ . '/vendor/autoload.php';

$envFile = __DIR__ . '/.env';
if (file_exists($envFile)) {
    $dotenv = Dotenv\Dotenv::createImmutable(__DIR__);
    $dotenv->load();
}

if (!isset($_ENV['DB_HOST'])) {
    throw new RuntimeException("Database host (DB_HOST) must be set in the environment.");
}
$host = $_ENV['DB_HOST'];

if (!isset($_ENV['DB_NAME'])) {
    throw new RuntimeException("Database name (DB_NAME) must be set in the environment.");
}
$db = $_ENV['DB_NAME'];

if (!isset($_ENV['DB_USER'])) {
    throw new RuntimeException("Database user (DB_USER) must be set in the environment.");
}
$user = $_ENV['DB_USER'];

// Security check: Never fallback to a hardcoded password
if (!isset($_ENV['DB_PASS'])) {
    throw new RuntimeException("Database password (DB_PASS) must be set in the environment.");
}
$pass = $_ENV['DB_PASS'];
$charset = 'utf8mb4';

$dsn = "mysql:host=$host;dbname=$db;charset=$charset";
$options = [
    PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    PDO::ATTR_EMULATE_PREPARES   => false,
];

try {
    $pdo = new PDO($dsn, $user, $pass, $options);
} catch (\PDOException $e) {
    error_log("Database connection failed: " . $e->getMessage());
    throw new \Exception("A database error occurred. Please contact the administrator.");
}
