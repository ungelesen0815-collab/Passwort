CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    role ENUM('admin', 'user') NOT NULL DEFAULT 'user',
    mfa_secret VARCHAR(255) DEFAULT NULL,
    mfa_enabled TINYINT(1) DEFAULT 0,
    full_name VARCHAR(255) DEFAULT NULL,
    personal_details TEXT DEFAULT NULL,
    profile_picture VARCHAR(255) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS login_attempts (
    ip_address VARCHAR(255) PRIMARY KEY,
    attempts INT NOT NULL DEFAULT 0,
    last_attempt INT NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
