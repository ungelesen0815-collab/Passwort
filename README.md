# PHP MySQL Dashboard Application

This is a central dashboard application built with PHP, MySQL, and Bootstrap. It features user registration, login, role management (user/admin), and optional Multi-Factor Authentication (MFA).

## Features

- **Registration & Login:** Secure authentication with password hashing.
- **Role Management:** New users are assigned the `user` role. The initial `admin` must be provisioned via a command-line script. Admins can promote other users to the `admin` role via the Admin Panel.
- **MFA (Multi-Factor Authentication):** Users can optionally enable MFA (TOTP) using authenticator apps like Google Authenticator or Authy.
- **Vault:** Store passwords and certificates end-to-end encrypted.
- **Password Generator:** Generate secure, random passwords with customizable options.
- **Profile Management:** Manage personal information and profile picture.
- **Crypt Share:** Teilen Sie Dateien sicher und verschlüsselt mit anderen. (Share files securely and encrypted with others.)
- **Secure:** Includes CSRF protection for sensitive actions and enforces HTTPS transmission (via `.htaccess`).

## Requirements

- PHP 8.1 or higher (with PDO extension)
- MySQL / MariaDB
- Composer (for dependency management)
- Apache (for `.htaccess` HTTPS redirection support) or equivalent server configuration

## Installation and Setup

When deploying this application to a server, follow these steps:

1. **Clone the repository or copy the files to your web server root.**
   Ensure the files are located in your web directory (e.g., `/var/www/html/` or similar).

2. **Install Dependencies via Composer:**
   Because third-party packages (like the MFA and QR Code libraries) are not included in the repository (ignored via `.gitignore`), you **must** run `composer install`.
   Navigate to the project directory on your server and run:
   ```bash
   composer install
   ```
   *Note: If you get a "Failed to open stream: No such file or directory" error for `vendor/autoload.php`, it means you skipped this step.*

3. **Configure the Environment:**
   Copy the provided example environment file and create your own `.env` file:
   ```bash
   cp .env.example .env
   ```
   Edit the `.env` file and enter your database connection details:
   ```env
   DB_HOST=127.0.0.1
   DB_NAME=your_database_name
   DB_USER=your_database_user
   DB_PASS=your_database_password
   ```

4. **Database Setup:**
   Run the migration script to initialize the database tables. Ensure your database user has sufficient privileges (`CREATE TABLE`).
   ```bash
   php migrate.php
   ```

5. **First Login / Admin Creation:**
   Run the following command in your terminal to create the initial admin user:
   ```bash
   php create_admin.php <username> <password>
   ```
   After creating the admin user, you can navigate to `login.php` in your browser to log in.

## Troubleshooting

- **`vendor/autoload.php` missing:** Run `composer install` in the project directory.
- **Database connection errors:** Verify that your `.env` file exists, is readable by the web server, and contains the correct credentials.
- **HTTPS Redirection issues:** Ensure your server supports `.htaccess` overrides (e.g., `AllowOverride All` in Apache configuration) and that the `mod_rewrite` module is enabled.