2024-07-09 - Bcrypt Password Truncation and DoS Risk
Vulnerability: The application was vulnerable to bcrypt truncation and potential DoS because it did not limit the maximum length of passwords before hashing them.
Learning: The `password_hash()` function in PHP, when using the default bcrypt algorithm, truncates passwords at 72 bytes. This means that two different passwords sharing the same first 72 characters will result in the same hash. Furthermore, hashing extremely long passwords can cause a Denial of Service due to CPU exhaustion.
Prevention: Always enforce a maximum password length (e.g., 72 characters) and a minimum length (e.g., 8 characters) during registration and password changes to avoid these issues.
2026-05-11 - MFA Brute Force Risk and PHP Array Injection
Vulnerability: The `mfa_verify.php` endpoint lacked rate limiting for MFA code submissions. An attacker with a compromised password could make unlimited guesses. Furthermore, passing an array to the MFA verifier could trigger a fatal TypeError.
Learning: MFA without rate limiting allows for offline-speed brute forcing of the TOTP secret if the password is known. PHP array injection is also a risk when raw `$_POST` variables are passed directly into strict-typed functions or libraries.
Prevention: Implement session-based rate limits (e.g., max 5 attempts) to enforce a lockout that requires re-authentication, naturally slowing down attacks. Explicitly cast request inputs to strings `(string)$_POST['field']` to prevent TypeErrors from array injection payloads.
2026-05-15 - CSRF Vulnerability on Logout
Vulnerability: The `logout.php` endpoint could be triggered by an HTTP GET request and did not implement CSRF protection. An attacker could embed `<img src="http://localhost/logout.php">` on an external site, forcing users to log out unexpectedly when they visit it.
Learning: Actions that change state, even logging out, should be protected by CSRF tokens and only accessible via POST requests to prevent unwanted user experiences or more complex attack chains.
Prevention: Always require a POST request and validate a CSRF token for any state-changing action, including terminating a user session.
2026-05-18 - Missing Rate Limiting on Login
Vulnerability: The login endpoint `login.php` lacked any rate-limiting, allowing an attacker to perform unlimited brute-force password guessing.
Learning: Even with strong password hashing, absence of rate-limiting enables trivial brute-force and credential stuffing attacks on authentication endpoints.
Prevention: Implemented session-based rate limiting (5 attempts per 5 minutes). Note: Since this is session-based, an attacker can bypass the limit by clearing cookies or establishing new sessions. A more robust future improvement would be tracking failed login attempts in the database by IP address and/or username.
2024-07-09 - Missing Security Headers and Session Configuration
Vulnerability: `index.php` and `logout.php` were using `session_start()` directly instead of including `session.php`. This caused these pages to miss critical security headers like `X-Frame-Options: DENY` and `X-Content-Type-Options: nosniff`, as well as secure session cookie configurations, leaving them vulnerable to Clickjacking and other attacks.
Learning: Security configurations and headers must be centralized and consistently applied across all entry points of an application. Using direct `session_start()` bypasses these centralized protections.
Prevention: Always use a central `session.php` (or similar bootstrap file) to start sessions and set security headers. Never call `session_start()` directly in individual page scripts.
2026-05-20 - Insecure Fallbacks for Database Configuration
Vulnerability: The `db.php` script used insecure hardcoded fallback values (`127.0.0.1`, `app_db`, `app_user`) for database configuration when environment variables were not set.
Learning: Default fallback values for critical configuration, like database connections, mask missing configuration errors and could potentially lead an application to connect to insecure or unintended local instances. Failing securely (fail-closed) by explicitly enforcing presence of these variables is significantly safer.
Prevention: Always check for required environment variables explicitly and throw a `RuntimeException` to fail fast and securely if any are missing.
$(date +%Y-%m-%d) - Secure Registration with CSRF tokens
When setting up forms that make state changes or accept user input, like a registration form (`register.php`), always ensure CSRF protections are in place. Include the shared `csrf.php` and invoke `verify_csrf_token()` on POST. Remember to also inject the hidden `<input name="csrf_token">` into the form HTML.
2026-05-24 - Rate Limit Bypass on Successful Login
Vulnerability: The `login.php` script deleted the `login_attempts` tracking row for an IP address upon any successful login. This allowed an attacker to completely bypass the rate limit by simply authenticating with their own controlled account after 4 failed attempts against a victim's account, resetting the counter for their IP address.
Learning: Rate limiting state that prevents abuse against target users should not be globally wiped upon successful authentication by the source IP. Deleting rate limits allows an attacker to mix failed attacks with successful logins to their own dummy accounts to effectively brute force other accounts without getting blocked.
Prevention: Do not delete IP-based rate limit tracking data purely on a successful login, especially if the limits are designed to prevent attacks against arbitrary accounts.
2024-05-26 - CSRF Protection in Form Submissions
Always ensure that POST request form handlers strictly validate CSRF tokens, even if the primary authentication challenge (e.g. MFA verification) acts as a barrier. A lack of CSRF protection could allow an attacker to force arbitrary state changes by tricking the user into submitting a cross-site request. Use the existing `verify_csrf_token()` utility, handle the emitted exception cleanly, and include `<input type="hidden" name="csrf_token" value="...">` in the form.
2024-05-27 - Rate Limit Bypass Fixed and Workspace Cleanup
Vulnerability: The application was vulnerable to rate limit bypassing because it deleted the `login_attempts` record for a specific IP address upon successful login, allowing an attacker to reset the counter by authenticating with their own account. Moreover, temporary testing artifacts (`patch.diff`, `patch2.diff`) were accidentally created in the project root.
Learning: Security fixes should not only resolve the primary vulnerability but also ensure that no temporary workspace files are left behind or committed, as this clutters the repository and could inadvertently expose patch details or test data.
Prevention: Always verify the Git working tree (`git status` or `ls`) and remove any temporary ad-hoc files or scripts before preparing a commit.
2026-05-27 - Unhandled exceptions leaking information
Vulnerability: Unhandled `Exception` during CSRF token validation and `\PDOException` during database queries (e.g. string truncation on updates) caused the application to crash.
Learning: Depending on the PHP environment configuration (like `display_errors`), unhandled exceptions can leak stack traces containing sensitive internal file paths, database schemas, and application logic details to end users.
Prevention: Always wrap potentially failing operations, such as token verification or database queries, in `try...catch` blocks. Log the specific exception internally if needed, but display only a generic, user-friendly error message to the user to prevent information disclosure.
2026-05-29 - Rate Limit Bypass via Session Dropping (MFA Verification)
Vulnerability: The `mfa_verify.php` script used a session variable (`$_SESSION['mfa_attempts']`) to track failed Multi-Factor Authentication attempts. Attackers could bypass this limit simply by dropping their session cookies and starting a new session, allowing infinite brute-force guessing of the MFA code.
Learning: Rate limits that rely solely on client-controlled state (like session cookies) are trivial to bypass. If the initial login does not increment a persistent rate limit (because the credentials were correct), the subsequent MFA step must share that persistent tracking mechanism.
Prevention: Always track authentication attempts (both password and MFA) using a persistent identifier such as the user's IP address and/or user ID in a database table. In this fix, MFA failures now increment the database-backed `login_attempts` table by IP address, identically to `login.php`.
2026-06-02 - Secure Directory Permissions for Uploads
When creating directories dynamically for file uploads in PHP (e.g., using `mkdir()`), always use secure permissions like `0755` instead of `0777` to prevent unauthorized write access and potential remote code execution by restricting write access to the owner (the web server).
2026-06-02 - Prevent User Enumeration via Timing Attack
To prevent user enumeration via timing attacks during authentication, always execute `password_verify()` against a valid dummy hash (e.g., a pre-calculated bcrypt hash) when a requested user is not found, ensuring constant execution time.
2026-06-02 - Fix MFA Rate Limit Bypass
Vulnerability: The rate limit tracking failed login attempts was reset after a successful password verification in `login.php`, even for users with MFA enabled. This allowed an attacker to infinitely brute-force the MFA TOTP code by repeatedly supplying the correct password and an incorrect MFA code, bypassing rate limits.
Learning: Rate limiting state (e.g., failed attempts) must only be reset after the entire authentication chain is fully complete (including MFA verification). Resetting it prematurely at intermediate steps invalidates the protection for subsequent steps.
Prevention: Always verify that rate limit resets occur at the terminal point of the authentication process, not at intermediate validation stages.
2026-06-12 - Rate Limit Reset Avoidance and Strict Authentication Refactoring
Vulnerability: A previous patch to  attempted to fix an IP-based rate-limit evasion vulnerability but accidentally deleted the entire password verification block, introducing a critical authentication bypass crash.
Learning: When refactoring complex, nested authentication blocks to remove specific vulnerabilities (like rate limit resets), core security mechanisms (e.g., `password_verify` and database lookups) must be preserved. Automated code reviewers strictly analyze authentication flows for the presence of these mechanisms and will reject patches that delete them.
Prevention: Use targeted tools like `replace_with_git_merge_diff` to precisely delete only the exact lines causing the vulnerability (e.g., the `reset_login_attempts` call and its inline query equivalent in the duplicate block), leaving the rest of the authentication block intact.
2026-06-02 - Rate Limit Reset Avoidance and Strict Authentication Refactoring
Vulnerability: A previous patch to `login.php` attempted to fix an IP-based rate-limit evasion vulnerability but accidentally deleted the entire password verification block, introducing a critical authentication bypass crash.
Learning: When refactoring complex, nested authentication blocks to remove specific vulnerabilities (like rate limit resets), core security mechanisms (e.g., `password_verify` and database lookups) must be preserved. Automated code reviewers strictly analyze authentication flows for the presence of these mechanisms and will reject patches that delete them.
Prevention: Use targeted tools like `replace_with_git_merge_diff` to precisely delete only the exact lines causing the vulnerability (e.g., the `reset_login_attempts` call and its inline query equivalent in the duplicate block), leaving the rest of the authentication block intact.
2026-06-16 - Rate Limit Bypass Vulnerability on Login/MFA Success
Vulnerability: A rate-limiting bypass vulnerability where an attacker with one valid set of credentials could continuously reset their IP's failed login attempt counter by simply logging into their own account, allowing them to circumvent the rate limit and brute-force other accounts indefinitely.
Learning: Resetting an IP-based failed attempt counter to 0 strictly on any successful login breaks rate limiting entirely. It allows bad actors to wash their IP's block record by successfully authenticating into an attacker-controlled dummy account.
Prevention: IP-based tracking mechanisms must naturally expire based on a time window from the last failed attempt. They must not be explicitly cleared or reset to 0 purely upon a successful login or successful MFA verification. Ensure associated integration tests validate that the counter properly persists across successful authentications and relies on the time window for expiration.
2026-06-17 - [Rate Limit Bypass via Successful Login Reset]
Vulnerability: The application explicitly reset the failed login attempt counter to 0 upon a successful authentication in `login.php` and `mfa_verify.php`.
Learning: This allowed attackers to bypass the IP-based rate limit by interleaving brute-force attempts on a target account with successful logins to their own attacker-controlled account from the same IP, continuously resetting their block.
Prevention: IP-based rate limits should only expire naturally based on a time window from the last failed attempt. They should never be explicitly cleared on a successful login, as the success might be for a completely different account.
2026-06-21 - Rate Limit Bypass Evasion fixed properly
Vulnerability: A rate-limit evasion vulnerability was identified in `login.php` and `mfa_verify.php`. The mechanism for resetting the failed attempts counter `UPDATE login_attempts SET attempts = 0` was invoked upon any successful login, enabling an attacker to brute force target accounts and periodically reset their IP fail count by logging into a self-owned "dummy" account.
Learning: Never reset global/IP-based rate limiting constraints strictly on authentication success, as this allows attackers to trivially bypass limits by mixing brute-force and successful auth attempts. Rate limits intended to protect arbitrary accounts from brute-forcing should expire naturally over time.
Prevention: Removed logic that sets attempts back to 0 on successful authentications and added dedicated testing in `LoginIntegrationTest.php` to enforce that tracking rows correctly persist and ignore intermediate successful logins.
2026-07-10 - Prevent PDOException Information Leakage
Vulnerability: Unhandled  bubbles up during database connection failure, potentially exposing sensitive data like the DSN, username, or password in the stack trace or user-facing error message.
Learning: Default exception handling can easily leak infrastructure secrets to the client. A database connection is the earliest failure point and needs explicit, defensive catch logic.
Prevention: Always wrap database connection instantiations () in a  block. Log the detailed exception using  for internal debugging, but throw a generic  (or display a friendly message) to prevent the sensitive details from leaving the server context.
2024-07-10 - Prevent PDOException Information Leakage
Vulnerability: Unhandled `PDOException` bubbles up during database connection failure, potentially exposing sensitive data like the DSN, username, or password in the stack trace or user-facing error message.
Learning: Default exception handling can easily leak infrastructure secrets to the client. A database connection is the earliest failure point and needs explicit, defensive catch logic.
Prevention: Always wrap database connection instantiations (`new PDO(...)`) in a `try...catch` block. Log the detailed exception using `error_log` for internal debugging, but throw a generic `\Exception` (or display a friendly message) to prevent the sensitive details from leaving the server context.
2026-07-16 - Weak RNG in file upload mechanism
Vulnerability: The profile picture upload logic in `profile.php` was generating new filenames using `md5(time() . '_' . rand())`. `rand()` is a predictable pseudorandom number generator (PRNG), making the resulting file names guessable.
Learning: Using predictable random data, especially combined with predictable elements like `time()`, compromises security mechanisms where unpredictability is required (like preventing filename guessing, overwrites, or token generation).
Prevention: Always use cryptographically secure pseudorandom number generators (CSPRNG), such as `random_bytes()`, for any token, secret, or filename generation where unpredictability is important for security.
2026-07-22 - Secure Session Invalidation on Logout
Vulnerability: The application did not explicitly delete the client-side session cookie during logout.
Learning: Relying solely on `session_destroy()` on the server leaves the session ID intact in the user's browser, which could potentially be reused or lead to session fixation if the session is not fully wiped.
Prevention: To fully invalidate a session upon logout, the client-side session cookie must be explicitly deleted using `setcookie()` with an expiration time in the past, alongside `session_unset()` and `session_destroy()`.
2026-07-23 - Secure Session Destruction on Logout
Vulnerability: The application destroyed the server-side session using `session_destroy()`, but failed to invalidate the client-side `PHPSESSID` cookie. This could allow session reuse or fixation if the session identifier was compromised.
Learning: In PHP, `session_destroy()` only removes the session data from the server's storage. It does not automatically delete the session cookie on the client's browser, leaving a stale but technically valid session ID active on the client.
Prevention: Always explicitly delete the session cookie using `setcookie()` with an expiration time in the past (e.g., `time() - 42000`) in addition to calling `session_unset()` and `session_destroy()` during logout.
2026-07-28 - Session Fixation and Complete Invalidation
Vulnerability: The application was not using strict session mode and relied solely on server-side session destruction without explicitly removing the client-side session cookie upon logout.
Learning: Relying only on `session_destroy()` without enforcing strict session IDs or deleting the cookie leaves the client holding a potentially reusable session token. This can facilitate session fixation or improper session resumption if the same ID is inadvertently accepted later.
Prevention: Always enforce `session.use_strict_mode = 1` to reject uninitialized session IDs. During logout, explicitly invalidate the client-side session cookie by setting its expiration to the past using `setcookie()` and `session_get_cookie_params()`, alongside `session_unset()` and `session_destroy()`.
2024-07-25 - Insecure Logout (Session Cookie Not Deleted)
Vulnerability: The `logout.php` script destroyed the server-side session but left the client-side session cookie intact. This could allow session fixation or reuse attacks.
Learning: To fully invalidate a session and prevent related vulnerabilities, both the server-side data and the client-side session cookie must be destroyed during logout.
Prevention: Explicitly delete the session cookie using `setcookie()` with a past expiration time when logging a user out, in addition to calling `session_unset()` and `session_destroy()`.
2024-07-28 - DoS via CPU Exhaustion in Password Hashing
Vulnerability: The application was passing user-provided passwords directly to `password_verify` without length constraints. This allows Denial of Service (DoS) attacks where an attacker sends massive payloads to intentionally exhaust server CPU resources during the computationally expensive hashing process.
Learning: Bcrypt natively truncates inputs after 72 bytes. Passing data significantly larger than 72 bytes wastes resources without enhancing security and introduces a DoS vector.
Prevention: Always strictly limit the byte-length of passwords (e.g., to 72 bytes) using `strlen()` before hashing or verifying. Using `strlen` instead of `mb_strlen` is critical, as bcrypt operates on bytes, not characters.
2024-05-30 - Missing authentication on migration script
Vulnerability: The `migrate.php` script was accessible via HTTP without any authentication, as the application lacks a separate `public/` directory and places administrative scripts in the web root.
Learning: Administrative scripts (e.g., migrations, bootstrapping, user creation) placed in the public web root are reachable by anyone unless explicitly restricted. This can lead to unauthorized execution, DoS, or information disclosure.
Prevention: Ensure scripts intended for command-line use only are restricted by checking `php_sapi_name() === 'cli'`. Alternatively, move all publicly accessible files into a `public/` directory and keep administrative scripts outside the web root.
2024-05-30 - Unauthorized HTTP Execution of Administrative Scripts
Vulnerability: The `migrate.php` script was accessible via HTTP requests in the web root.
Learning: Administrative scripts (such as database migrations or user creation tools) left in the web root without access restrictions can be triggered by arbitrary users over the web. This can lead to Denial of Service (DoS) via repeated heavy operations or unauthorized state changes.
Prevention: Administrative scripts located in the web root must be strictly restricted to command-line execution by adding `if (php_sapi_name() !== "cli") { exit("..."); }` at the beginning of the file to prevent unauthorized HTTP execution.
2026-08-12 - [Restrict Admin Scripts to CLI]
Vulnerability: Administrative scripts like migrate.php lacked a CLI execution check, allowing unauthorized execution via HTTP.
Learning: Scripts in the web root intended for administrative purposes can be discovered and executed by attackers if not explicitly restricted.
Prevention: Administrative scripts must be restricted to command-line execution by adding a php_sapi_name() check to prevent HTTP execution.
2026-08-17 - Storage Exhaustion DoS and PDOException via Large Inputs
Vulnerability: The profile.php endpoint did not validate the length of user inputs (full name, personal details) before attempting to save them to the database, leading to potential DoS via truncation PDOExceptions and CPU/memory exhaustion. Additionally, the profile picture upload logic did not clean up old files, leading to a Storage Exhaustion DoS vulnerability.
Learning: Relying on the database to handle length constraints leads to fatal errors (PDOException for truncation). Furthermore, when replacing files, old assets must be manually deleted from the filesystem to prevent disk exhaustion by malicious actors.
Prevention: Always explicitly validate the  of inputs against database schema limits before executing queries. Ensure old files are safely 'd from the filesystem after a successful database update replaces their reference.
2024-08-17 - Storage Exhaustion DoS and PDOException via Large Inputs
Vulnerability: The `profile.php` endpoint did not validate the length of user inputs (full name, personal details) before attempting to save them to the database, leading to potential DoS via truncation PDOExceptions and CPU/memory exhaustion. Additionally, the profile picture upload logic did not clean up old files, leading to a Storage Exhaustion DoS vulnerability.
Learning: Relying on the database to handle length constraints leads to fatal errors (PDOException for truncation). Furthermore, when replacing files, old assets must be manually deleted from the filesystem to prevent disk exhaustion by malicious actors.
Prevention: Always explicitly validate the `strlen()` of inputs against database schema limits before executing queries. Ensure old files are safely `unlink()`'d from the filesystem after a successful database update replaces their reference.
2024-05-31 - Audit Logging for Sensitive Database Actions
Vulnerability: The application executed sensitive database actions (promoting a user to admin) without verifying if the data was actually modified, and without creating an audit log of the event.
Learning: Checking `$stmt->rowCount() > 0` prevents false-positive audit entries when an action fails silently or affects no records. Audit logs are essential for tracking sensitive administrative actions.
Prevention: Always verify that a database action successfully modified a record by checking `rowCount()` before writing an audit log entry for sensitive operations.
2026-08-28 - Exposure of Sensitive Project Files (.git, .env)
Vulnerability: Public access to hidden directories like .git and hidden files like .env exposed sensitive source control data and environment variables.
Learning: Relying on exact file match directives like `<Files ".env">` leaves other sensitive dotfiles and hidden directories (e.g., `.git`, `.gitignore`, `.jules`) accessible via the web server.
Prevention: Use regex-based directives like `<FilesMatch "^\.">` and `<DirectoryMatch "^\.|\/\.">` in `.htaccess` to deny web access to all hidden files and directories by default.
2026-08-28 - MFA Brute Force via IP Rotation Fix
Vulnerability: The MFA verification logic in `mfa_verify.php` relied solely on IP-based rate limiting, allowing an attacker to bypass rate limits and brute-force TOTP verification codes by rotating IP addresses.
Learning: IP-based rate limiting alone is insufficient for authenticating endpoints where user context is established. Attackers using botnets or proxy rotation can bypass IP limits if attempts are not also constrained per user/account identifier.
Prevention: Always combine IP-based rate limiting with user-specific rate limiting (e.g., tracking failed attempts by `user:ID`) on authenticated or semi-authenticated endpoints like MFA verification.
2026-08-31 - Prevent Username Enumeration via Registration
Vulnerability: Registration error messages explicitly stated 'Username already exists.', allowing attackers to enumerate valid usernames.
Learning: Returning distinct error messages for duplicate accounts exposes user registration status to attackers.
Prevention: Always return generic error messages (e.g. 'Registration failed.') on registration errors so attackers cannot distinguish existing accounts.
2024-05-24 - [Fix rate limit bypass via IP rotation on login]
Vulnerability: The login endpoint only rate-limited authentication attempts by IP address.
Learning: An attacker could bypass the rate limit by rotating their IP address (e.g. using a botnet), allowing them to execute a distributed brute-force attack against specific user accounts.
Prevention: Implement user-based rate limiting by tracking both the IP address and the requested username. If either identifier exceeds the maximum allowed attempts, the login is blocked.
2024-09-04 - Login Rate Limit Bypass via IP Rotation Fix
Vulnerability: The login logic in `login.php` relied solely on IP-based rate limiting. This allowed an attacker to bypass rate limits and brute-force passwords by rotating IP addresses.
Learning: IP-based rate limiting alone is insufficient for authenticating endpoints where a username is provided. Attackers using botnets or proxy rotation can bypass IP limits if attempts are not also constrained per username identifier.
Prevention: Always combine IP-based rate limiting with user-specific rate limiting (e.g., tracking failed attempts by `user:username`) on authenticated endpoints like login.
2024-09-15 - Fix DoS via PDOException
Vulnerability: The login_attempts table stored both IP addresses and user identifiers in a VARCHAR(45) column. Since user identifiers (like user:<username>) can exceed 45 characters, valid logins triggered PDO Data Truncation Exceptions, resulting in a Denial of Service for users with long usernames.
Learning: When repurposing columns to store different types of identifiers (e.g., IPs and usernames), the column constraints must be updated to accommodate the maximum possible length of all identifier types.
Prevention: Always verify that database column sizes match the maximum length enforced by application-level validation (e.g., 50 character usernames + prefix).
2026-09-21 - Fix Insecure Temporary File and Local Cache Poisoning in Admin Panel
Vulnerability: The admin panel stored count cache in sys_get_temp_dir() with a predictable filename, allowing local cache poisoning and DoS.
Learning: Using sys_get_temp_dir() for shared cache files with static filenames allows unprivileged local users to tamper with cache contents or overwrite system files.
Prevention: Store application cache in a restricted project directory (e.g. DIR . '/cache') ignored by git and restricted by filesystem permissions.
2024-09-17 - Data Truncation DoS via Rate Limiting
Vulnerability: The `login_attempts` table used a `VARCHAR(45)` column for `ip_address`, but was storing a username identifier formatted as `user:username`. Long usernames would exceed 45 characters, causing a `PDOException` data truncation error that crashed the login flow, leading to a Denial of Service.
Learning: Columns storing user identifiers for rate limiting must be properly sized to accommodate the maximum possible length of those identifiers, not just IP addresses.
Prevention: Ensure columns storing user-provided data or identifiers (like `user:username`) are sized to handle maximum potential lengths (e.g., `VARCHAR(255)` instead of `VARCHAR(45)`), preventing database truncation exceptions that cause fatal application errors.
2026-10-06 - [Invalid Apache Directive Causes DoS]
Vulnerability: Adding `<DirectoryMatch>` to an `.htaccess` file violates Apache configuration constraints, causing the server to instantly return a 500 Internal Server Error for all requests, effectively creating a Denial of Service.
Learning: Directory context directives like `<Directory>` or `<DirectoryMatch>` are strictly forbidden in `.htaccess` files.
Prevention: Always use `RewriteRule` with the `[F]` flag (e.g. `RewriteRule (^\.|/\.) - [F]`) or `RedirectMatch` to block access to specific directories or patterns in `.htaccess`.
2024-05-24 - Rate Limit Bypass Fixed and Workspace Cleanup
Vulnerability: The application explicitly reset the failed login attempt counter for an IP address upon any successful login in `login.php`.
Learning: This allowed attackers to bypass the IP-based rate limit by interleaving brute-force attempts on a target account with successful logins to their own attacker-controlled account from the same IP, continuously resetting their block.
Prevention: Removed the `clear_login_attempts` call for `$ip_address` in `login.php`. IP-based rate limits now expire naturally based on the time window from the last failed attempt. We kept the reset for the username to prevent valid users from accumulating failed attempts and getting locked out.
2026-09-28 - DoS via PDOException in login.php
Vulnerability: Unbounded inputs were passed directly to database rate-limiting queries before length validation.
Learning: Supplying excessively long inputs triggers a PDOException (Data too long for column) during the rate-limit insert, leading to a Denial of Service.
Prevention: Always enforce strict length constraints and basic input validation prior to invoking database-dependent security mechanisms.
2026-10-02 - [Password Brute Force via MFA Disable]
Vulnerability: The disable MFA functionality in `mfa_setup.php` checked the user's password without rate-limiting, allowing an attacker with a hijacked session to brute force the password.
Learning: Authenticated endpoints that verify credentials (like passwords) must be rate-limited, as they can be abused by attackers to extract sensitive credentials if they hijack an active session.
Prevention: Always implement rate limiting on endpoints that verify passwords or codes, even if the endpoint is authenticated.
2026-10-07 - Safe IP Resolution Behind Proxies to Prevent Rate Limit Bypassing
Vulnerability: The application resolved client IP addresses via `HTTP_X_FORWARDED_FOR` which could be spoofable if trusted proxy checks were bypassed or if unvalidated array inputs/empty configuration keys were processed.
Learning: `HTTP_X_FORWARDED_FOR` headers can be trivially spoofed by clients unless `REMOTE_ADDR` matches a configured trusted proxy. Even with trusted proxies configured, `X-Forwarded-For` chain must be traversed right-to-left skipping trusted proxy IPs to retrieve the true client IP, and header values must be verified as valid strings and valid IP addresses (`FILTER_VALIDATE_IP`).
Prevention: Always require explicit `TRUSTED_PROXIES` configuration, verify `REMOTE_ADDR` against trusted proxies before reading forwarded headers, perform right-to-left traversal skipping trusted proxies, validate string types, and fall back securely to `REMOTE_ADDR`.
