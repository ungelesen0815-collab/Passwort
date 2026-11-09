<?php
require_once __DIR__ . '/session.php';
require_once 'csrf.php';
require_once 'auth_utils.php';

if (!isset($_SESSION['user_id'])) {
    header('Location: login.php');
    exit;
}

$username = $_SESSION['username'];
$role = $_SESSION['role'];

try {
    require_once 'db.php';
    if (isset($pdo) && $pdo instanceof PDO) {
        $permissions = get_user_permissions($pdo, $_SESSION['user_id'], $role);
    }
} catch (\Throwable $e) {
    // Fallback to session permissions if DB is unavailable
}

$permissions = $permissions ?? ($_SESSION['permissions'] ?? [
    'password_generator' => true,
    'vault' => true,
    'crypt_share' => true,
    'secure_notes' => true,
    'totp' => true,
    'security_audit' => true,
]);

$pageTitle = 'Dashboard';
require_once 'header.php';
?>
<?php require_once 'navbar.php'; ?>
<div class="container mt-5">
    <div class="row">
        <div class="col-md-12">
            <h2>Welcome to your Dashboard</h2>
            <p class="lead">You are successfully logged in as a <strong><?= htmlspecialchars($role) ?></strong>.</p>

            <div class="row mt-4">
                <?php if (!empty($permissions['vault'])): ?>
                <div class="col-md-6 col-lg-3 mb-3">
                    <div class="card h-100">
                        <div class="card-body">
                            <h5 class="card-title">🔐 Tresor</h5>
                            <p class="card-text">Speichern Sie Passwörter &amp; Zertifikate Ende-zu-Ende verschlüsselt.</p>
                            <a href="vault.php" class="btn btn-primary">Zum Tresor &rarr;</a>
                        </div>
                    </div>
                </div>
                <?php endif; ?>
                <?php if (!empty($permissions['password_generator'])): ?>
                <div class="col-md-6 col-lg-3 mb-3">
                    <div class="card h-100">
                        <div class="card-body">
                            <h5 class="card-title">🔑 Passwort-Generator</h5>
                            <p class="card-text">Generieren Sie sichere, zufällige Passwörter mit anpassbaren Optionen.</p>
                            <a href="password_generator.php" class="btn btn-primary">Zum Generator &rarr;</a>
                        </div>
                    </div>
                </div>
                <?php endif; ?>
                <div class="col-md-6 col-lg-3 mb-3">
                    <div class="card h-100">
                        <div class="card-body">
                            <h5 class="card-title">👤 Profil</h5>
                            <p class="card-text">Verwalten Sie Ihre persönlichen Angaben und Profilbild.</p>
                            <a href="profile.php" class="btn btn-secondary">Zum Profil &rarr;</a>
                        </div>
                    </div>
                </div>
                <div class="col-md-6 col-lg-3 mb-3">
                    <div class="card h-100">
                        <div class="card-body">
                            <h5 class="card-title">🛡️ MFA</h5>
                            <p class="card-text">Erhöhen Sie die Sicherheit Ihres Kontos mit 2FA/MFA.</p>
                            <a href="mfa_setup.php" class="btn btn-secondary">MFA Einrichten &rarr;</a>
                        </div>
                    </div>
                </div>
                <?php if (!empty($permissions['crypt_share'])): ?>
                <div class="col-md-6 col-lg-3 mb-3">
                    <div class="card h-100">
                        <div class="card-body">
                            <h5 class="card-title">🔗 Crypt Share</h5>
                            <p class="card-text">Teilen Sie Dateien sicher und verschlüsselt mit anderen.</p>
                            <a href="crypt_share.php" class="btn btn-primary">Zum Crypt Share &rarr;</a>
                        </div>
                    </div>
                </div>
                <?php endif; ?>
                <?php if (!empty($permissions['secure_notes'])): ?>
                <div class="col-md-6 col-lg-3 mb-3">
                    <div class="card h-100">
                        <div class="card-body">
                            <h5 class="card-title">📝 Sichere Notizen</h5>
                            <p class="card-text">Speichern Sie Markdown-Notizen &amp; Recovery-Codes Ende-zu-Ende verschlüsselt.</p>
                            <a href="secure_notes.php" class="btn btn-primary">Zu den Notizen &rarr;</a>
                        </div>
                    </div>
                </div>
                <?php endif; ?>
                <?php if (!empty($permissions['totp'])): ?>
                <div class="col-md-6 col-lg-3 mb-3">
                    <div class="card h-100">
                        <div class="card-body">
                            <h5 class="card-title">⏱️ 2FA Authenticator</h5>
                            <p class="card-text">Speichern Sie TOTP-Secrets (otpauth://) verschlüsselt &amp; generieren Sie Live-2FA-Codes.</p>
                            <a href="totp_authenticator.php" class="btn btn-primary">Zum Authenticator &rarr;</a>
                        </div>
                    </div>
                </div>
                <?php endif; ?>
                <?php if (!empty($permissions['security_audit'])): ?>
                <div class="col-md-6 col-lg-3 mb-3">
                    <div class="card h-100">
                        <div class="card-body">
                            <h5 class="card-title">🕵️ Security Audit</h5>
                            <p class="card-text">Prüfen Sie Passwörter &amp; Tresore anonym per k-Anonymity (HIBP) auf Datenlecks.</p>
                            <a href="security_audit.php" class="btn btn-primary">Zum Datenleck-Check &rarr;</a>
                        </div>
                    </div>
                </div>
                <?php endif; ?>
            </div>
        </div>
    </div>
</div>

<?php require_once 'footer.php'; ?>