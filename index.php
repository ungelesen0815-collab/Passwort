<?php
require_once __DIR__ . '/session.php';
require_once 'csrf.php';

if (!isset($_SESSION['user_id'])) {
    header('Location: login.php');
    exit;
}

$username = $_SESSION['username'];
$role = $_SESSION['role'];

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
                <div class="col-md-4 mb-3">
                    <div class="card h-100">
                        <div class="card-body">
                            <h5 class="card-title">🔐 Passwörter & Zertifikate Tresor</h5>
                            <p class="card-text">Speichern Sie Passwörter, Keyfiles und Zertifikate Ende-zu-Ende verschlüsselt.</p>
                            <a href="vault.php" class="btn btn-primary">Zum Tresor &rarr;</a>
                        </div>
                    </div>
                </div>
                <div class="col-md-4 mb-3">
                    <div class="card h-100">
                        <div class="card-body">
                            <h5 class="card-title">👤 Profil</h5>
                            <p class="card-text">Verwalten Sie Ihre persönlichen Angaben und Profilbild.</p>
                            <a href="profile.php" class="btn btn-secondary">Zum Profil &rarr;</a>
                        </div>
                    </div>
                </div>
                <div class="col-md-4 mb-3">
                    <div class="card h-100">
                        <div class="card-body">
                            <h5 class="card-title">🛡️ Zwei-Faktor-Authentifizierung</h5>
                            <p class="card-text">Erhöhen Sie die Sicherheit Ihres Kontos mit 2FA/MFA.</p>
                            <a href="mfa_setup.php" class="btn btn-secondary">MFA Einrichten &rarr;</a>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>

<?php require_once 'footer.php'; ?>