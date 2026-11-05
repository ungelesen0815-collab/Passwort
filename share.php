<?php
require_once __DIR__ . '/session.php';
require_once 'db.php';

$token = is_string($_GET['token'] ?? null) ? trim($_GET['token']) : '';
$error = '';
$share = null;

if ($token === '') {
    $error = 'Kein Zugriffs-Token angegeben.';
} else {
    try {
        $stmt = $pdo->prepare("SELECT file_name, encrypted_data, iv, salt, expires_at FROM crypt_shares WHERE access_token = ?");
        $stmt->execute([$token]);
        $share = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$share) {
            $error = 'Diese Freigabe existiert nicht oder wurde gelöscht.';
        } elseif (strtotime($share['expires_at']) < time()) {
            $error = 'Dieser Freigabe-Link ist abgelaufen.';
            $share = null;
        }
    } catch (\PDOException $e) {
        error_log("Database error in share.php: " . $e->getMessage());
        $error = 'Ein Datenbankfehler ist aufgetreten.';
    }
}

$pageTitle = 'Crypt Share - Datei Herunterladen';
require_once 'header.php';
?>
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark mb-4">
        <div class="container">
            <span class="navbar-brand">Crypt Share</span>
        </div>
    </nav>

    <div class="container">
        <div class="row justify-content-center">
            <div class="col-md-8 col-lg-6">
                <?php if ($error): ?>
                    <div class="alert alert-danger">
                        <h4>Fehler</h4>
                        <p><?= htmlspecialchars($error) ?></p>
                    </div>
                <?php elseif ($share): ?>
                    <div class="card shadow-sm">
                        <div class="card-header bg-primary text-white">
                            <h5 class="mb-0">Datei Herunterladen</h5>
                        </div>
                        <div class="card-body">
                            <p>Du wurdest eingeladen, die Datei <strong><?= htmlspecialchars($share['file_name']) ?></strong> herunterzuladen.</p>
                            <p>Diese Datei ist Ende-zu-Ende verschlüsselt. Bitte gib das Einmalpasswort ein, um die Datei lokal in deinem Browser zu entschlüsseln.</p>

                            <form id="decryptForm">
                                <input type="hidden" id="encrypted_data" value="<?= htmlspecialchars($share['encrypted_data']) ?>">
                                <input type="hidden" id="iv" value="<?= htmlspecialchars($share['iv']) ?>">
                                <input type="hidden" id="salt" value="<?= htmlspecialchars($share['salt']) ?>">

                                <div class="mb-3">
                                    <label for="otp" class="form-label">Einmal-Passwort</label>
                                    <input type="password" class="form-control" id="otp" required>
                                </div>

                                <button type="submit" class="btn btn-primary w-100" id="btnDecrypt">Entschlüsseln & Herunterladen</button>
                            </form>

                            <div id="errorMsg" class="alert alert-danger mt-3 d-none"></div>
                        </div>
                    </div>
                <?php endif; ?>
            </div>
        </div>
    </div>

    <script src="vault.js"></script>
    <script src="share.js"></script>
<?php require_once 'footer.php'; ?>
