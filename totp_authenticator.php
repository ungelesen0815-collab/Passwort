<?php
require_once __DIR__ . '/session.php';
require_once 'csrf.php';
require_once 'db.php';
require_once 'auth_utils.php';

if (!isset($_SESSION['user_id'])) {
    if (!empty($_SERVER['HTTP_X_REQUESTED_WITH']) && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest') {
        header('Content-Type: application/json');
        http_response_code(401);
        echo json_encode(['error' => 'Unauthorized']);
        exit();
    }
    header('Location: login.php');
    exit();
}

$userId = (int)$_SESSION['user_id'];
if (!user_has_feature($pdo, $userId, 'totp', $_SESSION['role'] ?? 'user')) {
    if (!empty($_SERVER['HTTP_X_REQUESTED_WITH']) || isset($_POST['ajax'])) {
        header('Content-Type: application/json');
        http_response_code(403);
        echo json_encode(['success' => false, 'error' => 'Keine Berechtigung für den 2FA Authenticator.']);
        exit();
    }
    header('Location: index.php');
    exit();
}

ensure_totp_entries_table($pdo);

$message = '';
$error = '';
$entries = [];

$sendResponse = function (bool $isError, string $msg, int $statusCode = 200, array $extraData = []) {
    if (!empty($_SERVER['HTTP_X_REQUESTED_WITH']) || isset($_POST['ajax'])) {
        header('Content-Type: application/json');
        if ($statusCode !== 200) {
            http_response_code($statusCode);
        }
        $response = ['success' => !$isError];
        if ($isError) {
            $response['error'] = $msg;
        } else {
            $response['message'] = $msg;
        }
        echo json_encode(array_merge($response, $extraData));
        exit();
    }
    return $msg;
};

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';
    $token = $_POST['csrf_token'] ?? '';

    $csrfError = validate_csrf_token($token);
    if ($csrfError !== null) {
        $error = $sendResponse(true, 'Ungültiger CSRF-Token.', 400);
    } else {
        try {
            if ($action === 'add') {
                $issuer = trim((string)($_POST['issuer'] ?? ''));
                $accountName = trim((string)($_POST['account_name'] ?? ''));
                $category = trim((string)($_POST['category'] ?? ''));
                $encryptedData = (string)($_POST['encrypted_data'] ?? '');
                $iv = trim((string)($_POST['iv'] ?? ''));
                $salt = trim((string)($_POST['salt'] ?? ''));

                if ($accountName === '' || strlen($accountName) > 255 || strlen($issuer) > 255 || strlen($category) > 100 || $encryptedData === '' || $iv === '' || strlen($iv) > 255 || $salt === '' || strlen($salt) > 255) {
                    $error = $sendResponse(true, 'Fehlende oder ungültige Felder.', 400);
                } else {
                    $stmt = $pdo->prepare("INSERT INTO totp_entries (user_id, issuer, account_name, category, encrypted_data, iv, salt) VALUES (?, ?, ?, ?, ?, ?, ?)");
                    $stmt->execute([$userId, $issuer, $accountName, $category, $encryptedData, $iv, $salt]);
                    $newId = (int)$pdo->lastInsertId();
                    $message = $sendResponse(false, '2FA-Token erfolgreich verschlüsselt gespeichert.', 200, ['id' => $newId]);
                }
            } elseif ($action === 'update') {
                $entryId = (int)($_POST['entry_id'] ?? 0);
                $issuer = trim((string)($_POST['issuer'] ?? ''));
                $accountName = trim((string)($_POST['account_name'] ?? ''));
                $category = trim((string)($_POST['category'] ?? ''));
                $encryptedData = (string)($_POST['encrypted_data'] ?? '');
                $iv = trim((string)($_POST['iv'] ?? ''));
                $salt = trim((string)($_POST['salt'] ?? ''));

                if ($entryId <= 0 || $accountName === '' || strlen($accountName) > 255 || strlen($issuer) > 255 || strlen($category) > 100 || $encryptedData === '' || $iv === '' || strlen($iv) > 255 || $salt === '' || strlen($salt) > 255) {
                    $error = $sendResponse(true, 'Fehlende oder ungültige Felder.', 400);
                } else {
                    $stmt = $pdo->prepare("UPDATE totp_entries SET issuer = ?, account_name = ?, category = ?, encrypted_data = ?, iv = ?, salt = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND user_id = ?");
                    $stmt->execute([$issuer, $accountName, $category, $encryptedData, $iv, $salt, $entryId, $userId]);
                    $message = $sendResponse(false, '2FA-Token erfolgreich aktualisiert.');
                }
            } elseif ($action === 'delete') {
                $entryId = (int)($_POST['entry_id'] ?? 0);
                if ($entryId <= 0) {
                    $error = $sendResponse(true, 'Ungültige Eintrags-ID.', 400);
                } else {
                    $stmt = $pdo->prepare("DELETE FROM totp_entries WHERE id = ? AND user_id = ?");
                    $stmt->execute([$entryId, $userId]);
                    $message = $sendResponse(false, '2FA-Token gelöscht.');
                }
            } elseif ($action === 'generate_qr') {
                $otpauthUri = trim((string)($_POST['otpauth_uri'] ?? ''));
                if ($otpauthUri === '' || !str_starts_with($otpauthUri, 'otpauth://')) {
                    $error = $sendResponse(true, 'Ungültige otpauth-URI.', 400);
                } else {
                    $qrDataUri = generate_qr_svg_data_uri($otpauthUri, 200);
                    $sendResponse(false, 'QR-Code generiert.', 200, ['qr_data_uri' => $qrDataUri]);
                }
            }
        } catch (\PDOException $e) {
            error_log("Database error in totp_authenticator.php: " . $e->getMessage());
            $error = $sendResponse(true, 'Ein Datenbankfehler ist aufgetreten.', 500);
        }
    }
}

try {
    $stmt = $pdo->prepare("SELECT id, issuer, account_name, category, encrypted_data, iv, salt, created_at FROM totp_entries WHERE user_id = ? ORDER BY issuer ASC, account_name ASC, id DESC");
    $stmt->execute([$userId]);
    $entries = $stmt->fetchAll(PDO::FETCH_ASSOC);
} catch (\PDOException $e) {
    error_log("Database error in totp_authenticator.php (fetch): " . $e->getMessage());
    $error = 'Ein Datenbankfehler ist aufgetreten.';
}

$pageTitle = '2FA / TOTP Web-Authenticator';
require_once 'header.php';
require_once 'navbar.php';
?>

<div class="container mt-4">
    <div class="d-flex justify-content-between align-items-center mb-3">
        <h2>⏱️ 2FA / TOTP Web-Authenticator</h2>
        <div>
            <button id="lock-totp-btn" class="btn btn-outline-warning d-none" type="button">
                🔒 Authenticator sperren
            </button>
        </div>
    </div>

    <?php if (!empty($error)): ?>
        <div class="alert alert-danger"><?= htmlspecialchars($error) ?></div>
    <?php endif; ?>
    <?php if (!empty($message)): ?>
        <div class="alert alert-success"><?= htmlspecialchars($message) ?></div>
    <?php endif; ?>

    <!-- Master Password Unlock Card -->
    <div id="totp-master-password-card" class="card mb-4 border-primary">
        <div class="card-header bg-primary text-white">
            <h5 class="mb-0">Master-Passwort für 2FA-Secrets eingeben</h5>
        </div>
        <div class="card-body">
            <p class="card-text">
                Ihre TOTP-Secrets (<code>otpauth://</code> / Base32) werden Ende-zu-Ende (Zero-Knowledge) im Browser mit <strong>AES-GCM-256</strong> verschlüsselt.
                Die 6-stelligen 2FA-Codes werden alle 30 Sekunden lokal im Browser berechnet – ideal für Teams oder als sicheres Backup zum Smartphone-Authenticator.
            </p>
            <form id="totp-master-password-form">
                <div class="row g-3 align-items-center">
                    <div class="col-md-8">
                        <input type="password" id="totp-master-password-input" class="form-control" placeholder="Master-Passwort" required>
                    </div>
                    <div class="col-md-4">
                        <button type="submit" class="btn btn-primary w-100">Entsperren &amp; Live-Codes starten</button>
                    </div>
                </div>
            </form>
        </div>
    </div>

    <!-- Main TOTP UI (Hidden until unlocked) -->
    <div id="totp-content" class="d-none">
        <div class="card mb-4 shadow-sm">
            <div class="card-header bg-dark text-white d-flex flex-wrap justify-content-between align-items-center gap-2">
                <div class="d-flex align-items-center gap-3">
                    <span>Aktive 2FA-Token (<span id="totp-total-count">0</span>)</span>
                    <span class="badge bg-info text-dark" id="totp-global-timer-badge">⏱️ Nächster Code in <span id="totp-global-seconds">30</span>s</span>
                </div>
                <div class="d-flex flex-wrap gap-2 align-items-center">
                    <input type="search" id="totp-search-input" class="form-control form-control-sm" placeholder="🔍 Suchen nach Dienst, Account oder Kategorie...">
                    <button id="btn-new-totp" class="btn btn-success btn-sm text-nowrap" type="button" data-bs-toggle="modal" data-bs-target="#totpEditorModal">
                        + 2FA-Secret hinzufügen
                    </button>
                </div>
            </div>
            <div class="card-body">
                <div id="totp-grid" class="row g-3">
                    <div class="col-12 text-center text-muted py-4">Keine 2FA-Secrets hinterlegt.</div>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- Modal: Add / Edit TOTP Secret -->
<div class="modal fade" id="totpEditorModal" tabindex="-1" aria-labelledby="totpEditorModalLabel" aria-hidden="true">
    <div class="modal-dialog modal-lg">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title" id="totpEditorModalLabel">2FA / TOTP-Secret hinzufügen</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Schließen"></button>
            </div>
            <form id="totp-editor-form">
                <input type="hidden" id="edit_totp_id" value="">
                <div class="modal-body">
                    <div class="mb-3 p-3 bg-light border rounded">
                        <label for="totp_otpauth_uri" class="form-label fw-bold">⚡ Schnell-Import per <code>otpauth://</code> URI (optional)</label>
                        <div class="input-group input-group-sm">
                            <input type="text" id="totp_otpauth_uri" class="form-control font-monospace" placeholder="otpauth://totp/GitHub:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub">
                            <button type="button" class="btn btn-outline-primary" id="btn-parse-otpauth">URI übernehmen</button>
                        </div>
                        <small class="text-muted">Füllt Dienst, Account, Base32-Secret, Algorithmus, Ziffern und Intervall automatisch aus.</small>
                    </div>

                    <div class="row g-3 mb-3">
                        <div class="col-md-5">
                            <label for="totp_issuer" class="form-label">Dienst / Anbieter (Issuer)</label>
                            <input type="text" id="totp_issuer" class="form-control" placeholder="z. B. GitHub, AWS, Cloudflare, PayPal" maxlength="255">
                        </div>
                        <div class="col-md-4">
                            <label for="totp_account" class="form-label">Account / Benutzername *</label>
                            <input type="text" id="totp_account" class="form-control" placeholder="z. B. team@firma.de" required maxlength="255">
                        </div>
                        <div class="col-md-3">
                            <label for="totp_category" class="form-label">Kategorie / Team</label>
                            <input type="text" id="totp_category" class="form-control" placeholder="z. B. DevOps, Team, Privat" maxlength="100">
                        </div>
                    </div>

                    <div class="mb-3">
                        <label for="totp_secret" class="form-label fw-bold">TOTP Base32 Secret *</label>
                        <input type="text" id="totp_secret" class="form-control font-monospace" placeholder="z. B. JBSWY3DPEHPK3PXP" required>
                        <small class="text-muted">Leerzeichen und Bindestriche werden automatisch entfernt.</small>
                    </div>

                    <div class="row g-3 mb-3">
                        <div class="col-md-4">
                            <label for="totp_digits" class="form-label">Code-Länge (Ziffern)</label>
                            <select id="totp_digits" class="form-select">
                                <option value="6" selected>6 Ziffern (Standard)</option>
                                <option value="8">8 Ziffern</option>
                            </select>
                        </div>
                        <div class="col-md-4">
                            <label for="totp_period" class="form-label">Intervall (Sekunden)</label>
                            <select id="totp_period" class="form-select">
                                <option value="30" selected>30 Sekunden (Standard)</option>
                                <option value="60">60 Sekunden</option>
                            </select>
                        </div>
                        <div class="col-md-4">
                            <label for="totp_algorithm" class="form-label">HMAC-Algorithmus</label>
                            <select id="totp_algorithm" class="form-select">
                                <option value="SHA-1" selected>SHA-1 (Standard)</option>
                                <option value="SHA-256">SHA-256</option>
                                <option value="SHA-512">SHA-512</option>
                            </select>
                        </div>
                    </div>

                    <div class="mb-2">
                        <label for="totp_notes" class="form-label">Notiz / Hinweis (optional)</label>
                        <input type="text" id="totp_notes" class="form-control" placeholder="z. B. Geteilter Team-Login für Prod-Cluster">
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Abbrechen</button>
                    <button type="submit" class="btn btn-success">🔒 Verschlüsseln &amp; Speichern</button>
                </div>
            </form>
        </div>
    </div>
</div>

<!-- Modal: Show QR Code for Smartphone Sync -->
<div class="modal fade" id="totpQrModal" tabindex="-1" aria-labelledby="totpQrModalLabel" aria-hidden="true">
    <div class="modal-dialog modal-sm modal-dialog-centered">
        <div class="modal-content">
            <div class="modal-header">
                <h6 class="modal-title" id="totpQrModalLabel">📱 Auf Smartphone übertragen</h6>
                <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Schließen"></button>
            </div>
            <div class="modal-body text-center">
                <p id="totpQrAccountLabel" class="small fw-bold mb-2"></p>
                <div class="p-2 bg-white border rounded d-inline-block mb-2">
                    <img id="totpQrImg" src="" alt="TOTP QR-Code" class="img-fluid share-qr-img">
                </div>
                <div class="small text-muted">Scannen Sie diesen Code mit Google Authenticator, Aegis, 2FAS oder Authy.</div>
            </div>
        </div>
    </div>
</div>

<div id="totp-data" data-json="<?= htmlspecialchars(json_encode(['csrfToken' => $_SESSION['csrf_token'] ?? '', 'entries' => $entries], JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT), ENT_QUOTES, 'UTF-8') ?>" class="d-none"></div>
<script src="vault.js"></script>
<script src="totp_authenticator.js"></script>

<?php require_once 'footer.php'; ?>
