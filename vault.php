<?php
require_once __DIR__ . '/session.php';
require_once 'csrf.php';
require_once 'db.php';

if (!isset($_SESSION['user_id'])) {
    if (!empty($_SERVER['HTTP_X_REQUESTED_WITH']) && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) == 'xmlhttprequest') {
        header('Content-Type: application/json');
        http_response_code(401);
        echo json_encode(['error' => 'Unauthorized']);
        exit;
    }
    header('Location: login.php');
    exit;
}

$userId = $_SESSION['user_id'];
$message = '';
$error = '';

// Handle POST actions (API / AJAX or Form submission)
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';
    $token = $_POST['csrf_token'] ?? '';

    if (!validate_csrf_token($token)) {
        if (!empty($_SERVER['HTTP_X_REQUESTED_WITH']) || isset($_POST['ajax'])) {
            header('Content-Type: application/json');
            http_response_code(400);
            echo json_encode(['success' => false, 'error' => 'Ungültiger CSRF-Token.']);
            exit;
        }
        $error = 'Ungültiger CSRF-Token.';
    } else {
        if ($action === 'add') {
            $itemType = $_POST['item_type'] ?? '';
            $title = trim($_POST['title'] ?? '');
            $encryptedData = $_POST['encrypted_data'] ?? '';
            $iv = $_POST['iv'] ?? '';
            $salt = $_POST['salt'] ?? '';

            $allowedTypes = ['password', 'keyfile', 'certificate'];

            if (!in_array($itemType, $allowedTypes, true) || empty($title) || empty($encryptedData) || empty($iv) || empty($salt)) {
                if (!empty($_SERVER['HTTP_X_REQUESTED_WITH']) || isset($_POST['ajax'])) {
                    header('Content-Type: application/json');
                    http_response_code(400);
                    echo json_encode(['success' => false, 'error' => 'Fehlende oder ungültige Felder.']);
                    exit;
                }
                $error = 'Fehlende oder ungültige Felder.';
            } else {
                $stmt = $pdo->prepare("INSERT INTO vault_items (user_id, item_type, title, encrypted_data, iv, salt) VALUES (?, ?, ?, ?, ?, ?)");
                $stmt->execute([$userId, $itemType, $title, $encryptedData, $iv, $salt]);
                $newId = $pdo->lastInsertId();

                if (!empty($_SERVER['HTTP_X_REQUESTED_WITH']) || isset($_POST['ajax'])) {
                    header('Content-Type: application/json');
                    echo json_encode(['success' => true, 'id' => $newId, 'message' => 'Eintrag erfolgreich gespeichert.']);
                    exit;
                }
                $message = 'Eintrag erfolgreich gespeichert.';
            }
        } elseif ($action === 'delete') {
            $itemId = (int)($_POST['item_id'] ?? 0);

            if ($itemId <= 0) {
                if (!empty($_SERVER['HTTP_X_REQUESTED_WITH']) || isset($_POST['ajax'])) {
                    header('Content-Type: application/json');
                    http_response_code(400);
                    echo json_encode(['success' => false, 'error' => 'Ungültige Bezeichner-ID.']);
                    exit;
                }
                $error = 'Ungültige Bezeichner-ID.';
            } else {
                $stmt = $pdo->prepare("DELETE FROM vault_items WHERE id = ? AND user_id = ?");
                $stmt->execute([$itemId, $userId]);

                if (!empty($_SERVER['HTTP_X_REQUESTED_WITH']) || isset($_POST['ajax'])) {
                    header('Content-Type: application/json');
                    echo json_encode(['success' => true, 'message' => 'Eintrag gelöscht.']);
                    exit;
                }
                $message = 'Eintrag gelöscht.';
            }
        }
    }
}

// Fetch vault items for current user
$stmt = $pdo->prepare("SELECT id, item_type, title, encrypted_data, iv, salt, created_at FROM vault_items WHERE user_id = ? ORDER BY created_at DESC");
$stmt->execute([$userId]);
$vaultItems = $stmt->fetchAll(PDO::FETCH_ASSOC);

$pageTitle = 'Tresor (Vault)';
require_once 'header.php';
require_once 'navbar.php';
?>

<div class="container mt-4">
    <div class="d-flex justify-content-between align-items-center mb-3">
        <h2><i class="bi bi-shield-lock"></i> Verschlüsselter Tresor</h2>
        <button id="lock-vault-btn" class="btn btn-outline-warning d-none">
            🔒 Tresor sperren
        </button>
    </div>

    <?php if (!empty($error)): ?>
        <div class="alert alert-danger"><?= htmlspecialchars($error) ?></div>
    <?php endif; ?>
    <?php if (!empty($message)): ?>
        <div class="alert alert-success"><?= htmlspecialchars($message) ?></div>
    <?php endif; ?>

    <!-- Master Password Setup / Unlock Banner -->
    <div id="master-password-card" class="card mb-4 border-primary">
        <div class="card-header bg-primary text-white">
            <h5 class="mb-0">Master-Passwort eingeben</h5>
        </div>
        <div class="card-body">
            <p class="card-text">
                Ihre Daten werden Ende-zu-Ende (E2E) im Browser mit AES-GCM-256 verschlüsselt.
                Geben Sie Ihr Master-Passwort ein, um Ihre Einträge zu entschlüsseln und neue zu erstellen.
            </p>
            <form id="master-password-form">
                <div class="row g-3 align-items-center">
                    <div class="col-md-8">
                        <input type="password" id="master-password-input" class="form-control" placeholder="Master-Passwort" required>
                    </div>
                    <div class="col-md-4">
                        <button type="submit" class="btn btn-primary w-100">Entsperren / Key Ableiten</button>
                    </div>
                </div>
            </form>
        </div>
    </div>

    <!-- Main Vault UI (Hidden until unlocked) -->
    <div id="vault-content" class="d-none">
        <div class="card mb-4">
            <div class="card-header bg-dark text-white d-flex justify-content-between align-items-center">
                <span>Einträge verwalten</span>
                <button class="btn btn-success btn-sm" data-bs-toggle="modal" data-bs-target="#addModal">
                    + Neuer Eintrag
                </button>
            </div>
            <div class="card-body">
                <ul class="nav nav-tabs mb-3" id="vaultTabs" role="tablist">
                    <li class="nav-item" role="presentation">
                        <button class="nav-link active" id="passwords-tab" data-bs-toggle="tab" data-bs-target="#passwords" type="button" role="tab"> Passwörter</button>
                    </li>
                    <li class="nav-item" role="presentation">
                        <button class="nav-link" id="keyfiles-tab" data-bs-toggle="tab" data-bs-target="#keyfiles" type="button" role="tab"> Keyfiles / Keys</button>
                    </li>
                    <li class="nav-item" role="presentation">
                        <button class="nav-link" id="certs-tab" data-bs-toggle="tab" data-bs-target="#certs" type="button" role="tab"> Zertifikate</button>
                    </li>
                </ul>

                <div class="tab-content" id="vaultTabsContent">
                    <!-- Passwords Tab -->
                    <div class="tab-pane fade show active" id="passwords" role="tabpanel">
                        <div class="table-responsive">
                            <table class="table table-hover align-middle">
                                <thead>
                                    <tr>
                                        <th>Titel</th>
                                        <th>Benutzername / Login</th>
                                        <th>Passwort</th>
                                        <th>Aktionen</th>
                                    </tr>
                                </thead>
                                <tbody id="passwords-list">
                                    <tr><td colspan="4" class="text-center text-muted">Keine Passwörter gespeichert.</td></tr>
                                </tbody>
                            </table>
                        </div>
                    </div>

                    <!-- Keyfiles Tab -->
                    <div class="tab-pane fade" id="keyfiles" role="tabpanel">
                        <div class="table-responsive">
                            <table class="table table-hover align-middle">
                                <thead>
                                    <tr>
                                        <th>Titel</th>
                                        <th>Beschreibung / Hinweis</th>
                                        <th>Aktionen</th>
                                    </tr>
                                </thead>
                                <tbody id="keyfiles-list">
                                    <tr><td colspan="3" class="text-center text-muted">Keine Keyfiles gespeichert.</td></tr>
                                </tbody>
                            </table>
                        </div>
                    </div>

                    <!-- Certificates Tab -->
                    <div class="tab-pane fade" id="certs" role="tabpanel">
                        <div class="table-responsive">
                            <table class="table table-hover align-middle">
                                <thead>
                                    <tr>
                                        <th>Titel</th>
                                        <th>Gültig bis / Hinweis</th>
                                        <th>Aktionen</th>
                                    </tr>
                                </thead>
                                <tbody id="certs-list">
                                    <tr><td colspan="3" class="text-center text-muted">Keine Zertifikate gespeichert.</td></tr>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- Modal: Add Item -->
<div class="modal fade" id="addModal" tabindex="-1" aria-labelledby="addModalLabel" aria-hidden="true">
    <div class="modal-dialog modal-lg">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title" id="addModalLabel">Neuen Tresor-Eintrag hinzufügen</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Schließen"></button>
            </div>
            <form id="add-item-form">
                <div class="modal-body">
                    <div class="mb-3">
                        <label for="item_type" class="form-label">Typ</label>
                        <select id="item_type" class="form-select" required>
                            <option value="password">Passwort</option>
                            <option value="keyfile">Keyfile / SSH Key</option>
                            <option value="certificate">Zertifikat</option>
                        </select>
                    </div>
                    <div class="mb-3">
                        <label for="item_title" class="form-label">Titel / Name</label>
                        <input type="text" id="item_title" class="form-control" placeholder="z. B. Webhosting Login, Server SSH Key, SSL Cert" required>
                    </div>

                    <!-- Password Fields -->
                    <div id="field-group-password">
                        <div class="mb-3">
                            <label for="pwd_username" class="form-label">Benutzername / E-Mail</label>
                            <input type="text" id="pwd_username" class="form-control">
                        </div>
                        <div class="mb-3">
                            <label for="pwd_secret" class="form-label">Passwort</label>
                            <input type="password" id="pwd_secret" class="form-control">
                        </div>
                        <div class="mb-3">
                            <label for="pwd_notes" class="form-label">Notizen / URL</label>
                            <textarea id="pwd_notes" class="form-control" rows="2"></textarea>
                        </div>
                    </div>

                    <!-- Keyfile Fields -->
                    <div id="field-group-keyfile" class="d-none">
                        <div class="mb-3">
                            <label for="kf_file" class="form-label">Datei hochladen (oder Text eingeben)</label>
                            <input type="file" id="kf_file" class="form-control">
                        </div>
                        <div class="mb-3">
                            <label for="kf_content" class="form-label">Key Inhalt (PEM / API Key / Keyfile Text)</label>
                            <textarea id="kf_content" class="form-control font-monospace" rows="5" placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"></textarea>
                        </div>
                        <div class="mb-3">
                            <label for="kf_notes" class="form-label">Notizen</label>
                            <textarea id="kf_notes" class="form-control" rows="2"></textarea>
                        </div>
                    </div>

                    <!-- Certificate Fields -->
                    <div id="field-group-certificate" class="d-none">
                        <div class="mb-3">
                            <label for="cert_file" class="form-label">Zertifikatsdatei hochladen (oder Text eingeben)</label>
                            <input type="file" id="cert_file" class="form-control">
                        </div>
                        <div class="mb-3">
                            <label for="cert_content" class="form-label">Zertifikatsinhalt (CRT / PEM / Public Key)</label>
                            <textarea id="cert_content" class="form-control font-monospace" rows="5" placeholder="-----BEGIN CERTIFICATE-----"></textarea>
                        </div>
                        <div class="mb-3">
                            <label for="cert_notes" class="form-label">Ablaufdatum / Notizen</label>
                            <input type="text" id="cert_notes" class="form-control" placeholder="z. B. Gültig bis 2026-12-31">
                        </div>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Abbrechen</button>
                    <button type="submit" class="btn btn-success">Verschlüsseln & Speichern</button>
                </div>
            </form>
        </div>
    </div>
</div>

<script type="application/json" id="vault-data"><?= json_encode(['csrfToken' => $_SESSION['csrf_token'] ?? '', 'items' => $vaultItems], JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?></script>
<script src="vault.js"></script>

<?php require_once 'footer.php'; ?>