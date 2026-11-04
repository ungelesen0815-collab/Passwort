<?php
require_once __DIR__ . '/session.php';
require_once 'csrf.php';
require_once 'db.php';

if (!isset($_SESSION['user_id'])) {
    if (!empty($_SERVER['HTTP_X_REQUESTED_WITH']) && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) == 'xmlhttprequest') {
        header('Content-Type: application/json');
        http_response_code(401);
        echo json_encode(['error' => 'Unauthorized']);
        exit();
    }
    header('Location: login.php');
    exit();
}

$userId = $_SESSION['user_id'];
$message = '';
$error = '';
$currentVaultId = isset($_GET['id']) ? (int)$_GET['id'] : null;
$vaultItems = [];
$userVaults = [];

// Helper to return response depending on AJAX or Form submission
$sendResponse = function ($isError, $msg, $statusCode = 200, $extraData = []) {
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

// Handle POST actions (API / AJAX or Form submission)
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';
    $token = $_POST['csrf_token'] ?? '';

    $csrfError = validate_csrf_token($token);
    if ($csrfError !== null) {
        $error = $sendResponse(true, 'Ungültiger CSRF-Token.', 400);
    } else {
        if ($action === 'create_vault') {
            $vaultName = trim($_POST['vault_name'] ?? '');
            if (empty($vaultName)) {
                $error = $sendResponse(true, 'Tresorname darf nicht leer sein.', 400);
            } else {
                $stmt = $pdo->prepare("INSERT INTO vaults (user_id, name) VALUES (?, ?)");
                $stmt->execute([$userId, $vaultName]);
                $message = $sendResponse(false, 'Tresor erfolgreich erstellt.');
            }
        } elseif ($action === 'delete_vault') {
            $vaultIdToDelete = (int)($_POST['vault_id'] ?? 0);
            if ($vaultIdToDelete <= 0) {
                $error = $sendResponse(true, 'Ungültige Tresor-ID.', 400);
            } else {
                $stmt = $pdo->prepare("DELETE FROM vaults WHERE id = ? AND user_id = ?");
                $stmt->execute([$vaultIdToDelete, $userId]);
                $message = $sendResponse(false, 'Tresor gelöscht.');
            }
        } elseif ($action === 'add') {
            $itemType = $_POST['item_type'] ?? '';
            $title = trim($_POST['title'] ?? '');
            $encryptedData = $_POST['encrypted_data'] ?? '';
            $iv = $_POST['iv'] ?? '';
            $salt = $_POST['salt'] ?? '';
            $vaultId = (int)($_POST['vault_id'] ?? 0);

            $allowedTypes = ['password', 'keyfile', 'certificate'];

            // Check if vault belongs to user
            $stmt = $pdo->prepare("SELECT id FROM vaults WHERE id = ? AND user_id = ?");
            $stmt->execute([$vaultId, $userId]);
            $validVault = $stmt->fetch();

            if (!$validVault || !in_array($itemType, $allowedTypes, true) || empty($title) || empty($encryptedData) || empty($iv) || empty($salt)) {
                $error = $sendResponse(true, 'Fehlende oder ungültige Felder.', 400);
            } else {
                $stmt = $pdo->prepare("INSERT INTO vault_items (user_id, vault_id, item_type, title, encrypted_data, iv, salt) VALUES (?, ?, ?, ?, ?, ?, ?)");
                $stmt->execute([$userId, $vaultId, $itemType, $title, $encryptedData, $iv, $salt]);
                $newId = $pdo->lastInsertId();

                $message = $sendResponse(false, 'Eintrag erfolgreich gespeichert.', 200, ['id' => $newId]);
            }
        } elseif ($action === 'delete') {
            $itemId = (int)($_POST['item_id'] ?? 0);
            $vaultId = (int)($_POST['vault_id'] ?? 0);

            if ($itemId <= 0 || $vaultId <= 0) {
                $error = $sendResponse(true, 'Ungültige Bezeichner-ID.', 400);
            } else {
                $stmt = $pdo->prepare("DELETE FROM vault_items WHERE id = ? AND user_id = ? AND vault_id = ?");
                $stmt->execute([$itemId, $userId, $vaultId]);

                $message = $sendResponse(false, 'Eintrag gelöscht.');
            }
        }
    }
}

if ($currentVaultId) {
    // Verify vault ownership
    $stmt = $pdo->prepare("SELECT name FROM vaults WHERE id = ? AND user_id = ?");
    $stmt->execute([$currentVaultId, $userId]);
    $vault = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$vault) {
        header('Location: vault.php');
        exit();
    }

    $pageTitle = 'Tresor: ' . htmlspecialchars($vault['name']);
    // Fetch vault items for current user and specific vault
    $stmt = $pdo->prepare("SELECT id, item_type, title, encrypted_data, iv, salt, created_at FROM vault_items WHERE user_id = ? AND vault_id = ? ORDER BY created_at DESC");
    $stmt->execute([$userId, $currentVaultId]);
    $vaultItems = $stmt->fetchAll(PDO::FETCH_ASSOC);
} else {
    $pageTitle = 'Meine Tresore';
    $stmt = $pdo->prepare("SELECT * FROM vaults WHERE user_id = ? ORDER BY created_at DESC");
    $stmt->execute([$userId]);
    $userVaults = $stmt->fetchAll(PDO::FETCH_ASSOC);
}

require_once 'header.php';
require_once 'navbar.php';
?>

<div class="container mt-4">
    <?php if (!$currentVaultId): ?>
        <h2><i class="bi bi-safe"></i> Meine Tresore</h2>

        <?php if (!empty($error)): ?>
            <div class="alert alert-danger"><?= htmlspecialchars($error) ?></div>
        <?php endif; ?>
        <?php if (!empty($message)): ?>
            <div class="alert alert-success"><?= htmlspecialchars($message) ?></div>
        <?php endif; ?>

        <div class="card mb-4">
            <div class="card-header bg-dark text-white d-flex justify-content-between align-items-center">
                <span>Tresore</span>
            </div>
            <div class="card-body">
                <form method="POST" action="vault.php" class="mb-4 d-flex align-items-center">
                    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token'] ?? '') ?>">
                    <input type="hidden" name="action" value="create_vault">
                    <input type="text" name="vault_name" class="form-control me-2" placeholder="Neuer Tresor Name" required>
                    <button type="submit" class="btn btn-success text-nowrap">+ Tresor Erstellen</button>
                </form>

                <div class="list-group">
                    <?php foreach ($userVaults as $v): ?>
                        <div class="list-group-item d-flex justify-content-between align-items-center">
                            <a href="vault.php?id=<?= $v['id'] ?>" class="text-decoration-none h5 mb-0 flex-grow-1">
                                <i class="bi bi-shield-lock me-2"></i><?= htmlspecialchars($v['name']) ?>
                            </a>
                            <form method="POST" action="vault.php" class="ms-3" onsubmit="return confirm('Tresor wirklich löschen? Alle Einträge darin gehen verloren!');">
                                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token'] ?? '') ?>">
                                <input type="hidden" name="action" value="delete_vault">
                                <input type="hidden" name="vault_id" value="<?= $v['id'] ?>">
                                <button type="submit" class="btn btn-danger btn-sm">Löschen</button>
                            </form>
                        </div>
                    <?php endforeach; ?>
                    <?php if (empty($userVaults)): ?>
                        <p class="text-muted">Sie haben noch keine Tresore.</p>
                    <?php endif; ?>
                </div>
            </div>
        </div>
    <?php else: ?>
        <div class="d-flex justify-content-between align-items-center mb-3">
            <h2><i class="bi bi-shield-lock"></i> <?= htmlspecialchars($vault['name']) ?></h2>
            <div>
                <a href="vault.php" class="btn btn-outline-secondary me-2">Zurück</a>
                <button id="lock-vault-btn" class="btn btn-outline-warning d-none">
                    🔒 Tresor sperren
                </button>
            </div>
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

<div id="vault-data" data-json="<?= htmlspecialchars(json_encode(['csrfToken' => $_SESSION['csrf_token'] ?? '', 'vaultId' => $currentVaultId, 'items' => $vaultItems], JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT), ENT_QUOTES, 'UTF-8') ?>" class="d-none"></div>
<script src="vault.js"></script>
<?php endif; ?>

<?php require_once 'footer.php'; ?>