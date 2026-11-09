<?php
require_once __DIR__ . '/session.php';
require_once 'csrf.php';
require_once 'db.php';
require_once 'auth_utils.php';

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
if (!user_has_feature($pdo, $userId, 'vault', $_SESSION['role'] ?? 'user')) {
    if (!empty($_SERVER['HTTP_X_REQUESTED_WITH']) || isset($_POST['ajax'])) {
        header('Content-Type: application/json');
        http_response_code(403);
        echo json_encode(['success' => false, 'error' => 'Keine Berechtigung für den Tresor.']);
        exit();
    }
    header('Location: index.php');
    exit();
}

ensure_vault_enhancements_schema($pdo);
$canUseCryptShare = user_has_feature($pdo, $userId, 'crypt_share', $_SESSION['role'] ?? 'user');

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
        try {
            if ($action === 'create_vault') {
                $vaultName = trim($_POST['vault_name'] ?? '');
                if (empty($vaultName)) {
                    $error = $sendResponse(true, 'Tresorname darf nicht leer sein.', 400);
                } elseif (strlen($vaultName) > 255) {
                    $error = $sendResponse(true, 'Tresorname darf maximal 255 Zeichen lang sein.', 400);
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
                $category = trim($_POST['category'] ?? '');
                $isFavorite = !empty($_POST['is_favorite']) ? 1 : 0;
                $encryptedData = $_POST['encrypted_data'] ?? '';
                $iv = $_POST['iv'] ?? '';
                $salt = $_POST['salt'] ?? '';
                $vaultId = (int)($_POST['vault_id'] ?? 0);

                $allowedTypes = ['password', 'keyfile', 'certificate'];

                // Check if vault belongs to user
                $stmt = $pdo->prepare("SELECT id FROM vaults WHERE id = ? AND user_id = ?");
                $stmt->execute([$vaultId, $userId]);
                $validVault = $stmt->fetch();

                if (!$validVault || !in_array($itemType, $allowedTypes, true) || empty($title) || strlen($title) > 255 || strlen($category) > 100 || empty($encryptedData) || empty($iv) || strlen($iv) > 255 || empty($salt) || strlen($salt) > 255) {
                    $error = $sendResponse(true, 'Fehlende oder ungültige Felder.', 400);
                } else {
                    $stmt = $pdo->prepare("INSERT INTO vault_items (user_id, vault_id, item_type, title, category, is_favorite, encrypted_data, iv, salt) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)");
                    $stmt->execute([$userId, $vaultId, $itemType, $title, $category, $isFavorite, $encryptedData, $iv, $salt]);
                    $newId = (int)$pdo->lastInsertId();

                    $message = $sendResponse(false, 'Eintrag erfolgreich gespeichert.', 200, ['id' => $newId]);
                }
            } elseif ($action === 'update') {
                $itemId = (int)($_POST['item_id'] ?? 0);
                $vaultId = (int)($_POST['vault_id'] ?? 0);
                $itemType = $_POST['item_type'] ?? '';
                $title = trim($_POST['title'] ?? '');
                $category = trim($_POST['category'] ?? '');
                $isFavorite = !empty($_POST['is_favorite']) ? 1 : 0;
                $encryptedData = $_POST['encrypted_data'] ?? '';
                $iv = $_POST['iv'] ?? '';
                $salt = $_POST['salt'] ?? '';

                $allowedTypes = ['password', 'keyfile', 'certificate'];

                $stmtExisting = $pdo->prepare("SELECT id, encrypted_data, iv, salt FROM vault_items WHERE id = ? AND user_id = ? AND vault_id = ?");
                $stmtExisting->execute([$itemId, $userId, $vaultId]);
                $existingItem = $stmtExisting->fetch(PDO::FETCH_ASSOC);

                if (!$existingItem || !in_array($itemType, $allowedTypes, true) || empty($title) || strlen($title) > 255 || strlen($category) > 100 || empty($encryptedData) || empty($iv) || strlen($iv) > 255 || empty($salt) || strlen($salt) > 255) {
                    $error = $sendResponse(true, 'Fehlende oder ungültige Felder.', 400);
                } else {
                    // Save previous state into vault_item_history
                    $stmtHist = $pdo->prepare("INSERT INTO vault_item_history (vault_item_id, user_id, encrypted_data, iv, salt) VALUES (?, ?, ?, ?, ?)");
                    $stmtHist->execute([$itemId, $userId, $existingItem['encrypted_data'], $existingItem['iv'], $existingItem['salt']]);

                    // Keep at most 20 history entries per item
                    $stmtOldHist = $pdo->prepare("SELECT id FROM vault_item_history WHERE vault_item_id = ? AND user_id = ? ORDER BY id DESC");
                    $stmtOldHist->execute([$itemId, $userId]);
                    $histIds = $stmtOldHist->fetchAll(PDO::FETCH_COLUMN);
                    if (count($histIds) > 20) {
                        $idsToDelete = array_slice($histIds, 20);
                        $placeholders = implode(',', array_fill(0, count($idsToDelete), '?'));
                        $stmtDelHist = $pdo->prepare("DELETE FROM vault_item_history WHERE id IN ($placeholders)");
                        $stmtDelHist->execute($idsToDelete);
                    }

                    $stmtUpd = $pdo->prepare("UPDATE vault_items SET item_type = ?, title = ?, category = ?, is_favorite = ?, encrypted_data = ?, iv = ?, salt = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND user_id = ? AND vault_id = ?");
                    $stmtUpd->execute([$itemType, $title, $category, $isFavorite, $encryptedData, $iv, $salt, $itemId, $userId, $vaultId]);

                    $message = $sendResponse(false, 'Eintrag erfolgreich aktualisiert (Vorversion im Verlauf gesichert).');
                }
            } elseif ($action === 'toggle_favorite') {
                $itemId = (int)($_POST['item_id'] ?? 0);
                $vaultId = (int)($_POST['vault_id'] ?? 0);
                $isFavorite = !empty($_POST['is_favorite']) ? 1 : 0;

                if ($itemId <= 0 || $vaultId <= 0) {
                    $error = $sendResponse(true, 'Ungültige Bezeichner-ID.', 400);
                } else {
                    $stmt = $pdo->prepare("UPDATE vault_items SET is_favorite = ? WHERE id = ? AND user_id = ? AND vault_id = ?");
                    $stmt->execute([$isFavorite, $itemId, $userId, $vaultId]);
                    $message = $sendResponse(false, 'Favoritenstatus aktualisiert.', 200, ['is_favorite' => $isFavorite]);
                }
            } elseif ($action === 'get_history') {
                $itemId = (int)($_POST['item_id'] ?? 0);
                $vaultId = (int)($_POST['vault_id'] ?? 0);

                $stmtCheck = $pdo->prepare("SELECT id FROM vault_items WHERE id = ? AND user_id = ? AND vault_id = ?");
                $stmtCheck->execute([$itemId, $userId, $vaultId]);
                if (!$stmtCheck->fetch()) {
                    $error = $sendResponse(true, 'Eintrag nicht gefunden.', 404);
                } else {
                    $stmtHist = $pdo->prepare("SELECT id, encrypted_data, iv, salt, created_at FROM vault_item_history WHERE vault_item_id = ? AND user_id = ? ORDER BY id DESC");
                    $stmtHist->execute([$itemId, $userId]);
                    $history = $stmtHist->fetchAll(PDO::FETCH_ASSOC);
                    $sendResponse(false, 'Verlauf geladen.', 200, ['history' => $history]);
                }
            } elseif ($action === 'restore_history') {
                $itemId = (int)($_POST['item_id'] ?? 0);
                $historyId = (int)($_POST['history_id'] ?? 0);
                $vaultId = (int)($_POST['vault_id'] ?? 0);

                $stmtCurrent = $pdo->prepare("SELECT id, encrypted_data, iv, salt FROM vault_items WHERE id = ? AND user_id = ? AND vault_id = ?");
                $stmtCurrent->execute([$itemId, $userId, $vaultId]);
                $currentItem = $stmtCurrent->fetch(PDO::FETCH_ASSOC);

                $stmtHist = $pdo->prepare("SELECT id, encrypted_data, iv, salt FROM vault_item_history WHERE id = ? AND vault_item_id = ? AND user_id = ?");
                $stmtHist->execute([$historyId, $itemId, $userId]);
                $histEntry = $stmtHist->fetch(PDO::FETCH_ASSOC);

                if (!$currentItem || !$histEntry) {
                    $error = $sendResponse(true, 'Verlaufseintrag nicht gefunden.', 404);
                } else {
                    // Save current state to history before restoring
                    $stmtSaveCurr = $pdo->prepare("INSERT INTO vault_item_history (vault_item_id, user_id, encrypted_data, iv, salt) VALUES (?, ?, ?, ?, ?)");
                    $stmtSaveCurr->execute([$itemId, $userId, $currentItem['encrypted_data'], $currentItem['iv'], $currentItem['salt']]);

                    // Restore selected history entry onto vault_items
                    $stmtRestore = $pdo->prepare("UPDATE vault_items SET encrypted_data = ?, iv = ?, salt = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND user_id = ? AND vault_id = ?");
                    $stmtRestore->execute([$histEntry['encrypted_data'], $histEntry['iv'], $histEntry['salt'], $itemId, $userId, $vaultId]);

                    // Remove the consumed history row
                    $stmtDelHist = $pdo->prepare("DELETE FROM vault_item_history WHERE id = ? AND user_id = ?");
                    $stmtDelHist->execute([$historyId, $userId]);

                    $sendResponse(false, 'Frühere Version erfolgreich wiederhergestellt.', 200, [
                        'encrypted_data' => $histEntry['encrypted_data'],
                        'iv' => $histEntry['iv'],
                        'salt' => $histEntry['salt']
                    ]);
                }
            } elseif ($action === 'delete_history_entry') {
                $historyId = (int)($_POST['history_id'] ?? 0);
                if ($historyId <= 0) {
                    $error = $sendResponse(true, 'Ungültige Verlaufs-ID.', 400);
                } else {
                    $stmt = $pdo->prepare("DELETE FROM vault_item_history WHERE id = ? AND user_id = ?");
                    $stmt->execute([$historyId, $userId]);
                    $sendResponse(false, 'Verlaufseintrag gelöscht.');
                }
            } elseif ($action === 'bulk_import') {
                $vaultId = (int)($_POST['vault_id'] ?? 0);
                $itemsJson = $_POST['items_json'] ?? '';

                $stmtVault = $pdo->prepare("SELECT id FROM vaults WHERE id = ? AND user_id = ?");
                $stmtVault->execute([$vaultId, $userId]);
                $validVault = $stmtVault->fetch();

                $decodedItems = is_string($itemsJson) ? json_decode($itemsJson, true) : null;
                if (!$validVault || !is_array($decodedItems) || empty($decodedItems) || count($decodedItems) > 500) {
                    $error = $sendResponse(true, 'Ungültige Importdaten (maximal 500 Einträge gleichzeitig).', 400);
                } else {
                    $allowedTypes = ['password', 'keyfile', 'certificate'];
                    $insertedItems = [];
                    $stmtInsert = $pdo->prepare("INSERT INTO vault_items (user_id, vault_id, item_type, title, category, is_favorite, encrypted_data, iv, salt) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)");

                    foreach ($decodedItems as $entry) {
                        if (!is_array($entry)) {
                            continue;
                        }
                        $type = (string)($entry['item_type'] ?? 'password');
                        if (!in_array($type, $allowedTypes, true)) {
                            $type = 'password';
                        }
                        $title = substr(trim((string)($entry['title'] ?? '')), 0, 255);
                        $category = substr(trim((string)($entry['category'] ?? '')), 0, 100);
                        $isFav = !empty($entry['is_favorite']) ? 1 : 0;
                        $encData = (string)($entry['encrypted_data'] ?? '');
                        $iv = substr(trim((string)($entry['iv'] ?? '')), 0, 255);
                        $salt = substr(trim((string)($entry['salt'] ?? '')), 0, 255);

                        if ($title === '' || $encData === '' || $iv === '' || $salt === '') {
                            continue;
                        }

                        $stmtInsert->execute([$userId, $vaultId, $type, $title, $category, $isFav, $encData, $iv, $salt]);
                        $newId = (int)$pdo->lastInsertId();
                        $insertedItems[] = [
                            'id' => $newId,
                            'item_type' => $type,
                            'title' => $title,
                            'category' => $category,
                            'is_favorite' => $isFav,
                            'encrypted_data' => $encData,
                            'iv' => $iv,
                            'salt' => $salt,
                            'created_at' => date('Y-m-d H:i:s'),
                            'history_count' => 0
                        ];
                    }

                    $sendResponse(false, count($insertedItems) . ' Einträge erfolgreich importiert.', 200, [
                        'imported_count' => count($insertedItems),
                        'items' => $insertedItems
                    ]);
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
        } catch (\PDOException $e) {
            error_log("Database error in vault.php: " . $e->getMessage());
            $error = $sendResponse(true, 'Ein Datenbankfehler ist aufgetreten.', 500);
        }
    }
}

try {
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
        // Fetch vault items for current user and specific vault including category, favorites, and history count
        $stmt = $pdo->prepare("
            SELECT vi.id, vi.item_type, vi.title, vi.category, vi.is_favorite, vi.encrypted_data, vi.iv, vi.salt, vi.created_at,
                   (SELECT COUNT(*) FROM vault_item_history vih WHERE vih.vault_item_id = vi.id) AS history_count
            FROM vault_items vi
            WHERE vi.user_id = ? AND vi.vault_id = ?
            ORDER BY vi.is_favorite DESC, vi.created_at DESC
        ");
        $stmt->execute([$userId, $currentVaultId]);
        $vaultItems = $stmt->fetchAll(PDO::FETCH_ASSOC);
    } else {
        $pageTitle = 'Meine Tresore';
        $stmt = $pdo->prepare("SELECT * FROM vaults WHERE user_id = ? ORDER BY created_at DESC");
        $stmt->execute([$userId]);
        $userVaults = $stmt->fetchAll(PDO::FETCH_ASSOC);
    }
} catch (\PDOException $e) {
    error_log("Database error in vault.php (fetch): " . $e->getMessage());
    $error = 'Ein Datenbankfehler ist aufgetreten.';
}

require_once 'header.php';
require_once 'navbar.php';
?>

<div class="container mt-4">
    <div id="pending-vault-entry-banner" class="alert alert-info d-none">
        🔑 <strong>Vorgemerktes Passwort aus dem Generator:</strong> Bitte wählen bzw. entsperren Sie einen Tresor mit Ihrem Master-Passwort – das Formular öffnet sich danach automatisch mit den übernommenen Zugangsdaten.
    </div>
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
                            <form method="POST" action="vault.php" class="ms-3 delete-vault-form">
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
                <button id="lock-vault-btn" class="btn btn-outline-warning d-none" type="button">
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
                <div class="card-header bg-dark text-white d-flex flex-wrap justify-content-between align-items-center gap-2">
                    <span>Einträge verwalten</span>
                    <div class="d-flex flex-wrap gap-2">
                        <button class="btn btn-outline-light btn-sm" type="button" id="btn-open-import-export" data-bs-toggle="modal" data-bs-target="#importExportModal">
                            🔄 Import / Export
                        </button>
                        <button class="btn btn-success btn-sm" type="button" id="btn-open-add-modal" data-bs-toggle="modal" data-bs-target="#addModal">
                            + Neuer Eintrag
                        </button>
                    </div>
                </div>
                <div class="card-body">
                    <!-- Filter Bar: Search, Category/Folder, Favorites -->
                    <div class="row g-2 align-items-center mb-3 p-2 bg-light border rounded">
                        <div class="col-md-5">
                            <input type="search" id="vault-search-input" class="form-control form-control-sm" placeholder="🔍 Suchen nach Titel, Benutzername, Kategorie oder Notiz...">
                        </div>
                        <div class="col-md-4">
                            <select id="vault-category-filter" class="form-select form-select-sm">
                                <option value="all">📁 Alle Kategorien / Ordner</option>
                                <option value="Arbeit">💼 Arbeit</option>
                                <option value="Privat">🏠 Privat</option>
                                <option value="Server">🖥️ Server</option>
                                <option value="Finanzen">💳 Finanzen</option>
                                <option value="uncategorized">Ohne Kategorie</option>
                            </select>
                        </div>
                        <div class="col-md-3 d-flex justify-content-md-end">
                            <button type="button" id="vault-favorite-filter-btn" class="btn btn-outline-warning btn-sm w-100" data-active="0">
                                ⭐ Nur Favoriten (<span id="favorites-count">0</span>)
                            </button>
                        </div>
                    </div>

                    <ul class="nav nav-tabs mb-3" id="vaultTabs" role="tablist">
                        <li class="nav-item" role="presentation">
                            <button class="nav-link active" id="passwords-tab" data-bs-toggle="tab" data-bs-target="#passwords" type="button" role="tab">🔑 Passwörter (<span id="tab-count-passwords">0</span>)</button>
                        </li>
                        <li class="nav-item" role="presentation">
                            <button class="nav-link" id="keyfiles-tab" data-bs-toggle="tab" data-bs-target="#keyfiles" type="button" role="tab">🗝️ Keyfiles / Keys (<span id="tab-count-keyfiles">0</span>)</button>
                        </li>
                        <li class="nav-item" role="presentation">
                            <button class="nav-link" id="certs-tab" data-bs-toggle="tab" data-bs-target="#certs" type="button" role="tab">📜 Zertifikate (<span id="tab-count-certs">0</span>)</button>
                        </li>
                    </ul>

                    <div class="tab-content" id="vaultTabsContent">
                        <!-- Passwords Tab -->
                        <div class="tab-pane fade show active" id="passwords" role="tabpanel">
                            <div class="table-responsive">
                                <table class="table table-hover align-middle">
                                    <thead>
                                        <tr>
                                            <th>⭐</th>
                                            <th>Titel &amp; Ordner</th>
                                            <th>Benutzername / Login</th>
                                            <th>Passwort</th>
                                            <th>Aktionen</th>
                                        </tr>
                                    </thead>
                                    <tbody id="passwords-list">
                                        <tr><td colspan="5" class="text-center text-muted">Keine Passwörter gespeichert.</td></tr>
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
                                            <th>⭐</th>
                                            <th>Titel &amp; Ordner</th>
                                            <th>Beschreibung / Hinweis</th>
                                            <th>Aktionen</th>
                                        </tr>
                                    </thead>
                                    <tbody id="keyfiles-list">
                                        <tr><td colspan="4" class="text-center text-muted">Keine Keyfiles gespeichert.</td></tr>
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
                                            <th>⭐</th>
                                            <th>Titel &amp; Ordner</th>
                                            <th>Gültig bis / Hinweis</th>
                                            <th>Aktionen</th>
                                        </tr>
                                    </thead>
                                    <tbody id="certs-list">
                                        <tr><td colspan="4" class="text-center text-muted">Keine Zertifikate gespeichert.</td></tr>
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    <?php endif; ?>
</div>

<?php if ($currentVaultId): ?>
<!-- Modal: Add / Edit Item -->
<div class="modal fade" id="addModal" tabindex="-1" aria-labelledby="addModalLabel" aria-hidden="true">
    <div class="modal-dialog modal-lg">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title" id="addModalLabel">Neuen Tresor-Eintrag hinzufügen</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Schließen"></button>
            </div>
            <form id="add-item-form">
                <input type="hidden" id="edit_item_id" value="">
                <div class="modal-body">
                    <div class="row g-3 mb-3">
                        <div class="col-md-4">
                            <label for="item_type" class="form-label">Typ</label>
                            <select id="item_type" class="form-select" required>
                                <option value="password">Passwort</option>
                                <option value="keyfile">Keyfile / SSH Key</option>
                                <option value="certificate">Zertifikat</option>
                            </select>
                        </div>
                        <div class="col-md-5">
                            <label for="item_category" class="form-label">Kategorie / Ordner</label>
                            <input type="text" id="item_category" class="form-control" list="vault-category-suggestions" placeholder="z. B. Arbeit, Privat, Server, Finanzen" maxlength="100">
                            <datalist id="vault-category-suggestions">
                                <option value="Arbeit"></option>
                                <option value="Privat"></option>
                                <option value="Server"></option>
                                <option value="Finanzen"></option>
                            </datalist>
                        </div>
                        <div class="col-md-3 d-flex align-items-end">
                            <div class="form-check mb-2">
                                <input class="form-check-input" type="checkbox" id="item_favorite" value="1">
                                <label class="form-check-label fw-bold" for="item_favorite">
                                    ⭐ Als Favorit markieren
                                </label>
                            </div>
                        </div>
                    </div>

                    <div class="mb-3">
                        <label for="item_title" class="form-label">Titel / Name</label>
                        <input type="text" id="item_title" class="form-control" placeholder="z. B. Webhosting Login, Server SSH Key, SSL Cert" required maxlength="255">
                    </div>

                    <!-- Password Fields -->
                    <div id="field-group-password">
                        <div class="mb-3">
                            <label for="pwd_username" class="form-label">Benutzername / E-Mail</label>
                            <input type="text" id="pwd_username" class="form-control">
                        </div>
                        <div class="mb-3">
                            <label for="pwd_secret" class="form-label">Passwort</label>
                            <div class="input-group">
                                <input type="password" id="pwd_secret" class="form-control">
                                <button class="btn btn-outline-secondary" type="button" id="btn-toggle-modal-pwd">👁️</button>
                            </div>
                        </div>
                        <div class="mb-3">
                            <label for="pwd_notes" class="form-label">Notizen / URL</label>
                            <textarea id="pwd_notes" class="form-control" rows="2" placeholder="https://beispiel.de oder zusätzliche Hinweise"></textarea>
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
                    <button type="submit" class="btn btn-success" id="btn-save-vault-item">Verschlüsseln &amp; Speichern</button>
                </div>
            </form>
        </div>
    </div>
</div>

<!-- Modal: Password & Item History -->
<div class="modal fade" id="historyModal" tabindex="-1" aria-labelledby="historyModalLabel" aria-hidden="true">
    <div class="modal-dialog modal-lg">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title" id="historyModalLabel">🕒 Passwort- &amp; Änderungshistorie</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Schließen"></button>
            </div>
            <div class="modal-body">
                <p class="small text-muted mb-3">
                    Jedes Mal, wenn Sie einen Eintrag bearbeiten, wird der vorherige Stand Ende-zu-Ende verschlüsselt gesichert. Sie können frühere Passwörter kopieren oder mit einem Klick wiederherstellen.
                </p>
                <div id="history-list-container">
                    <div class="text-center text-muted py-3">Lade Verlauf...</div>
                </div>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Schließen</button>
            </div>
        </div>
    </div>
</div>

<!-- Modal: Encrypted Import / Export -->
<div class="modal fade" id="importExportModal" tabindex="-1" aria-labelledby="importExportModalLabel" aria-hidden="true">
    <div class="modal-dialog modal-lg">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title" id="importExportModalLabel">🔄 Tresor Import &amp; Export</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Schließen"></button>
            </div>
            <div class="modal-body">
                <ul class="nav nav-pills mb-3" id="importExportTabs" role="tablist">
                    <li class="nav-item" role="presentation">
                        <button class="nav-link active" id="export-tab-btn" data-bs-toggle="pill" data-bs-target="#exportPane" type="button" role="tab">📤 Export (Verschlüsseltes Backup)</button>
                    </li>
                    <li class="nav-item" role="presentation">
                        <button class="nav-link" id="import-tab-btn" data-bs-toggle="pill" data-bs-target="#importPane" type="button" role="tab">📥 Import (Backup / Bitwarden / KeePass / CSV)</button>
                    </li>
                </ul>

                <div class="tab-content">
                    <!-- Export Pane -->
                    <div class="tab-pane fade show active" id="exportPane" role="tabpanel">
                        <div class="card bg-light border mb-3">
                            <div class="card-body">
                                <h6 class="fw-bold">🔒 Verschlüsseltes JSON-Backup erstellen</h6>
                                <p class="small text-muted">
                                    Alle Einträge dieses Tresors inkl. Kategorien und Favoriten werden mit <strong>AES-GCM-256</strong> verschlüsselt in eine JSON-Datei exportiert. Optional können Sie ein eigenes Backup-Passwort vergeben (andernfalls wird Ihr aktuelles Tresor-Master-Passwort verwendet).
                                </p>
                                <div class="mb-3">
                                    <label for="export_backup_password" class="form-label">Optionales Backup-Passwort (leer lassen für aktuelles Master-Passwort)</label>
                                    <input type="password" id="export_backup_password" class="form-control form-control-sm" placeholder="Eigenes Passwort für die Backup-Datei (optional)">
                                </div>
                                <div class="d-flex flex-wrap gap-2">
                                    <button type="button" id="btn-export-encrypted-json" class="btn btn-primary btn-sm">
                                        🔐 Verschlüsseltes JSON-Backup herunterladen
                                    </button>
                                    <button type="button" id="btn-export-csv" class="btn btn-outline-secondary btn-sm">
                                        📄 Als CSV exportieren (Klartext)
                                    </button>
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- Import Pane -->
                    <div class="tab-pane fade" id="importPane" role="tabpanel">
                        <form id="vault-import-form">
                            <div class="mb-3">
                                <label for="import_format" class="form-label fw-bold">Import-Format auswählen</label>
                                <select id="import_format" class="form-select form-select-sm">
                                    <option value="auto">✨ Automatisch erkennen (Verschlüsseltes Backup, Bitwarden JSON, CSV / KeePass CSV)</option>
                                    <option value="encrypted_json">🔐 Verschlüsseltes Tresor-Backup (.json)</option>
                                    <option value="bitwarden_json">🛡️ Bitwarden Export (.json)</option>
                                    <option value="csv">📊 CSV-Datei (Bitwarden / KeePass / Browser CSV)</option>
                                </select>
                            </div>
                            <div class="mb-3">
                                <label for="import_file" class="form-label">Datei auswählen (<code>.json</code> oder <code>.csv</code>)</label>
                                <input type="file" id="import_file" class="form-control form-control-sm" accept=".json,.csv,.txt" required>
                            </div>
                            <div class="mb-3" id="import-password-group">
                                <label for="import_backup_password" class="form-label">Backup-Passwort (nur falls das verschlüsselte Backup mit einem anderen Passwort erstellt wurde)</label>
                                <input type="password" id="import_backup_password" class="form-control form-control-sm" placeholder="Leer lassen für aktuelles Master-Passwort">
                            </div>
                            <div id="import-status-msg" class="alert d-none small"></div>
                            <button type="submit" id="btn-run-import" class="btn btn-success btn-sm">
                                📥 Datei entschlüsseln / einlesen &amp; in Tresor importieren
                            </button>
                        </form>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- Modal: One-Click Crypt Share Result -->
<div class="modal fade" id="vaultCryptShareModal" tabindex="-1" aria-labelledby="vaultCryptShareModalLabel" aria-hidden="true">
    <div class="modal-dialog">
        <div class="modal-content">
            <div class="modal-header bg-primary text-white">
                <h5 class="modal-title" id="vaultCryptShareModalLabel">🔗 Crypt Share Einmal-Link erstellt</h5>
                <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal" aria-label="Schließen"></button>
            </div>
            <div class="modal-body">
                <p class="small text-muted">
                    Der Tresor-Eintrag <strong id="vaultShareItemTitle"></strong> wurde lokal im Browser mit einem zufälligen Einmal-Passwort verschlüsselt und als 24 Stunden gültiger Crypt-Share-Link hinterlegt.
                </p>
                <div class="mb-3">
                    <label class="form-label fw-bold">Freigabe-Link (24h gültig, 1x Aufruf):</label>
                    <div class="input-group input-group-sm">
                        <input type="text" id="vaultShareLinkInput" class="form-control font-monospace" readonly>
                        <button type="button" class="btn btn-outline-primary" id="btn-copy-vault-share-link">📋 Link</button>
                    </div>
                </div>
                <div class="mb-3">
                    <label class="form-label fw-bold">Einmal-Passwort (zum Entschlüsseln):</label>
                    <div class="input-group input-group-sm">
                        <input type="text" id="vaultShareOtpInput" class="form-control font-monospace fw-bold" readonly>
                        <button type="button" class="btn btn-outline-primary" id="btn-copy-vault-share-otp">📋 Passwort</button>
                    </div>
                </div>
                <div id="vaultShareQrWrapper" class="text-center mt-3 d-none">
                    <div class="p-2 bg-white border rounded d-inline-block">
                        <img id="vaultShareQrImg" src="" alt="QR-Code für Share-Link" class="img-fluid share-qr-img">
                        <div class="small text-muted mt-1">📱 QR-Code für Smartphone</div>
                    </div>
                </div>
            </div>
            <div class="modal-footer justify-content-between">
                <button type="button" class="btn btn-success btn-sm" id="btn-copy-vault-share-both">📋 Link &amp; Passwort zusammen kopieren</button>
                <button type="button" class="btn btn-secondary btn-sm" data-bs-dismiss="modal">Schließen</button>
            </div>
        </div>
    </div>
</div>

<div id="vault-data" data-json="<?= htmlspecialchars(json_encode(['csrfToken' => $_SESSION['csrf_token'] ?? '', 'vaultId' => $currentVaultId, 'canUseCryptShare' => $canUseCryptShare, 'items' => $vaultItems], JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT), ENT_QUOTES, 'UTF-8') ?>" class="d-none"></div>
<?php endif; ?>
<script src="vault.js"></script>

<?php require_once 'footer.php'; ?>
