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
if (!user_has_feature($pdo, $userId, 'secure_notes', $_SESSION['role'] ?? 'user')) {
    if (!empty($_SERVER['HTTP_X_REQUESTED_WITH']) || isset($_POST['ajax'])) {
        header('Content-Type: application/json');
        http_response_code(403);
        echo json_encode(['success' => false, 'error' => 'Keine Berechtigung für Sichere Notizen.']);
        exit();
    }
    header('Location: index.php');
    exit();
}

ensure_secure_notes_table($pdo);

$message = '';
$error = '';
$notes = [];

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
            $allowedTypes = ['note', 'recovery'];

            if ($action === 'add') {
                $noteType = $_POST['note_type'] ?? 'note';
                $title = trim($_POST['title'] ?? '');
                $encryptedData = $_POST['encrypted_data'] ?? '';
                $iv = $_POST['iv'] ?? '';
                $salt = $_POST['salt'] ?? '';

                if (!in_array($noteType, $allowedTypes, true) || $title === '' || strlen($title) > 255 || $encryptedData === '' || $iv === '' || strlen($iv) > 255 || $salt === '' || strlen($salt) > 255) {
                    $error = $sendResponse(true, 'Fehlende oder ungültige Felder.', 400);
                } else {
                    $stmt = $pdo->prepare("INSERT INTO secure_notes (user_id, note_type, title, encrypted_data, iv, salt) VALUES (?, ?, ?, ?, ?, ?)");
                    $stmt->execute([$userId, $noteType, $title, $encryptedData, $iv, $salt]);
                    $newId = (int)$pdo->lastInsertId();
                    $message = $sendResponse(false, 'Notiz erfolgreich verschlüsselt gespeichert.', 200, ['id' => $newId]);
                }
            } elseif ($action === 'update') {
                $noteId = (int)($_POST['note_id'] ?? 0);
                $noteType = $_POST['note_type'] ?? 'note';
                $title = trim($_POST['title'] ?? '');
                $encryptedData = $_POST['encrypted_data'] ?? '';
                $iv = $_POST['iv'] ?? '';
                $salt = $_POST['salt'] ?? '';

                if ($noteId <= 0 || !in_array($noteType, $allowedTypes, true) || $title === '' || strlen($title) > 255 || $encryptedData === '' || $iv === '' || strlen($iv) > 255 || $salt === '' || strlen($salt) > 255) {
                    $error = $sendResponse(true, 'Fehlende oder ungültige Felder.', 400);
                } else {
                    $stmt = $pdo->prepare("UPDATE secure_notes SET note_type = ?, title = ?, encrypted_data = ?, iv = ?, salt = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND user_id = ?");
                    $stmt->execute([$noteType, $title, $encryptedData, $iv, $salt, $noteId, $userId]);
                    $message = $sendResponse(false, 'Notiz erfolgreich aktualisiert.');
                }
            } elseif ($action === 'delete') {
                $noteId = (int)($_POST['note_id'] ?? 0);
                if ($noteId <= 0) {
                    $error = $sendResponse(true, 'Ungültige Notiz-ID.', 400);
                } else {
                    $stmt = $pdo->prepare("DELETE FROM secure_notes WHERE id = ? AND user_id = ?");
                    $stmt->execute([$noteId, $userId]);
                    $message = $sendResponse(false, 'Notiz gelöscht.');
                }
            }
        } catch (\PDOException $e) {
            error_log("Database error in secure_notes.php: " . $e->getMessage());
            $error = $sendResponse(true, 'Ein Datenbankfehler ist aufgetreten.', 500);
        }
    }
}

try {
    $stmt = $pdo->prepare("SELECT id, note_type, title, encrypted_data, iv, salt, created_at, updated_at FROM secure_notes WHERE user_id = ? ORDER BY updated_at DESC, id DESC");
    $stmt->execute([$userId]);
    $notes = $stmt->fetchAll(PDO::FETCH_ASSOC);
} catch (\PDOException $e) {
    error_log("Database error in secure_notes.php (fetch): " . $e->getMessage());
    $error = 'Ein Datenbankfehler ist aufgetreten.';
}

$pageTitle = 'Sichere Notizen & Recovery-Codes';
require_once 'header.php';
require_once 'navbar.php';
?>

<div class="container mt-4">
    <div class="d-flex justify-content-between align-items-center mb-3">
        <h2>📝 Sichere Notizen &amp; Recovery-Codes</h2>
        <div>
            <button id="lock-notes-btn" class="btn btn-outline-warning d-none" type="button">
                🔒 Notizen sperren
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
    <div id="notes-master-password-card" class="card mb-4 border-primary">
        <div class="card-header bg-primary text-white">
            <h5 class="mb-0">Master-Passwort für Sichere Notizen eingeben</h5>
        </div>
        <div class="card-body">
            <p class="card-text">
                Ihre Notizen und Recovery-Codes werden Ende-zu-Ende (Zero-Knowledge) im Browser mit <strong>AES-GCM-256</strong> verschlüsselt.
                Geben Sie Ihr Master-Passwort ein, um Ihre Notizen zu entschlüsseln oder neue anzulegen.
            </p>
            <form id="notes-master-password-form">
                <div class="row g-3 align-items-center">
                    <div class="col-md-8">
                        <input type="password" id="notes-master-password-input" class="form-control" placeholder="Master-Passwort" required>
                    </div>
                    <div class="col-md-4">
                        <button type="submit" class="btn btn-primary w-100">Entsperren / Key Ableiten</button>
                    </div>
                </div>
            </form>
        </div>
    </div>

    <!-- Main Secure Notes UI (Hidden until unlocked) -->
    <div id="notes-content" class="d-none">
        <div class="card mb-4">
            <div class="card-header bg-dark text-white d-flex flex-wrap justify-content-between align-items-center gap-2">
                <span>Verschlüsselte Notizen &amp; Recovery-Codes</span>
                <div class="d-flex gap-2 align-items-center">
                    <input type="search" id="notes-search-input" class="form-control form-control-sm" placeholder="Suchen nach Titel, Tag oder Inhalt...">
                    <button id="btn-new-note" class="btn btn-success btn-sm text-nowrap" type="button" data-bs-toggle="modal" data-bs-target="#noteEditorModal">
                        + Neue Notiz
                    </button>
                </div>
            </div>
            <div class="card-body">
                <ul class="nav nav-tabs mb-3" id="notesFilterTabs" role="tablist">
                    <li class="nav-item" role="presentation">
                        <button class="nav-link active" data-filter="all" type="button">Alle (<span id="count-all">0</span>)</button>
                    </li>
                    <li class="nav-item" role="presentation">
                        <button class="nav-link" data-filter="note" type="button">📄 Freitext / Markdown (<span id="count-note">0</span>)</button>
                    </li>
                    <li class="nav-item" role="presentation">
                        <button class="nav-link" data-filter="recovery" type="button">🛟 Recovery-Codes (<span id="count-recovery">0</span>)</button>
                    </li>
                </ul>

                <div id="notes-grid" class="row g-3">
                    <div class="col-12 text-center text-muted py-4">Keine sicheren Notizen vorhanden.</div>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- Modal: Add / Edit Note -->
<div class="modal fade" id="noteEditorModal" tabindex="-1" aria-labelledby="noteEditorModalLabel" aria-hidden="true">
    <div class="modal-dialog modal-lg">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title" id="noteEditorModalLabel">Neue sichere Notiz erstellen</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Schließen"></button>
            </div>
            <form id="note-editor-form">
                <input type="hidden" id="edit_note_id" value="">
                <div class="modal-body">
                    <div class="row g-3 mb-3">
                        <div class="col-md-5">
                            <label for="note_type" class="form-label">Typ</label>
                            <select id="note_type" class="form-select" required>
                                <option value="note">📄 Freitext / Markdown-Notiz</option>
                                <option value="recovery">🛟 Recovery-Codes / Backup-Codes</option>
                            </select>
                        </div>
                        <div class="col-md-7">
                            <label for="note_tags" class="form-label">Kategorie / Tags (optional)</label>
                            <input type="text" id="note_tags" class="form-control" placeholder="z. B. Server, Privat, GitHub, 2FA-Backup">
                        </div>
                    </div>

                    <div class="mb-3">
                        <label for="note_title" class="form-label">Titel</label>
                        <input type="text" id="note_title" class="form-control" placeholder="z. B. GitHub Recovery-Codes, Server-Dokumentation, Lizenzschlüssel" required maxlength="255">
                    </div>

                    <div class="mb-3">
                        <label for="note_file_import" class="form-label">Optional: Aus Text-/Markdown-Datei importieren (<code>.txt</code>, <code>.md</code>)</label>
                        <input type="file" id="note_file_import" class="form-control form-control-sm" accept=".txt,.md,. recovery,.log">
                    </div>

                    <div class="mb-3">
                        <label for="note_content" id="note_content_label" class="form-label">Inhalt (Markdown unterstützt: <code># Titel</code>, <code>**fett**</code>, <code>`code`</code>, Listen)</label>
                        <textarea id="note_content" class="form-control font-monospace" rows="10" placeholder="Geheime Notiz oder Recovery-Codes (ein Code pro Zeile) eingeben..." required></textarea>
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

<!-- Modal: View Note -->
<div class="modal fade" id="noteViewModal" tabindex="-1" aria-labelledby="noteViewModalLabel" aria-hidden="true">
    <div class="modal-dialog modal-lg">
        <div class="modal-content">
            <div class="modal-header">
                <div>
                    <h5 class="modal-title mb-0" id="noteViewModalLabel">Notiz ansehen</h5>
                    <small id="noteViewMeta" class="text-muted"></small>
                </div>
                <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Schließen"></button>
            </div>
            <div class="modal-body">
                <div id="noteViewTags" class="mb-3"></div>
                <div id="noteViewRendered" class="p-3 bg-light border rounded"></div>
            </div>
            <div class="modal-footer justify-content-between">
                <div>
                    <button type="button" id="btn-view-copy" class="btn btn-outline-primary btn-sm">📋 Inhalt kopieren</button>
                    <button type="button" id="btn-view-download" class="btn btn-outline-secondary btn-sm">📥 Als Datei herunterladen</button>
                </div>
                <div>
                    <button type="button" id="btn-view-edit" class="btn btn-primary btn-sm">✏️ Bearbeiten</button>
                    <button type="button" class="btn btn-secondary btn-sm" data-bs-dismiss="modal">Schließen</button>
                </div>
            </div>
        </div>
    </div>
</div>

<div id="secure-notes-data" data-json="<?= htmlspecialchars(json_encode(['csrfToken' => $_SESSION['csrf_token'] ?? '', 'notes' => $notes], JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT), ENT_QUOTES, 'UTF-8') ?>" class="d-none"></div>
<script src="secure_notes.js"></script>

<?php require_once 'footer.php'; ?>
