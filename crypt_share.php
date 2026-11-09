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
if (!user_has_feature($pdo, $userId, 'crypt_share', $_SESSION['role'] ?? 'user')) {
    if (!empty($_SERVER['HTTP_X_REQUESTED_WITH']) || isset($_POST['ajax'])) {
        header('Content-Type: application/json');
        http_response_code(403);
        echo json_encode(['success' => false, 'error' => 'Keine Berechtigung für Crypt Share.']);
        exit();
    }
    header('Location: index.php');
    exit();
}

ensure_crypt_shares_enhancements_schema($pdo);

$message = '';
$error = '';
const MAX_ENCRYPTED_SHARE_BYTES = 20971520; // ~20 MB encrypted payload limit

function get_share_base_url(): string {
    $configuredUrl = $_ENV['APP_URL'] ?? getenv('APP_URL') ?: '';
    if (is_string($configuredUrl) && trim($configuredUrl) !== '') {
        return rtrim(trim($configuredUrl), '/');
    }

    $scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
    $rawHost = $_SERVER['HTTP_HOST'] ?? 'localhost';
    $host = preg_match('/^[a-zA-Z0-9.-]+(:[0-9]+)?$/', $rawHost) ? $rawHost : 'localhost';
    $basePath = rtrim(str_replace('\\', '/', dirname($_SERVER['PHP_SELF'] ?? '')), '/');

    return $scheme . '://' . $host . $basePath;
}

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

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $csrfError = validate_csrf_token($_POST['csrf_token'] ?? null);
    if ($csrfError !== null) {
        $error = $sendResponse(true, "Ungültiger CSRF-Token.", 403);
    } else {
        $action = $_POST['action'] ?? '';

        if ($action === 'create_share') {
            $fileName = trim((string)($_POST['file_name'] ?? ''));
            $encryptedData = (string)($_POST['encrypted_data'] ?? '');
            $iv = trim((string)($_POST['iv'] ?? ''));
            $salt = trim((string)($_POST['salt'] ?? ''));
            $accessPin = trim((string)($_POST['access_pin'] ?? ''));
            $rawMaxViews = isset($_POST['max_views']) ? (int)$_POST['max_views'] : 1;

            if ($rawMaxViews < 0 || $rawMaxViews > 100) {
                $rawMaxViews = 1;
            }
            $maxViews = $rawMaxViews; // 0 = unlimited within 24h, >=1 = exact view limit

            if ($fileName === '' || $encryptedData === '' || $iv === '' || $salt === '') {
                $error = $sendResponse(true, "Bitte alle Felder ausfüllen.", 400);
            } elseif (strlen($fileName) > 255 || strlen($iv) > 255 || strlen($salt) > 255 || strlen($accessPin) > 64) {
                $error = $sendResponse(true, "Ungültige Eingabelänge.", 400);
            } elseif (strlen($encryptedData) > MAX_ENCRYPTED_SHARE_BYTES) {
                $error = $sendResponse(true, "Die Datei überschreitet das zulässige Größenlimit (max. 10 MB).", 400);
            } else {
                $accessToken = bin2hex(random_bytes(16));
                $expiresAt = date('Y-m-d H:i:s', strtotime('+24 hours'));
                $pinHash = $accessPin !== '' ? password_hash($accessPin, PASSWORD_DEFAULT) : null;

                try {
                    $stmt = $pdo->prepare("INSERT INTO crypt_shares (user_id, file_name, encrypted_data, iv, salt, access_token, pin_hash, max_views, view_count, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?)");
                    $stmt->execute([$userId, $fileName, $encryptedData, $iv, $salt, $accessToken, $pinHash, $maxViews, $expiresAt]);

                    $shareUrl = get_share_base_url() . "/share.php?token=" . $accessToken;
                    $qrDataUri = generate_qr_svg_data_uri($shareUrl, 200);

                    $sendResponse(false, "Share erfolgreich erstellt.", 200, [
                        'share_url' => $shareUrl,
                        'qr_data_uri' => $qrDataUri,
                        'has_pin' => $pinHash !== null,
                        'max_views' => $maxViews
                    ]);
                } catch (\PDOException $e) {
                    error_log($e->getMessage());
                    $error = $sendResponse(true, "Fehler beim Speichern des Shares.", 500);
                }
            }
        } elseif ($action === 'delete_share') {
            $shareId = (int)($_POST['share_id'] ?? 0);
            if ($shareId <= 0) {
                $error = $sendResponse(true, "Ungültige Freigabe-ID.", 400);
            } else {
                try {
                    $stmt = $pdo->prepare("DELETE FROM crypt_shares WHERE id = ? AND user_id = ?");
                    $stmt->execute([$shareId, $userId]);
                    $message = $sendResponse(false, "Freigabe wurde gelöscht.");
                } catch (\PDOException $e) {
                    error_log($e->getMessage());
                    $error = $sendResponse(true, "Fehler beim Löschen der Freigabe.", 500);
                }
            }
        }
    }
}

// Clean up expired or exhausted shares for current user and fetch active shares
$shares = [];
try {
    $nowFormatted = date('Y-m-d H:i:s');
    $cleanupStmt = $pdo->prepare("DELETE FROM crypt_shares WHERE user_id = ? AND (expires_at <= ? OR (max_views > 0 AND view_count >= max_views))");
    $cleanupStmt->execute([$userId, $nowFormatted]);

    $stmt = $pdo->prepare("SELECT id, file_name, access_token, pin_hash, max_views, view_count, expires_at, created_at FROM crypt_shares WHERE user_id = ? AND expires_at > ? ORDER BY created_at DESC");
    $stmt->execute([$userId, $nowFormatted]);
    $shares = $stmt->fetchAll(PDO::FETCH_ASSOC);
} catch (\PDOException $e) {
    error_log("Database error in crypt_share.php: " . $e->getMessage());
    $error = 'Fehler beim Laden der aktiven Freigaben.';
}

require_once 'header.php';
require_once 'navbar.php';
?>

<div class="container mt-4">
    <h2>🔗 Crypt Share</h2>
    <p>Lade eine Datei hoch, um sie sicher zu teilen. Die Datei wird lokal in deinem Browser Ende-zu-Ende verschlüsselt, bevor sie an den Server gesendet wird. Zusätzlich kannst du einen <strong>Zugriffs-PIN</strong> (für 2-Kanal-Übermittlung) und eine <strong>maximale Aufrufanzahl</strong> festlegen.</p>

    <?php if ($error): ?>
        <div class="alert alert-danger"><?= htmlspecialchars($error) ?></div>
    <?php endif; ?>
    <?php if ($message): ?>
        <div class="alert alert-success"><?= htmlspecialchars($message) ?></div>
    <?php endif; ?>

    <div class="card mb-4 shadow-sm">
        <div class="card-header bg-dark text-white">Neue Datei verschlüsselt teilen</div>
        <div class="card-body">
            <form id="shareForm">
                <input type="hidden" id="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token'] ?? '') ?>">
                <div class="mb-3">
                    <label for="shareFile" class="form-label fw-bold">Datei auswählen (max. 10 MB)</label>
                    <input type="file" class="form-control" id="shareFile" required>
                </div>

                <div class="row g-3 mb-3">
                    <div class="col-md-6">
                        <label for="shareMaxViews" class="form-label fw-bold">Maximale Aufrufanzahl</label>
                        <select id="shareMaxViews" class="form-select">
                            <option value="1" selected>🔥 1x ansehen / herunterladen (Burn-after-reading)</option>
                            <option value="3">3x ansehen / herunterladen</option>
                            <option value="5">5x ansehen / herunterladen</option>
                            <option value="10">10x ansehen / herunterladen</option>
                            <option value="25">25x ansehen / herunterladen</option>
                            <option value="0">♾️ Unbegrenzt (innerhalb von 24 Stunden)</option>
                        </select>
                        <small class="text-muted">Nach Erreichen des Limits wird die Freigabe automatisch vom Server gelöscht.</small>
                    </div>
                    <div class="col-md-6">
                        <label for="shareAccessPin" class="form-label fw-bold">Optionaler Zugriffs-PIN / Passwort (2-Kanal-Schutz)</label>
                        <div class="input-group">
                            <input type="password" id="shareAccessPin" class="form-control" placeholder="z. B. 6-stellige PIN oder Passwort (optional)" maxlength="64">
                            <button class="btn btn-outline-secondary" type="button" id="btnToggleSharePin" title="PIN anzeigen/verbergen">👁️</button>
                            <button class="btn btn-outline-primary" type="button" id="btnGenerateSharePin" title="Zufällige 6-stellige PIN generieren">🎲 PIN</button>
                        </div>
                        <small class="text-muted">Empfohlen für 2-Kanal-Übermittlung: Link per E-Mail, PIN + Einmal-Passwort per SMS/Messenger.</small>
                    </div>
                </div>

                <button type="submit" class="btn btn-primary" id="btnShare">🔒 Verschlüsseln &amp; Link erstellen</button>
            </form>

            <div id="shareResult" class="mt-4 d-none">
                <div class="alert alert-success">
                    <div class="row align-items-center g-3">
                        <div class="col-md-8">
                            <h5 class="mb-2">✅ Datei erfolgreich verschlüsselt und hochgeladen!</h5>
                            <p class="small mb-2">Gib den folgenden Link und das Einmal-Passwort (sowie ggf. den PIN über einen zweiten Kanal) an den Empfänger weiter. Gültigkeit: 24 Stunden (<span id="shareMaxViewsResult"></span>).</p>
                            <div class="mb-2">
                                <strong>Link:</strong> <a href="#" id="shareLinkResult" target="_blank" class="text-break"></a>
                            </div>
                            <div class="mb-2">
                                <strong>Einmal-Passwort (E2E-Key):</strong> <code id="sharePasswordResult" class="fs-5 bg-light p-1 border rounded"></code>
                            </div>
                            <div id="sharePinResultRow" class="mb-2 d-none">
                                <strong>Zugriffs-PIN (2. Kanal):</strong> <code id="sharePinResult" class="fs-5 bg-warning-subtle text-dark p-1 border rounded"></code>
                            </div>
                            <div class="d-flex flex-wrap gap-2 mt-3">
                                <button type="button" class="btn btn-sm btn-outline-secondary" id="btnCopyShareInfo">📋 Alle Infos kopieren</button>
                                <button type="button" class="btn btn-sm btn-outline-primary" id="btnCopyShareLinkOnly">🔗 Nur Link kopieren</button>
                            </div>
                        </div>
                        <div class="col-md-4 text-center" id="shareQrContainer">
                            <div class="p-2 bg-white border rounded d-inline-block">
                                <img id="shareQrImage" src="" alt="QR-Code für Share-Link" class="img-fluid share-qr-img">
                                <div class="small text-muted mt-1">📱 QR-Code für Smartphone</div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <div class="card shadow-sm">
        <div class="card-header bg-dark text-white">Deine aktiven Freigaben</div>
        <div class="card-body">
            <?php if (count($shares) > 0): ?>
            <div class="table-responsive">
                <table class="table table-striped align-middle">
                    <thead>
                        <tr>
                            <th>Dateiname</th>
                            <th>Schutz</th>
                            <th>Aufrufe</th>
                            <th>Läuft ab am</th>
                            <th>Aktionen</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($shares as $share): ?>
                        <?php
                            $url = get_share_base_url() . "/share.php?token=" . urlencode($share['access_token']);
                            $qrUri = generate_qr_svg_data_uri($url, 200);
                            $maxViewsVal = (int)($share['max_views'] ?? 1);
                            $viewCountVal = (int)($share['view_count'] ?? 0);
                            $hasPin = !empty($share['pin_hash']);
                        ?>
                        <tr>
                            <td><strong><?= htmlspecialchars($share['file_name']) ?></strong></td>
                            <td>
                                <?php if ($hasPin): ?>
                                    <span class="badge bg-warning text-dark">🔐 PIN-geschützt</span>
                                <?php else: ?>
                                    <span class="badge bg-secondary">Standard (Link + OTP)</span>
                                <?php endif; ?>
                            </td>
                            <td>
                                <?php if ($maxViewsVal > 0): ?>
                                    <span class="badge bg-info text-dark"><?= $viewCountVal ?> / <?= $maxViewsVal ?> Aufrufe</span>
                                <?php else: ?>
                                    <span class="badge bg-light text-dark border"><?= $viewCountVal ?> / ♾️</span>
                                <?php endif; ?>
                            </td>
                            <td><?= htmlspecialchars(date('d.m.Y H:i', strtotime($share['expires_at']))) ?></td>
                            <td>
                                <button type="button" class="btn btn-sm btn-outline-primary btn-copy-share-link me-1" data-url="<?= htmlspecialchars($url) ?>">🔗 Link kopieren</button>
                                <?php if ($qrUri !== ''): ?>
                                    <button type="button" class="btn btn-sm btn-outline-secondary btn-show-share-qr me-1" data-url="<?= htmlspecialchars($url) ?>" data-qr="<?= htmlspecialchars($qrUri) ?>" data-filename="<?= htmlspecialchars($share['file_name']) ?>">📱 QR-Code</button>
                                <?php endif; ?>
                                <form method="POST" action="crypt_share.php" class="d-inline delete-share-form">
                                    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token'] ?? '') ?>">
                                    <input type="hidden" name="action" value="delete_share">
                                    <input type="hidden" name="share_id" value="<?= (int)$share['id'] ?>">
                                    <button type="submit" class="btn btn-sm btn-outline-danger">Löschen</button>
                                </form>
                            </td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
            <?php else: ?>
            <p class="text-muted mb-0">Keine aktiven Freigaben gefunden.</p>
            <?php endif; ?>
        </div>
    </div>
</div>

<!-- Modal: QR Code Viewer for Active Share -->
<div class="modal fade" id="shareQrModal" tabindex="-1" aria-labelledby="shareQrModalLabel" aria-hidden="true">
    <div class="modal-dialog modal-sm modal-dialog-centered">
        <div class="modal-content">
            <div class="modal-header">
                <h6 class="modal-title" id="shareQrModalLabel">📱 Share-Link QR-Code</h6>
                <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Schließen"></button>
            </div>
            <div class="modal-body text-center">
                <p id="shareQrModalFilename" class="small fw-bold mb-2"></p>
                <div class="p-2 bg-white border rounded d-inline-block mb-2">
                    <img id="shareQrModalImg" src="" alt="QR-Code" class="img-fluid share-qr-img">
                </div>
                <div class="small text-muted">Scannen Sie den Code mit der Smartphone-Kamera, um den Share-Link zu öffnen.</div>
            </div>
        </div>
    </div>
</div>

<script src="vault.js"></script>
<script src="crypt_share.js"></script>

<?php require_once 'footer.php'; ?>
