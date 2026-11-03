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
            $fileName = $_POST['file_name'] ?? '';
            $encryptedData = $_POST['encrypted_data'] ?? '';
            $iv = $_POST['iv'] ?? '';
            $salt = $_POST['salt'] ?? '';

            if (!$fileName || !$encryptedData || !$iv || !$salt) {
                $error = $sendResponse(true, "Bitte alle Felder ausfüllen.", 400);
            } else {
                $accessToken = bin2hex(random_bytes(16));
                $expiresAt = date('Y-m-d H:i:s', strtotime('+24 hours'));

                try {
                    $stmt = $pdo->prepare("INSERT INTO crypt_shares (user_id, file_name, encrypted_data, iv, salt, access_token, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)");
                    $stmt->execute([$userId, $fileName, $encryptedData, $iv, $salt, $accessToken, $expiresAt]);

                    $shareUrl = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? "https" : "http") . "://$_SERVER[HTTP_HOST]" . dirname($_SERVER['PHP_SELF']) . "/share.php?token=" . $accessToken;

                    $sendResponse(false, "Share erfolgreich erstellt.", 200, ['share_url' => $shareUrl]);
                } catch (\PDOException $e) {
                    error_log($e->getMessage());
                    $error = $sendResponse(true, "Fehler beim Speichern des Shares.", 500);
                }
            }
        }
    }
}

// Fetch active shares for user
$stmt = $pdo->prepare("SELECT id, file_name, access_token, expires_at, created_at FROM crypt_shares WHERE user_id = ? AND expires_at > NOW() ORDER BY created_at DESC");
$stmt->execute([$userId]);
$shares = $stmt->fetchAll(PDO::FETCH_ASSOC);

require_once 'header.php';
require_once 'navbar.php';
?>

<div class="container mt-4">
    <h2>Crypt Share</h2>
    <p>Lade eine Datei hoch, um sie sicher zu teilen. Die Datei wird lokal in deinem Browser verschlüsselt, bevor sie an den Server gesendet wird. Der generierte Link und das Einmalpasswort sind 24 Stunden gültig.</p>

    <?php if ($error): ?>
        <div class="alert alert-danger"><?= htmlspecialchars($error) ?></div>
    <?php endif; ?>
    <?php if ($message): ?>
        <div class="alert alert-success"><?= htmlspecialchars($message) ?></div>
    <?php endif; ?>

    <div class="card mb-4">
        <div class="card-header">Neue Datei teilen</div>
        <div class="card-body">
            <form id="shareForm">
                <input type="hidden" id="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
                <div class="mb-3">
                    <label for="shareFile" class="form-label">Datei auswählen</label>
                    <input type="file" class="form-control" id="shareFile" required>
                </div>
                <button type="submit" class="btn btn-primary" id="btnShare">Verschlüsseln & Teilen</button>
            </form>

            <div id="shareResult" class="mt-4 d-none">
                <div class="alert alert-success">
                    <h5>Datei erfolgreich verschlüsselt und hochgeladen!</h5>
                    <p>Gib den folgenden Link und das Passwort an den Empfänger weiter. Beide sind für 24 Stunden gültig.</p>
                    <div class="mb-2">
                        <strong>Link:</strong> <a href="#" id="shareLinkResult" target="_blank"></a>
                    </div>
                    <div class="mb-2">
                        <strong>Einmal-Passwort:</strong> <code id="sharePasswordResult" class="fs-5 bg-light p-1 border rounded"></code>
                    </div>
                    <button class="btn btn-sm btn-outline-secondary" onclick="copyShareInfo()">Info kopieren</button>
                </div>
            </div>
        </div>
    </div>

    <div class="card">
        <div class="card-header">Deine aktiven Freigaben</div>
        <div class="card-body">
            <?php if (count($shares) > 0): ?>
            <table class="table table-striped">
                <thead>
                    <tr>
                        <th>Dateiname</th>
                        <th>Läuft ab am</th>
                        <th>Aktionen</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($shares as $share): ?>
                    <tr>
                        <td><?= htmlspecialchars($share['file_name']) ?></td>
                        <td><?= htmlspecialchars(date('d.m.Y H:i', strtotime($share['expires_at']))) ?></td>
                        <td>
                            <?php
                                $url = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? "https" : "http") . "://$_SERVER[HTTP_HOST]" . dirname($_SERVER['PHP_SELF']) . "/share.php?token=" . urlencode($share['access_token']);
                            ?>
                            <button class="btn btn-sm btn-outline-primary" onclick="navigator.clipboard.writeText('<?= htmlspecialchars($url) ?>')">Link kopieren</button>
                        </td>
                    </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
            <?php else: ?>
            <p class="text-muted">Keine aktiven Freigaben gefunden.</p>
            <?php endif; ?>
        </div>
    </div>
</div>

<script src="vault.js"></script>
<script src="crypt_share.js"></script>
<script>
    function copyShareInfo() {
        const link = document.getElementById('shareLinkResult').href;
        const pwd = document.getElementById('sharePasswordResult').innerText;
        const text = `Hier ist eine sicher geteilte Datei für dich:\n\nLink: ${link}\nPasswort: ${pwd}\n\nDieser Link ist für 24 Stunden gültig.`;
        navigator.clipboard.writeText(text).then(() => {
            alert('Link und Passwort in die Zwischenablage kopiert.');
        });
    }
</script>

<?php require_once 'footer.php'; ?>
