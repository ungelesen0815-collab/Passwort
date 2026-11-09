<?php
require_once __DIR__ . '/session.php';
require_once 'db.php';
require_once 'auth_utils.php';

ensure_crypt_shares_enhancements_schema($pdo);

$token = is_string($_GET['token'] ?? null) ? trim($_GET['token']) : '';
$error = '';
$shareMeta = null;
$unlockedPayload = null;
$remainingViewsAfterCurrent = null;

if ($token === '') {
    $error = 'Kein Zugriffs-Token angegeben.';
} else {
    try {
        $stmt = $pdo->prepare("SELECT id, file_name, encrypted_data, iv, salt, pin_hash, max_views, view_count, expires_at FROM crypt_shares WHERE access_token = ?");
        $stmt->execute([$token]);
        $share = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$share) {
            $error = 'Diese Freigabe existiert nicht oder wurde bereits nach Erreichen der maximalen Aufrufe gelöscht.';
        } elseif (strtotime($share['expires_at']) < time()) {
            $delStmt = $pdo->prepare("DELETE FROM crypt_shares WHERE id = ?");
            $delStmt->execute([$share['id']]);
            $error = 'Dieser Freigabe-Link ist abgelaufen.';
        } else {
            $maxViews = (int)($share['max_views'] ?? 1);
            $viewCount = (int)($share['view_count'] ?? 0);

            if ($maxViews > 0 && $viewCount >= $maxViews) {
                $delStmt = $pdo->prepare("DELETE FROM crypt_shares WHERE id = ?");
                $delStmt->execute([$share['id']]);
                $error = 'Diese Freigabe hat die maximale Anzahl an Aufrufen erreicht und wurde gelöscht.';
            } else {
                $hasPin = !empty($share['pin_hash']);
                $shareMeta = [
                    'id' => (int)$share['id'],
                    'file_name' => $share['file_name'],
                    'has_pin' => $hasPin,
                    'max_views' => $maxViews,
                    'view_count' => $viewCount,
                    'expires_at' => $share['expires_at'],
                ];

                if ($hasPin) {
                    // Protected by PIN: only unlock and increment view_count on valid POST submission
                    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['verify_share_pin'])) {
                        $submittedPin = trim((string)($_POST['access_pin'] ?? ''));
                        $ipAddress = get_client_ip();
                        $rateIdentifier = 'share_pin:' . $token . ':' . $ipAddress;
                        $now = time();

                        try {
                            $rateLimited = is_rate_limited($pdo, [$rateIdentifier], $now, 5);
                        } catch (\Throwable $e) {
                            $rateLimited = false;
                        }

                        if ($rateLimited) {
                            $error = 'Zu viele Fehlversuche bei der PIN-Eingabe. Bitte warten Sie 5 Minuten.';
                        } elseif ($submittedPin === '' || !password_verify($submittedPin, $share['pin_hash'])) {
                            try {
                                increment_login_attempts($pdo, $rateIdentifier, $now);
                            } catch (\Throwable $e) {}
                            $error = 'Ungültiger Zugriffs-PIN / Passwort.';
                        } else {
                            try {
                                clear_login_attempts($pdo, $rateIdentifier);
                            } catch (\Throwable $e) {}

                            $newViewCount = $viewCount + 1;
                            if ($maxViews > 0 && $newViewCount >= $maxViews) {
                                // Last allowed view: delete row from DB after serving encrypted payload in memory
                                $delStmt = $pdo->prepare("DELETE FROM crypt_shares WHERE id = ?");
                                $delStmt->execute([$share['id']]);
                                $remainingViewsAfterCurrent = 0;
                            } else {
                                $updStmt = $pdo->prepare("UPDATE crypt_shares SET view_count = view_count + 1 WHERE id = ?");
                                $updStmt->execute([$share['id']]);
                                $remainingViewsAfterCurrent = $maxViews > 0 ? ($maxViews - $newViewCount) : null;
                            }

                            $unlockedPayload = [
                                'encrypted_data' => $share['encrypted_data'],
                                'iv' => $share['iv'],
                                'salt' => $share['salt'],
                            ];
                        }
                    }
                } else {
                    // No PIN required: unlock immediately and count this access
                    $newViewCount = $viewCount + 1;
                    if ($maxViews > 0 && $newViewCount >= $maxViews) {
                        $delStmt = $pdo->prepare("DELETE FROM crypt_shares WHERE id = ?");
                        $delStmt->execute([$share['id']]);
                        $remainingViewsAfterCurrent = 0;
                    } else {
                        $updStmt = $pdo->prepare("UPDATE crypt_shares SET view_count = view_count + 1 WHERE id = ?");
                        $updStmt->execute([$share['id']]);
                        $remainingViewsAfterCurrent = $maxViews > 0 ? ($maxViews - $newViewCount) : null;
                    }

                    $unlockedPayload = [
                        'encrypted_data' => $share['encrypted_data'],
                        'iv' => $share['iv'],
                        'salt' => $share['salt'],
                    ];
                }
            }
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
            <span class="navbar-brand">🔗 Crypt Share</span>
        </div>
    </nav>

    <div class="container">
        <div class="row justify-content-center">
            <div class="col-md-8 col-lg-6">
                <?php if ($error && !$shareMeta): ?>
                    <div class="alert alert-danger shadow-sm">
                        <h4>Zugriff nicht möglich</h4>
                        <p class="mb-0"><?= htmlspecialchars($error) ?></p>
                    </div>
                <?php elseif ($shareMeta && $unlockedPayload === null && $shareMeta['has_pin']): ?>
                    <div class="card shadow-sm border-warning">
                        <div class="card-header bg-warning text-dark">
                            <h5 class="mb-0">🔐 Zusätzlicher Zugriffs-PIN erforderlich</h5>
                        </div>
                        <div class="card-body">
                            <?php if ($error): ?>
                                <div class="alert alert-danger"><?= htmlspecialchars($error) ?></div>
                            <?php endif; ?>
                            <p>Die Datei <strong><?= htmlspecialchars($shareMeta['file_name']) ?></strong> ist durch einen zusätzlichen Zugriffs-PIN / ein Passwort geschützt.</p>
                            <?php if ($shareMeta['max_views'] > 0): ?>
                                <p class="small text-muted">Verbleibende Abrufe vor diesem Aufruf: <strong><?= (int)($shareMeta['max_views'] - $shareMeta['view_count']) ?> von <?= (int)$shareMeta['max_views'] ?></strong></p>
                            <?php endif; ?>

                            <form method="POST" action="share.php?token=<?= urlencode($token) ?>">
                                <div class="mb-3">
                                    <label for="access_pin" class="form-label fw-bold">Zugriffs-PIN / Passwort eingeben</label>
                                    <input type="password" class="form-control" id="access_pin" name="access_pin" placeholder="PIN eingeben..." required autofocus>
                                </div>
                                <button type="submit" name="verify_share_pin" value="1" class="btn btn-warning w-100 fw-bold">
                                    🔓 PIN bestätigen &amp; zur Entschlüsselung
                                </button>
                            </form>
                        </div>
                    </div>
                <?php elseif ($shareMeta && $unlockedPayload !== null): ?>
                    <div class="card shadow-sm">
                        <div class="card-header bg-primary text-white d-flex justify-content-between align-items-center">
                            <h5 class="mb-0">📥 Datei entschlüsseln &amp; herunterladen</h5>
                            <?php if ($remainingViewsAfterCurrent !== null): ?>
                                <span class="badge bg-light text-dark">
                                    <?= $remainingViewsAfterCurrent === 0 ? '🔥 Letzter Aufruf (wird nach Schließen gelöscht)' : 'Noch ' . (int)$remainingViewsAfterCurrent . ' weitere(r) Aufruf(e) möglich' ?>
                                </span>
                            <?php endif; ?>
                        </div>
                        <div class="card-body">
                            <p>Du wurdest eingeladen, die Datei <strong><?= htmlspecialchars($shareMeta['file_name']) ?></strong> herunterzuladen.</p>
                            <p>Diese Datei ist Ende-zu-Ende verschlüsselt. Bitte gib das <strong>Einmal-Passwort</strong> ein, um die Datei lokal in deinem Browser zu entschlüsseln.</p>

                            <form id="decryptForm">
                                <input type="hidden" id="encrypted_data" value="<?= htmlspecialchars($unlockedPayload['encrypted_data']) ?>">
                                <input type="hidden" id="iv" value="<?= htmlspecialchars($unlockedPayload['iv']) ?>">
                                <input type="hidden" id="salt" value="<?= htmlspecialchars($unlockedPayload['salt']) ?>">

                                <div class="mb-3">
                                    <label for="otp" class="form-label fw-bold">Einmal-Passwort</label>
                                    <input type="password" class="form-control font-monospace" id="otp" required>
                                </div>

                                <button type="submit" class="btn btn-primary w-100" id="btnDecrypt">🔒 Entschlüsseln &amp; Herunterladen</button>
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
