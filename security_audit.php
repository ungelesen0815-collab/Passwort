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
if (!user_has_feature($pdo, $userId, 'security_audit', $_SESSION['role'] ?? 'user')) {
    if (!empty($_SERVER['HTTP_X_REQUESTED_WITH']) || isset($_POST['ajax'])) {
        header('Content-Type: application/json');
        http_response_code(403);
        echo json_encode(['success' => false, 'error' => 'Keine Berechtigung für das Security Audit.']);
        exit();
    }
    header('Location: index.php');
    exit();
}

ensure_vault_enhancements_schema($pdo);

$sendResponse = function (bool $isError, string $msg, int $statusCode = 200, array $extraData = []) {
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
};

/**
 * Queries the HaveIBeenPwned Pwned Passwords Range API using ONLY the 5-char SHA-1 prefix (k-Anonymity).
 */
function fetch_hibp_range(string $prefix): ?string {
    $prefix = strtoupper(trim($prefix));
    if (!preg_match('/^[0-9A-F]{5}$/', $prefix)) {
        return null;
    }

    $url = 'https://api.pwnedpasswords.com/range/' . $prefix;

    if (function_exists('curl_init')) {
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => 8,
            CURLOPT_CONNECTTIMEOUT => 5,
            CURLOPT_USERAGENT => 'Passwort-Manager-Security-Audit/1.0 (k-Anonymity)',
            CURLOPT_HTTPHEADER => ['Add-Padding: true'],
        ]);
        $body = curl_exec($ch);
        $status = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        if (is_string($body) && $status === 200) {
            return $body;
        }
    }

    $ctx = stream_context_create([
        'http' => [
            'method' => 'GET',
            'timeout' => 8,
            'header' => "User-Agent: Passwort-Manager-Security-Audit/1.0 (k-Anonymity)\r\nAdd-Padding: true\r\n",
        ],
    ]);
    $body = @file_get_contents($url, false, $ctx);
    return is_string($body) ? $body : null;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';
    $token = $_POST['csrf_token'] ?? '';

    $csrfError = validate_csrf_token($token);
    if ($csrfError !== null) {
        $sendResponse(true, 'Ungültiger CSRF-Token.', 400);
    }

    if ($action === 'hibp_range') {
        $prefix = strtoupper(trim((string)($_POST['prefix'] ?? '')));
        if (!preg_match('/^[0-9A-F]{5}$/', $prefix)) {
            $sendResponse(true, 'Ungültiges SHA-1-Präfix (muss genau 5 Hex-Zeichen lang sein).', 400);
        }

        $rangeBody = fetch_hibp_range($prefix);
        if ($rangeBody === null) {
            $sendResponse(true, 'Die HaveIBeenPwned-API konnte nicht erreicht werden.', 502);
        }

        $sendResponse(false, 'OK', 200, ['range_data' => $rangeBody]);
    } elseif ($action === 'get_vault_items') {
        $vaultId = (int)($_POST['vault_id'] ?? 0);
        try {
            $stmtVault = $pdo->prepare("SELECT id, name FROM vaults WHERE id = ? AND user_id = ?");
            $stmtVault->execute([$vaultId, $userId]);
            $vault = $stmtVault->fetch(PDO::FETCH_ASSOC);
            if (!$vault) {
                $sendResponse(true, 'Tresor nicht gefunden.', 404);
            }

            $stmtItems = $pdo->prepare("SELECT id, item_type, title, category, encrypted_data, iv, salt FROM vault_items WHERE user_id = ? AND vault_id = ? AND item_type = 'password' ORDER BY title ASC");
            $stmtItems->execute([$userId, $vaultId]);
            $items = $stmtItems->fetchAll(PDO::FETCH_ASSOC);

            $sendResponse(false, 'Tresor-Einträge geladen.', 200, ['items' => $items]);
        } catch (\PDOException $e) {
            error_log("Database error in security_audit.php: " . $e->getMessage());
            $sendResponse(true, 'Datenbankfehler.', 500);
        }
    }
}

$userVaults = [];
try {
    if (user_has_feature($pdo, $userId, 'vault', $_SESSION['role'] ?? 'user')) {
        $stmt = $pdo->prepare("
            SELECT v.id, v.name,
                   (SELECT COUNT(*) FROM vault_items vi WHERE vi.vault_id = v.id AND vi.user_id = v.user_id AND vi.item_type = 'password') AS password_count
            FROM vaults v
            WHERE v.user_id = ?
            ORDER BY v.created_at DESC
        ");
        $stmt->execute([$userId]);
        $userVaults = $stmt->fetchAll(PDO::FETCH_ASSOC);
    }
} catch (\PDOException $e) {
    error_log("Database error in security_audit.php (vaults): " . $e->getMessage());
}

$pageTitle = 'Passwort-Check & Datenleck-Prüfer (Security Audit)';
require_once 'header.php';
require_once 'navbar.php';
?>

<div class="container mt-4 mb-5">
    <div class="d-flex justify-content-between align-items-center mb-3">
        <h2>🕵️ Passwort-Check &amp; Datenleck-Prüfer (Security Audit)</h2>
    </div>

    <div class="alert alert-info shadow-sm">
        <strong>🛡️ Zero-Knowledge &amp; k-Anonymity (HaveIBeenPwned):</strong>
        Ihr Passwort und auch der vollständige Hash verlassen <strong>niemals</strong> Ihren Browser. Der Browser berechnet lokal den SHA-1-Hash und übermittelt lediglich die <strong>ersten 5 Zeichen</strong> (Präfix) an die HIBP-API. Aus den ~500 zurückgelieferten Hash-Suffixen prüft Ihr Browser lokal, ob das Passwort in bekannten Datenlecks aufgetaucht ist.
    </div>

    <div class="row g-4">
        <!-- Single Password Check Card -->
        <div class="col-lg-5">
            <div class="card shadow-sm h-100">
                <div class="card-header bg-primary text-white">
                    <h5 class="mb-0">🔍 Einzelnes Passwort prüfen</h5>
                </div>
                <div class="card-body">
                    <p class="small text-muted">
                        Prüfen Sie ein beliebiges Passwort sofort auf Entropie, Stärke und bekannte Datenlecks (HaveIBeenPwned).
                    </p>
                    <form id="single-audit-form">
                        <div class="mb-3">
                            <label for="single-audit-password" class="form-label fw-bold">Zu prüfendes Passwort</label>
                            <div class="input-group">
                                <input type="password" id="single-audit-password" class="form-control font-monospace" placeholder="Passwort eingeben..." required>
                                <button type="button" class="btn btn-outline-secondary" id="btn-toggle-single-audit-pwd">👁️</button>
                            </div>
                        </div>
                        <button type="submit" id="btn-run-single-audit" class="btn btn-primary w-100">
                            🛡️ Auf Datenlecks &amp; Stärke prüfen
                        </button>
                    </form>

                    <div id="single-audit-result" class="mt-4 d-none"></div>
                </div>
            </div>
        </div>

        <!-- Full Vault Security Audit Card -->
        <div class="col-lg-7">
            <div class="card shadow-sm h-100">
                <div class="card-header bg-dark text-white">
                    <h5 class="mb-0">🔐 Gesamten Tresor prüfen (Tresor-Audit)</h5>
                </div>
                <div class="card-body">
                    <?php if (empty($userVaults)): ?>
                        <p class="text-muted mb-0">Sie haben noch keinen Tresor mit Passwörtern angelegt. <a href="vault.php">Zum Tresor &rarr;</a></p>
                    <?php else: ?>
                        <p class="small text-muted">
                            Entschlüsselt alle Passwörter des gewählten Tresors lokal im Browser und prüft jedes Passwort auf:
                            <strong>Datenlecks (HIBP k-Anonymity)</strong>, <strong>mehrfache Verwendung (Passwort-Reuse)</strong> und <strong>schwache Komplexität</strong>.
                        </p>
                        <form id="vault-audit-form">
                            <div class="row g-3 mb-3">
                                <div class="col-md-6">
                                    <label for="audit-vault-select" class="form-label fw-bold">Tresor auswählen</label>
                                    <select id="audit-vault-select" class="form-select" required>
                                        <?php foreach ($userVaults as $uv): ?>
                                            <option value="<?= (int)$uv['id'] ?>">
                                                <?= htmlspecialchars($uv['name']) ?> (<?= (int)$uv['password_count'] ?> Passwörter)
                                            </option>
                                        <?php endforeach; ?>
                                    </select>
                                </div>
                                <div class="col-md-6">
                                    <label for="audit-vault-master-pwd" class="form-label fw-bold">Tresor Master-Passwort</label>
                                    <input type="password" id="audit-vault-master-pwd" class="form-control" placeholder="Master-Passwort zum Entschlüsseln" required>
                                </div>
                            </div>
                            <button type="submit" id="btn-run-vault-audit" class="btn btn-success w-100">
                                🚀 Vollständiges Tresor-Sicherheitsaudit starten
                            </button>
                        </form>
                    <?php endif; ?>

                    <div id="vault-audit-summary" class="mt-4 d-none"></div>
                </div>
            </div>
        </div>
    </div>

    <!-- Detailed Vault Audit Report Table -->
    <div id="vault-audit-details-card" class="card shadow-sm mt-4 d-none">
        <div class="card-header bg-dark text-white d-flex justify-content-between align-items-center">
            <span>📊 Detaillierter Tresor-Audit-Bericht</span>
            <a href="vault.php" id="audit-open-vault-link" class="btn btn-outline-light btn-sm">Zum Tresor wechseln &rarr;</a>
        </div>
        <div class="card-body">
            <div class="table-responsive">
                <table class="table table-hover align-middle">
                    <thead>
                        <tr>
                            <th>Eintrag &amp; Kategorie</th>
                            <th>Benutzername</th>
                            <th>Stärke / Entropie</th>
                            <th>Wiederverwendung</th>
                            <th>HIBP Datenleck-Status</th>
                        </tr>
                    </thead>
                    <tbody id="vault-audit-tbody"></tbody>
                </table>
            </div>
        </div>
    </div>
</div>

<div id="security-audit-data" data-json="<?= htmlspecialchars(json_encode(['csrfToken' => $_SESSION['csrf_token'] ?? ''], JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT), ENT_QUOTES, 'UTF-8') ?>" class="d-none"></div>
<script src="vault.js"></script>
<script src="security_audit.js"></script>

<?php require_once 'footer.php'; ?>
