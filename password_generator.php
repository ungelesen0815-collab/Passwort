<?php
require_once __DIR__ . '/session.php';
require_once __DIR__ . '/PasswordGenerator.php';
require_once __DIR__ . '/auth_utils.php';

if (!isset($_SESSION['user_id'])) {
    header('Location: login.php');
    exit;
}

$canUseVault = true;
$userVaults = [];

try {
    require_once __DIR__ . '/db.php';
    if (isset($pdo) && $pdo instanceof PDO) {
        if (!user_has_feature($pdo, $_SESSION['user_id'], 'password_generator', $_SESSION['role'] ?? 'user')) {
            header('Location: index.php');
            exit;
        }
        $canUseVault = user_has_feature($pdo, $_SESSION['user_id'], 'vault', $_SESSION['role'] ?? 'user');
        if ($canUseVault) {
            $stmtVaults = $pdo->prepare("SELECT id, name FROM vaults WHERE user_id = ? ORDER BY created_at DESC");
            $stmtVaults->execute([$_SESSION['user_id']]);
            $userVaults = $stmtVaults->fetchAll(PDO::FETCH_ASSOC);
        }
    }
} catch (\Throwable $e) {
    if (isset($_SESSION['permissions']['password_generator']) && !$_SESSION['permissions']['password_generator']) {
        header('Location: index.php');
        exit;
    }
    $canUseVault = !empty($_SESSION['permissions']['vault']);
}

$generator = new PasswordGenerator();

$length = isset($_REQUEST['length']) ? (int)$_REQUEST['length'] : PasswordGenerator::DEFAULT_LENGTH;
$hasCharsetParams = isset($_REQUEST['uppercase']) || isset($_REQUEST['lowercase']) || isset($_REQUEST['numbers']) || isset($_REQUEST['special']);
$isFormSubmit = isset($_REQUEST['length_range']) || $hasCharsetParams || isset($_REQUEST['exclude_ambiguous']) || isset($_REQUEST['special_count']);

$useUppercase = isset($_REQUEST['uppercase']) ? (bool)$_REQUEST['uppercase'] : !$isFormSubmit;
$useLowercase = isset($_REQUEST['lowercase']) ? (bool)$_REQUEST['lowercase'] : !$isFormSubmit;
$useNumbers = isset($_REQUEST['numbers']) ? (bool)$_REQUEST['numbers'] : !$isFormSubmit;
$useSpecial = isset($_REQUEST['special']) ? (bool)$_REQUEST['special'] : !$isFormSubmit;
$specialCount = (isset($_REQUEST['special_count']) && $_REQUEST['special_count'] !== '') ? (int)$_REQUEST['special_count'] : null;
$excludeAmbiguous = isset($_REQUEST['exclude_ambiguous']) ? (bool)$_REQUEST['exclude_ambiguous'] : false;

$options = [
    'uppercase' => $useUppercase,
    'lowercase' => $useLowercase,
    'numbers' => $useNumbers,
    'special' => $useSpecial,
    'exclude_ambiguous' => $excludeAmbiguous,
];

if ($specialCount !== null) {
    $options['special_count'] = $specialCount;
}

$generatedPassword = '';
$error = '';

try {
    $generatedPassword = $generator->generate($length, $options);
} catch (\InvalidArgumentException $e) {
    $error = $e->getMessage();
}

// Username / Email-Alias Generator parameters
$usernameMode = isset($_REQUEST['username_mode']) && $_REQUEST['username_mode'] === 'alias' ? 'alias' : 'random';
$usernameSeparator = isset($_REQUEST['username_separator']) && in_array($_REQUEST['username_separator'], ['-', '_', '.', ''], true)
    ? (string)$_REQUEST['username_separator']
    : '-';
$isUsernameSubmit = isset($_REQUEST['username_mode']);
$usernameIncludeNumber = isset($_REQUEST['username_numbers']) ? (bool)$_REQUEST['username_numbers'] : !$isUsernameSubmit;
$usernameCapitalize = isset($_REQUEST['username_capitalize']) ? (bool)$_REQUEST['username_capitalize'] : false;
$baseEmail = trim((string)($_REQUEST['base_email'] ?? ''));
$aliasTag = trim((string)($_REQUEST['alias_tag'] ?? ''));

$generatedUsername = '';
$usernameError = '';

try {
    if ($usernameMode === 'alias' && $baseEmail === '') {
        // Default to a random username until the user provides a base email
        $generatedUsername = $generator->generateUsername([
            'mode' => 'random',
            'separator' => $usernameSeparator,
            'include_number' => $usernameIncludeNumber,
            'capitalize' => $usernameCapitalize,
        ]);
    } else {
        $generatedUsername = $generator->generateUsername([
            'mode' => $usernameMode,
            'separator' => $usernameSeparator,
            'include_number' => $usernameIncludeNumber,
            'capitalize' => $usernameCapitalize,
            'base_email' => $baseEmail,
            'alias_tag' => $aliasTag,
        ]);
    }
} catch (\InvalidArgumentException $e) {
    $usernameError = $e->getMessage();
}

$pageTitle = 'Passwort-Generator';
require_once 'header.php';
?>
<?php require_once 'navbar.php'; ?>

<div class="container mt-5">
    <div class="row justify-content-center">
        <div class="col-md-8">
            <div class="card shadow-sm">
                <div class="card-header bg-primary text-white">
                    <h4 class="mb-0">🔑 Passwort-Generator</h4>
                </div>
                <div class="card-body">
                    <?php if ($error): ?>
                        <div class="alert alert-danger" role="alert">
                            <?= htmlspecialchars($error) ?>
                        </div>
                    <?php endif; ?>

                    <?php if ($generatedPassword): ?>
                        <div class="mb-4">
                            <label class="form-label fw-bold">Generiertes Passwort:</label>
                            <div class="input-group">
                                <input type="text" id="passwordResult" class="form-control font-monospace fs-5" value="<?= htmlspecialchars($generatedPassword) ?>" readonly>
                                <button class="btn btn-outline-secondary" type="button" id="copyBtn">📋 Kopieren</button>
                                <button class="btn btn-outline-primary" type="button" id="regenerateBtn">🔄 Neu generieren</button>
                                <?php if ($canUseVault): ?>
                                    <button class="btn btn-success" type="button" id="saveToVaultBtn" data-bs-toggle="modal" data-bs-target="#saveToVaultModal">🔐 Direkt im Tresor speichern</button>
                                <?php endif; ?>
                            </div>
                            <small id="copyFeedback" class="form-text text-success d-none">In die Zwischenablage kopiert!</small>
                        </div>
                    <?php endif; ?>

                    <form id="generatorForm" method="get" action="password_generator.php">
                        <div class="mb-3">
                            <label for="lengthInput" class="form-label fw-bold">Passwortlänge: <span id="lengthVal"><?= htmlspecialchars((string)$length) ?></span> Zeichen</label>
                            <div class="d-flex align-items-center gap-3">
                                <input type="range" class="form-range flex-grow-1" id="lengthRange" name="length_range" min="<?= PasswordGenerator::MIN_LENGTH ?>" max="<?= PasswordGenerator::MAX_LENGTH ?>" value="<?= htmlspecialchars((string)$length) ?>">
                                <input type="number" class="form-control length-input-width" id="lengthInput" name="length" min="<?= PasswordGenerator::MIN_LENGTH ?>" max="<?= PasswordGenerator::MAX_LENGTH ?>" value="<?= htmlspecialchars((string)$length) ?>">
                            </div>
                        </div>

                        <div class="mb-3">
                            <label class="form-label fw-bold">Zeichenauswahl (Zusammenstellung):</label>

                            <div class="form-check">
                                <input class="form-check-input" type="checkbox" id="uppercase" name="uppercase" value="1" <?= $useUppercase ? 'checked' : '' ?>>
                                <label class="form-check-label" for="uppercase">
                                    Großbuchstaben (A-Z)
                                </label>
                            </div>

                            <div class="form-check">
                                <input class="form-check-input" type="checkbox" id="lowercase" name="lowercase" value="1" <?= $useLowercase ? 'checked' : '' ?>>
                                <label class="form-check-label" for="lowercase">
                                    Kleinbuchstaben (a-z)
                                </label>
                            </div>

                            <div class="form-check">
                                <input class="form-check-input" type="checkbox" id="numbers" name="numbers" value="1" <?= $useNumbers ? 'checked' : '' ?>>
                                <label class="form-check-label" for="numbers">
                                    Zahlen (0-9)
                                </label>
                            </div>

                            <div class="form-check">
                                <input class="form-check-input" type="checkbox" id="special" name="special" value="1" <?= $useSpecial ? 'checked' : '' ?>>
                                <label class="form-check-label" for="special">
                                    Sonderzeichen (!@#$%^&amp;*()_+-=[]{}|;:,.&lt;&gt;?)
                                </label>
                            </div>

                            <div class="ms-4 mt-2 mb-3">
                                <label for="specialCountInput" class="form-label mb-1"><small>Genaue Anzahl Sonderzeichen (optional):</small></label>
                                <input type="number" class="form-control form-control-sm w-auto" id="specialCountInput" name="special_count" min="0" max="<?= PasswordGenerator::MAX_LENGTH ?>" value="<?= htmlspecialchars((string)($specialCount ?? '')) ?>" <?= $useSpecial ? '' : 'disabled' ?>>
                            </div>

                            <hr class="my-3">

                            <div class="form-check">
                                <input class="form-check-input" type="checkbox" id="exclude_ambiguous" name="exclude_ambiguous" value="1" <?= $excludeAmbiguous ? 'checked' : '' ?>>
                                <label class="form-check-label" for="exclude_ambiguous">
                                    Ähnliche Zeichen ausschließen (0, O, 1, l, I)
                                </label>
                            </div>
                        </div>

                        <button type="submit" class="btn btn-primary w-100">Passwort Generieren</button>
                    </form>
                </div>
            </div>

            <!-- Username & Email Alias Generator Card -->
            <div class="card shadow-sm mt-4 mb-5">
                <div class="card-header bg-dark text-white">
                    <h4 class="mb-0">👤 Benutzername- &amp; E-Mail-Alias-Generator</h4>
                </div>
                <div class="card-body">
                    <?php if ($usernameError): ?>
                        <div class="alert alert-danger" role="alert">
                            <?= htmlspecialchars($usernameError) ?>
                        </div>
                    <?php endif; ?>

                    <div class="mb-4">
                        <label class="form-label fw-bold">Generierter Benutzername / Alias:</label>
                        <div class="input-group">
                            <input type="text" id="usernameResult" class="form-control font-monospace fs-5" value="<?= htmlspecialchars($generatedUsername) ?>" readonly>
                            <button class="btn btn-outline-secondary" type="button" id="copyUsernameBtn">📋 Kopieren</button>
                            <button class="btn btn-outline-primary" type="button" id="regenerateUsernameBtn">🔄 Neu generieren</button>
                            <?php if ($canUseVault): ?>
                                <button class="btn btn-success" type="button" id="saveUsernameAndPasswordToVaultBtn" data-bs-toggle="modal" data-bs-target="#saveToVaultModal">🔐 Im Tresor speichern</button>
                            <?php endif; ?>
                        </div>
                        <small id="copyUsernameFeedback" class="form-text text-success d-none">Benutzername / Alias in die Zwischenablage kopiert!</small>
                    </div>

                    <form id="usernameGeneratorForm" method="get" action="password_generator.php">
                        <input type="hidden" name="length" value="<?= htmlspecialchars((string)$length) ?>">
                        <?php if ($useUppercase): ?><input type="hidden" name="uppercase" value="1"><?php endif; ?>
                        <?php if ($useLowercase): ?><input type="hidden" name="lowercase" value="1"><?php endif; ?>
                        <?php if ($useNumbers): ?><input type="hidden" name="numbers" value="1"><?php endif; ?>
                        <?php if ($useSpecial): ?><input type="hidden" name="special" value="1"><?php endif; ?>
                        <?php if ($specialCount !== null): ?><input type="hidden" name="special_count" value="<?= htmlspecialchars((string)$specialCount) ?>"><?php endif; ?>
                        <?php if ($excludeAmbiguous): ?><input type="hidden" name="exclude_ambiguous" value="1"><?php endif; ?>

                        <div class="mb-3">
                            <label for="usernameMode" class="form-label fw-bold">Generator-Modus:</label>
                            <select id="usernameMode" name="username_mode" class="form-select">
                                <option value="random" <?= $usernameMode === 'random' ? 'selected' : '' ?>>🎲 Zufälliger Benutzername (z. B. silent-falcon-4821)</option>
                                <option value="alias" <?= $usernameMode === 'alias' ? 'selected' : '' ?>>📧 E-Mail Plus-Addressing-Alias (z. B. name+shop-a8f3k2@domain.de)</option>
                            </select>
                        </div>

                        <!-- Options for Random Username -->
                        <div id="randomUsernameOptions" class="<?= $usernameMode === 'alias' ? 'd-none' : '' ?>">
                            <div class="row g-3 mb-3">
                                <div class="col-md-6">
                                    <label for="usernameSeparator" class="form-label">Trennzeichen:</label>
                                    <select id="usernameSeparator" name="username_separator" class="form-select">
                                        <option value="-" <?= $usernameSeparator === '-' ? 'selected' : '' ?>>Bindestrich (-)</option>
                                        <option value="_" <?= $usernameSeparator === '_' ? 'selected' : '' ?>>Unterstrich (_)</option>
                                        <option value="." <?= $usernameSeparator === '.' ? 'selected' : '' ?>>Punkt (.)</option>
                                        <option value="" <?= $usernameSeparator === '' ? 'selected' : '' ?>>Kein Trennzeichen</option>
                                    </select>
                                </div>
                                <div class="col-md-6 d-flex flex-column justify-content-end">
                                    <div class="form-check">
                                        <input class="form-check-input" type="checkbox" id="usernameNumbers" name="username_numbers" value="1" <?= $usernameIncludeNumber ? 'checked' : '' ?>>
                                        <label class="form-check-label" for="usernameNumbers">Zufallszahlen anhängen</label>
                                    </div>
                                    <div class="form-check">
                                        <input class="form-check-input" type="checkbox" id="usernameCapitalize" name="username_capitalize" value="1" <?= $usernameCapitalize ? 'checked' : '' ?>>
                                        <label class="form-check-label" for="usernameCapitalize">Wörter großschreiben (PascalCase)</label>
                                    </div>
                                </div>
                            </div>
                        </div>

                        <!-- Options for Email Alias -->
                        <div id="emailAliasOptions" class="<?= $usernameMode === 'alias' ? '' : 'd-none' ?>">
                            <div class="row g-3 mb-3">
                                <div class="col-md-7">
                                    <label for="baseEmail" class="form-label">Basis-E-Mail-Adresse:</label>
                                    <input type="email" id="baseEmail" name="base_email" class="form-control" placeholder="ihre.mail@beispiel.de" value="<?= htmlspecialchars($baseEmail) ?>">
                                </div>
                                <div class="col-md-5">
                                    <label for="aliasTag" class="form-label">Dienst / Präfix (optional):</label>
                                    <input type="text" id="aliasTag" name="alias_tag" class="form-control" placeholder="z. B. shop, github, newsletter" value="<?= htmlspecialchars($aliasTag) ?>">
                                </div>
                            </div>
                        </div>

                        <button type="submit" class="btn btn-dark w-100">Benutzername / Alias Generieren</button>
                    </form>
                </div>
            </div>
        </div>
    </div>
</div>

<?php if ($canUseVault): ?>
<!-- Modal: Save Generated Credentials Directly to Vault -->
<div class="modal fade" id="saveToVaultModal" tabindex="-1" aria-labelledby="saveToVaultModalLabel" aria-hidden="true">
    <div class="modal-dialog">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title" id="saveToVaultModalLabel">🔐 Direkt im Tresor speichern</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Schließen"></button>
            </div>
            <form id="saveToVaultTransferForm">
                <div class="modal-body">
                    <p class="small text-muted">
                        Das generierte Passwort und der Benutzername werden sicher im lokalen Browser-Speicher (ohne Übertragung in der URL) an das Tresor-Formular übergeben.
                    </p>
                    <div class="mb-3">
                        <label for="transferVaultSelect" class="form-label">Ziel-Tresor auswählen</label>
                        <?php if (!empty($userVaults)): ?>
                            <select id="transferVaultSelect" class="form-select" required>
                                <?php foreach ($userVaults as $uv): ?>
                                    <option value="<?= (int)$uv['id'] ?>"><?= htmlspecialchars($uv['name']) ?></option>
                                <?php endforeach; ?>
                            </select>
                        <?php else: ?>
                            <div class="alert alert-warning small mb-0">
                                Sie haben noch keinen Tresor angelegt. Sie werden zur Tresor-Übersicht weitergeleitet, wo Sie einen Tresor erstellen können – die Daten bleiben vorgemerkt.
                            </div>
                            <input type="hidden" id="transferVaultSelect" value="">
                        <?php endif; ?>
                    </div>
                    <div class="mb-3">
                        <label for="transferTitle" class="form-label">Titel / Dienstname (optional)</label>
                        <input type="text" id="transferTitle" class="form-control" placeholder="z. B. GitHub, Amazon, Firmen-Login">
                    </div>
                    <div class="mb-3">
                        <label for="transferUsername" class="form-label">Benutzername / E-Mail-Alias</label>
                        <input type="text" id="transferUsername" class="form-control font-monospace" value="<?= htmlspecialchars($generatedUsername) ?>">
                    </div>
                    <div class="mb-3">
                        <label for="transferPassword" class="form-label">Passwort</label>
                        <input type="text" id="transferPassword" class="form-control font-monospace" value="<?= htmlspecialchars($generatedPassword) ?>" readonly>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Abbrechen</button>
                    <button type="submit" class="btn btn-success">Zum Tresor &amp; Übernehmen &rarr;</button>
                </div>
            </form>
        </div>
    </div>
</div>
<?php endif; ?>

<script src="password_generator.js"></script>

<?php require_once 'footer.php'; ?>