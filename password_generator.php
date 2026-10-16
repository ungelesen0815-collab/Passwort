<?php
require_once __DIR__ . '/session.php';
require_once __DIR__ . '/PasswordGenerator.php';

if (!isset($_SESSION['user_id'])) {
    header('Location: login.php');
    exit;
}

$generator = new PasswordGenerator();

$length = isset($_REQUEST['length']) ? (int)$_REQUEST['length'] : PasswordGenerator::DEFAULT_LENGTH;
$useUppercase = isset($_REQUEST['uppercase']) ? (bool)$_REQUEST['uppercase'] : (empty($_REQUEST) || isset($_REQUEST['uppercase']));
$useLowercase = isset($_REQUEST['lowercase']) ? (bool)$_REQUEST['lowercase'] : (empty($_REQUEST) || isset($_REQUEST['lowercase']));
$useNumbers = isset($_REQUEST['numbers']) ? (bool)$_REQUEST['numbers'] : (empty($_REQUEST) || isset($_REQUEST['numbers']));
$useSpecial = isset($_REQUEST['special']) ? (bool)$_REQUEST['special'] : (empty($_REQUEST) || isset($_REQUEST['special']));
$excludeAmbiguous = isset($_REQUEST['exclude_ambiguous']) ? (bool)$_REQUEST['exclude_ambiguous'] : false;

$options = [
    'uppercase' => $useUppercase,
    'lowercase' => $useLowercase,
    'numbers' => $useNumbers,
    'special' => $useSpecial,
    'exclude_ambiguous' => $excludeAmbiguous,
];

$generatedPassword = '';
$error = '';

try {
    $generatedPassword = $generator->generate($length, $options);
} catch (\InvalidArgumentException $e) {
    $error = $e->getMessage();
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
                            </div>
                            <small id="copyFeedback" class="form-text text-success d-none">In die Zwischenablage kopiert!</small>
                        </div>
                    <?php endif; ?>

                    <form id="generatorForm" method="get" action="password_generator.php">
                        <div class="mb-3">
                            <label for="lengthInput" class="form-label fw-bold">Passwortlänge: <span id="lengthVal"><?= htmlspecialchars((string)$length) ?></span> Zeichen</label>
                            <div class="d-flex align-items-center gap-3">
                                <input type="range" class="form-range flex-grow-1" id="lengthRange" name="length_range" min="<?= PasswordGenerator::MIN_LENGTH ?>" max="<?= PasswordGenerator::MAX_LENGTH ?>" value="<?= htmlspecialchars((string)$length) ?>">
                                <input type="number" class="form-control" id="lengthInput" name="length" min="<?= PasswordGenerator::MIN_LENGTH ?>" max="<?= PasswordGenerator::MAX_LENGTH ?>" value="<?= htmlspecialchars((string)$length) ?>" style="width: 90px;">
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
        </div>
    </div>
</div>

<script src="password_generator.js"></script>

<?php require_once 'footer.php'; ?>