<?php
$username = $_SESSION['username'] ?? '';
$role = $_SESSION['role'] ?? ($user['role'] ?? '');
?>
<nav class="navbar navbar-expand-lg navbar-dark bg-dark">
    <div class="container">
        <a class="navbar-brand" href="index.php">Dashboard</a>
        <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav" aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
            <span class="navbar-toggler-icon"></span>
        </button>
        <div class="collapse navbar-collapse" id="navbarNav">
            <ul class="navbar-nav ms-auto">
                <?php if ($username !== ''): ?>
                <li class="nav-item">
                    <span class="nav-link text-white">Hello, <?= htmlspecialchars($username) ?> (<?= htmlspecialchars($role) ?>)</span>
                </li>
                <?php endif; ?>
                <li class="nav-item">
                    <a class="nav-link" href="vault.php">Tresor / Vault</a>
                </li>
                <li class="nav-item">
                    <a class="nav-link" href="password_generator.php">Passwort-Generator</a>
                </li>
                <li class="nav-item">
                    <a class="nav-link" href="crypt_share.php">Crypt Share</a>
                </li>
                <li class="nav-item">
                    <a class="nav-link" href="profile.php">Profile</a>
                </li>
                <li class="nav-item">
                    <a class="nav-link" href="mfa_setup.php">MFA Setup</a>
                </li>
                <?php if ($role === 'admin'): ?>
                <li class="nav-item">
                    <a class="nav-link" href="admin.php">Admin Panel</a>
                </li>
                <?php endif; ?>
                <li class="nav-item">
                    <form method="post" action="logout.php" class="d-inline m-0 p-0">
                        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token'] ?? '') ?>">
                        <button type="submit" class="nav-link bg-transparent border-0 py-2 px-3 c-pointer">Logout</button>
                    </form>
                </li>
            </ul>
        </div>
    </div>
</nav>
