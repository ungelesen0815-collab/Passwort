<?php
require_once __DIR__ . '/session.php';
require_once 'db.php';
require_once 'csrf.php';

if (!isset($_SESSION['user_id']) || $_SESSION['role'] !== 'admin') {
    header('Location: index.php');
    exit;
}

$message = '';
$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['promote_id'])) {
    try {
        verify_csrf_token($_POST['csrf_token'] ?? null);

        $promoteId = (int)$_POST['promote_id'];

        // Prevent admin from demoting themselves or doing weird things, just promote to admin
        try {
            $stmt = $pdo->prepare("UPDATE users SET role = 'admin' WHERE id = ?");
            if ($stmt->execute([$promoteId]) && $stmt->rowCount() > 0) {
                $adminId = $_SESSION['user_id'];
                error_log("AUDIT: Admin ID {$adminId} promoted User ID {$promoteId} to admin.");
                $message = "User promoted to admin successfully.";
            } else {
                $message = "Failed to promote user. User may already be an admin or does not exist.";
            }
        } catch (\PDOException $e) {
            error_log("Database error occurred while promoting user: " . $e->getMessage());
            $message = "Database error occurred while promoting user.";
        }
    } catch (Exception $e) {
        $message = 'Invalid CSRF token. Please refresh the page and try again.';
    }
}

$page = filter_input(INPUT_GET, 'page', FILTER_VALIDATE_INT);
if (!$page || $page < 1) {
    $page = 1;
}
$perPage = 20;

$users = [];
$totalPages = 1;

try {
    $cacheDir = __DIR__ . '/cache';
    @mkdir($cacheDir, 0750, true);
    $cacheHtaccess = $cacheDir . '/.htaccess';
    if (is_dir($cacheDir) && !file_exists($cacheHtaccess)) {
        @file_put_contents($cacheHtaccess, "Require all denied\n");
    }
    $cacheFile = $cacheDir . '/admin_user_count.cache';
    $cacheTtl = 60;
    $totalUsers = null;

    if (file_exists($cacheFile) && is_readable($cacheFile) && (time() - filemtime($cacheFile)) < $cacheTtl) {
        $cachedValue = file_get_contents($cacheFile);
        if ($cachedValue !== false && is_numeric($cachedValue)) {
            $totalUsers = (int)$cachedValue;
        }
    }

    if ($totalUsers === null) {
        // Security: This is a static query with no user input. It is safe from SQL injection.
        // @phpstan-ignore-next-line
        $totalUsers = (int)$pdo->query("SELECT COUNT(*) FROM users")->fetchColumn();
        if (is_writable(dirname($cacheFile)) && (!file_exists($cacheFile) || is_writable($cacheFile))) {
            $tmpFile = $cacheFile . '.' . bin2hex(random_bytes(4)) . '.tmp';
            if (file_put_contents($tmpFile, (string)$totalUsers, LOCK_EX) !== false) {
                @rename($tmpFile, $cacheFile);
            }
        }
    }

    $totalPages = (int)ceil($totalUsers / $perPage);
    if ($totalPages < 1) {
        $totalPages = 1;
    }
    if ($page > $totalPages) {
        $page = $totalPages;
    }
    $offset = ($page - 1) * $perPage;

    $stmt = $pdo->prepare("SELECT id, username, role, mfa_enabled FROM users ORDER BY id ASC LIMIT :limit OFFSET :offset");
    $stmt->bindValue(':limit', $perPage, PDO::PARAM_INT);
    $stmt->bindValue(':offset', $offset, PDO::PARAM_INT);
    $stmt->execute();
    $users = $stmt->fetchAll();
} catch (\PDOException $e) {
    error_log("Database error in admin.php: " . $e->getMessage());
    $users = [];
    $error = 'A database error occurred. Please contact the administrator.';
}

$pageTitle = 'Admin Panel';
require_once 'header.php';
?>
<?php require_once 'navbar.php'; ?>
<div class="container mt-5">
    <h2>Admin Panel</h2>
    <p>Manage users and roles.</p>

    <?php if ($message): ?>
        <div class="alert alert-info"><?= htmlspecialchars($message) ?></div>
    <?php endif; ?>
    <?php if ($error): ?>
        <div class="alert alert-danger"><?= htmlspecialchars($error) ?></div>
    <?php endif; ?>

    <table class="table table-bordered table-striped bg-white">
        <thead>
            <tr>
                <th>ID</th>
                <th>Username</th>
                <th>Role</th>
                <th>MFA Enabled</th>
                <th>Action</th>
            </tr>
        </thead>
        <tbody>
            <?php foreach ($users as $u): ?>
            <tr>
                <td><?= htmlspecialchars($u['id']) ?></td>
                <td><?= htmlspecialchars($u['username']) ?></td>
                <td><?= htmlspecialchars($u['role']) ?></td>
                <td><?= $u['mfa_enabled'] ? 'Yes' : 'No' ?></td>
                <td>
                    <?php if ($u['role'] !== 'admin'): ?>
                    <form method="post" action="admin.php" class="d-inline">
                        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
                        <input type="hidden" name="promote_id" value="<?= $u['id'] ?>">
                        <button type="submit" class="btn btn-sm btn-success">Promote to Admin</button>
                    </form>
                    <?php else: ?>
                        <span class="badge bg-secondary">Admin</span>
                    <?php endif; ?>
                </td>
            </tr>
            <?php endforeach; ?>
        </tbody>
    </table>

    <?php if ($totalPages > 1): ?>
    <nav aria-label="Page navigation">
        <ul class="pagination justify-content-center">
            <li class="page-item <?= ($page <= 1) ? 'disabled' : '' ?>">
                <a class="page-link" href="admin.php?page=<?= $page - 1 ?>">Previous</a>
            </li>
            <?php for ($i = 1; $i <= $totalPages; $i++): ?>
                <li class="page-item <?= ($i === $page) ? 'active' : '' ?>">
                    <a class="page-link" href="admin.php?page=<?= $i ?>"><?= $i ?></a>
                </li>
            <?php endfor; ?>
            <li class="page-item <?= ($page >= $totalPages) ? 'disabled' : '' ?>">
                <a class="page-link" href="admin.php?page=<?= $page + 1 ?>">Next</a>
            </li>
        </ul>
    </nav>
    <?php endif; ?>
</div>

<?php require_once 'footer.php'; ?>