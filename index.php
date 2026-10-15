<?php
require_once __DIR__ . '/session.php';
require_once 'csrf.php';

if (!isset($_SESSION['user_id'])) {
    header('Location: login.php');
    exit;
}

$username = $_SESSION['username'];
$role = $_SESSION['role'];

$pageTitle = 'Dashboard';
require_once 'header.php';
?>
<?php require_once 'navbar.php'; ?>
<div class="container mt-5">
    <div class="row">
        <div class="col-md-12">
            <h2>Welcome to your Dashboard</h2>
            <p class="lead">You are successfully logged in as a <strong><?= htmlspecialchars($role) ?></strong>.</p>
        </div>
    </div>
</div>

<?php require_once 'footer.php'; ?>