<?php
require_once __DIR__ . '/session.php';
require_once 'db.php';
require_once 'csrf.php';

/**
 * Detects the MIME type of a file.
 *
 * @param string $filePath Path to the file.
 * @return string|false MIME type string or false on failure.
 */
function get_file_mime_type(string $filePath)
{
    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    $mime = finfo_file($finfo, $filePath);
    finfo_close($finfo);
    return $mime;
}

/**
 * Validates uploaded profile picture MIME type and file size.
 *
 * @param string $mime Detected MIME type.
 * @param int $fileSize File size in bytes.
 * @param array<string, string> $allowedTypes Map of MIME type to file extension.
 * @param int $maxSize Max allowed file size in bytes (default 2MB).
 * @return string|null Error message string on validation failure, or null on success.
 */
function validate_profile_picture(string $mime, int $fileSize, array $allowedTypes, int $maxSize = 2097152): ?string
{
    if (!array_key_exists($mime, $allowedTypes)) {
        return 'Invalid file type. Only JPG, PNG, and WEBP are allowed.';
    }

    if ($fileSize > $maxSize) {
        return 'File size exceeds 2MB limit.';
    }

    return null;
}

/**
 * Saves the uploaded profile picture to the uploads directory.
 *
 * @param string $fileTmpPath Temporary file path.
 * @param string $fileExtension File extension for saved image.
 * @return string|null Relative file path on success, or null on failure.
 */
function save_profile_picture(string $fileTmpPath, string $fileExtension): ?string
{
    $imageData = @file_get_contents($fileTmpPath);
    if ($imageData === false) {
        return null;
    }

    $image = @imagecreatefromstring($imageData);
    if ($image === false) {
        return null;
    }

    $newFileName = bin2hex(random_bytes(16)) . '.' . $fileExtension;
    $uploadDir = __DIR__ . '/uploads/';

    if (!is_dir($uploadDir)) {
        mkdir($uploadDir, 0755, true);
    }

    $destPath = $uploadDir . $newFileName;
    $saved = false;

    switch ($fileExtension) {
        case 'jpg':
            $saved = imagejpeg($image, $destPath, 90);
            break;
        case 'png':
            $saved = imagepng($image, $destPath, 6);
            break;
        case 'webp':
            $saved = imagewebp($image, $destPath, 80);
            break;
    }

    imagedestroy($image);

    if ($saved) {
        return 'uploads/' . $newFileName;
    }

    return null;
}

/**
 * Validates the MIME type and file size of an uploaded profile picture file.
 *
 * @param array $fileData Uploaded file array.
 * @param array<string, string> $allowedTypes Map of allowed MIME types to extensions.
 * @return array{0: string|null, 1: string|null} Array containing [?string $fileExtension, ?string $error]
 * Checks if upload data contains a valid uploaded file without error.
 *
 * @param array|null $fileData The $_FILES array item or null.
 * @return bool
 */
function has_valid_upload_file(?array $fileData): bool
{
    return isset($fileData['error']) && $fileData['error'] === UPLOAD_ERR_OK;
}

/**
 * Validates the MIME type and file size of an uploaded profile picture.
 *
 * @param array $fileData The $_FILES array item.
 * @param array<string, string> $allowedTypes Map of allowed MIME types to extensions.
 * @return array{0: string|null, 1: string|null} Array containing [?string $fileExtension, ?string $error]
 */
function validate_upload_mime_and_size(array $fileData, array $allowedTypes): array
{
    $mime = get_file_mime_type($fileData['tmp_name']);
    if (!$mime) {
        return [null, 'Invalid file type. Only JPG, PNG, and WEBP are allowed.'];
    }

    $validationError = validate_profile_picture((string)$mime, (int)$fileData['size'], $allowedTypes);
    if ($validationError) {
        return [null, $validationError];
    }

    return [$allowedTypes[$mime], null];
}

/**
 * Processes and saves an uploaded profile picture file.
 *
 * @param array $fileData Uploaded file array.
 * @param array<string, string> $allowedTypes Map of allowed MIME types to extensions.
 * @return array{0: string|null, 1: string|null} Array containing [?string $path, ?string $error]
 */
function process_profile_upload(array $fileData, array $allowedTypes): array
{
    [$fileExtension, $validationError] = validate_upload_mime_and_size($fileData, $allowedTypes);
    if ($validationError) {
        return [null, $validationError];
    }

    $savedPath = save_profile_picture($fileData['tmp_name'], $fileExtension);
    if (!$savedPath) {
        return [null, 'Error moving uploaded file.'];
    }

    return [$savedPath, null];
}

/**
 * Handles profile picture upload validation and storage.
 *
 * @param array|null $fileData The $_FILES['profile_picture'] array or null if omitted.
 * @return array{0: string|null, 1: string|null} Array containing [?string $path, ?string $error]
 */
function handle_profile_upload(?array $fileData): array
{
    if (!has_valid_upload_file($fileData)) {
        return [null, null];
    }

    $allowedTypes = ['image/jpeg' => 'jpg', 'image/png' => 'png', 'image/webp' => 'webp'];
    return process_profile_upload($fileData, $allowedTypes);
}

if (!isset($_SESSION['user_id'])) {
    header('Location: login.php');
    exit;
}

$userId = $_SESSION['user_id'];
$message = '';
$error = '';

// Fetch current user details upfront
try {
    $stmt = $pdo->prepare('SELECT username, role, full_name, personal_details, profile_picture FROM users WHERE id = ?');
    $stmt->execute([$userId]);
    $user = $stmt->fetch();
} catch (\PDOException $e) {
    error_log("Database error in profile.php: " . $e->getMessage());
    die('A database error occurred. Please contact the administrator.');
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    try {
        verify_csrf_token($_POST['csrf_token'] ?? null);
    } catch (Exception $e) {
        $error = 'Invalid CSRF token. Please refresh the page and try again.';
    }

    if (!$error) {
        $fullName = trim((string)($_POST['full_name'] ?? ''));
        $personalDetails = trim((string)($_POST['personal_details'] ?? ''));

        if (strlen($fullName) > 255) {
            $error = 'Full name must not exceed 255 characters.';
        } elseif (strlen($personalDetails) > 65535) {
            $error = 'Personal details must not exceed 65535 characters.';
        }

        // Handle Profile Picture Upload
        [$profilePicturePath, $uploadError] = handle_profile_upload($_FILES['profile_picture'] ?? null);
        if ($uploadError) {
            $error = $uploadError;
        }

        if (!$error) {
            try {
                $oldPicture = $user['profile_picture'] ?? null;

                $query = 'UPDATE users SET full_name = ?, personal_details = ?';
                $params = [$fullName, $personalDetails];

                if ($profilePicturePath) {
                    $query .= ', profile_picture = ?';
                    $params[] = $profilePicturePath;
                }

                $query .= ' WHERE id = ?';
                $params[] = $userId;

                $stmt = $pdo->prepare($query);
                if ($stmt->execute($params)) {
                    $message = 'Profile updated successfully.';

                    $user['full_name'] = $fullName;
                    $user['personal_details'] = $personalDetails;
                    if ($profilePicturePath) {
                        $user['profile_picture'] = $profilePicturePath;
                    }

                    if ($profilePicturePath && $oldPicture && file_exists(__DIR__ . '/' . $oldPicture)) {
                        unlink(__DIR__ . '/' . $oldPicture);
                    }
                } else {
                    $error = 'Database update failed.';
                }
            } catch (\PDOException $e) {
                error_log("Database error in profile.php (update): " . $e->getMessage());
                $error = 'A database error occurred while updating your profile. Please check your input.';
            }
        }
    }
}

$pageTitle = 'Profile';
require_once 'header.php';
?>
<?php require_once 'navbar.php'; ?>
<div class="container mt-5">
    <div class="row justify-content-center">
        <div class="col-md-8">
            <div class="card">
                <div class="card-header">
                    <h4>Edit Profile</h4>
                </div>
                <div class="card-body">
                    <?php if ($message): ?>
                        <div class="alert alert-success"><?= htmlspecialchars($message) ?></div>
                    <?php endif; ?>
                    <?php if ($error): ?>
                        <div class="alert alert-danger"><?= htmlspecialchars($error) ?></div>
                    <?php endif; ?>

                    <div class="text-center">
                        <?php if ($user['profile_picture']): ?>
                            <img src="<?= htmlspecialchars($user['profile_picture']) ?>" alt="Profile Picture" class="profile-picture">
                        <?php else: ?>
                            <div class="profile-picture bg-secondary d-inline-flex align-items-center justify-content-center text-white">
                                <span>No Image</span>
                            </div>
                        <?php endif; ?>
                    </div>

                    <form method="post" action="profile.php" enctype="multipart/form-data">
                        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">

                        <div class="mb-3">
                            <label class="form-label">Username (Read-only)</label>
                            <input type="text" class="form-control" value="<?= htmlspecialchars($user['username']) ?>" disabled>
                        </div>

                        <div class="mb-3">
                            <label for="full_name" class="form-label">Full Name</label>
                            <input type="text" class="form-control" id="full_name" name="full_name" value="<?= htmlspecialchars((string)$user['full_name']) ?>">
                        </div>

                        <div class="mb-3">
                            <label for="personal_details" class="form-label">Personal Details</label>
                            <textarea class="form-control" id="personal_details" name="personal_details" rows="4"><?= htmlspecialchars((string)$user['personal_details']) ?></textarea>
                        </div>

                        <div class="mb-3">
                            <label for="profile_picture" class="form-label">Upload New Profile Picture (JPG, PNG, WEBP, max 2MB)</label>
                            <input class="form-control" type="file" id="profile_picture" name="profile_picture" accept="image/jpeg, image/png, image/webp">
                        </div>

                        <button type="submit" class="btn btn-primary w-100">Save Changes</button>
                    </form>
                </div>
            </div>
        </div>
    </div>
</div>

<?php require_once 'footer.php'; ?>