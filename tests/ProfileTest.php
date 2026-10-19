<?php

use PHPUnit\Framework\TestCase;

// Set up minimal env vars so db.php loads without exception when requiring profile.php
$_ENV['DB_HOST'] = $_SERVER['DB_HOST'] ?? '127.0.0.1';
$_ENV['DB_NAME'] = $_SERVER['DB_NAME'] ?? 'test_db';
$_ENV['DB_USER'] = $_SERVER['DB_USER'] ?? 'test_user';
$_ENV['DB_PASS'] = $_SERVER['DB_PASS'] ?? 'test_pass';

$_SERVER['REQUEST_METHOD'] = 'GET';

try {
    ob_start();
    require_once __DIR__ . '/../profile.php';
    ob_end_clean();
} catch (Throwable $e) {
    ob_end_clean();
}

class ProfileTest extends TestCase
{
    private array $allowedTypes;

    protected function setUp(): void
    {
        $this->allowedTypes = [
            'image/jpeg' => 'jpg',
            'image/png'  => 'png',
            'image/webp' => 'webp',
        ];
    }

    public function testValidateProfilePictureSuccessWithJpeg(): void
    {
        $result = validate_profile_picture('image/jpeg', 1024, $this->allowedTypes);
        $this->assertNull($result);
    }

    public function testValidateProfilePictureSuccessWithPng(): void
    {
        $result = validate_profile_picture('image/png', 2048, $this->allowedTypes);
        $this->assertNull($result);
    }

    public function testValidateProfilePictureSuccessWithWebp(): void
    {
        $result = validate_profile_picture('image/webp', 5000, $this->allowedTypes);
        $this->assertNull($result);
    }

    public function testValidateProfilePictureExactMaxSizeBoundary(): void
    {
        $maxSize = 2097152; // 2MB
        $result = validate_profile_picture('image/png', $maxSize, $this->allowedTypes, $maxSize);
        $this->assertNull($result);
    }

    public function testValidateProfilePictureDisallowedMimeType(): void
    {
        $result = validate_profile_picture('image/gif', 1024, $this->allowedTypes);
        $this->assertEquals('Invalid file type. Only JPG, PNG, and WEBP are allowed.', $result);
    }

    public function testValidateProfilePictureTextMimeType(): void
    {
        $result = validate_profile_picture('text/plain', 500, $this->allowedTypes);
        $this->assertEquals('Invalid file type. Only JPG, PNG, and WEBP are allowed.', $result);
    }

    public function testValidateProfilePictureExceedsDefaultMaxSize(): void
    {
        $oversized = 2097153; // 2MB + 1 byte
        $result = validate_profile_picture('image/jpeg', $oversized, $this->allowedTypes);
        $this->assertEquals('File size exceeds 2MB limit.', $result);
    }

    public function testValidateProfilePictureExceedsCustomMaxSize(): void
    {
        $customMaxSize = 1024;
        $result = validate_profile_picture('image/png', 1025, $this->allowedTypes, $customMaxSize);
        $this->assertEquals('File size exceeds 2MB limit.', $result);
    }

    public function testValidateProfilePictureWithinCustomMaxSize(): void
    {
        $customMaxSize = 1024;
        $result = validate_profile_picture('image/png', 1024, $this->allowedTypes, $customMaxSize);
        $this->assertNull($result);
    }

    public function testSaveProfilePictureWithInvalidImageContent(): void
    {
        $tmpFile = tempnam(sys_get_temp_dir(), 'test_img');
        file_put_contents($tmpFile, '<?php echo "malicious payload"; ?>');

        $savedPath = save_profile_picture($tmpFile, 'png');
        $this->assertNull($savedPath);

        @unlink($tmpFile);
    }

    public function testSaveProfilePictureWithValidImageReencoding(): void
    {
        $validPng = "\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\nIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01\r\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82";
        $tmpFile = tempnam(sys_get_temp_dir(), 'test_img');
        file_put_contents($tmpFile, $validPng);

        $savedPath = save_profile_picture($tmpFile, 'png');
        $this->assertNotNull($savedPath);
        $this->assertFileExists(__DIR__ . '/../' . $savedPath);

        @unlink($tmpFile);
        @unlink(__DIR__ . '/../' . $savedPath);
    }

    public function testSaveProfilePictureWithNonUploadedFileReturnsNull(): void
    {
        $tmpFile = tempnam(sys_get_temp_dir(), 'test_img');
        file_put_contents($tmpFile, 'fake image data');

        $result = save_profile_picture($tmpFile, 'jpg');
        $this->assertNull($result);
        $this->assertDirectoryExists(__DIR__ . '/../uploads/');

        if (file_exists($tmpFile)) {
            unlink($tmpFile);
        }
    }

    public function testHandleProfileUploadNullOrInvalidError(): void
    {
        $this->assertEquals([null, null], handle_profile_upload(null));
        $this->assertEquals([null, null], handle_profile_upload([]));
        $this->assertEquals([null, null], handle_profile_upload(['error' => UPLOAD_ERR_NO_FILE]));
    }

    public function testHandleProfileUploadInvalidMimeType(): void
    {
        $tmpFile = tempnam(sys_get_temp_dir(), 'test_txt');
        file_put_contents($tmpFile, 'Hello world text content');

        $fileData = [
            'error' => UPLOAD_ERR_OK,
            'tmp_name' => $tmpFile,
            'size' => filesize($tmpFile),
        ];

        $result = handle_profile_upload($fileData);
        $this->assertEquals([null, 'Invalid file type. Only JPG, PNG, and WEBP are allowed.'], $result);

        if (file_exists($tmpFile)) {
            unlink($tmpFile);
        }
    }

    public function testHandleProfileUploadOversizedFile(): void
    {
        $tmpFile = tempnam(sys_get_temp_dir(), 'test_png');
        $validPng = "\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\nIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01\r\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82";
        file_put_contents($tmpFile, $validPng);

        $fileData = [
            'error' => UPLOAD_ERR_OK,
            'tmp_name' => $tmpFile,
            'size' => 2097153,
        ];

        $result = handle_profile_upload($fileData);
        $this->assertEquals([null, 'File size exceeds 2MB limit.'], $result);

        if (file_exists($tmpFile)) {
            unlink($tmpFile);
        }
    }

    public function testHandleProfileUploadMoveFailure(): void
    {
        $tmpFile = tempnam(sys_get_temp_dir(), 'test_png');
        $validPng = "\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\nIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01\r\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82";
        file_put_contents($tmpFile, $validPng);

        $fileData = [
            'error' => UPLOAD_ERR_OK,
            'tmp_name' => $tmpFile,
            'size' => strlen($validPng),
        ];

        // We'll simulate a failure to move the uploaded file by making the uploads directory read-only
        $uploadsDir = __DIR__ . '/../uploads/';
        if (!is_dir($uploadsDir)) {
            mkdir($uploadsDir, 0755, true);
        }
        chmod($uploadsDir, 0555);

        $result = @handle_profile_upload($fileData);
        $this->assertEquals([null, 'Error moving uploaded file.'], $result);

        chmod($uploadsDir, 0755);

        if (file_exists($tmpFile)) {
            unlink($tmpFile);
        }
    }

    public function testGetFileMimeTypePng(): void
    {
        $tmpFile = tempnam(sys_get_temp_dir(), 'test_png');
        file_put_contents($tmpFile, "\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89");
        $mime = get_file_mime_type($tmpFile);
        unlink($tmpFile);
        $this->assertEquals('image/png', $mime);
    }

    public function testGetFileMimeTypeJpeg(): void
    {
        $tmpFile = tempnam(sys_get_temp_dir(), 'test_jpg');
        file_put_contents($tmpFile, "\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x01\x00\x60\x00\x60\x00\x00");
        $mime = get_file_mime_type($tmpFile);
        unlink($tmpFile);
        $this->assertEquals('image/jpeg', $mime);
    }

    public function testGetFileMimeTypeWebp(): void
    {
        $tmpFile = tempnam(sys_get_temp_dir(), 'test_webp');
        file_put_contents($tmpFile, "RIFF\x1a\x00\x00\x00WEBPVP8 ");
        $mime = get_file_mime_type($tmpFile);
        unlink($tmpFile);
        $this->assertEquals('image/webp', $mime);
    }

    public function testGetFileMimeTypeTextPlain(): void
    {
        $tmpFile = tempnam(sys_get_temp_dir(), 'test_txt');
        file_put_contents($tmpFile, "Sample plain text content");
        $mime = get_file_mime_type($tmpFile);
        unlink($tmpFile);
        $this->assertEquals('text/plain', $mime);
    }

    public function testGetFileMimeTypeNonExistentFile(): void
    {
        $mime = @get_file_mime_type('/non/existent/file/path/that/does/not/exist');
        $this->assertFalse($mime);
    }
}
