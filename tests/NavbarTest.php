<?php

use PHPUnit\Framework\TestCase;

class NavbarTest extends TestCase
{
    public function testNavbarContainsBootstrapClassesAndLinks()
    {
        $navbarContent = file_get_contents(__DIR__ . '/../navbar.php');

        $this->assertStringContainsString(
            'class="navbar navbar-expand-lg navbar-dark bg-dark"',
            $navbarContent,
            'navbar.php should contain the navbar Bootstrap classes'
        );

        $this->assertStringContainsString(
            'href="index.php">Dashboard</a>',
            $navbarContent,
            'navbar.php should contain link to index.php'
        );

        $this->assertStringContainsString(
            'href="password_generator.php">Passwort-Generator</a>',
            $navbarContent,
            'navbar.php should contain link to password_generator.php'
        );

        $this->assertStringContainsString(
            'href="profile.php">Profile</a>',
            $navbarContent,
            'navbar.php should contain link to profile.php'
        );

        $this->assertStringContainsString(
            'href="mfa_setup.php">MFA Setup</a>',
            $navbarContent,
            'navbar.php should contain link to mfa_setup.php'
        );

        $this->assertStringContainsString(
            'action="logout.php"',
            $navbarContent,
            'navbar.php should contain logout form action'
        );

        $this->assertStringContainsString(
            'name="csrf_token"',
            $navbarContent,
            'navbar.php should contain CSRF token field'
        );
    }

    public function testNavbarRenderingWithSessionData()
    {
        $_SESSION['username'] = 'testuser';
        $_SESSION['role'] = 'admin';
        $_SESSION['csrf_token'] = 'token123';

        ob_start();
        include __DIR__ . '/../navbar.php';
        $output = ob_get_clean();

        $this->assertStringContainsString('Hello, testuser (admin)', $output);
        $this->assertStringContainsString('href="admin.php">Admin Panel</a>', $output);
        $this->assertStringContainsString('value="token123"', $output);
    }
}
