<?php

use PHPUnit\Framework\TestCase;

class FooterTest extends TestCase
{
    public function testFooterCdnScriptIncludesSriAndCrossorigin()
    {
        $footerContent = file_get_contents(__DIR__ . '/../footer.php');

        $this->assertStringContainsString(
            'https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js',
            $footerContent,
            'footer.php should contain the Bootstrap CDN JS script'
        );

        $this->assertStringContainsString(
            'integrity="sha384-geWF76RCwLtnZ8qwWowPQNguL3RmwHVBC9FhGdlKrxdiJJigb/j/68SIy3Te4Bkz"',
            $footerContent,
            'footer.php Bootstrap CDN script should include the SHA-384 integrity attribute'
        );

        $this->assertStringContainsString(
            'crossorigin="anonymous"',
            $footerContent,
            'footer.php Bootstrap CDN script should include crossorigin="anonymous"'
        );
    }
}
