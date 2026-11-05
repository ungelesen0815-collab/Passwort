<?php

use PHPUnit\Framework\TestCase;

class CspTest extends TestCase
{
    public function testSessionCspHeaderFormat(): void
    {
        $sessionContent = file_get_contents(__DIR__ . '/../session.php');

        $this->assertStringContainsString(
            "header(\"Content-Security-Policy: default-src 'self'; connect-src 'self' https://cdn.jsdelivr.net; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; img-src 'self' data:; font-src 'self' data:;\");",
            $sessionContent,
            'session.php should configure CSP headers allowing inline styles and scripts'
        );
    }

    public function testNoInlineEventHandlersInPhpFiles(): void
    {
        $phpFiles = glob(__DIR__ . '/../*.php');
        foreach ($phpFiles as $file) {
            $content = file_get_contents($file);
            $this->assertDoesNotMatchRegularExpression(
                '/\bon(?:click|submit|change|load|error|keyup|keydown|mouseover)\s*=\s*["\']/i',
                $content,
                basename($file) . ' should not contain inline JS event handlers'
            );
        }
    }

    public function testPasswordGeneratorNoInlineStyles(): void
    {
        $pgContent = file_get_contents(__DIR__ . '/../password_generator.php');

        $this->assertDoesNotMatchRegularExpression(
            '/style\s*=\s*["\']/i',
            $pgContent,
            'password_generator.php should not contain inline style attributes'
        );

        $this->assertStringContainsString(
            'length-input-width',
            $pgContent,
            'password_generator.php should use length-input-width CSS class'
        );
    }

    public function testNoInlineScriptsInPhpFiles(): void
    {
        $phpFiles = glob(__DIR__ . '/../*.php');
        foreach ($phpFiles as $file) {
            $content = file_get_contents($file);
            // Check that any <script> tag has a src attribute (i.e. external script, no inline JS block)
            if (preg_match_all('/<script(?:\s+[^>]*)?>(.*?)<\/script>/is', $content, $matches, PREG_SET_ORDER)) {
                foreach ($matches as $match) {
                    $fullTag = $match[0];
                    $innerJs = trim($match[1]);
                    $this->assertStringContainsString(
                        'src=',
                        $fullTag,
                        'Script tags in ' . basename($file) . ' must use src attribute rather than inline JS'
                    );
                    $this->assertEmpty(
                        $innerJs,
                        'Script tags in ' . basename($file) . ' must not contain inline JS content'
                    );
                }
            }
        }
    }
}
