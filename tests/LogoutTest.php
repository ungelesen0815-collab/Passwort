<?php

use PHPUnit\Framework\TestCase;

class LogoutTest extends TestCase
{
    private function executeLogoutScript(string $method, array $postData = []): array
    {
        $code = sprintf(
            '$_SERVER["REQUEST_METHOD"] = %s; $_POST = %s; require __DIR__ . "/logout.php";',
            var_export($method, true),
            var_export($postData, true)
        );

        $cmd = sprintf(
            '%s -d variables_order=EGPCS -r %s',
            PHP_BINARY,
            escapeshellarg($code)
        );

        $output = [];
        $returnCode = 0;
        exec($cmd, $output, $returnCode);

        return [
            'output' => implode("\n", $output),
            'returnCode' => $returnCode
        ];
    }

    public function testLogoutWithInvalidRequestMethodTerminatesWithError(): void
    {
        $result = $this->executeLogoutScript('GET');

        $this->assertEquals('Invalid request method.', $result['output']);
    }

    public function testLogoutWithMissingCsrfTokenTerminatesWithError(): void
    {
        $result = $this->executeLogoutScript('POST', []);

        $this->assertEquals('Invalid CSRF token.', $result['output']);
    }

    public function testLogoutWithInvalidCsrfTokenTerminatesWithError(): void
    {
        $result = $this->executeLogoutScript('POST', ['csrf_token' => 'invalid_token']);

        $this->assertEquals('Invalid CSRF token.', $result['output']);
    }
}
