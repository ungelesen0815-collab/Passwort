<?php
$password = "some_password_string_here";

$start = microtime(true);
for ($i = 0; $i < 10000000; $i++) {
    if (strlen($password) < 8 || strlen($password) > 72) {
        // do nothing
    }
}
$end = microtime(true);
echo "Before: " . ($end - $start) . " seconds\n";

$start = microtime(true);
for ($i = 0; $i < 10000000; $i++) {
    $len = strlen($password);
    if ($len < 8 || $len > 72) {
        // do nothing
    }
}
$end = microtime(true);
echo "After: " . ($end - $start) . " seconds\n";
