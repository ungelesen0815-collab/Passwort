<?php
class MockPDO extends PDO {
    public function __construct() {}
    #[\ReturnTypeWillChange]
    public function getAttribute($attribute) {
        return 'mysql';
    }
    #[\ReturnTypeWillChange]
    public function prepare($query, $options = []) {
        return new class extends PDOStatement {
            public function __construct() {}
            #[\ReturnTypeWillChange]
            public function execute($params = null) { return true; }
        };
    }
    #[\ReturnTypeWillChange]
    public function lastInsertId($name = null) {
        return '1';
    }
}
require 'auth_utils.php';
$pdo = new MockPDO();
$start = microtime(true);
for($i=0; $i<1000000; $i++) {
    increment_login_attempts($pdo, '127.0.0.1', 1234567890);
}
echo "Time: " . (microtime(true) - $start) . " seconds\n";
