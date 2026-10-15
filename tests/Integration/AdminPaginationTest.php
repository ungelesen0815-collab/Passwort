<?php

use PHPUnit\Framework\TestCase;

class AdminPaginationTest extends TestCase {
    private \PDO $pdo;

    protected function setUp(): void {
        $this->pdo = new \PDO('sqlite::memory:');
        $this->pdo->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);

        $this->pdo->exec('CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            role TEXT NOT NULL,
            mfa_enabled INTEGER DEFAULT 0
        )');

        for ($i = 1; $i <= 25; $i++) {
            $stmt = $this->pdo->prepare("INSERT INTO users (username, role, mfa_enabled) VALUES (?, 'user', 0)");
            $stmt->execute(["user_{$i}"]);
        }
    }

    public function testPaginationCalculationsAndQuery() {
        $perPage = 20;
        $page = 1;

        $totalUsers = (int)$this->pdo->query("SELECT COUNT(*) FROM users")->fetchColumn();
        $this->assertEquals(25, $totalUsers);

        $totalPages = (int)ceil($totalUsers / $perPage);
        $this->assertEquals(2, $totalPages);

        $offset = ($page - 1) * $perPage;
        $stmt = $this->pdo->prepare("SELECT id, username, role, mfa_enabled FROM users ORDER BY id ASC LIMIT :limit OFFSET :offset");
        $stmt->bindValue(':limit', $perPage, \PDO::PARAM_INT);
        $stmt->bindValue(':offset', $offset, \PDO::PARAM_INT);
        $stmt->execute();
        $page1Users = $stmt->fetchAll();

        $this->assertCount(20, $page1Users);
        $this->assertEquals('user_1', $page1Users[0]['username']);

        $page = 2;
        $offset = ($page - 1) * $perPage;
        $stmt = $this->pdo->prepare("SELECT id, username, role, mfa_enabled FROM users ORDER BY id ASC LIMIT :limit OFFSET :offset");
        $stmt->bindValue(':limit', $perPage, \PDO::PARAM_INT);
        $stmt->bindValue(':offset', $offset, \PDO::PARAM_INT);
        $stmt->execute();
        $page2Users = $stmt->fetchAll();

        $this->assertCount(5, $page2Users);
        $this->assertEquals('user_21', $page2Users[0]['username']);
    }
}
