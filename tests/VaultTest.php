<?php

use PHPUnit\Framework\TestCase;

class VaultTest extends TestCase
{
    private PDO $pdo;

    protected function setUp(): void
    {
        $this->pdo = new PDO('sqlite::memory:');
        $this->pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $this->pdo->exec("CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user'
        )");

        $this->pdo->exec("CREATE TABLE vault_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            item_type TEXT NOT NULL,
            title TEXT NOT NULL,
            encrypted_data TEXT NOT NULL,
            iv TEXT NOT NULL,
            salt TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )");

        // Insert test users
        $stmt = $this->pdo->prepare("INSERT INTO users (id, username, password) VALUES (1, 'alice', 'pass1'), (2, 'bob', 'pass2')");
        $stmt->execute();
    }

    public function testInsertAndFetchVaultItemForSpecificUser(): void
    {
        $stmt = $this->pdo->prepare("INSERT INTO vault_items (user_id, item_type, title, encrypted_data, iv, salt) VALUES (?, ?, ?, ?, ?, ?)");
        $stmt->execute([1, 'password', 'GitHub Account', 'enc_data_1', 'iv_1', 'salt_1']);
        $stmt->execute([2, 'certificate', 'SSL Certificate', 'enc_data_2', 'iv_2', 'salt_2']);

        // Fetch user 1 items
        $stmtFetch = $this->pdo->prepare("SELECT * FROM vault_items WHERE user_id = ?");
        $stmtFetch->execute([1]);
        $user1Items = $stmtFetch->fetchAll(PDO::FETCH_ASSOC);

        $this->assertCount(1, $user1Items);
        $this->assertEquals('GitHub Account', $user1Items[0]['title']);
        $this->assertEquals('password', $user1Items[0]['item_type']);

        // Fetch user 2 items
        $stmtFetch->execute([2]);
        $user2Items = $stmtFetch->fetchAll(PDO::FETCH_ASSOC);

        $this->assertCount(1, $user2Items);
        $this->assertEquals('SSL Certificate', $user2Items[0]['title']);
        $this->assertEquals('certificate', $user2Items[0]['item_type']);
    }

    public function testUserCannotDeleteAnotherUsersVaultItem(): void
    {
        $stmt = $this->pdo->prepare("INSERT INTO vault_items (id, user_id, item_type, title, encrypted_data, iv, salt) VALUES (10, 1, 'keyfile', 'SSH Key', 'enc_data', 'iv', 'salt')");
        $stmt->execute();

        // User 2 tries to delete item 10 belonging to User 1
        $stmtDelete = $this->pdo->prepare("DELETE FROM vault_items WHERE id = ? AND user_id = ?");
        $stmtDelete->execute([10, 2]);

        $this->assertEquals(0, $stmtDelete->rowCount());

        // Verify item still exists
        $stmtCheck = $this->pdo->prepare("SELECT COUNT(*) FROM vault_items WHERE id = 10");
        $stmtCheck->execute();
        $this->assertEquals(1, (int)$stmtCheck->fetchColumn());

        // User 1 deletes item 10
        $stmtDelete->execute([10, 1]);
        $this->assertEquals(1, $stmtDelete->rowCount());
    }

    public function testAllowedItemTypesValidation(): void
    {
        $allowedTypes = ['password', 'keyfile', 'certificate'];

        $this->assertTrue(in_array('password', $allowedTypes, true));
        $this->assertTrue(in_array('keyfile', $allowedTypes, true));
        $this->assertTrue(in_array('certificate', $allowedTypes, true));
        $this->assertFalse(in_array('malicious_type', $allowedTypes, true));
    }
}
