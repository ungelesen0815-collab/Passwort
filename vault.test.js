const assert = require('assert');

let mockVaultData = {
    dataset: { json: '{"csrfToken":"test_token_123","vaultId":42,"canUseCryptShare":true,"items":[{"id":1,"title":"Test Item","category":"Server","is_favorite":1}]}' },
    getAttribute: (attr) => (attr === 'data-json' ? '{"csrfToken":"test_token_123","vaultId":42,"canUseCryptShare":true,"items":[{"id":1,"title":"Test Item","category":"Server","is_favorite":1}]}' : null),
    textContent: ''
};

global.window = global;
global.document = {
    readyState: 'complete',
    getElementById: (id) => {
        if (id === 'vault-data') return mockVaultData;
        return null;
    },
    addEventListener: () => {}
};

const { VaultCrypto, VaultImportExport, initVaultUI, getCsrfToken, getRawVaultItems, getVaultId, getCanUseCryptShare } = require('./vault.js');

// Test initVaultUI reading data-json
initVaultUI();
assert.strictEqual(getCsrfToken(), 'test_token_123');
assert.strictEqual(getRawVaultItems().length, 1);
assert.strictEqual(getRawVaultItems()[0].title, 'Test Item');
assert.strictEqual(getRawVaultItems()[0].category, 'Server');
assert.strictEqual(getRawVaultItems()[0].is_favorite, 1);
assert.strictEqual(getVaultId(), 42);
assert.strictEqual(getCanUseCryptShare(), true);

// Test CSV Parser & Exporter
const sampleCsv = 'title,item_type,category,favorite,username,password,notes\r\n"GitHub, Inc.",password,Arbeit,1,alice,sec"ret,"https://github.com\nLine 2"';
const parsedCsv = VaultImportExport.parseCsvImport(sampleCsv);
assert.strictEqual(parsedCsv.length, 1);
assert.strictEqual(parsedCsv[0].title, 'GitHub, Inc.');
assert.strictEqual(parsedCsv[0].category, 'Arbeit');
assert.strictEqual(parsedCsv[0].is_favorite, 1);
assert.strictEqual(parsedCsv[0].payload.username, 'alice');
assert.strictEqual(parsedCsv[0].payload.secret, 'sec"ret');

// Test Bitwarden JSON Parser
const sampleBitwarden = {
    folders: [{ id: 'f1', name: 'Finanzen' }],
    items: [
        {
            name: 'Online Banking',
            folderId: 'f1',
            favorite: true,
            notes: 'TAN Generator',
            login: {
                username: 'bank_user',
                password: 'bank_password',
                uris: [{ uri: 'https://bank.example' }]
            }
        }
    ]
};
const parsedBw = VaultImportExport.parseBitwardenJson(sampleBitwarden);
assert.strictEqual(parsedBw.length, 1);
assert.strictEqual(parsedBw[0].title, 'Online Banking');
assert.strictEqual(parsedBw[0].category, 'Finanzen');
assert.strictEqual(parsedBw[0].is_favorite, 1);
assert.strictEqual(parsedBw[0].payload.username, 'bank_user');
assert.strictEqual(parsedBw[0].payload.secret, 'bank_password');

// Test fallback reading data-json when dataset is undefined
mockVaultData = {
    dataset: undefined,
    getAttribute: (attr) => (attr === 'data-json' ? '{"csrfToken":"fallback_token","items":[]}' : null),
    textContent: ''
};
initVaultUI();
assert.strictEqual(getCsrfToken(), 'fallback_token');

