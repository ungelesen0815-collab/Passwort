const assert = require('assert');

let mockVaultData = {
    dataset: { json: '{"csrfToken":"test_token_123","items":[{"id":1,"title":"Test Item"}]}' },
    getAttribute: (attr) => (attr === 'data-json' ? '{"csrfToken":"test_token_123","items":[{"id":1,"title":"Test Item"}]}' : null),
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

const { VaultCrypto, initVaultUI, getCsrfToken, getRawVaultItems } = require('./vault.js');

// Test initVaultUI reading data-json
initVaultUI();
assert.strictEqual(getCsrfToken(), 'test_token_123');
assert.strictEqual(getRawVaultItems().length, 1);
assert.strictEqual(getRawVaultItems()[0].title, 'Test Item');

// Test fallback reading data-json when dataset is undefined
mockVaultData = {
    dataset: undefined,
    getAttribute: (attr) => (attr === 'data-json' ? '{"csrfToken":"fallback_token","items":[]}' : null),
    textContent: ''
};
initVaultUI();
assert.strictEqual(getCsrfToken(), 'fallback_token');

console.log('Vault JS tests passed');
