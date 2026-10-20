const assert = require('assert');
const fs = require('fs');

let mockLengthVal = { textContent: '' };
let mockLengthRange = { value: '', addEventListener: () => {} };
let mockLengthInput = { value: '', addEventListener: () => {} };
let mockCopyBtn = { addEventListener: () => {} };
let mockRegenerateBtn = { addEventListener: () => {} };
let mockCopyFeedback = {
    _c: new Set(['d-none']),
    classList: {
        remove: function(c) { mockCopyFeedback._c.delete(c); },
        add: function(c) { mockCopyFeedback._c.add(c); },
        contains: function(c) { return mockCopyFeedback._c.has(c); }
    }
};

global.document = {
    readyState: 'complete',
    getElementById: (id) => {
        if (id === 'lengthVal') return mockLengthVal;
        if (id === 'lengthRange') return mockLengthRange;
        if (id === 'lengthInput') return mockLengthInput;
        if (id === 'copyBtn') return mockCopyBtn;
        if (id === 'regenerateBtn') return mockRegenerateBtn;
        if (id === 'copyFeedback') return mockCopyFeedback;
        return null;
    },
    addEventListener: () => {}
};

const code = fs.readFileSync('password_generator.js', 'utf8');
eval(code);

// Test syncLength
syncLength('16');
assert.strictEqual(mockLengthVal.textContent, '16');
assert.strictEqual(mockLengthRange.value, '16');
assert.strictEqual(mockLengthInput.value, '16');

// Test showFeedback
showFeedback();
assert.strictEqual(mockCopyFeedback.classList.contains('d-none'), false);
