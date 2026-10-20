const assert = require('assert');
const fs = require('fs');

global.localStorage = {
    setItem: (k, v) => global.localStorage[k] = v,
    getItem: (k) => global.localStorage[k] || null
};
let mockThemeBtn = null;

global.document = {
    readyState: 'complete',
    body: { classList: {
        _c: new Set(),
        add: function(c) { this._c.add(c); },
        toggle: function(c) { this._c.has(c) ? this._c.delete(c) : this._c.add(c); },
        contains: function(c) { return this._c.has(c); }
    } },
    getElementById: (id) => (id === 'theme-toggle-btn' ? mockThemeBtn : null),
    addEventListener: () => {}
};

let code = fs.readFileSync('theme.js', 'utf8');
// Mocking DOMContentLoaded listener wasn't working since we evaluate theme.js directly.
eval(code);

// Test updateThemeButton directly with element present
mockThemeBtn = { textContent: '' };
updateThemeButton(true);
assert.strictEqual(mockThemeBtn.textContent, '☀️ Light');

updateThemeButton(false);
assert.strictEqual(mockThemeBtn.textContent, '🌙 Dark');

// Test updateThemeButton when button element is missing (null)
mockThemeBtn = null;
assert.doesNotThrow(() => updateThemeButton(true));
assert.doesNotThrow(() => updateThemeButton(false));

// Test toggleTheme updates class, localStorage, and theme button
global.document.body.classList._c.clear();
mockThemeBtn = { textContent: '' };

toggleTheme();
assert.strictEqual(global.document.body.classList.contains('dark-mode'), true);
assert.strictEqual(global.localStorage.theme, 'dark');
assert.strictEqual(mockThemeBtn.textContent, '☀️ Light');

toggleTheme();
assert.strictEqual(global.document.body.classList.contains('dark-mode'), false);
assert.strictEqual(global.localStorage.theme, 'light');
assert.strictEqual(mockThemeBtn.textContent, '🌙 Dark');

// Test initTheme when theme is 'dark' and button exists
global.document.body.classList._c.clear();
global.localStorage.theme = 'dark';
mockThemeBtn = {
    textContent: '',
    listeners: {},
    addEventListener: function(event, handler) {
        this.listeners[event] = handler;
    }
};

initTheme();
assert.strictEqual(global.document.body.classList.contains('dark-mode'), true);
assert.strictEqual(mockThemeBtn.textContent, '☀️ Light');
assert.strictEqual(typeof mockThemeBtn.listeners['click'], 'function');

// Verify attached click handler toggles theme
mockThemeBtn.listeners['click']();
assert.strictEqual(global.document.body.classList.contains('dark-mode'), false);
assert.strictEqual(global.localStorage.theme, 'light');

// Test initTheme when theme is not 'dark'
global.document.body.classList._c.clear();
global.localStorage.theme = 'light';
mockThemeBtn = {
    textContent: '',
    listeners: {},
    addEventListener: function(event, handler) {
        this.listeners[event] = handler;
    }
};

initTheme();
assert.strictEqual(global.document.body.classList.contains('dark-mode'), false);
assert.strictEqual(mockThemeBtn.textContent, '🌙 Dark');

// Test initTheme when button element is null
global.document.body.classList._c.clear();
global.localStorage.theme = 'dark';
mockThemeBtn = null;

assert.doesNotThrow(() => initTheme());
assert.strictEqual(global.document.body.classList.contains('dark-mode'), true);

