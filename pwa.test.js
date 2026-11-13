const assert = require('assert');
const fs = require('fs');
const path = require('path');

console.log('Running PWA and Mobile Optimization tests...');

// 1. Validate manifest.json
const manifestPath = path.join(__dirname, 'manifest.json');
assert.strictEqual(fs.existsSync(manifestPath), true, 'manifest.json must exist');
const manifestContent = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));

assert.strictEqual(manifestContent.display, 'standalone', 'manifest.json display must be standalone');
assert.ok(manifestContent.name, 'manifest.json must have a name');
assert.ok(manifestContent.short_name, 'manifest.json must have a short_name');
assert.ok(manifestContent.start_url, 'manifest.json must have a start_url');
assert.ok(manifestContent.icons && manifestContent.icons.length > 0, 'manifest.json must define icons');

const svgIconInManifest = manifestContent.icons.find(i => i.src === 'icon.svg');
assert.ok(svgIconInManifest, 'manifest.json must include icon.svg');
assert.ok(svgIconInManifest.purpose.includes('maskable'), 'SVG icon must support maskable purpose');

// 2. Validate icon.svg
const iconPath = path.join(__dirname, 'icon.svg');
assert.strictEqual(fs.existsSync(iconPath), true, 'icon.svg must exist');
const iconContent = fs.readFileSync(iconPath, 'utf8');
assert.ok(iconContent.includes('<svg'), 'icon.svg must contain an SVG element');
assert.ok(iconContent.includes('viewBox='), 'icon.svg must define a viewBox');
assert.ok(iconContent.includes('xmlns='), 'icon.svg must have XML namespace');

// 3. Validate sw.js
const swPath = path.join(__dirname, 'sw.js');
assert.strictEqual(fs.existsSync(swPath), true, 'sw.js must exist');
const swContent = fs.readFileSync(swPath, 'utf8');
assert.ok(swContent.includes("addEventListener('install'"), 'sw.js must handle install event');
assert.ok(swContent.includes("addEventListener('activate'"), 'sw.js must handle activate event');
assert.ok(swContent.includes("addEventListener('fetch'"), 'sw.js must handle fetch event');
assert.ok(swContent.includes('offline.html'), 'sw.js must reference offline fallback page');
assert.ok(swContent.includes('style.css'), 'sw.js precache must include style.css');
assert.ok(swContent.includes('icon.svg'), 'sw.js precache must include icon.svg');

// 4. Validate pwa.js
const pwaScriptPath = path.join(__dirname, 'pwa.js');
assert.strictEqual(fs.existsSync(pwaScriptPath), true, 'pwa.js must exist');
const pwaModule = require('./pwa.js');
assert.strictEqual(typeof pwaModule.registerServiceWorker, 'function');
assert.strictEqual(typeof pwaModule.updateOnlineStatus, 'function');
assert.strictEqual(typeof pwaModule.setupPWAEvents, 'function');

// Test updateOnlineStatus DOM updates
let mockBanner = null;
global.document = {
    getElementById: (id) => (id === 'pwa-offline-banner' ? mockBanner : null),
    createElement: (tag) => ({
        id: '',
        className: '',
        _c: new Set(),
        classList: {
            add: function(c) { this._parent._c.add(c); },
            remove: function(c) { this._parent._c.delete(c); },
            contains: function(c) { return this._parent._c.has(c); },
            _parent: null
        },
        setAttribute: () => {},
        textContent: '',
        parentNode: { removeChild: () => {} }
    }),
    body: {
        prepend: (el) => {
            el.classList._parent = el;
            mockBanner = el;
        }
    }
};
pwaModule.updateOnlineStatus(false);
assert.ok(mockBanner !== null, 'Offline banner should be created when offline');
assert.ok(mockBanner.textContent.includes('Offline'), 'Offline banner should have offline text');

pwaModule.updateOnlineStatus(true);
assert.ok(mockBanner.textContent.includes('Verbindung'), 'Online banner should display reconnected text');

// 5. Validate header.php
const headerContent = fs.readFileSync(path.join(__dirname, 'header.php'), 'utf8');
assert.ok(headerContent.includes('rel="manifest" href="manifest.json"'), 'header.php must link manifest.json');
assert.ok(headerContent.includes('href="icon.svg"'), 'header.php must link icon.svg');
assert.ok(headerContent.includes('name="viewport"'), 'header.php must have viewport meta tag');
assert.ok(headerContent.includes('viewport-fit=cover'), 'header.php viewport must include viewport-fit=cover');
assert.ok(headerContent.includes('name="theme-color"'), 'header.php must include theme-color meta tag');

// 6. Validate footer.php
const footerContent = fs.readFileSync(path.join(__dirname, 'footer.php'), 'utf8');
assert.ok(footerContent.includes('src="pwa.js"'), 'footer.php must include pwa.js');
assert.ok(footerContent.includes('bootstrap.bundle.min.js'), 'footer.php must retain bootstrap script');

// 7. Validate offline.html
const offlinePath = path.join(__dirname, 'offline.html');
assert.strictEqual(fs.existsSync(offlinePath), true, 'offline.html must exist');
const offlineContent = fs.readFileSync(offlinePath, 'utf8');
assert.ok(offlineContent.includes('icon.svg'), 'offline.html should reference icon.svg');

// 8. Validate style.css mobile rules
const styleContent = fs.readFileSync(path.join(__dirname, 'style.css'), 'utf8');
assert.ok(styleContent.includes('safe-area-inset-bottom'), 'style.css should support safe-area-inset-bottom');
assert.ok(styleContent.includes('table-responsive'), 'style.css should include table-responsive rules');
assert.ok(styleContent.includes('@media (max-width: 768px)'), 'style.css should have mobile media query');

console.log('All PWA and Mobile Optimization tests PASSED!');
