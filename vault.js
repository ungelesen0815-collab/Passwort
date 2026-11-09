/**
 * Web Crypto API End-to-End Encryption helpers & UI for Vault
 * Includes:
 * - Categories / Folders & Favorites
 * - Password / Entry History & One-Click Restore
 * - Encrypted JSON Backup Export & Multi-Format Import (Encrypted JSON, Bitwarden JSON, KeePass / CSV)
 * - One-Click Crypt Share Transfer
 */

const VaultCrypto = {
    /**
     * Converts an ArrayBuffer or Uint8Array to a Base64 string
     */
    bufferToBase64(buffer) {
        const bytes = new Uint8Array(buffer);
        let binary = '';
        for (let i = 0, len = bytes.byteLength; i < len; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return window.btoa(binary);
    },

    /**
     * Converts a Base64 string to a Uint8Array
     */
    base64ToBuffer(base64) {
        const binary = window.atob(base64);
        const len = binary.length;
        const bytes = new Uint8Array(len);
        for (let i = 0; i < len; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes;
    },

    /**
     * Generates a cryptographically secure random salt (16 bytes) in Base64 format
     */
    generateSalt() {
        const salt = window.crypto.getRandomValues(new Uint8Array(16));
        return this.bufferToBase64(salt);
    },

    /**
     * Generates a cryptographically secure one-time password for Crypt Share
     */
    generateOneTimePassword(length = 18) {
        const charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=';
        let retVal = '';
        const randomValues = new Uint32Array(length);
        window.crypto.getRandomValues(randomValues);
        for (let i = 0, n = charset.length; i < length; ++i) {
            retVal += charset.charAt(randomValues[i] % n);
        }
        return retVal;
    },

    /**
     * Derives a CryptoKey using PBKDF2 (100,000 iterations, SHA-256) -> AES-GCM 256
     * @param {string} masterPassword
     * @param {string} saltBase64
     * @returns {Promise<CryptoKey>}
     */
    async deriveMasterKey(masterPassword, saltBase64) {
        const encoder = new TextEncoder();
        const passwordBuffer = encoder.encode(masterPassword);
        const saltBuffer = this.base64ToBuffer(saltBase64);

        const keyMaterial = await window.crypto.subtle.importKey(
            'raw',
            passwordBuffer,
            { name: 'PBKDF2' },
            false,
            ['deriveKey']
        );

        return await window.crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: saltBuffer,
                iterations: 100000,
                hash: 'SHA-256'
            },
            keyMaterial,
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt', 'decrypt']
        );
    },

    /**
     * Encrypts plaintext JSON data using AES-GCM 256
     * @param {CryptoKey} key
     * @param {object|string} data
     * @returns {Promise<{ciphertext: string, iv: string}>}
     */
    async encryptVaultData(key, data) {
        const encoder = new TextEncoder();
        const plaintext = typeof data === 'string' ? data : JSON.stringify(data);
        const plaintextBuffer = encoder.encode(plaintext);

        const iv = window.crypto.getRandomValues(new Uint8Array(12));

        const encryptedBuffer = await window.crypto.subtle.encrypt(
            {
                name: 'AES-GCM',
                iv: iv
            },
            key,
            plaintextBuffer
        );

        return {
            ciphertext: this.bufferToBase64(encryptedBuffer),
            iv: this.bufferToBase64(iv)
        };
    },

    /**
     * Decrypts AES-GCM encrypted ciphertext back to plaintext
     * @param {CryptoKey} key
     * @param {string} ciphertextBase64
     * @param {string} ivBase64
     * @returns {Promise<string>}
     */
    async decryptVaultData(key, ciphertextBase64, ivBase64) {
        const ciphertextBuffer = this.base64ToBuffer(ciphertextBase64);
        const ivBuffer = this.base64ToBuffer(ivBase64);

        const decryptedBuffer = await window.crypto.subtle.decrypt(
            {
                name: 'AES-GCM',
                iv: ivBuffer
            },
            key,
            ciphertextBuffer
        );

        const decoder = new TextDecoder();
        return decoder.decode(decryptedBuffer);
    },

    /**
     * Reads a File object as plain text
     * @param {File} file
     * @returns {Promise<string>}
     */
    readFileAsText(file) {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.onload = () => resolve(reader.result);
            reader.onerror = () => reject(reader.error);
            reader.readAsText(file);
        });
    }
};

/**
 * Import / Export & CSV Parser Utilities
 */
const VaultImportExport = {
    /**
     * RFC 4180 compliant CSV parser supporting quoted fields, commas, and multiline values
     */
    parseCsvRows(csvText) {
        const rows = [];
        let currentRow = [];
        let currentField = '';
        let inQuotes = false;
        const text = String(csvText || '').replace(/^\uFEFF/, ''); // strip BOM

        for (let i = 0; i < text.length; i++) {
            const char = text[i];
            const nextChar = text[i + 1];

            if (inQuotes) {
                if (char === '"' && nextChar === '"') {
                    currentField += '"';
                    i++;
                } else if (char === '"') {
                    inQuotes = false;
                } else {
                    currentField += char;
                }
            } else {
                if (char === '"') {
                    inQuotes = true;
                } else if (char === ',') {
                    currentRow.push(currentField);
                    currentField = '';
                } else if (char === '\r' && nextChar === '\n') {
                    currentRow.push(currentField);
                    rows.push(currentRow);
                    currentRow = [];
                    currentField = '';
                    i++;
                } else if (char === '\n' || char === '\r') {
                    currentRow.push(currentField);
                    rows.push(currentRow);
                    currentRow = [];
                    currentField = '';
                } else {
                    currentField += char;
                }
            }
        }
        if (currentField !== '' || currentRow.length > 0) {
            currentRow.push(currentField);
            rows.push(currentRow);
        }
        return rows.filter(r => r.some(cell => String(cell).trim() !== ''));
    },

    escapeCsvField(val) {
        const str = String(val ?? '');
        if (/[",\r\n]/.test(str)) {
            return '"' + str.replace(/"/g, '""') + '"';
        }
        return str;
    },

    /**
     * Converts decrypted items into CSV string
     */
    itemsToCsv(itemsWithPayloads) {
        const headers = ['title', 'item_type', 'category', 'favorite', 'username', 'password', 'notes', 'content'];
        const lines = [headers.join(',')];

        itemsWithPayloads.forEach(({ item, payload }) => {
            const row = [
                this.escapeCsvField(item.title || ''),
                this.escapeCsvField(item.item_type || 'password'),
                this.escapeCsvField(item.category || payload.category || ''),
                this.escapeCsvField(item.is_favorite ? '1' : '0'),
                this.escapeCsvField(payload.username || ''),
                this.escapeCsvField(payload.secret || ''),
                this.escapeCsvField(payload.notes || ''),
                this.escapeCsvField(payload.content || '')
            ];
            lines.push(row.join(','));
        });

        return lines.join('\r\n');
    },

    /**
     * Parses Bitwarden JSON export into normalized vault entry objects
     */
    parseBitwardenJson(jsonObj) {
        const foldersMap = new Map();
        if (Array.isArray(jsonObj.folders)) {
            jsonObj.folders.forEach(f => {
                if (f && f.id && f.name) {
                    foldersMap.set(String(f.id), String(f.name));
                }
            });
        }

        const rawItems = Array.isArray(jsonObj.items) ? jsonObj.items : [];
        const normalized = [];

        rawItems.forEach(bwItem => {
            if (!bwItem || !bwItem.name) return;
            const category = bwItem.folderId && foldersMap.has(String(bwItem.folderId))
                ? foldersMap.get(String(bwItem.folderId))
                : (bwItem.category || '');
            const isFav = bwItem.favorite ? 1 : 0;

            if (bwItem.login) {
                const uris = Array.isArray(bwItem.login.uris)
                    ? bwItem.login.uris.map(u => u && u.uri).filter(Boolean).join(', ')
                    : '';
                const combinedNotes = [uris, bwItem.notes || ''].filter(Boolean).join('\n');

                normalized.push({
                    item_type: 'password',
                    title: String(bwItem.name).trim(),
                    category: String(category).trim(),
                    is_favorite: isFav,
                    payload: {
                        username: String(bwItem.login.username || ''),
                        secret: String(bwItem.login.password || ''),
                        notes: combinedNotes,
                        category: String(category).trim()
                    }
                });
            } else {
                normalized.push({
                    item_type: 'keyfile',
                    title: String(bwItem.name).trim(),
                    category: String(category).trim(),
                    is_favorite: isFav,
                    payload: {
                        content: String(bwItem.notes || ''),
                        notes: 'Importiert aus Bitwarden Secure Note',
                        category: String(category).trim()
                    }
                });
            }
        });

        return normalized;
    },

    /**
     * Parses CSV (Bitwarden CSV, KeePass CSV, Chrome/Firefox CSV, or native Vault CSV)
     */
    parseCsvImport(csvText) {
        const rows = this.parseCsvRows(csvText);
        if (rows.length < 2) return [];

        const rawHeaders = rows[0].map(h => String(h || '').trim().toLowerCase());
        const findCol = (candidates) => {
            for (const c of candidates) {
                const idx = rawHeaders.indexOf(c);
                if (idx !== -1) return idx;
            }
            return -1;
        };

        const idxTitle = findCol(['title', 'name', 'account', 'login_name', 'service']);
        const idxUser = findCol(['username', 'login_username', 'user name', 'login', 'user']);
        const idxPass = findCol(['password', 'login_password', 'secret']);
        const idxNotes = findCol(['notes', 'comments', 'comment', 'extra', 'description']);
        const idxUrl = findCol(['url', 'login_uri', 'web site', 'website', 'uri']);
        const idxFolder = findCol(['category', 'folder', 'group', 'grouping']);
        const idxFav = findCol(['favorite', 'is_favorite', 'fav']);
        const idxType = findCol(['item_type', 'type']);
        const idxContent = findCol(['content', 'key_content']);

        const normalized = [];
        for (let r = 1; r < rows.length; r++) {
            const row = rows[r];
            const title = (idxTitle !== -1 ? row[idxTitle] : row[0]) || '';
            if (!String(title).trim()) continue;

            const username = idxUser !== -1 ? (row[idxUser] || '') : '';
            const secret = idxPass !== -1 ? (row[idxPass] || '') : '';
            const url = idxUrl !== -1 ? (row[idxUrl] || '') : '';
            const notesRaw = idxNotes !== -1 ? (row[idxNotes] || '') : '';
            const category = idxFolder !== -1 ? String(row[idxFolder] || '').trim() : '';
            const favRaw = idxFav !== -1 ? String(row[idxFav] || '').trim().toLowerCase() : '0';
            const isFavorite = (favRaw === '1' || favRaw === 'true' || favRaw === 'yes') ? 1 : 0;
            const rawType = idxType !== -1 ? String(row[idxType] || '').trim().toLowerCase() : 'password';
            const content = idxContent !== -1 ? (row[idxContent] || '') : '';

            let itemType = 'password';
            if (rawType === 'keyfile' || rawType === 'certificate') {
                itemType = rawType;
            }

            const combinedNotes = [url, notesRaw].filter(Boolean).join('\n');

            if (itemType === 'password') {
                normalized.push({
                    item_type: 'password',
                    title: String(title).trim(),
                    category: category,
                    is_favorite: isFavorite,
                    payload: {
                        username: String(username),
                        secret: String(secret),
                        notes: combinedNotes,
                        category: category
                    }
                });
            } else {
                normalized.push({
                    item_type: itemType,
                    title: String(title).trim(),
                    category: category,
                    is_favorite: isFavorite,
                    payload: {
                        content: String(content || secret),
                        notes: combinedNotes,
                        category: category
                    }
                });
            }
        }

        return normalized;
    }
};

var csrfToken = "";
var vaultId = null;
var canUseCryptShare = false;
var rawVaultItems = [];
var decryptedPayloadsById = new Map();
var derivedMasterKey = null;
var activeSalt = null;
var activeMasterPassword = null;
var derivedKeysBySalt = new Map();

var activeCategoryFilter = 'all';
var activeFavoriteOnly = false;
var activeSearchQuery = '';
var currentHistoryItemId = null;

async function getKeyForSalt(salt) {
    if (!salt || salt === activeSalt) {
        return derivedMasterKey;
    }
    if (derivedKeysBySalt.has(salt)) {
        return derivedKeysBySalt.get(salt);
    }
    if (!activeMasterPassword) {
        return derivedMasterKey;
    }
    const key = await VaultCrypto.deriveMasterKey(activeMasterPassword, salt);
    derivedKeysBySalt.set(salt, key);
    return key;
}

function toggleFormFields() {
    const typeEl = document.getElementById('item_type');
    if (!typeEl) return;
    const type = typeEl.value;
    const pwdGroup = document.getElementById('field-group-password');
    const kfGroup = document.getElementById('field-group-keyfile');
    const certGroup = document.getElementById('field-group-certificate');
    if (pwdGroup) pwdGroup.classList.toggle('d-none', type !== 'password');
    if (kfGroup) kfGroup.classList.toggle('d-none', type !== 'keyfile');
    if (certGroup) certGroup.classList.toggle('d-none', type !== 'certificate');
}

async function readKeyfileInput(input) {
    if (input.files && input.files[0]) {
        try {
            const text = await VaultCrypto.readFileAsText(input.files[0]);
            document.getElementById('kf_content').value = text;
        } catch (e) {
            alert("Fehler beim Lesen der Datei.");
        }
    }
}

async function readCertFileInput(input) {
    if (input.files && input.files[0]) {
        try {
            const text = await VaultCrypto.readFileAsText(input.files[0]);
            document.getElementById('cert_content').value = text;
        } catch (e) {
            alert("Fehler beim Lesen der Zertifikatsdatei.");
        }
    }
}

async function handleUnlockVault(e) {
    e.preventDefault();
    const masterPassword = document.getElementById('master-password-input').value;
    if (!masterPassword) return;

    if (rawVaultItems.length > 0) {
        activeSalt = rawVaultItems[0].salt;
    } else if (!activeSalt) {
        activeSalt = VaultCrypto.generateSalt();
    }

    try {
        derivedMasterKey = await VaultCrypto.deriveMasterKey(masterPassword, activeSalt);
        activeMasterPassword = masterPassword;
        derivedKeysBySalt.clear();
        derivedKeysBySalt.set(activeSalt, derivedMasterKey);

        if (rawVaultItems.length > 0) {
            try {
                await VaultCrypto.decryptVaultData(derivedMasterKey, rawVaultItems[0].encrypted_data, rawVaultItems[0].iv);
            } catch (err) {
                alert("Entschlüsselung fehlgeschlagen! Das Master-Passwort ist möglicherweise falsch.");
                derivedMasterKey = null;
                activeMasterPassword = null;
                derivedKeysBySalt.clear();
                return;
            }
        }

        document.getElementById('master-password-card').classList.add('d-none');
        document.getElementById('vault-content').classList.remove('d-none');
        document.getElementById('lock-vault-btn').classList.remove('d-none');

        await decryptAndRenderVaultItems();
        applyPendingVaultEntryIfPresent();
    } catch (err) {
        alert("Fehler beim Entschlüsseln: " + err.message);
    }
}

function applyPendingVaultEntryIfPresent() {
    if (typeof sessionStorage === 'undefined') return;
    const rawPending = sessionStorage.getItem('pendingVaultEntry');
    if (!rawPending) return;

    try {
        const pending = JSON.parse(rawPending);
        sessionStorage.removeItem('pendingVaultEntry');

        const banner = document.getElementById('pending-vault-entry-banner');
        if (banner) banner.classList.add('d-none');

        openAddModalForNewItem();

        const typeSelect = document.getElementById('item_type');
        if (typeSelect) {
            typeSelect.value = 'password';
            toggleFormFields();
        }

        const titleInput = document.getElementById('item_title');
        const userInput = document.getElementById('pwd_username');
        const secretInput = document.getElementById('pwd_secret');

        if (titleInput) titleInput.value = pending.title || '';
        if (userInput) userInput.value = pending.username || '';
        if (secretInput) {
            secretInput.value = pending.password || '';
            secretInput.type = 'text';
        }

        const modalEl = document.getElementById('addModal');
        if (modalEl && typeof bootstrap !== 'undefined' && bootstrap.Modal) {
            const modal = bootstrap.Modal.getOrCreateInstance(modalEl);
            modal.show();
        }
    } catch (e) {
        console.error('Failed to apply pending vault entry:', e);
    }
}

function lockVault() {
    derivedMasterKey = null;
    activeMasterPassword = null;
    derivedKeysBySalt.clear();
    decryptedPayloadsById.clear();
    document.getElementById('master-password-input').value = '';
    document.getElementById('master-password-card').classList.remove('d-none');
    document.getElementById('vault-content').classList.add('d-none');
    document.getElementById('lock-vault-btn').classList.add('d-none');
}

function updateCategoryDropdownOptions() {
    const selectEl = document.getElementById('vault-category-filter');
    if (!selectEl) return;

    const currentValue = selectEl.value || 'all';
    const defaultCategories = ['Arbeit', 'Privat', 'Server', 'Finanzen'];
    const customCategories = new Set();

    rawVaultItems.forEach(item => {
        const payload = decryptedPayloadsById.get(Number(item.id)) || {};
        const cat = String(item.category || payload.category || '').trim();
        if (cat && !defaultCategories.includes(cat)) {
            customCategories.add(cat);
        }
    });

    let html = `
        <option value="all">📁 Alle Kategorien / Ordner</option>
        <option value="Arbeit">💼 Arbeit</option>
        <option value="Privat">🏠 Privat</option>
        <option value="Server">🖥️ Server</option>
        <option value="Finanzen">💳 Finanzen</option>
    `;
    Array.from(customCategories).sort().forEach(cat => {
        html += `<option value="${escapeHtml(cat)}">🏷️ ${escapeHtml(cat)}</option>`;
    });
    html += `<option value="uncategorized">Ohne Kategorie</option>`;

    selectEl.innerHTML = html;
    if (Array.from(selectEl.options).some(opt => opt.value === currentValue)) {
        selectEl.value = currentValue;
    } else {
        selectEl.value = 'all';
        activeCategoryFilter = 'all';
    }
}

async function decryptAndRenderVaultItems() {
    decryptedPayloadsById.clear();

    const uniqueSalts = new Set(rawVaultItems.map(item => item.salt).filter(Boolean));
    for (const salt of uniqueSalts) {
        await getKeyForSalt(salt);
    }

    await Promise.all(rawVaultItems.map(async (item) => {
        try {
            const itemKey = await getKeyForSalt(item.salt);
            const jsonStr = await VaultCrypto.decryptVaultData(itemKey, item.encrypted_data, item.iv);
            const parsed = JSON.parse(jsonStr);
            if (!item.category && parsed.category) {
                item.category = parsed.category;
            }
            decryptedPayloadsById.set(Number(item.id), parsed);
        } catch (e) {
            decryptedPayloadsById.set(Number(item.id), { error: 'Entschlüsselungsfehler' });
        }
    }));

    updateCategoryDropdownOptions();
    renderVaultItemsFromCache();
}

function renderCategoryBadge(category) {
    const cat = String(category || '').trim();
    if (!cat) return '';
    const iconMap = {
        'Arbeit': '💼',
        'Privat': '🏠',
        'Server': '🖥️',
        'Finanzen': '💳'
    };
    const icon = iconMap[cat] || '📁';
    return `<span class="badge bg-secondary ms-2">${icon} ${escapeHtml(cat)}</span>`;
}

function renderVaultItemsFromCache() {
    const passwordsList = document.getElementById('passwords-list');
    const keyfilesList = document.getElementById('keyfiles-list');
    const certsList = document.getElementById('certs-list');
    if (!passwordsList || !keyfilesList || !certsList) return;

    passwordsList.innerHTML = '';
    keyfilesList.innerHTML = '';
    certsList.innerHTML = '';

    let passwordCount = 0;
    let keyfileCount = 0;
    let certCount = 0;
    let totalFavorites = rawVaultItems.filter(i => Number(i.is_favorite) === 1).length;

    const favCountEl = document.getElementById('favorites-count');
    if (favCountEl) favCountEl.textContent = String(totalFavorites);

    // Sort: favorites first, then newest
    const sortedItems = [...rawVaultItems].sort((a, b) => {
        const favDiff = (Number(b.is_favorite) || 0) - (Number(a.is_favorite) || 0);
        if (favDiff !== 0) return favDiff;
        return Number(b.id) - Number(a.id);
    });

    const query = activeSearchQuery.trim().toLowerCase();

    for (let i = 0; i < sortedItems.length; i++) {
        const item = sortedItems[i];
        const payload = decryptedPayloadsById.get(Number(item.id)) || {};
        const itemCategory = String(item.category || payload.category || '').trim();
        const isFav = Number(item.is_favorite) === 1;
        const historyCount = Number(item.history_count) || 0;

        // Filter checks
        if (activeFavoriteOnly && !isFav) {
            continue;
        }
        if (activeCategoryFilter !== 'all') {
            if (activeCategoryFilter === 'uncategorized') {
                if (itemCategory !== '') continue;
            } else if (itemCategory.toLowerCase() !== activeCategoryFilter.toLowerCase()) {
                continue;
            }
        }
        if (query !== '') {
            const haystack = [
                item.title,
                itemCategory,
                payload.username || '',
                payload.notes || ''
            ].join(' ').toLowerCase();
            if (!haystack.includes(query)) {
                continue;
            }
        }

        const favStarBtn = `
            <button type="button" class="btn btn-sm p-0 border-0 btn-toggle-favorite" data-id="${item.id}" title="${isFav ? 'Aus Favoriten entfernen' : 'Als Favorit markieren'}">
                <span class="fs-5">${isFav ? '⭐' : '☆'}</span>
            </button>
        `;

        const catBadge = renderCategoryBadge(itemCategory);
        const notesSub = payload.notes ? `<div class="small text-muted text-truncate vault-notes-preview" title="${escapeHtml(payload.notes)}">${escapeHtml(payload.notes)}</div>` : '';
        const historyBtn = `
            <button class="btn btn-outline-secondary btn-sm btn-history" type="button" data-id="${item.id}" title="Passwort-Historie (${historyCount})">
                🕒${historyCount > 0 ? ' <span class="badge bg-secondary">' + historyCount + '</span>' : ''}
            </button>
        `;
        const editBtn = `<button class="btn btn-outline-primary btn-sm btn-edit-item" type="button" data-id="${item.id}" title="Bearbeiten">✏️</button>`;
        const shareBtn = canUseCryptShare
            ? `<button class="btn btn-outline-info btn-sm btn-crypt-share-item" type="button" data-id="${item.id}" title="Mit 1 Klick als Crypt Share Einmal-Link teilen">🔗 Teilen</button>`
            : '';
        const deleteBtn = `<button class="btn btn-outline-danger btn-sm btn-delete" type="button" data-id="${item.id}" title="Löschen">🗑️</button>`;

        if (item.item_type === 'password') {
            passwordCount++;
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td class="text-center">${favStarBtn}</td>
                <td>
                    <div><strong>${escapeHtml(item.title)}</strong>${catBadge}</div>
                    ${notesSub}
                </td>
                <td>${escapeHtml(payload.username || '-')}</td>
                <td>
                    <div class="input-group input-group-sm">
                        <input type="password" class="form-control font-monospace" value="${escapeHtml(payload.secret || '')}" readonly id="pwd-val-${item.id}">
                        <button class="btn btn-outline-secondary btn-toggle-pwd" type="button" data-target="pwd-val-${item.id}">👁️</button>
                        <button class="btn btn-outline-primary btn-copy" type="button" data-copy="${escapeHtml(payload.secret || '')}">📋 Copy</button>
                    </div>
                </td>
                <td>
                    <div class="d-flex flex-wrap gap-1">
                        ${editBtn}
                        ${historyBtn}
                        ${shareBtn}
                        ${deleteBtn}
                    </div>
                </td>
            `;
            passwordsList.appendChild(tr);
        } else if (item.item_type === 'keyfile') {
            keyfileCount++;
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td class="text-center">${favStarBtn}</td>
                <td><strong>${escapeHtml(item.title)}</strong>${catBadge}</td>
                <td>${escapeHtml(payload.notes || '-')}</td>
                <td>
                    <div class="d-flex flex-wrap gap-1">
                        <button class="btn btn-outline-primary btn-sm btn-download" type="button" data-filename="${escapeHtml(item.title)}.key" data-content="${escapeHtml(payload.content || '')}">📥 Key</button>
                        ${editBtn}
                        ${historyBtn}
                        ${shareBtn}
                        ${deleteBtn}
                    </div>
                </td>
            `;
            keyfilesList.appendChild(tr);
        } else if (item.item_type === 'certificate') {
            certCount++;
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td class="text-center">${favStarBtn}</td>
                <td><strong>${escapeHtml(item.title)}</strong>${catBadge}</td>
                <td>${escapeHtml(payload.notes || '-')}</td>
                <td>
                    <div class="d-flex flex-wrap gap-1">
                        <button class="btn btn-outline-primary btn-sm btn-download" type="button" data-filename="${escapeHtml(item.title)}.crt" data-content="${escapeHtml(payload.content || '')}">📥 Cert</button>
                        ${editBtn}
                        ${historyBtn}
                        ${shareBtn}
                        ${deleteBtn}
                    </div>
                </td>
            `;
            certsList.appendChild(tr);
        }
    }

    const countPwdEl = document.getElementById('tab-count-passwords');
    const countKfEl = document.getElementById('tab-count-keyfiles');
    const countCertEl = document.getElementById('tab-count-certs');
    if (countPwdEl) countPwdEl.textContent = String(passwordCount);
    if (countKfEl) countKfEl.textContent = String(keyfileCount);
    if (countCertEl) countCertEl.textContent = String(certCount);

    if (passwordCount === 0) passwordsList.innerHTML = '<tr><td colspan="5" class="text-center text-muted">Keine passenden Passwörter gefunden.</td></tr>';
    if (keyfileCount === 0) keyfilesList.innerHTML = '<tr><td colspan="4" class="text-center text-muted">Keine passenden Keyfiles gefunden.</td></tr>';
    if (certCount === 0) certsList.innerHTML = '<tr><td colspan="4" class="text-center text-muted">Keine passenden Zertifikate gefunden.</td></tr>';
}

// Keep backward-compatible alias
async function renderVaultItems() {
    await decryptAndRenderVaultItems();
}

function openAddModalForNewItem() {
    const form = document.getElementById('add-item-form');
    if (form) form.reset();
    const editIdEl = document.getElementById('edit_item_id');
    if (editIdEl) editIdEl.value = '';
    const labelEl = document.getElementById('addModalLabel');
    if (labelEl) labelEl.textContent = 'Neuen Tresor-Eintrag hinzufügen';
    const pwdInput = document.getElementById('pwd_secret');
    if (pwdInput) pwdInput.type = 'password';
    toggleFormFields();
}

function openEditModalForItem(itemId) {
    const item = rawVaultItems.find(i => Number(i.id) === Number(itemId));
    if (!item) return;
    const payload = decryptedPayloadsById.get(Number(item.id)) || {};

    document.getElementById('edit_item_id').value = String(item.id);
    document.getElementById('item_type').value = item.item_type || 'password';
    document.getElementById('item_title').value = item.title || '';
    document.getElementById('item_category').value = item.category || payload.category || '';
    document.getElementById('item_favorite').checked = Number(item.is_favorite) === 1;

    toggleFormFields();

    if (item.item_type === 'password') {
        document.getElementById('pwd_username').value = payload.username || '';
        document.getElementById('pwd_secret').value = payload.secret || '';
        document.getElementById('pwd_notes').value = payload.notes || '';
    } else if (item.item_type === 'keyfile') {
        document.getElementById('kf_content').value = payload.content || '';
        document.getElementById('kf_notes').value = payload.notes || '';
    } else if (item.item_type === 'certificate') {
        document.getElementById('cert_content').value = payload.content || '';
        document.getElementById('cert_notes').value = payload.notes || '';
    }

    const labelEl = document.getElementById('addModalLabel');
    if (labelEl) labelEl.textContent = 'Tresor-Eintrag bearbeiten (Vorversion wird im Verlauf gesichert)';

    const modalEl = document.getElementById('addModal');
    if (modalEl && typeof bootstrap !== 'undefined' && bootstrap.Modal) {
        const modal = bootstrap.Modal.getOrCreateInstance(modalEl);
        modal.show();
    }
}

async function handleAddOrUpdateItem(e) {
    e.preventDefault();
    if (!derivedMasterKey) {
        alert("Bitte schalten Sie den Tresor zuerst mit dem Master-Passwort frei.");
        return;
    }

    const editId = (document.getElementById('edit_item_id')?.value || '').trim();
    const type = document.getElementById('item_type').value;
    const title = document.getElementById('item_title').value.trim();
    const category = (document.getElementById('item_category')?.value || '').trim();
    const isFavorite = document.getElementById('item_favorite')?.checked ? 1 : 0;

    let payload = {};
    if (type === 'password') {
        payload = {
            username: document.getElementById('pwd_username').value,
            secret: document.getElementById('pwd_secret').value,
            notes: document.getElementById('pwd_notes').value,
            category: category
        };
    } else if (type === 'keyfile') {
        payload = {
            content: document.getElementById('kf_content').value,
            notes: document.getElementById('kf_notes').value,
            category: category
        };
    } else if (type === 'certificate') {
        payload = {
            content: document.getElementById('cert_content').value,
            notes: document.getElementById('cert_notes').value,
            category: category
        };
    }

    if (!activeSalt) {
        activeSalt = rawVaultItems.length > 0 ? rawVaultItems[0].salt : VaultCrypto.generateSalt();
    }
    const salt = activeSalt;
    const key = await getKeyForSalt(salt);
    const encrypted = await VaultCrypto.encryptVaultData(key, payload);

    const formData = new FormData();
    formData.append('action', editId ? 'update' : 'add');
    if (editId) {
        formData.append('item_id', editId);
    }
    formData.append('csrf_token', csrfToken);
    formData.append('item_type', type);
    formData.append('title', title);
    formData.append('category', category);
    formData.append('is_favorite', String(isFavorite));
    formData.append('encrypted_data', encrypted.ciphertext);
    formData.append('iv', encrypted.iv);
    formData.append('salt', salt);
    formData.append('vault_id', vaultId);
    formData.append('ajax', '1');

    try {
        const response = await fetch('vault.php', {
            method: 'POST',
            body: formData,
            headers: { 'X-Requested-With': 'XMLHttpRequest' }
        });
        const res = await response.json();
        if (res.success) {
            if (editId) {
                const idx = rawVaultItems.findIndex(i => Number(i.id) === Number(editId));
                if (idx !== -1) {
                    rawVaultItems[idx].item_type = type;
                    rawVaultItems[idx].title = title;
                    rawVaultItems[idx].category = category;
                    rawVaultItems[idx].is_favorite = isFavorite;
                    rawVaultItems[idx].encrypted_data = encrypted.ciphertext;
                    rawVaultItems[idx].iv = encrypted.iv;
                    rawVaultItems[idx].salt = salt;
                    rawVaultItems[idx].history_count = (Number(rawVaultItems[idx].history_count) || 0) + 1;
                }
                decryptedPayloadsById.set(Number(editId), payload);
            } else {
                const newId = Number(res.id);
                rawVaultItems.unshift({
                    id: newId,
                    item_type: type,
                    title: title,
                    category: category,
                    is_favorite: isFavorite,
                    encrypted_data: encrypted.ciphertext,
                    iv: encrypted.iv,
                    salt: salt,
                    created_at: new Date().toISOString(),
                    history_count: 0
                });
                decryptedPayloadsById.set(newId, payload);
            }

            const modalEl = document.getElementById('addModal');
            if (typeof bootstrap !== 'undefined' && bootstrap.Modal) {
                const modal = bootstrap.Modal.getInstance(modalEl);
                if (modal) modal.hide();
            }
            openAddModalForNewItem();

            updateCategoryDropdownOptions();
            renderVaultItemsFromCache();
        } else {
            alert("Fehler beim Speichern: " + (res.error || 'Unbekannter Fehler'));
        }
    } catch (err) {
        alert("Netzwerkfehler beim Speichern.");
    }
}

async function toggleFavoriteItem(itemId) {
    const item = rawVaultItems.find(i => Number(i.id) === Number(itemId));
    if (!item) return;

    const newFav = Number(item.is_favorite) === 1 ? 0 : 1;
    const formData = new FormData();
    formData.append('action', 'toggle_favorite');
    formData.append('csrf_token', csrfToken);
    formData.append('item_id', itemId);
    formData.append('vault_id', vaultId);
    formData.append('is_favorite', String(newFav));
    formData.append('ajax', '1');

    try {
        const response = await fetch('vault.php', {
            method: 'POST',
            body: formData,
            headers: { 'X-Requested-With': 'XMLHttpRequest' }
        });
        const res = await response.json();
        if (res.success) {
            item.is_favorite = newFav;
            renderVaultItemsFromCache();
        }
    } catch (err) {
        console.error('Favoritenstatus konnte nicht geändert werden:', err);
    }
}

async function openHistoryModal(itemId) {
    const item = rawVaultItems.find(i => Number(i.id) === Number(itemId));
    if (!item) return;
    currentHistoryItemId = Number(item.id);

    const container = document.getElementById('history-list-container');
    const titleEl = document.getElementById('historyModalLabel');
    if (titleEl) {
        titleEl.textContent = `🕒 Passwort-Historie: ${item.title}`;
    }
    if (container) {
        container.innerHTML = '<div class="text-center text-muted py-3">Lade und entschlüssele Verlauf...</div>';
    }

    const modalEl = document.getElementById('historyModal');
    if (modalEl && typeof bootstrap !== 'undefined' && bootstrap.Modal) {
        const modal = bootstrap.Modal.getOrCreateInstance(modalEl);
        modal.show();
    }

    const formData = new FormData();
    formData.append('action', 'get_history');
    formData.append('csrf_token', csrfToken);
    formData.append('item_id', item.id);
    formData.append('vault_id', vaultId);
    formData.append('ajax', '1');

    try {
        const response = await fetch('vault.php', {
            method: 'POST',
            body: formData,
            headers: { 'X-Requested-With': 'XMLHttpRequest' }
        });
        const res = await response.json();
        if (!res.success) {
            container.innerHTML = `<div class="alert alert-danger">${escapeHtml(res.error || 'Fehler beim Laden.')}</div>`;
            return;
        }

        const historyRows = res.history || [];
        if (historyRows.length === 0) {
            container.innerHTML = '<div class="text-center text-muted py-3">Noch keine früheren Versionen für diesen Eintrag vorhanden.</div>';
            return;
        }

        let html = `
            <div class="table-responsive">
                <table class="table table-sm table-hover align-middle">
                    <thead>
                        <tr>
                            <th>Zeitpunkt</th>
                            <th>Benutzer / Info</th>
                            <th>Früheres Passwort / Inhalt</th>
                            <th>Aktionen</th>
                        </tr>
                    </thead>
                    <tbody>
        `;

        for (const h of historyRows) {
            let decPayload = {};
            try {
                const hKey = await getKeyForSalt(h.salt);
                const decStr = await VaultCrypto.decryptVaultData(hKey, h.encrypted_data, h.iv);
                decPayload = JSON.parse(decStr);
            } catch (err) {
                decPayload = { error: true };
            }

            const secretVal = decPayload.secret !== undefined ? decPayload.secret : (decPayload.content || '');
            const userOrNote = decPayload.username || decPayload.notes || '-';

            html += `
                <tr>
                    <td class="small text-nowrap">${escapeHtml(h.created_at || '')}</td>
                    <td class="small">${escapeHtml(userOrNote)}</td>
                    <td>
                        ${decPayload.error ? '<span class="text-danger small">Entschlüsselungsfehler</span>' : `
                            <div class="input-group input-group-sm">
                                <input type="password" class="form-control font-monospace" value="${escapeHtml(secretVal)}" readonly id="hist-pwd-${h.id}">
                                <button class="btn btn-outline-secondary btn-toggle-pwd" type="button" data-target="hist-pwd-${h.id}">👁️</button>
                                <button class="btn btn-outline-primary btn-copy" type="button" data-copy="${escapeHtml(secretVal)}">📋</button>
                            </div>
                        `}
                    </td>
                    <td class="text-nowrap">
                        <button type="button" class="btn btn-success btn-sm btn-restore-history" data-item-id="${item.id}" data-history-id="${h.id}">
                            ⏪ Wiederherstellen
                        </button>
                    </td>
                </tr>
            `;
        }

        html += `</tbody></table></div>`;
        container.innerHTML = html;
    } catch (err) {
        container.innerHTML = '<div class="alert alert-danger">Netzwerkfehler beim Laden des Verlaufs.</div>';
    }
}

async function restoreHistoryVersion(itemId, historyId) {
    if (!confirm('Möchten Sie diese frühere Version wiederherstellen? Der aktuelle Stand wird dabei automatisch im Verlauf gesichert.')) {
        return;
    }

    const formData = new FormData();
    formData.append('action', 'restore_history');
    formData.append('csrf_token', csrfToken);
    formData.append('item_id', itemId);
    formData.append('history_id', historyId);
    formData.append('vault_id', vaultId);
    formData.append('ajax', '1');

    try {
        const response = await fetch('vault.php', {
            method: 'POST',
            body: formData,
            headers: { 'X-Requested-With': 'XMLHttpRequest' }
        });
        const res = await response.json();
        if (res.success) {
            const item = rawVaultItems.find(i => Number(i.id) === Number(itemId));
            if (item) {
                item.encrypted_data = res.encrypted_data;
                item.iv = res.iv;
                item.salt = res.salt;
                const key = await getKeyForSalt(item.salt);
                const decStr = await VaultCrypto.decryptVaultData(key, item.encrypted_data, item.iv);
                decryptedPayloadsById.set(Number(item.id), JSON.parse(decStr));
            }
            renderVaultItemsFromCache();
            await openHistoryModal(itemId);
        } else {
            alert('Fehler beim Wiederherstellen: ' + (res.error || 'Unbekannter Fehler'));
        }
    } catch (err) {
        alert('Netzwerkfehler beim Wiederherstellen.');
    }
}

/**
 * One-Click Crypt Share Transfer for a Vault Entry
 */
async function shareVaultItemViaCryptShare(itemId) {
    const item = rawVaultItems.find(i => Number(i.id) === Number(itemId));
    if (!item) return;
    const payload = decryptedPayloadsById.get(Number(item.id)) || {};

    let shareTextContent = '';
    let shareFilename = '';
    const safeTitle = String(item.title || 'eintrag').replace(/[^a-zA-Z0-9_-]+/g, '_');

    if (item.item_type === 'password') {
        shareFilename = `${safeTitle}_Zugangsdaten.txt`;
        shareTextContent = [
            `=== Geteilter Tresor-Eintrag: ${item.title} ===`,
            item.category ? `Kategorie: ${item.category}` : null,
            `Benutzername / Login: ${payload.username || '-'}`,
            `Passwort: ${payload.secret || ''}`,
            payload.notes ? `Notizen / URL:\n${payload.notes}` : null
        ].filter(Boolean).join('\n');
    } else if (item.item_type === 'keyfile') {
        shareFilename = `${safeTitle}.key`;
        shareTextContent = payload.content || '';
    } else if (item.item_type === 'certificate') {
        shareFilename = `${safeTitle}.crt`;
        shareTextContent = payload.content || '';
    }

    try {
        const otp = VaultCrypto.generateOneTimePassword(18);
        const salt = VaultCrypto.generateSalt();
        const shareKey = await VaultCrypto.deriveMasterKey(otp, salt);

        const encoder = new TextEncoder();
        const fileBytes = encoder.encode(shareTextContent);
        const fileBase64 = VaultCrypto.bufferToBase64(fileBytes);

        const sharePayload = JSON.stringify({
            name: shareFilename,
            type: 'text/plain;charset=utf-8',
            data: fileBase64
        });

        const encrypted = await VaultCrypto.encryptVaultData(shareKey, sharePayload);

        const formData = new FormData();
        formData.append('action', 'create_share');
        formData.append('csrf_token', csrfToken);
        formData.append('file_name', shareFilename);
        formData.append('encrypted_data', encrypted.ciphertext);
        formData.append('iv', encrypted.iv);
        formData.append('salt', salt);
        formData.append('ajax', '1');

        const response = await fetch('crypt_share.php', {
            method: 'POST',
            body: formData,
            headers: { 'X-Requested-With': 'XMLHttpRequest' }
        });

        const res = await response.json();
        if (res.success && res.share_url) {
            document.getElementById('vaultShareItemTitle').textContent = item.title;
            document.getElementById('vaultShareLinkInput').value = res.share_url;
            document.getElementById('vaultShareOtpInput').value = otp;

            const modalEl = document.getElementById('vaultCryptShareModal');
            if (modalEl && typeof bootstrap !== 'undefined' && bootstrap.Modal) {
                const modal = bootstrap.Modal.getOrCreateInstance(modalEl);
                modal.show();
            }
        } else {
            alert('Fehler beim Erstellen des Crypt-Share-Links: ' + (res.error || 'Unbekannter Fehler'));
        }
    } catch (err) {
        alert('Fehler bei der Übergabe an Crypt Share: ' + err.message);
    }
}

/**
 * Encrypted JSON Backup Export & CSV Export
 */
async function handleExportEncryptedJson() {
    if (!derivedMasterKey) {
        alert('Bitte entsperren Sie zuerst den Tresor.');
        return;
    }

    const customPassword = (document.getElementById('export_backup_password')?.value || '').trim();
    const passwordToUse = customPassword || activeMasterPassword;
    if (!passwordToUse) {
        alert('Kein Passwort für die Backup-Verschlüsselung verfügbar.');
        return;
    }

    const plainEntries = rawVaultItems.map(item => ({
        item_type: item.item_type,
        title: item.title,
        category: item.category || '',
        is_favorite: Number(item.is_favorite) === 1 ? 1 : 0,
        payload: decryptedPayloadsById.get(Number(item.id)) || {}
    }));

    const backupSalt = VaultCrypto.generateSalt();
    const backupKey = await VaultCrypto.deriveMasterKey(passwordToUse, backupSalt);
    const encrypted = await VaultCrypto.encryptVaultData(backupKey, {
        exported_at: new Date().toISOString(),
        entries: plainEntries
    });

    const backupBundle = {
        format: 'passwort_vault_encrypted_backup_v1',
        kdf: 'PBKDF2-SHA256-100000',
        cipher: 'AES-256-GCM',
        exported_at: new Date().toISOString(),
        salt: backupSalt,
        iv: encrypted.iv,
        encrypted_data: encrypted.ciphertext
    };

    const dateSuffix = new Date().toISOString().slice(0, 10);
    downloadFile(`tresor_backup_${vaultId}_${dateSuffix}.enc.json`, JSON.stringify(backupBundle, null, 2));
}

function handleExportCsv() {
    if (!derivedMasterKey) {
        alert('Bitte entsperren Sie zuerst den Tresor.');
        return;
    }
    if (!confirm('Hinweis: Die CSV-Datei enthält Ihre Zugangsdaten im Klartext. Möchten Sie fortfahren?')) {
        return;
    }

    const itemsWithPayloads = rawVaultItems.map(item => ({
        item,
        payload: decryptedPayloadsById.get(Number(item.id)) || {}
    }));

    const csvContent = VaultImportExport.itemsToCsv(itemsWithPayloads);
    const dateSuffix = new Date().toISOString().slice(0, 10);
    downloadFile(`tresor_export_${vaultId}_${dateSuffix}.csv`, csvContent);
}

/**
 * Import Handler (Encrypted Backup JSON, Bitwarden JSON, CSV / KeePass CSV)
 */
async function handleImportVaultData(e) {
    e.preventDefault();
    if (!derivedMasterKey) {
        alert('Bitte entsperren Sie zuerst den Tresor.');
        return;
    }

    const fileInput = document.getElementById('import_file');
    const formatSelect = document.getElementById('import_format');
    const backupPwdInput = document.getElementById('import_backup_password');
    const statusBox = document.getElementById('import-status-msg');

    if (!fileInput || !fileInput.files || !fileInput.files[0]) {
        alert('Bitte wählen Sie eine Import-Datei aus.');
        return;
    }

    const file = fileInput.files[0];
    const selectedFormat = formatSelect ? formatSelect.value : 'auto';
    const customBackupPassword = (backupPwdInput ? backupPwdInput.value : '').trim();

    try {
        const text = await VaultCrypto.readFileAsText(file);
        let entriesToImport = [];

        const isJsonFile = file.name.toLowerCase().endsWith('.json') || text.trim().startsWith('{');

        if (selectedFormat === 'encrypted_json' || (selectedFormat === 'auto' && isJsonFile)) {
            let parsedJson = null;
            try {
                parsedJson = JSON.parse(text);
            } catch (jsonErr) {
                if (selectedFormat === 'encrypted_json') {
                    throw new Error('Ungültige JSON-Datei.');
                }
            }

            if (parsedJson && parsedJson.format === 'passwort_vault_encrypted_backup_v1') {
                const pwdForBackup = customBackupPassword || activeMasterPassword;
                const backupKey = await VaultCrypto.deriveMasterKey(pwdForBackup, parsedJson.salt);
                let decryptedBackupStr = '';
                try {
                    decryptedBackupStr = await VaultCrypto.decryptVaultData(backupKey, parsedJson.encrypted_data, parsedJson.iv);
                } catch (decErr) {
                    throw new Error('Backup-Datei konnte nicht entschlüsselt werden. Bitte prüfen Sie das Backup-Passwort.');
                }
                const decryptedBundle = JSON.parse(decryptedBackupStr);
                entriesToImport = Array.isArray(decryptedBundle.entries) ? decryptedBundle.entries : [];
            } else if (parsedJson && Array.isArray(parsedJson.items)) {
                // Bitwarden JSON format
                entriesToImport = VaultImportExport.parseBitwardenJson(parsedJson);
            } else if (selectedFormat === 'bitwarden_json' && parsedJson) {
                entriesToImport = VaultImportExport.parseBitwardenJson(parsedJson);
            } else if (!isJsonFile || selectedFormat === 'csv') {
                entriesToImport = VaultImportExport.parseCsvImport(text);
            }
        } else if (selectedFormat === 'bitwarden_json') {
            const parsedJson = JSON.parse(text);
            entriesToImport = VaultImportExport.parseBitwardenJson(parsedJson);
        } else {
            entriesToImport = VaultImportExport.parseCsvImport(text);
        }

        if (!entriesToImport || entriesToImport.length === 0) {
            throw new Error('Keine gültigen Einträge in der ausgewählten Datei gefunden.');
        }

        if (!activeSalt) {
            activeSalt = rawVaultItems.length > 0 ? rawVaultItems[0].salt : VaultCrypto.generateSalt();
        }
        const salt = activeSalt;
        const key = await getKeyForSalt(salt);

        const encryptedItemsBatch = [];
        for (const entry of entriesToImport) {
            const enc = await VaultCrypto.encryptVaultData(key, entry.payload || {});
            encryptedItemsBatch.push({
                item_type: entry.item_type || 'password',
                title: entry.title || 'Importierter Eintrag',
                category: entry.category || '',
                is_favorite: entry.is_favorite ? 1 : 0,
                encrypted_data: enc.ciphertext,
                iv: enc.iv,
                salt: salt
            });
        }

        const formData = new FormData();
        formData.append('action', 'bulk_import');
        formData.append('csrf_token', csrfToken);
        formData.append('vault_id', vaultId);
        formData.append('items_json', JSON.stringify(encryptedItemsBatch));
        formData.append('ajax', '1');

        const response = await fetch('vault.php', {
            method: 'POST',
            body: formData,
            headers: { 'X-Requested-With': 'XMLHttpRequest' }
        });
        const res = await response.json();

        if (res.success && Array.isArray(res.items)) {
            res.items.forEach((insertedItem, idx) => {
                rawVaultItems.unshift(insertedItem);
                decryptedPayloadsById.set(Number(insertedItem.id), entriesToImport[idx]?.payload || {});
            });

            updateCategoryDropdownOptions();
            renderVaultItemsFromCache();

            if (statusBox) {
                statusBox.className = 'alert alert-success small';
                statusBox.textContent = `✅ ${res.imported_count} Einträge erfolgreich verschlüsselt importiert!`;
                statusBox.classList.remove('d-none');
            }
            fileInput.value = '';
        } else {
            throw new Error(res.error || 'Import fehlgeschlagen.');
        }
    } catch (err) {
        if (statusBox) {
            statusBox.className = 'alert alert-danger small';
            statusBox.textContent = '❌ ' + err.message;
            statusBox.classList.remove('d-none');
        } else {
            alert('Import-Fehler: ' + err.message);
        }
    }
}

async function deleteVaultItem(id) {
    if (!confirm("Möchten Sie diesen Eintrag wirklich löschen?")) return;

    const formData = new FormData();
    formData.append('action', 'delete');
    formData.append('csrf_token', csrfToken);
    formData.append('item_id', id);
    formData.append('vault_id', vaultId);
    formData.append('ajax', '1');

    try {
        const response = await fetch('vault.php', {
            method: 'POST',
            body: formData,
            headers: { 'X-Requested-With': 'XMLHttpRequest' }
        });
        const res = await response.json();
        if (res.success) {
            const idx = rawVaultItems.findIndex(i => i.id == id);
            if (idx !== -1) rawVaultItems.splice(idx, 1);
            decryptedPayloadsById.delete(Number(id));
            updateCategoryDropdownOptions();
            renderVaultItemsFromCache();
        } else {
            alert("Fehler beim Löschen: " + (res.error || 'Unbekannter Fehler'));
        }
    } catch (err) {
        alert("Netzwerkfehler beim Löschen.");
    }
}

function togglePasswordVisibility(id) {
    const input = document.getElementById(id);
    if (input) {
        input.type = input.type === 'password' ? 'text' : 'password';
    }
}

function copyToClipboard(text, customMessage) {
    navigator.clipboard.writeText(text).then(() => {
        alert(customMessage || "Passwort in die Zwischenablage kopiert!");
    }).catch(() => {
        alert("Kopieren fehlgeschlagen.");
    });
}

function downloadFile(filename, content) {
    const element = document.createElement('a');
    if (typeof Blob !== 'undefined' && typeof URL !== 'undefined' && URL.createObjectURL) {
        const blob = new Blob([content], { type: 'text/plain;charset=utf-8' });
        const url = URL.createObjectURL(blob);
        element.setAttribute('href', url);
        element.setAttribute('download', filename);
        element.hidden = true;
        document.body.appendChild(element);
        element.click();
        document.body.removeChild(element);
        setTimeout(() => URL.revokeObjectURL(url), 100);
    } else {
        element.setAttribute('href', 'data:text/plain;charset=utf-8,' + encodeURIComponent(content));
        element.setAttribute('download', filename);
        element.hidden = true;
        document.body.appendChild(element);
        element.click();
        document.body.removeChild(element);
    }
}

function escapeHtml(str) {
    if (!str) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

function initVaultUI() {
    const dataEl = document.getElementById('vault-data');
    if (dataEl) {
        try {
            const rawJson = dataEl.dataset && dataEl.dataset.json ? dataEl.dataset.json : (dataEl.getAttribute('data-json') || dataEl.textContent);
            const data = JSON.parse(rawJson);
            csrfToken = data.csrfToken || "";
            vaultId = data.vaultId || null;
            canUseCryptShare = Boolean(data.canUseCryptShare);
            rawVaultItems = data.items || [];
        } catch (e) {
            console.error("Failed to parse vault data:", e);
        }
    }

    if (typeof document.querySelectorAll === 'function') {
        const deleteForms = document.querySelectorAll('.delete-vault-form');
        deleteForms.forEach((form) => {
            form.addEventListener('submit', function(e) {
                if (!confirm('Tresor wirklich löschen? Alle Einträge darin gehen verloren!')) {
                    e.preventDefault();
                }
            });
        });
    }

    if (typeof sessionStorage !== 'undefined' && sessionStorage.getItem('pendingVaultEntry')) {
        const banner = document.getElementById('pending-vault-entry-banner');
        if (banner) banner.classList.remove('d-none');
    }

    const lockBtn = document.getElementById('lock-vault-btn');
    if (lockBtn) lockBtn.addEventListener('click', lockVault);

    const masterForm = document.getElementById('master-password-form');
    if (masterForm) masterForm.addEventListener('submit', handleUnlockVault);

    const openAddBtn = document.getElementById('btn-open-add-modal');
    if (openAddBtn) openAddBtn.addEventListener('click', openAddModalForNewItem);

    const toggleModalPwdBtn = document.getElementById('btn-toggle-modal-pwd');
    if (toggleModalPwdBtn) {
        toggleModalPwdBtn.addEventListener('click', function() {
            togglePasswordVisibility('pwd_secret');
        });
    }

    const addItemForm = document.getElementById('add-item-form');
    if (addItemForm) addItemForm.addEventListener('submit', handleAddOrUpdateItem);

    const itemTypeSelect = document.getElementById('item_type');
    if (itemTypeSelect) itemTypeSelect.addEventListener('change', toggleFormFields);

    const kfFile = document.getElementById('kf_file');
    if (kfFile) kfFile.addEventListener('change', function() { readKeyfileInput(this); });

    const certFile = document.getElementById('cert_file');
    if (certFile) certFile.addEventListener('change', function() { readCertFileInput(this); });

    // Filter controls
    const searchInput = document.getElementById('vault-search-input');
    if (searchInput) {
        searchInput.addEventListener('input', function() {
            activeSearchQuery = this.value || '';
            renderVaultItemsFromCache();
        });
    }

    const categorySelect = document.getElementById('vault-category-filter');
    if (categorySelect) {
        categorySelect.addEventListener('change', function() {
            activeCategoryFilter = this.value || 'all';
            renderVaultItemsFromCache();
        });
    }

    const favFilterBtn = document.getElementById('vault-favorite-filter-btn');
    if (favFilterBtn) {
        favFilterBtn.addEventListener('click', function() {
            activeFavoriteOnly = !activeFavoriteOnly;
            this.classList.toggle('btn-warning', activeFavoriteOnly);
            this.classList.toggle('btn-outline-warning', !activeFavoriteOnly);
            renderVaultItemsFromCache();
        });
    }

    // Export / Import listeners
    const btnExportJson = document.getElementById('btn-export-encrypted-json');
    if (btnExportJson) btnExportJson.addEventListener('click', handleExportEncryptedJson);

    const btnExportCsv = document.getElementById('btn-export-csv');
    if (btnExportCsv) btnExportCsv.addEventListener('click', handleExportCsv);

    const importForm = document.getElementById('vault-import-form');
    if (importForm) importForm.addEventListener('submit', handleImportVaultData);

    // Crypt Share Modal copy buttons
    const btnCopyShareLink = document.getElementById('btn-copy-vault-share-link');
    if (btnCopyShareLink) {
        btnCopyShareLink.addEventListener('click', function() {
            const link = document.getElementById('vaultShareLinkInput')?.value || '';
            copyToClipboard(link, 'Freigabe-Link in die Zwischenablage kopiert!');
        });
    }

    const btnCopyShareOtp = document.getElementById('btn-copy-vault-share-otp');
    if (btnCopyShareOtp) {
        btnCopyShareOtp.addEventListener('click', function() {
            const otp = document.getElementById('vaultShareOtpInput')?.value || '';
            copyToClipboard(otp, 'Einmal-Passwort in die Zwischenablage kopiert!');
        });
    }

    const btnCopyShareBoth = document.getElementById('btn-copy-vault-share-both');
    if (btnCopyShareBoth) {
        btnCopyShareBoth.addEventListener('click', function() {
            const title = document.getElementById('vaultShareItemTitle')?.textContent || 'Tresor-Eintrag';
            const link = document.getElementById('vaultShareLinkInput')?.value || '';
            const otp = document.getElementById('vaultShareOtpInput')?.value || '';
            const combined = `Hier ist ein verschlüsselter Tresor-Eintrag (${title}):\n\nLink: ${link}\nEinmal-Passwort: ${otp}\n\n(Gültig für 24 Stunden)`;
            copyToClipboard(combined, 'Link und Einmal-Passwort zusammen kopiert!');
        });
    }

    // History Modal event delegation
    const historyModal = document.getElementById('historyModal');
    if (historyModal) {
        historyModal.addEventListener('click', function(e) {
            const toggleBtn = e.target.closest('.btn-toggle-pwd');
            if (toggleBtn) {
                togglePasswordVisibility(toggleBtn.dataset.target);
                return;
            }
            const copyBtn = e.target.closest('.btn-copy');
            if (copyBtn) {
                copyToClipboard(copyBtn.dataset.copy);
                return;
            }
            const restoreBtn = e.target.closest('.btn-restore-history');
            if (restoreBtn) {
                restoreHistoryVersion(restoreBtn.dataset.itemId, restoreBtn.dataset.historyId);
            }
        });
    }

    const vaultContent = document.getElementById('vault-content');
    if (vaultContent) {
        vaultContent.addEventListener('click', function(e) {
            const favBtn = e.target.closest('.btn-toggle-favorite');
            if (favBtn) {
                toggleFavoriteItem(favBtn.dataset.id);
                return;
            }

            const editBtn = e.target.closest('.btn-edit-item');
            if (editBtn) {
                openEditModalForItem(editBtn.dataset.id);
                return;
            }

            const histBtn = e.target.closest('.btn-history');
            if (histBtn) {
                openHistoryModal(histBtn.dataset.id);
                return;
            }

            const shareBtn = e.target.closest('.btn-crypt-share-item');
            if (shareBtn) {
                shareVaultItemViaCryptShare(shareBtn.dataset.id);
                return;
            }

            const toggleBtn = e.target.closest('.btn-toggle-pwd');
            if (toggleBtn) {
                togglePasswordVisibility(toggleBtn.dataset.target);
                return;
            }

            const copyBtn = e.target.closest('.btn-copy');
            if (copyBtn) {
                copyToClipboard(copyBtn.dataset.copy);
                return;
            }

            const deleteBtn = e.target.closest('.btn-delete');
            if (deleteBtn) {
                deleteVaultItem(deleteBtn.dataset.id);
                return;
            }

            const downloadBtn = e.target.closest('.btn-download');
            if (downloadBtn) {
                downloadFile(downloadBtn.dataset.filename, downloadBtn.dataset.content);
                return;
            }
        });
    }
}

if (typeof window !== 'undefined') {
    window.VaultCrypto = VaultCrypto;
    window.VaultImportExport = VaultImportExport;
}

if (typeof document !== 'undefined') {
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initVaultUI);
    } else {
        initVaultUI();
    }
}

if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        VaultCrypto,
        VaultImportExport,
        initVaultUI,
        getCsrfToken: () => csrfToken,
        getRawVaultItems: () => rawVaultItems,
        getVaultId: () => vaultId,
        getCanUseCryptShare: () => canUseCryptShare
    };
}
