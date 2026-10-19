/**
 * Web Crypto API End-to-End Encryption helpers for Vault
 */

const VaultCrypto = {
    /**
     * Converts an ArrayBuffer or Uint8Array to a Base64 string
     */
    bufferToBase64(buffer) {
        const bytes = new Uint8Array(buffer);
        let binary = '';
        for (let i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return window.btoa(binary);
    },

    /**
     * Converts a Base64 string to a Uint8Array
     */
    base64ToBuffer(base64) {
        const binary = window.atob(base64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
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
     * Reads a File object as plain text or base64 data
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

var csrfToken = "";
var vaultId = null;
var rawVaultItems = [];
var derivedMasterKey = null;
var activeSalt = null;

function toggleFormFields() {
    const type = document.getElementById('item_type').value;
    document.getElementById('field-group-password').classList.toggle('d-none', type !== 'password');
    document.getElementById('field-group-keyfile').classList.toggle('d-none', type !== 'keyfile');
    document.getElementById('field-group-certificate').classList.toggle('d-none', type !== 'certificate');
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

        if (rawVaultItems.length > 0) {
            try {
                await VaultCrypto.decryptVaultData(derivedMasterKey, rawVaultItems[0].encrypted_data, rawVaultItems[0].iv);
            } catch (err) {
                alert("Entschlüsselung fehlgeschlagen! Das Master-Passwort ist möglicherweise falsch.");
                derivedMasterKey = null;
                return;
            }
        }

        document.getElementById('master-password-card').classList.add('d-none');
        document.getElementById('vault-content').classList.remove('d-none');
        document.getElementById('lock-vault-btn').classList.remove('d-none');

        await renderVaultItems();
    } catch (err) {
        alert("Fehler beim Entschlüsseln: " + err.message);
    }
}

function lockVault() {
    derivedMasterKey = null;
    document.getElementById('master-password-input').value = '';
    document.getElementById('master-password-card').classList.remove('d-none');
    document.getElementById('vault-content').classList.add('d-none');
    document.getElementById('lock-vault-btn').classList.add('d-none');
}

async function renderVaultItems() {
    const passwordsList = document.getElementById('passwords-list');
    const keyfilesList = document.getElementById('keyfiles-list');
    const certsList = document.getElementById('certs-list');

    passwordsList.innerHTML = '';
    keyfilesList.innerHTML = '';
    certsList.innerHTML = '';

    let passwordCount = 0;
    let keyfileCount = 0;
    let certCount = 0;

    for (const item of rawVaultItems) {
        let payload = null;
        try {
            const jsonStr = await VaultCrypto.decryptVaultData(derivedMasterKey, item.encrypted_data, item.iv);
            payload = JSON.parse(jsonStr);
        } catch (e) {
            payload = { error: 'Entschlüsselungsfehler' };
        }

        if (item.item_type === 'password') {
            passwordCount++;
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td><strong>${escapeHtml(item.title)}</strong></td>
                <td>${escapeHtml(payload.username || '-')}</td>
                <td>
                    <div class="input-group input-group-sm">
                        <input type="password" class="form-control" value="${escapeHtml(payload.secret || '')}" readonly id="pwd-val-${item.id}">
                        <button class="btn btn-outline-secondary btn-toggle-pwd" type="button" data-target="pwd-val-${item.id}">👁️</button>
                        <button class="btn btn-outline-primary btn-copy" type="button" data-copy="${escapeHtml(payload.secret || '')}">📋 Copy</button>
                    </div>
                </td>
                <td>
                    <button class="btn btn-danger btn-sm btn-delete" type="button" data-id="${item.id}">Löschen</button>
                </td>
            `;
            passwordsList.appendChild(tr);
        } else if (item.item_type === 'keyfile') {
            keyfileCount++;
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td><strong>${escapeHtml(item.title)}</strong></td>
                <td>${escapeHtml(payload.notes || '-')}</td>
                <td>
                    <button class="btn btn-outline-primary btn-sm me-2 btn-download" type="button" data-filename="${escapeHtml(item.title)}.key" data-content="${escapeHtml(payload.content || '')}">📥 Download Key</button>
                    <button class="btn btn-danger btn-sm btn-delete" type="button" data-id="${item.id}">Löschen</button>
                </td>
            `;
            keyfilesList.appendChild(tr);
        } else if (item.item_type === 'certificate') {
            certCount++;
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td><strong>${escapeHtml(item.title)}</strong></td>
                <td>${escapeHtml(payload.notes || '-')}</td>
                <td>
                    <button class="btn btn-outline-primary btn-sm me-2 btn-download" type="button" data-filename="${escapeHtml(item.title)}.crt" data-content="${escapeHtml(payload.content || '')}">📥 Download Cert</button>
                    <button class="btn btn-danger btn-sm btn-delete" type="button" data-id="${item.id}">Löschen</button>
                </td>
            `;
            certsList.appendChild(tr);
        }
    }

    if (passwordCount === 0) passwordsList.innerHTML = '<tr><td colspan="4" class="text-center text-muted">Keine Passwörter gespeichert.</td></tr>';
    if (keyfileCount === 0) keyfilesList.innerHTML = '<tr><td colspan="3" class="text-center text-muted">Keine Keyfiles gespeichert.</td></tr>';
    if (certCount === 0) certsList.innerHTML = '<tr><td colspan="3" class="text-center text-muted">Keine Zertifikate gespeichert.</td></tr>';
}

async function handleAddItem(e) {
    e.preventDefault();
    if (!derivedMasterKey) {
        alert("Bitte schalten Sie den Tresor zuerst mit dem Master-Passwort frei.");
        return;
    }

    const type = document.getElementById('item_type').value;
    const title = document.getElementById('item_title').value.trim();

    let payload = {};
    if (type === 'password') {
        payload = {
            username: document.getElementById('pwd_username').value,
            secret: document.getElementById('pwd_secret').value,
            notes: document.getElementById('pwd_notes').value
        };
    } else if (type === 'keyfile') {
        payload = {
            content: document.getElementById('kf_content').value,
            notes: document.getElementById('kf_notes').value
        };
    } else if (type === 'certificate') {
        payload = {
            content: document.getElementById('cert_content').value,
            notes: document.getElementById('cert_notes').value
        };
    }

    if (!activeSalt) {
        activeSalt = rawVaultItems.length > 0 ? rawVaultItems[0].salt : VaultCrypto.generateSalt();
    }
    const salt = activeSalt;
    const encrypted = await VaultCrypto.encryptVaultData(derivedMasterKey, payload);

    const formData = new FormData();
    formData.append('action', 'add');
    formData.append('csrf_token', csrfToken);
    formData.append('item_type', type);
    formData.append('title', title);
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
            rawVaultItems.unshift({
                id: res.id,
                item_type: type,
                title: title,
                encrypted_data: encrypted.ciphertext,
                iv: encrypted.iv,
                salt: salt,
                created_at: new Date().toISOString()
            });

            const modalEl = document.getElementById('addModal');
            if (typeof bootstrap !== 'undefined' && bootstrap.Modal) {
                const modal = bootstrap.Modal.getInstance(modalEl);
                if (modal) modal.hide();
            }
            document.getElementById('add-item-form').reset();

            await renderVaultItems();
        } else {
            alert("Fehler beim Speichern: " + (res.error || 'Unbekannter Fehler'));
        }
    } catch (err) {
        alert("Netzwerkfehler beim Speichern.");
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
            await renderVaultItems();
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

function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
        alert("Passwort in die Zwischenablage kopiert!");
    }).catch(() => {
        alert("Kopieren fehlgeschlagen.");
    });
}

function downloadFile(filename, content) {
    const element = document.createElement('a');
    element.setAttribute('href', 'data:text/plain;charset=utf-8,' + encodeURIComponent(content));
    element.setAttribute('download', filename);
    element.hidden = true;
    document.body.appendChild(element);
    element.click();
    document.body.removeChild(element);
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
            rawVaultItems = data.items || [];
        } catch (e) {
            console.error("Failed to parse vault data:", e);
        }
    }

    const lockBtn = document.getElementById('lock-vault-btn');
    if (lockBtn) lockBtn.addEventListener('click', lockVault);

    const masterForm = document.getElementById('master-password-form');
    if (masterForm) masterForm.addEventListener('submit', handleUnlockVault);

    const addItemForm = document.getElementById('add-item-form');
    if (addItemForm) addItemForm.addEventListener('submit', handleAddItem);

    const itemTypeSelect = document.getElementById('item_type');
    if (itemTypeSelect) itemTypeSelect.addEventListener('change', toggleFormFields);

    const kfFile = document.getElementById('kf_file');
    if (kfFile) kfFile.addEventListener('change', function() { readKeyfileInput(this); });

    const certFile = document.getElementById('cert_file');
    if (certFile) certFile.addEventListener('change', function() { readCertFileInput(this); });

    const vaultContent = document.getElementById('vault-content');
    if (vaultContent) {
        vaultContent.addEventListener('click', function(e) {
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
        initVaultUI,
        getCsrfToken: () => csrfToken,
        getRawVaultItems: () => rawVaultItems,
        getVaultId: () => vaultId
    };
}
