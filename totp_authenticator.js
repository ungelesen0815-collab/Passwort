/**
 * 2FA / TOTP Web-Authenticator
 * - Zero-Knowledge AES-GCM-256 encryption of TOTP secrets
 * - RFC 6238 / RFC 4226 Web Crypto HMAC-SHA1/256/512 live code generation
 * - otpauth:// URI parser & builder
 */

const TotpEngine = {
    BASE32_ALPHABET: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567',

    /**
     * Cleans and decodes a Base32 string into a Uint8Array
     */
    base32ToBytes(base32Str) {
        const cleaned = String(base32Str || '')
            .toUpperCase()
            .replace(/[\s\-=]+/g, '');

        if (!cleaned) {
            throw new Error('Leeres Base32-Secret.');
        }

        let bits = 0;
        let value = 0;
        const output = [];

        for (let i = 0; i < cleaned.length; i++) {
            const idx = this.BASE32_ALPHABET.indexOf(cleaned[i]);
            if (idx === -1) {
                throw new Error('Ungültiges Base32-Zeichen: ' + cleaned[i]);
            }
            value = (value << 5) | idx;
            bits += 5;

            if (bits >= 8) {
                output.push((value >>> (bits - 8)) & 0xff);
                bits -= 8;
            }
        }

        return new Uint8Array(output);
    },

    /**
     * Parses an otpauth://totp/... URI into its components
     */
    parseOtpAuthUri(uri) {
        const raw = String(uri || '').trim();
        if (!raw.toLowerCase().startsWith('otpauth://')) {
            throw new Error('URI muss mit otpauth:// beginnen.');
        }

        let parsedUrl;
        try {
            parsedUrl = new URL(raw);
        } catch (e) {
            throw new Error('Ungültiges otpauth-URI-Format.');
        }

        const pathLabel = decodeURIComponent(parsedUrl.pathname.replace(/^\/+(totp|hotp)\/?/i, '').replace(/^\/+/, ''));
        let issuer = parsedUrl.searchParams.get('issuer') || '';
        let accountName = pathLabel;

        if (pathLabel.includes(':')) {
            const parts = pathLabel.split(':');
            const labelIssuer = parts[0].trim();
            accountName = parts.slice(1).join(':').trim();
            if (!issuer) {
                issuer = labelIssuer;
            }
        }

        const secret = (parsedUrl.searchParams.get('secret') || '').replace(/[\s\-]+/g, '').toUpperCase();
        if (!secret) {
            throw new Error('Kein secret-Parameter in der otpauth-URI gefunden.');
        }

        const rawAlgo = (parsedUrl.searchParams.get('algorithm') || 'SHA1').toUpperCase().replace(/[^A-Z0-9]/g, '');
        let algorithm = 'SHA-1';
        if (rawAlgo === 'SHA256') algorithm = 'SHA-256';
        else if (rawAlgo === 'SHA512') algorithm = 'SHA-512';

        const digits = parseInt(parsedUrl.searchParams.get('digits') || '6', 10) === 8 ? 8 : 6;
        const period = parseInt(parsedUrl.searchParams.get('period') || '30', 10) === 60 ? 60 : 30;

        return {
            issuer: issuer.trim(),
            accountName: accountName.trim() || issuer.trim() || 'Account',
            secret: secret,
            algorithm: algorithm,
            digits: digits,
            period: period
        };
    },

    /**
     * Builds an otpauth://totp/... URI from entry metadata and decrypted payload
     */
    buildOtpAuthUri({ issuer, accountName, secret, digits = 6, period = 30, algorithm = 'SHA-1' }) {
        const cleanSecret = String(secret || '').replace(/[\s\-=]+/g, '').toUpperCase();
        const label = issuer
            ? `${encodeURIComponent(issuer)}:${encodeURIComponent(accountName)}`
            : encodeURIComponent(accountName);
        const algoParam = String(algorithm || 'SHA-1').replace('-', '');
        const params = new URLSearchParams();
        params.set('secret', cleanSecret);
        if (issuer) params.set('issuer', issuer);
        params.set('algorithm', algoParam);
        params.set('digits', String(digits));
        params.set('period', String(period));
        return `otpauth://totp/${label}?${params.toString()}`;
    },

    /**
     * Generates a TOTP code for a given timestamp using Web Crypto HMAC
     */
    async generateTotpCode(secretBase32, options = {}) {
        const digits = Number(options.digits) === 8 ? 8 : 6;
        const period = Number(options.period) === 60 ? 60 : 30;
        const algorithm = ['SHA-1', 'SHA-256', 'SHA-512'].includes(options.algorithm) ? options.algorithm : 'SHA-1';
        const timestampMs = options.timestampMs !== undefined ? options.timestampMs : Date.now();

        const keyBytes = this.base32ToBytes(secretBase32);
        const epochSeconds = Math.floor(timestampMs / 1000);
        const counter = Math.floor(epochSeconds / period);
        const remainingSeconds = period - (epochSeconds % period);

        // 8-byte big-endian counter buffer
        const counterBuffer = new ArrayBuffer(8);
        const view = new DataView(counterBuffer);
        const high = Math.floor(counter / 0x100000000);
        const low = counter >>> 0;
        view.setUint32(0, high, false);
        view.setUint32(4, low, false);

        const cryptoKey = await window.crypto.subtle.importKey(
            'raw',
            keyBytes,
            { name: 'HMAC', hash: { name: algorithm } },
            false,
            ['sign']
        );

        const signature = await window.crypto.subtle.sign('HMAC', cryptoKey, counterBuffer);
        const hmacBytes = new Uint8Array(signature);

        // Dynamic truncation (RFC 4226 Section 5.4)
        const offset = hmacBytes[hmacBytes.length - 1] & 0x0f;
        const binaryCode =
            ((hmacBytes[offset] & 0x7f) << 24) |
            ((hmacBytes[offset + 1] & 0xff) << 16) |
            ((hmacBytes[offset + 2] & 0xff) << 8) |
            (hmacBytes[offset + 3] & 0xff);

        const mod = Math.pow(10, digits);
        const otp = (binaryCode % mod).toString().padStart(digits, '0');

        return {
            code: otp,
            remainingSeconds: remainingSeconds,
            period: period
        };
    }
};

var totpCsrfToken = '';
var rawTotpEntries = [];
var decryptedTotpCache = new Map();
var totpMasterKey = null;
var totpActiveSalt = null;
var totpMasterPassword = null;
var totpKeysBySalt = new Map();
var totpSearchQuery = '';
var totpTimerInterval = null;

function escapeTotpHtml(str) {
    if (!str) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

function formatCodeForDisplay(code) {
    const s = String(code || '');
    if (s.length === 6) {
        return s.slice(0, 3) + ' ' + s.slice(3);
    }
    if (s.length === 8) {
        return s.slice(0, 4) + ' ' + s.slice(4);
    }
    return s;
}

async function getTotpKeyForSalt(salt) {
    if (!salt || salt === totpActiveSalt) {
        return totpMasterKey;
    }
    if (totpKeysBySalt.has(salt)) {
        return totpKeysBySalt.get(salt);
    }
    if (!totpMasterPassword) {
        return totpMasterKey;
    }
    const key = await VaultCrypto.deriveMasterKey(totpMasterPassword, salt);
    totpKeysBySalt.set(salt, key);
    return key;
}

async function handleUnlockTotp(e) {
    e.preventDefault();
    const masterPassword = document.getElementById('totp-master-password-input').value;
    if (!masterPassword) return;

    if (rawTotpEntries.length > 0) {
        totpActiveSalt = rawTotpEntries[0].salt;
    } else if (!totpActiveSalt) {
        totpActiveSalt = VaultCrypto.generateSalt();
    }

    try {
        totpMasterKey = await VaultCrypto.deriveMasterKey(masterPassword, totpActiveSalt);
        totpMasterPassword = masterPassword;
        totpKeysBySalt.clear();
        totpKeysBySalt.set(totpActiveSalt, totpMasterKey);

        if (rawTotpEntries.length > 0) {
            try {
                await VaultCrypto.decryptVaultData(totpMasterKey, rawTotpEntries[0].encrypted_data, rawTotpEntries[0].iv);
            } catch (err) {
                alert('Entschlüsselung fehlgeschlagen! Das Master-Passwort ist möglicherweise falsch.');
                totpMasterKey = null;
                totpMasterPassword = null;
                totpKeysBySalt.clear();
                return;
            }
        }

        document.getElementById('totp-master-password-card').classList.add('d-none');
        document.getElementById('totp-content').classList.remove('d-none');
        document.getElementById('lock-totp-btn').classList.remove('d-none');

        await decryptAllTotpEntriesAndRender();
        startTotpLiveTicker();
    } catch (err) {
        alert('Fehler beim Entsperren: ' + err.message);
    }
}

function lockTotpAuthenticator() {
    if (totpTimerInterval) {
        clearInterval(totpTimerInterval);
        totpTimerInterval = null;
    }
    totpMasterKey = null;
    totpMasterPassword = null;
    totpKeysBySalt.clear();
    decryptedTotpCache.clear();
    document.getElementById('totp-master-password-input').value = '';
    document.getElementById('totp-master-password-card').classList.remove('d-none');
    document.getElementById('totp-content').classList.add('d-none');
    document.getElementById('lock-totp-btn').classList.add('d-none');
}

async function decryptAllTotpEntriesAndRender() {
    decryptedTotpCache.clear();

    const uniqueSalts = new Set(rawTotpEntries.map(e => e.salt).filter(Boolean));
    for (const salt of uniqueSalts) {
        await getTotpKeyForSalt(salt);
    }

    await Promise.all(rawTotpEntries.map(async (entry) => {
        try {
            const key = await getTotpKeyForSalt(entry.salt);
            const jsonStr = await VaultCrypto.decryptVaultData(key, entry.encrypted_data, entry.iv);
            const parsed = JSON.parse(jsonStr);
            decryptedTotpCache.set(Number(entry.id), {
                secret: parsed.secret || '',
                digits: Number(parsed.digits) || 6,
                period: Number(parsed.period) || 30,
                algorithm: parsed.algorithm || 'SHA-1',
                notes: parsed.notes || ''
            });
        } catch (err) {
            decryptedTotpCache.set(Number(entry.id), { error: true });
        }
    }));

    await renderTotpGrid();
}

async function renderTotpGrid() {
    const grid = document.getElementById('totp-grid');
    if (!grid) return;

    const totalEl = document.getElementById('totp-total-count');
    if (totalEl) totalEl.textContent = String(rawTotpEntries.length);

    const query = totpSearchQuery.trim().toLowerCase();
    const filtered = rawTotpEntries.filter(entry => {
        if (!query) return true;
        const dec = decryptedTotpCache.get(Number(entry.id)) || {};
        const haystack = [entry.issuer, entry.account_name, entry.category, dec.notes || ''].join(' ').toLowerCase();
        return haystack.includes(query);
    });

    if (filtered.length === 0) {
        grid.innerHTML = '<div class="col-12 text-center text-muted py-4">Keine passenden 2FA-Secrets gefunden.</div>';
        return;
    }

    grid.innerHTML = '';

    for (const entry of filtered) {
        const dec = decryptedTotpCache.get(Number(entry.id)) || {};
        let codeResult = { code: '------', remainingSeconds: 30, period: 30, invalid: false };

        if (dec.error || !dec.secret) {
            codeResult.invalid = true;
        } else {
            try {
                codeResult = await TotpEngine.generateTotpCode(dec.secret, {
                    digits: dec.digits,
                    period: dec.period,
                    algorithm: dec.algorithm
                });
            } catch (e) {
                codeResult.invalid = true;
            }
        }

        const pct = Math.max(0, Math.min(100, Math.round((codeResult.remainingSeconds / codeResult.period) * 100)));
        const isExpiringSoon = codeResult.remainingSeconds <= 5;
        const barClass = isExpiringSoon ? 'bg-danger' : 'bg-primary';
        const codeTextClass = isExpiringSoon ? 'text-danger' : 'text-primary';

        const col = document.createElement('div');
        col.className = 'col-md-6 col-lg-4';
        col.innerHTML = `
            <div class="card h-100 shadow-sm totp-card" data-entry-id="${entry.id}">
                <div class="card-body d-flex flex-column">
                    <div class="d-flex justify-content-between align-items-start mb-1">
                        <div>
                            <h5 class="card-title mb-0">${escapeTotpHtml(entry.issuer || entry.account_name)}</h5>
                            <small class="text-muted">${escapeTotpHtml(entry.account_name)}</small>
                        </div>
                        ${entry.category ? `<span class="badge bg-secondary">${escapeTotpHtml(entry.category)}</span>` : ''}
                    </div>
                    ${dec.notes ? `<div class="small text-muted mb-2">${escapeTotpHtml(dec.notes)}</div>` : ''}

                    <div class="my-3 p-2 bg-light border rounded text-center">
                        ${codeResult.invalid ? `
                            <span class="text-danger small fw-bold">Ungültiges Base32-Secret</span>
                        ` : `
                            <div class="fs-2 fw-bold font-monospace ${codeTextClass} totp-live-code" id="totp-code-${entry.id}" data-raw-code="${escapeTotpHtml(codeResult.code)}">
                                ${escapeTotpHtml(formatCodeForDisplay(codeResult.code))}
                            </div>
                            <div class="progress totp-progress mt-2">
                                <div class="progress-bar ${barClass}" id="totp-bar-${entry.id}" role="progressbar"></div>
                            </div>
                            <small class="text-muted d-block mt-1"><span id="totp-rem-${entry.id}">${codeResult.remainingSeconds}</span>s gültig (${escapeTotpHtml(dec.algorithm || 'SHA-1')})</small>
                        `}
                    </div>

                    <div class="d-flex justify-content-between align-items-center mt-auto pt-2 border-top">
                        <div class="btn-group btn-group-sm">
                            <button type="button" class="btn btn-outline-primary btn-copy-totp" data-id="${entry.id}" title="Aktuellen 2FA-Code kopieren">📋 Code</button>
                            <button type="button" class="btn btn-outline-secondary btn-qr-totp" data-id="${entry.id}" title="QR-Code für Smartphone anzeigen">📱 QR</button>
                            <button type="button" class="btn btn-outline-secondary btn-edit-totp" data-id="${entry.id}" title="Bearbeiten">✏️</button>
                        </div>
                        <button type="button" class="btn btn-outline-danger btn-sm btn-delete-totp" data-id="${entry.id}" title="Löschen">🗑️</button>
                    </div>
                </div>
            </div>
        `;
        grid.appendChild(col);
        const barEl = col.querySelector(`#totp-bar-${entry.id}`);
        if (barEl) {
            barEl.style.width = pct + '%';
        }
    }
}

async function updateLiveTotpCodesTick() {
    if (!totpMasterKey) return;
    const nowSec = Math.floor(Date.now() / 1000);
    const globalRem = 30 - (nowSec % 30);
    const globalSecEl = document.getElementById('totp-global-seconds');
    if (globalSecEl) globalSecEl.textContent = String(globalRem);

    for (const entry of rawTotpEntries) {
        const dec = decryptedTotpCache.get(Number(entry.id));
        if (!dec || dec.error || !dec.secret) continue;

        const codeEl = document.getElementById(`totp-code-${entry.id}`);
        const barEl = document.getElementById(`totp-bar-${entry.id}`);
        const remEl = document.getElementById(`totp-rem-${entry.id}`);
        if (!codeEl) continue;

        try {
            const res = await TotpEngine.generateTotpCode(dec.secret, {
                digits: dec.digits,
                period: dec.period,
                algorithm: dec.algorithm
            });

            codeEl.textContent = formatCodeForDisplay(res.code);
            codeEl.setAttribute('data-raw-code', res.code);
            const isExpiring = res.remainingSeconds <= 5;
            codeEl.classList.toggle('text-danger', isExpiring);
            codeEl.classList.toggle('text-primary', !isExpiring);

            if (remEl) remEl.textContent = String(res.remainingSeconds);
            if (barEl) {
                const pct = Math.max(0, Math.min(100, Math.round((res.remainingSeconds / res.period) * 100)));
                barEl.style.width = pct + '%';
                barEl.classList.toggle('bg-danger', isExpiring);
                barEl.classList.toggle('bg-primary', !isExpiring);
            }
        } catch (e) {}
    }
}

function startTotpLiveTicker() {
    if (totpTimerInterval) {
        clearInterval(totpTimerInterval);
    }
    updateLiveTotpCodesTick();
    totpTimerInterval = setInterval(updateLiveTotpCodesTick, 1000);
}

function openNewTotpModal() {
    const form = document.getElementById('totp-editor-form');
    if (form) form.reset();
    document.getElementById('edit_totp_id').value = '';
    document.getElementById('totpEditorModalLabel').textContent = '2FA / TOTP-Secret hinzufügen';
}

function openEditTotpModal(entryId) {
    const entry = rawTotpEntries.find(e => Number(e.id) === Number(entryId));
    if (!entry) return;
    const dec = decryptedTotpCache.get(Number(entry.id)) || {};

    document.getElementById('edit_totp_id').value = String(entry.id);
    document.getElementById('totp_otpauth_uri').value = '';
    document.getElementById('totp_issuer').value = entry.issuer || '';
    document.getElementById('totp_account').value = entry.account_name || '';
    document.getElementById('totp_category').value = entry.category || '';
    document.getElementById('totp_secret').value = dec.secret || '';
    document.getElementById('totp_digits').value = String(dec.digits || 6);
    document.getElementById('totp_period').value = String(dec.period || 30);
    document.getElementById('totp_algorithm').value = dec.algorithm || 'SHA-1';
    document.getElementById('totp_notes').value = dec.notes || '';
    document.getElementById('totpEditorModalLabel').textContent = '2FA / TOTP-Secret bearbeiten';

    const modalEl = document.getElementById('totpEditorModal');
    if (modalEl && typeof bootstrap !== 'undefined' && bootstrap.Modal) {
        const modal = bootstrap.Modal.getOrCreateInstance(modalEl);
        modal.show();
    }
}

function handleParseOtpAuthUri() {
    const uriInput = document.getElementById('totp_otpauth_uri');
    if (!uriInput || !uriInput.value.trim()) {
        alert('Bitte fügen Sie eine otpauth:// URI ein.');
        return;
    }
    try {
        const parsed = TotpEngine.parseOtpAuthUri(uriInput.value);
        document.getElementById('totp_issuer').value = parsed.issuer;
        document.getElementById('totp_account').value = parsed.accountName;
        document.getElementById('totp_secret').value = parsed.secret;
        document.getElementById('totp_digits').value = String(parsed.digits);
        document.getElementById('totp_period').value = String(parsed.period);
        document.getElementById('totp_algorithm').value = parsed.algorithm;
    } catch (err) {
        alert('Fehler beim Lesen der otpauth-URI: ' + err.message);
    }
}

async function handleSaveTotpEntry(e) {
    e.preventDefault();
    if (!totpMasterKey) {
        alert('Bitte entsperren Sie zuerst den Authenticator.');
        return;
    }

    const editId = document.getElementById('edit_totp_id').value.trim();
    const issuer = document.getElementById('totp_issuer').value.trim();
    const accountName = document.getElementById('totp_account').value.trim();
    const category = document.getElementById('totp_category').value.trim();
    const rawSecret = document.getElementById('totp_secret').value.replace(/[\s\-=]+/g, '').toUpperCase();
    const digits = parseInt(document.getElementById('totp_digits').value, 10) === 8 ? 8 : 6;
    const period = parseInt(document.getElementById('totp_period').value, 10) === 60 ? 60 : 30;
    const algorithm = document.getElementById('totp_algorithm').value || 'SHA-1';
    const notes = document.getElementById('totp_notes').value.trim();

    try {
        TotpEngine.base32ToBytes(rawSecret);
    } catch (err) {
        alert('Ungültiges Base32-Secret: ' + err.message);
        return;
    }

    if (!totpActiveSalt) {
        totpActiveSalt = rawTotpEntries.length > 0 ? rawTotpEntries[0].salt : VaultCrypto.generateSalt();
    }
    const salt = totpActiveSalt;
    const key = await getTotpKeyForSalt(salt);

    const payload = {
        secret: rawSecret,
        digits: digits,
        period: period,
        algorithm: algorithm,
        notes: notes
    };

    const encrypted = await VaultCrypto.encryptVaultData(key, payload);

    const formData = new FormData();
    formData.append('action', editId ? 'update' : 'add');
    if (editId) {
        formData.append('entry_id', editId);
    }
    formData.append('csrf_token', totpCsrfToken);
    formData.append('issuer', issuer);
    formData.append('account_name', accountName);
    formData.append('category', category);
    formData.append('encrypted_data', encrypted.ciphertext);
    formData.append('iv', encrypted.iv);
    formData.append('salt', salt);
    formData.append('ajax', '1');

    try {
        const response = await fetch('totp_authenticator.php', {
            method: 'POST',
            body: formData,
            headers: { 'X-Requested-With': 'XMLHttpRequest' }
        });
        const res = await response.json();
        if (res.success) {
            if (editId) {
                const idx = rawTotpEntries.findIndex(item => Number(item.id) === Number(editId));
                if (idx !== -1) {
                    rawTotpEntries[idx].issuer = issuer;
                    rawTotpEntries[idx].account_name = accountName;
                    rawTotpEntries[idx].category = category;
                    rawTotpEntries[idx].encrypted_data = encrypted.ciphertext;
                    rawTotpEntries[idx].iv = encrypted.iv;
                    rawTotpEntries[idx].salt = salt;
                }
                decryptedTotpCache.set(Number(editId), payload);
            } else {
                const newId = Number(res.id);
                rawTotpEntries.unshift({
                    id: newId,
                    issuer: issuer,
                    account_name: accountName,
                    category: category,
                    encrypted_data: encrypted.ciphertext,
                    iv: encrypted.iv,
                    salt: salt
                });
                decryptedTotpCache.set(newId, payload);
            }

            const modalEl = document.getElementById('totpEditorModal');
            if (typeof bootstrap !== 'undefined' && bootstrap.Modal) {
                const modal = bootstrap.Modal.getInstance(modalEl);
                if (modal) modal.hide();
            }
            openNewTotpModal();
            await renderTotpGrid();
        } else {
            alert('Fehler beim Speichern: ' + (res.error || 'Unbekannter Fehler'));
        }
    } catch (err) {
        alert('Netzwerkfehler beim Speichern.');
    }
}

async function deleteTotpEntry(entryId) {
    if (!confirm('Möchten Sie dieses 2FA-Secret wirklich unwiderruflich löschen?')) return;

    const formData = new FormData();
    formData.append('action', 'delete');
    formData.append('csrf_token', totpCsrfToken);
    formData.append('entry_id', entryId);
    formData.append('ajax', '1');

    try {
        const response = await fetch('totp_authenticator.php', {
            method: 'POST',
            body: formData,
            headers: { 'X-Requested-With': 'XMLHttpRequest' }
        });
        const res = await response.json();
        if (res.success) {
            const idx = rawTotpEntries.findIndex(item => Number(item.id) === Number(entryId));
            if (idx !== -1) rawTotpEntries.splice(idx, 1);
            decryptedTotpCache.delete(Number(entryId));
            await renderTotpGrid();
        } else {
            alert('Fehler beim Löschen: ' + (res.error || 'Unbekannter Fehler'));
        }
    } catch (err) {
        alert('Netzwerkfehler beim Löschen.');
    }
}

async function showTotpQrCode(entryId) {
    const entry = rawTotpEntries.find(item => Number(item.id) === Number(entryId));
    if (!entry) return;
    const dec = decryptedTotpCache.get(Number(entry.id));
    if (!dec || !dec.secret) return;

    const otpauthUri = TotpEngine.buildOtpAuthUri({
        issuer: entry.issuer,
        accountName: entry.account_name,
        secret: dec.secret,
        digits: dec.digits,
        period: dec.period,
        algorithm: dec.algorithm
    });

    const formData = new FormData();
    formData.append('action', 'generate_qr');
    formData.append('csrf_token', totpCsrfToken);
    formData.append('otpauth_uri', otpauthUri);
    formData.append('ajax', '1');

    try {
        const response = await fetch('totp_authenticator.php', {
            method: 'POST',
            body: formData,
            headers: { 'X-Requested-With': 'XMLHttpRequest' }
        });
        const res = await response.json();
        if (res.success && res.qr_data_uri) {
            document.getElementById('totpQrAccountLabel').textContent = (entry.issuer ? entry.issuer + ' – ' : '') + entry.account_name;
            document.getElementById('totpQrImg').src = res.qr_data_uri;
            const modalEl = document.getElementById('totpQrModal');
            if (modalEl && typeof bootstrap !== 'undefined' && bootstrap.Modal) {
                const modal = bootstrap.Modal.getOrCreateInstance(modalEl);
                modal.show();
            }
        }
    } catch (err) {
        alert('QR-Code konnte nicht geladen werden.');
    }
}

function initTotpAuthenticatorUI() {
    const dataEl = document.getElementById('totp-data');
    if (dataEl) {
        try {
            const rawJson = dataEl.dataset && dataEl.dataset.json ? dataEl.dataset.json : (dataEl.getAttribute('data-json') || dataEl.textContent);
            const parsed = JSON.parse(rawJson);
            totpCsrfToken = parsed.csrfToken || '';
            rawTotpEntries = parsed.entries || [];
        } catch (e) {
            console.error('Failed to parse totp data:', e);
        }
    }

    const unlockForm = document.getElementById('totp-master-password-form');
    if (unlockForm) unlockForm.addEventListener('submit', handleUnlockTotp);

    const lockBtn = document.getElementById('lock-totp-btn');
    if (lockBtn) lockBtn.addEventListener('click', lockTotpAuthenticator);

    const newBtn = document.getElementById('btn-new-totp');
    if (newBtn) newBtn.addEventListener('click', openNewTotpModal);

    const parseUriBtn = document.getElementById('btn-parse-otpauth');
    if (parseUriBtn) parseUriBtn.addEventListener('click', handleParseOtpAuthUri);

    const editorForm = document.getElementById('totp-editor-form');
    if (editorForm) editorForm.addEventListener('submit', handleSaveTotpEntry);

    const searchInput = document.getElementById('totp-search-input');
    if (searchInput) {
        searchInput.addEventListener('input', function () {
            totpSearchQuery = this.value || '';
            renderTotpGrid();
        });
    }

    const grid = document.getElementById('totp-grid');
    if (grid) {
        grid.addEventListener('click', function (e) {
            const copyBtn = e.target.closest('.btn-copy-totp');
            if (copyBtn) {
                const id = copyBtn.dataset.id;
                const codeEl = document.getElementById(`totp-code-${id}`);
                const rawCode = codeEl ? codeEl.getAttribute('data-raw-code') : '';
                if (rawCode && navigator.clipboard) {
                    navigator.clipboard.writeText(rawCode).then(() => {
                        alert('2FA-Code (' + rawCode + ') in die Zwischenablage kopiert!');
                    });
                }
                return;
            }

            const qrBtn = e.target.closest('.btn-qr-totp');
            if (qrBtn) {
                showTotpQrCode(qrBtn.dataset.id);
                return;
            }

            const editBtn = e.target.closest('.btn-edit-totp');
            if (editBtn) {
                openEditTotpModal(editBtn.dataset.id);
                return;
            }

            const delBtn = e.target.closest('.btn-delete-totp');
            if (delBtn) {
                deleteTotpEntry(delBtn.dataset.id);
            }
        });
    }
}

if (typeof window !== 'undefined') {
    window.TotpEngine = TotpEngine;
}

if (typeof document !== 'undefined') {
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initTotpAuthenticatorUI);
    } else {
        initTotpAuthenticatorUI();
    }
}

if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        TotpEngine,
        initTotpAuthenticatorUI
    };
}
