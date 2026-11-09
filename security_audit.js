/**
 * Passwort-Check & Datenleck-Prüfer (Security Audit / HIBP k-Anonymity Breach Check)
 * - Computes SHA-1 locally in the browser using Web Crypto API
 * - Sends ONLY the first 5 hex characters (k-Anonymity prefix) to the backend proxy
 * - Evaluates password strength/entropy and password reuse across a vault locally
 */

const SecurityAuditEngine = {
    rangeCache: new Map(),

    /**
     * Computes uppercase 40-char hexadecimal SHA-1 hash of a string using Web Crypto
     */
    async sha1Hex(text) {
        const encoder = new TextEncoder();
        const data = encoder.encode(String(text || ''));
        const hashBuffer = await window.crypto.subtle.digest('SHA-1', data);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        return hashArray.map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
    },

    /**
     * Parses the HIBP range response body (lines of "SUFFIX:COUNT") and returns breach count for a 35-char suffix
     */
    findSuffixCountInRangeData(rangeText, suffix) {
        const target = String(suffix || '').toUpperCase().trim();
        if (!target || !rangeText) return 0;

        const lines = String(rangeText).split(/\r?\n/);
        for (let i = 0; i < lines.length; i++) {
            const line = lines[i].trim();
            if (!line) continue;
            const parts = line.split(':');
            if (parts.length >= 2 && parts[0].trim().toUpperCase() === target) {
                const count = parseInt(parts[1].trim(), 10);
                // HIBP padded responses have count 0
                return isNaN(count) ? 0 : count;
            }
        }
        return 0;
    },

    /**
     * Evaluates password strength and entropy in bits
     */
    evaluatePasswordStrength(password) {
        const pwd = String(password || '');
        const length = pwd.length;
        if (length === 0) {
            return { score: 0, entropyBits: 0, label: 'Leer', badgeClass: 'bg-secondary', isWeak: true };
        }

        let poolSize = 0;
        if (/[a-z]/.test(pwd)) poolSize += 26;
        if (/[A-Z]/.test(pwd)) poolSize += 26;
        if (/[0-9]/.test(pwd)) poolSize += 10;
        if (/[^a-zA-Z0-9]/.test(pwd)) poolSize += 32;

        const uniqueChars = new Set(pwd.split('')).size;
        const rawEntropy = length * Math.log2(Math.max(poolSize, 2));
        // Penalize heavily repeated characters
        const repetitionFactor = Math.min(1, (uniqueChars / Math.max(length, 1)) + 0.25);
        const entropyBits = Math.round(rawEntropy * repetitionFactor);

        if (length < 8 || entropyBits < 40) {
            return { score: 1, entropyBits, label: 'Schwach', badgeClass: 'bg-danger', isWeak: true };
        }
        if (length < 12 || entropyBits < 60) {
            return { score: 2, entropyBits, label: 'Mittel', badgeClass: 'bg-warning text-dark', isWeak: false };
        }
        if (entropyBits < 80) {
            return { score: 3, entropyBits, label: 'Stark', badgeClass: 'bg-success', isWeak: false };
        }
        return { score: 4, entropyBits, label: 'Sehr stark', badgeClass: 'bg-success', isWeak: false };
    },

    /**
     * Queries HIBP via k-Anonymity (only 5-char SHA-1 prefix leaves the browser)
     */
    async checkPasswordBreachKAnonymity(password, csrfToken) {
        if (!password) {
            return { pwnedCount: 0, sha1Prefix: '-----' };
        }

        const fullHash = await this.sha1Hex(password);
        const prefix = fullHash.slice(0, 5);
        const suffix = fullHash.slice(5);

        let rangeData = this.rangeCache.get(prefix);
        if (!rangeData) {
            const formData = new FormData();
            formData.append('action', 'hibp_range');
            formData.append('csrf_token', csrfToken);
            formData.append('prefix', prefix);
            formData.append('ajax', '1');

            const response = await fetch('security_audit.php', {
                method: 'POST',
                body: formData,
                headers: { 'X-Requested-With': 'XMLHttpRequest' }
            });
            const res = await response.json();
            if (!res.success || typeof res.range_data !== 'string') {
                throw new Error(res.error || 'HIBP-Abfrage fehlgeschlagen.');
            }
            rangeData = res.range_data;
            this.rangeCache.set(prefix, rangeData);
        }

        const pwnedCount = this.findSuffixCountInRangeData(rangeData, suffix);
        return {
            pwnedCount: pwnedCount,
            sha1Prefix: prefix
        };
    }
};

var auditCsrfToken = '';

function escapeAuditHtml(str) {
    if (!str) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

async function handleSinglePasswordAudit(e) {
    e.preventDefault();
    const pwdInput = document.getElementById('single-audit-password');
    const resultDiv = document.getElementById('single-audit-result');
    const btn = document.getElementById('btn-run-single-audit');
    if (!pwdInput || !resultDiv) return;

    const password = pwdInput.value;
    if (!password) return;

    btn.disabled = true;
    resultDiv.classList.remove('d-none');
    resultDiv.innerHTML = '<div class="text-muted small">Berechne lokalen SHA-1-Hash und prüfe k-Anonymity-Präfix...</div>';

    try {
        const strength = SecurityAuditEngine.evaluatePasswordStrength(password);
        const breach = await SecurityAuditEngine.checkPasswordBreachKAnonymity(password, auditCsrfToken);

        const isPwned = breach.pwnedCount > 0;
        const alertClass = isPwned ? 'alert-danger' : (strength.isWeak ? 'alert-warning' : 'alert-success');

        resultDiv.innerHTML = `
            <div class="alert ${alertClass} mb-0">
                <div class="d-flex justify-content-between align-items-center mb-2">
                    <strong>Ergebnis der Sicherheitsprüfung</strong>
                    <span class="badge ${strength.badgeClass}">${escapeAuditHtml(strength.label)} (~${strength.entropyBits} Bit)</span>
                </div>
                <hr class="my-2">
                ${isPwned ? `
                    <div class="fw-bold text-danger mb-1">
                        🚨 WARNUNG: Dieses Passwort wurde <u>${breach.pwnedCount.toLocaleString('de-DE')} Mal</u> in bekannten Datenlecks gefunden!
                    </div>
                    <div class="small">Sie sollten dieses Passwort nirgendwo mehr verwenden und umgehend durch ein frisch generiertes Passwort ersetzen.</div>
                ` : `
                    <div class="fw-bold text-success mb-1">
                        ✅ Keine Treffer in der HaveIBeenPwned-Datenbank!
                    </div>
                    <div class="small">Dieses Passwort taucht in keinem der über 800 Millionen bekannten geleakten Passwörter auf.</div>
                `}
                <div class="small text-muted mt-2">
                    🔒 Geprüft via k-Anonymity (übertragenes SHA-1-Präfix: <code>${escapeAuditHtml(breach.sha1Prefix)}*****</code>)
                </div>
            </div>
        `;
    } catch (err) {
        resultDiv.innerHTML = `<div class="alert alert-danger mb-0">Fehler bei der Prüfung: ${escapeAuditHtml(err.message)}</div>`;
    } finally {
        btn.disabled = false;
    }
}

async function handleVaultAudit(e) {
    e.preventDefault();
    const vaultSelect = document.getElementById('audit-vault-select');
    const masterPwdInput = document.getElementById('audit-vault-master-pwd');
    const summaryDiv = document.getElementById('vault-audit-summary');
    const detailsCard = document.getElementById('vault-audit-details-card');
    const tbody = document.getElementById('vault-audit-tbody');
    const btn = document.getElementById('btn-run-vault-audit');
    const openVaultLink = document.getElementById('audit-open-vault-link');

    if (!vaultSelect || !masterPwdInput || !summaryDiv || !tbody) return;

    const selectedVaultId = vaultSelect.value;
    const masterPassword = masterPwdInput.value;
    if (!selectedVaultId || !masterPassword) return;

    if (openVaultLink) {
        openVaultLink.href = 'vault.php?id=' + encodeURIComponent(selectedVaultId);
    }

    btn.disabled = true;
    summaryDiv.classList.remove('d-none');
    summaryDiv.innerHTML = '<div class="alert alert-secondary mb-0">Lade verschlüsselte Tresor-Einträge und entschlüssele lokal im Browser...</div>';
    detailsCard.classList.add('d-none');

    try {
        const formData = new FormData();
        formData.append('action', 'get_vault_items');
        formData.append('csrf_token', auditCsrfToken);
        formData.append('vault_id', selectedVaultId);
        formData.append('ajax', '1');

        const response = await fetch('security_audit.php', {
            method: 'POST',
            body: formData,
            headers: { 'X-Requested-With': 'XMLHttpRequest' }
        });
        const res = await response.json();
        if (!res.success) {
            throw new Error(res.error || 'Tresor konnte nicht geladen werden.');
        }

        const encryptedItems = res.items || [];
        if (encryptedItems.length === 0) {
            summaryDiv.innerHTML = '<div class="alert alert-info mb-0">In diesem Tresor befinden sich noch keine Passwort-Einträge.</div>';
            return;
        }

        // Derive keys per salt & decrypt locally
        const keysBySalt = new Map();
        const decryptedEntries = [];

        for (const item of encryptedItems) {
            let key = keysBySalt.get(item.salt);
            if (!key) {
                key = await VaultCrypto.deriveMasterKey(masterPassword, item.salt);
                keysBySalt.set(item.salt, key);
            }
            try {
                const jsonStr = await VaultCrypto.decryptVaultData(key, item.encrypted_data, item.iv);
                const payload = JSON.parse(jsonStr);
                decryptedEntries.push({
                    id: item.id,
                    title: item.title,
                    category: item.category || payload.category || '',
                    username: payload.username || '-',
                    secret: payload.secret || ''
                });
            } catch (decErr) {
                throw new Error('Entschlüsselung fehlgeschlagen! Das eingegebene Master-Passwort für diesen Tresor ist falsch.');
            }
        }

        // Count password reuse
        const passwordFrequency = new Map();
        for (const entry of decryptedEntries) {
            if (!entry.secret) continue;
            passwordFrequency.set(entry.secret, (passwordFrequency.get(entry.secret) || 0) + 1);
        }

        summaryDiv.innerHTML = `<div class="alert alert-secondary mb-0">Prüfe ${decryptedEntries.length} Passwörter per k-Anonymity gegen HaveIBeenPwned...</div>`;

        let breachedCount = 0;
        let reusedCount = 0;
        let weakCount = 0;
        const rowsHtml = [];

        for (const entry of decryptedEntries) {
            const strength = SecurityAuditEngine.evaluatePasswordStrength(entry.secret);
            const reuseTimes = entry.secret ? (passwordFrequency.get(entry.secret) || 1) : 0;
            const isReused = reuseTimes > 1;

            let pwnedCount = 0;
            let hibpError = false;
            try {
                const breachRes = await SecurityAuditEngine.checkPasswordBreachKAnonymity(entry.secret, auditCsrfToken);
                pwnedCount = breachRes.pwnedCount;
            } catch (err) {
                hibpError = true;
            }

            if (pwnedCount > 0) breachedCount++;
            if (isReused) reusedCount++;
            if (strength.isWeak) weakCount++;

            const catBadge = entry.category ? `<span class="badge bg-secondary ms-1">${escapeAuditHtml(entry.category)}</span>` : '';
            const reuseBadge = isReused
                ? `<span class="badge bg-warning text-dark">⚠️ ${reuseTimes}x verwendet</span>`
                : `<span class="badge bg-light text-success border">✓ Einzigartig</span>`;

            let hibpBadge = '';
            if (hibpError) {
                hibpBadge = `<span class="badge bg-secondary">API nicht erreichbar</span>`;
            } else if (pwnedCount > 0) {
                hibpBadge = `<span class="badge bg-danger">🚨 ${pwnedCount.toLocaleString('de-DE')}x geleakt!</span>`;
            } else {
                hibpBadge = `<span class="badge bg-success">✅ Sicher (0 Treffer)</span>`;
            }

            rowsHtml.push(`
                <tr class="${pwnedCount > 0 ? 'table-danger' : (isReused || strength.isWeak ? 'table-warning' : '')}">
                    <td><strong>${escapeAuditHtml(entry.title)}</strong>${catBadge}</td>
                    <td>${escapeAuditHtml(entry.username)}</td>
                    <td><span class="badge ${strength.badgeClass}">${escapeAuditHtml(strength.label)} (~${strength.entropyBits} Bit)</span></td>
                    <td>${reuseBadge}</td>
                    <td>${hibpBadge}</td>
                </tr>
            `);
        }

        const total = decryptedEntries.length;
        const healthyCount = decryptedEntries.filter(e => {
            const st = SecurityAuditEngine.evaluatePasswordStrength(e.secret);
            const r = (passwordFrequency.get(e.secret) || 1) > 1;
            return !st.isWeak && !r;
        }).length;

        summaryDiv.innerHTML = `
            <div class="row g-2 text-center">
                <div class="col-6 col-md-3">
                    <div class="p-2 border rounded bg-light">
                        <div class="fs-4 fw-bold">${total}</div>
                        <div class="small text-muted">Geprüfte Logins</div>
                    </div>
                </div>
                <div class="col-6 col-md-3">
                    <div class="p-2 border rounded ${breachedCount > 0 ? 'bg-danger text-white' : 'bg-success text-white'}">
                        <div class="fs-4 fw-bold">${breachedCount}</div>
                        <div class="small">In Datenlecks (HIBP)</div>
                    </div>
                </div>
                <div class="col-6 col-md-3">
                    <div class="p-2 border rounded ${reusedCount > 0 ? 'bg-warning text-dark' : 'bg-light'}">
                        <div class="fs-4 fw-bold">${reusedCount}</div>
                        <div class="small">Mehrfach genutzt</div>
                    </div>
                </div>
                <div class="col-6 col-md-3">
                    <div class="p-2 border rounded ${weakCount > 0 ? 'bg-warning text-dark' : 'bg-light'}">
                        <div class="fs-4 fw-bold">${weakCount}</div>
                        <div class="small">Schwache Passwörter</div>
                    </div>
                </div>
            </div>
        `;

        tbody.innerHTML = rowsHtml.join('');
        detailsCard.classList.remove('d-none');
        masterPwdInput.value = '';
    } catch (err) {
        summaryDiv.innerHTML = `<div class="alert alert-danger mb-0">${escapeAuditHtml(err.message)}</div>`;
    } finally {
        btn.disabled = false;
    }
}

function initSecurityAuditUI() {
    const dataEl = document.getElementById('security-audit-data');
    if (dataEl) {
        try {
            const rawJson = dataEl.dataset && dataEl.dataset.json ? dataEl.dataset.json : (dataEl.getAttribute('data-json') || dataEl.textContent);
            const parsed = JSON.parse(rawJson);
            auditCsrfToken = parsed.csrfToken || '';
        } catch (e) {
            console.error('Failed to parse security audit data:', e);
        }
    }

    const toggleSingleBtn = document.getElementById('btn-toggle-single-audit-pwd');
    if (toggleSingleBtn) {
        toggleSingleBtn.addEventListener('click', function () {
            const input = document.getElementById('single-audit-password');
            if (input) {
                input.type = input.type === 'password' ? 'text' : 'password';
            }
        });
    }

    const singleForm = document.getElementById('single-audit-form');
    if (singleForm) singleForm.addEventListener('submit', handleSinglePasswordAudit);

    const vaultForm = document.getElementById('vault-audit-form');
    if (vaultForm) vaultForm.addEventListener('submit', handleVaultAudit);
}

if (typeof window !== 'undefined') {
    window.SecurityAuditEngine = SecurityAuditEngine;
}

if (typeof document !== 'undefined') {
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initSecurityAuditUI);
    } else {
        initSecurityAuditUI();
    }
}

if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        SecurityAuditEngine,
        initSecurityAuditUI
    };
}
