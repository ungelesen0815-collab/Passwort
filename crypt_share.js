/**
 * Crypt Share - Client-Side Encryption, Optional PIN/Password Protection, Max Views & QR Code UI
 */

function generateOneTimePassword(length = 16) {
    const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+";
    let retVal = "";
    const randomValues = new Uint32Array(length);
    window.crypto.getRandomValues(randomValues);
    for (let i = 0, n = charset.length; i < length; ++i) {
        retVal += charset.charAt(randomValues[i] % n);
    }
    return retVal;
}

function generateNumericPin(length = 6) {
    const digits = "0123456789";
    let pin = "";
    const randomValues = new Uint32Array(length);
    window.crypto.getRandomValues(randomValues);
    for (let i = 0; i < length; ++i) {
        pin += digits.charAt(randomValues[i] % 10);
    }
    return pin;
}

async function readFileAsArrayBuffer(file) {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => resolve(reader.result);
        reader.onerror = error => reject(error);
        reader.readAsArrayBuffer(file);
    });
}

const MAX_SHARE_FILE_BYTES = 10 * 1024 * 1024; // 10 MB

document.addEventListener('DOMContentLoaded', () => {
    const copyInfoBtn = document.getElementById('btnCopyShareInfo');
    if (copyInfoBtn) {
        copyInfoBtn.addEventListener('click', copyShareInfo);
    }

    const copyLinkOnlyBtn = document.getElementById('btnCopyShareLinkOnly');
    if (copyLinkOnlyBtn) {
        copyLinkOnlyBtn.addEventListener('click', () => {
            const link = document.getElementById('shareLinkResult')?.href || '';
            if (link && navigator.clipboard) {
                navigator.clipboard.writeText(link).then(() => {
                    alert('Freigabe-Link in die Zwischenablage kopiert.');
                });
            }
        });
    }

    const togglePinBtn = document.getElementById('btnToggleSharePin');
    if (togglePinBtn) {
        togglePinBtn.addEventListener('click', () => {
            const pinInput = document.getElementById('shareAccessPin');
            if (pinInput) {
                pinInput.type = pinInput.type === 'password' ? 'text' : 'password';
            }
        });
    }

    const genPinBtn = document.getElementById('btnGenerateSharePin');
    if (genPinBtn) {
        genPinBtn.addEventListener('click', () => {
            const pinInput = document.getElementById('shareAccessPin');
            if (pinInput) {
                pinInput.value = generateNumericPin(6);
                pinInput.type = 'text';
            }
        });
    }

    document.querySelectorAll('.btn-copy-share-link').forEach((btn) => {
        btn.addEventListener('click', () => {
            const url = btn.getAttribute('data-url');
            if (url && navigator.clipboard) {
                navigator.clipboard.writeText(url).then(() => {
                    alert('Link in die Zwischenablage kopiert.');
                });
            }
        });
    });

    document.querySelectorAll('.btn-show-share-qr').forEach((btn) => {
        btn.addEventListener('click', () => {
            const qrUri = btn.getAttribute('data-qr') || '';
            const filename = btn.getAttribute('data-filename') || '';
            const imgEl = document.getElementById('shareQrModalImg');
            const nameEl = document.getElementById('shareQrModalFilename');
            if (imgEl) imgEl.src = qrUri;
            if (nameEl) nameEl.textContent = filename;

            const modalEl = document.getElementById('shareQrModal');
            if (modalEl && typeof bootstrap !== 'undefined' && bootstrap.Modal) {
                const modal = bootstrap.Modal.getOrCreateInstance(modalEl);
                modal.show();
            }
        });
    });

    document.querySelectorAll('.delete-share-form').forEach((delForm) => {
        delForm.addEventListener('submit', (e) => {
            if (!confirm('Möchten Sie diese Freigabe wirklich löschen?')) {
                e.preventDefault();
            }
        });
    });

    const form = document.getElementById('shareForm');
    if (!form) return;

    form.addEventListener('submit', async (e) => {
        e.preventDefault();

        const fileInput = document.getElementById('shareFile');
        const file = fileInput.files[0];
        if (!file) return;

        if (file.size > MAX_SHARE_FILE_BYTES) {
            alert('Die Datei ist zu groß (maximal 10 MB erlaubt).');
            return;
        }

        const maxViewsSelect = document.getElementById('shareMaxViews');
        const maxViews = maxViewsSelect ? maxViewsSelect.value : '1';
        const accessPinInput = document.getElementById('shareAccessPin');
        const accessPin = accessPinInput ? accessPinInput.value.trim() : '';

        const btn = document.getElementById('btnShare');
        const originalBtnText = btn.innerText;
        btn.innerText = 'Verschlüssele...';
        btn.disabled = true;

        try {
            // Read file
            const fileData = await readFileAsArrayBuffer(file);

            // Generate OTP and Salt
            const otp = generateOneTimePassword(16);
            const salt = VaultCrypto.generateSalt();

            // Derive Key
            const key = await VaultCrypto.deriveMasterKey(otp, salt);

            const fileBase64 = VaultCrypto.bufferToBase64(fileData);

            const payload = JSON.stringify({
                name: file.name,
                type: file.type,
                data: fileBase64
            });

            // Encrypt
            const encrypted = await VaultCrypto.encryptVaultData(key, payload);

            // Upload
            const csrfToken = document.getElementById('csrf_token').value;
            const formData = new FormData();
            formData.append('action', 'create_share');
            formData.append('csrf_token', csrfToken);
            formData.append('file_name', file.name);
            formData.append('encrypted_data', encrypted.ciphertext);
            formData.append('iv', encrypted.iv);
            formData.append('salt', salt);
            formData.append('max_views', maxViews);
            formData.append('access_pin', accessPin);
            formData.append('ajax', '1');

            btn.innerText = 'Lade hoch...';

            const response = await fetch('crypt_share.php', {
                method: 'POST',
                body: formData,
                headers: { 'X-Requested-With': 'XMLHttpRequest' }
            });

            const res = await response.json();

            if (res.success) {
                document.getElementById('shareResult').classList.remove('d-none');
                const linkEl = document.getElementById('shareLinkResult');
                linkEl.href = res.share_url;
                linkEl.innerText = res.share_url;
                document.getElementById('sharePasswordResult').innerText = otp;

                const maxViewsLabelEl = document.getElementById('shareMaxViewsResult');
                if (maxViewsLabelEl) {
                    const mv = Number(res.max_views ?? maxViews);
                    maxViewsLabelEl.textContent = mv > 0 ? `max. ${mv}x abrufbar` : 'unbegrenzte Aufrufe für 24h';
                }

                const pinRow = document.getElementById('sharePinResultRow');
                const pinCodeEl = document.getElementById('sharePinResult');
                if (accessPin !== '' && pinRow && pinCodeEl) {
                    pinCodeEl.textContent = accessPin;
                    pinRow.classList.remove('d-none');
                } else if (pinRow && pinCodeEl) {
                    pinCodeEl.textContent = '';
                    pinRow.classList.add('d-none');
                }

                const qrContainer = document.getElementById('shareQrContainer');
                const qrImage = document.getElementById('shareQrImage');
                if (res.qr_data_uri && qrImage && qrContainer) {
                    qrImage.src = res.qr_data_uri;
                    qrContainer.classList.remove('d-none');
                } else if (qrContainer) {
                    qrContainer.classList.add('d-none');
                }

                form.reset();
            } else {
                alert("Fehler: " + (res.error || "Unbekannter Fehler beim Hochladen."));
            }

        } catch (err) {
            console.error(err);
            alert("Ein Fehler ist bei der Verschlüsselung aufgetreten.");
        } finally {
            btn.innerText = originalBtnText;
            btn.disabled = false;
        }
    });
});

function copyShareInfo() {
    const link = document.getElementById('shareLinkResult').href;
    const pwd = document.getElementById('sharePasswordResult').innerText;
    const pinEl = document.getElementById('sharePinResult');
    const pin = pinEl ? pinEl.innerText.trim() : '';
    const maxViewsText = document.getElementById('shareMaxViewsResult')?.textContent || '24 Stunden gültig';

    let text = `Hier ist eine sicher geteilte Datei für dich:\n\nLink: ${link}\nEinmal-Passwort: ${pwd}`;
    if (pin !== '') {
        text += `\nZugriffs-PIN: ${pin}`;
    }
    text += `\n\nHinweis: Dieser Link ist 24 Stunden gültig (${maxViewsText}).`;

    navigator.clipboard.writeText(text).then(() => {
        alert('Link und Zugangsdaten in die Zwischenablage kopiert.');
    });
}
