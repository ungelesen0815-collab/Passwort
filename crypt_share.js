/**
 * Crypt Share - Client-Side Encryption
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

async function readFileAsArrayBuffer(file) {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => resolve(reader.result);
        reader.onerror = error => reject(error);
        reader.readAsArrayBuffer(file);
    });
}

document.addEventListener('DOMContentLoaded', () => {
    const form = document.getElementById('shareForm');
    if (!form) return;

    form.addEventListener('submit', async (e) => {
        e.preventDefault();

        const fileInput = document.getElementById('shareFile');
        const file = fileInput.files[0];
        if (!file) return;

        const btn = document.getElementById('btnShare');
        const originalBtnText = btn.innerText;
        btn.innerText = 'Verschlüssele...';
        btn.disabled = true;

        try {
            // Read file
            const fileData = await readFileAsArrayBuffer(file);

            // Encode file data as base64 so we can treat it as a string for VaultCrypto
            // Or better yet, we should encrypt the ArrayBuffer directly.
            // Let's modify VaultCrypto's encrypt method to accept ArrayBuffer or string

            // Generate OTP and Salt
            const otp = generateOneTimePassword(16);
            const salt = VaultCrypto.generateSalt();

            // Derive Key
            const key = await VaultCrypto.deriveMasterKey(otp, salt);

            // We'll base64 encode the file first to reuse the existing VaultCrypto logic
            // which expects string/JSON
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
