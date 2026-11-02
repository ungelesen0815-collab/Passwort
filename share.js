/**
 * Crypt Share - Client-Side Decryption
 */

function downloadBlob(blob, filename) {
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(() => URL.revokeObjectURL(url), 100);
}

document.addEventListener('DOMContentLoaded', () => {
    const form = document.getElementById('decryptForm');
    if (!form) return;

    form.addEventListener('submit', async (e) => {
        e.preventDefault();

        const errorDiv = document.getElementById('errorMsg');
        errorDiv.classList.add('d-none');

        const otp = document.getElementById('otp').value;
        if (!otp) return;

        const btn = document.getElementById('btnDecrypt');
        const originalBtnText = btn.innerText;
        btn.innerText = 'Entschlüssele...';
        btn.disabled = true;

        try {
            const encryptedData = document.getElementById('encrypted_data').value;
            const iv = document.getElementById('iv').value;
            const salt = document.getElementById('salt').value;

            // Derive Key
            const key = await VaultCrypto.deriveMasterKey(otp, salt);

            // Decrypt
            const decryptedString = await VaultCrypto.decryptVaultData(key, encryptedData, iv);

            // Parse Payload
            const payload = JSON.parse(decryptedString);

            if (!payload || !payload.data || !payload.name) {
                throw new Error("Ungültiges Dateiformat.");
            }

            // Convert base64 back to Uint8Array
            const fileBytes = VaultCrypto.base64ToBuffer(payload.data);

            // Create Blob and trigger download
            const blob = new Blob([fileBytes], { type: payload.type || 'application/octet-stream' });
            downloadBlob(blob, payload.name);

            // Clear password field for safety
            document.getElementById('otp').value = '';

        } catch (err) {
            console.error(err);
            errorDiv.innerText = "Fehler bei der Entschlüsselung. Falsches Passwort oder beschädigte Daten.";
            errorDiv.classList.remove('d-none');
        } finally {
            btn.innerText = originalBtnText;
            btn.disabled = false;
        }
    });
});
