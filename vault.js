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

if (typeof module !== 'undefined' && module.exports) {
    module.exports = VaultCrypto;
}
