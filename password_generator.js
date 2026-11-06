const USERNAME_ADJECTIVES = [
    'silent', 'swift', 'cyber', 'lunar', 'solar', 'amber', 'crimson', 'cobalt',
    'emerald', 'frosty', 'golden', 'hidden', 'iron', 'misty', 'neon', 'noble',
    'quantum', 'rapid', 'shadow', 'silver', 'stellar', 'stormy', 'velvet', 'vivid'
];

const USERNAME_NOUNS = [
    'falcon', 'phoenix', 'tiger', 'orca', 'wolf', 'lynx', 'raven', 'viper',
    'comet', 'nebula', 'pulsar', 'vertex', 'cipher', 'vector', 'shield', 'anchor',
    'beacon', 'forge', 'harbor', 'matrix', 'nexus', 'prism', 'quartz', 'zephyr'
];

function secureRandomInt(max) {
    if (typeof window !== 'undefined' && window.crypto && window.crypto.getRandomValues) {
        const arr = new Uint32Array(1);
        window.crypto.getRandomValues(arr);
        return arr[0] % max;
    }
    return Math.floor(Math.random() * max);
}

function syncLength(val) {
    const valEl = document.getElementById('lengthVal');
    const rangeEl = document.getElementById('lengthRange');
    const inputEl = document.getElementById('lengthInput');
    if (valEl) valEl.textContent = val;
    if (rangeEl) rangeEl.value = val;
    if (inputEl) inputEl.value = val;
}

function copyPassword() {
    const input = document.getElementById('passwordResult');
    if (!input) return;

    input.select();
    input.setSelectionRange(0, 99999);

    if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(input.value).then(showFeedback);
    } else {
        document.execCommand('copy');
        showFeedback();
    }
}

function showFeedback() {
    const feedback = document.getElementById('copyFeedback');
    if (feedback) {
        feedback.classList.remove('d-none');
        setTimeout(() => feedback.classList.add('d-none'), 2500);
    }
}

function copyUsername() {
    const input = document.getElementById('usernameResult');
    if (!input) return;

    input.select();
    input.setSelectionRange(0, 99999);

    const showUserFeedback = () => {
        const feedback = document.getElementById('copyUsernameFeedback');
        if (feedback) {
            feedback.classList.remove('d-none');
            setTimeout(() => feedback.classList.add('d-none'), 2500);
        }
    };

    if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(input.value).then(showUserFeedback);
    } else {
        document.execCommand('copy');
        showUserFeedback();
    }
}

function toggleUsernameMode() {
    const modeSelect = document.getElementById('usernameMode');
    const randomOpts = document.getElementById('randomUsernameOptions');
    const aliasOpts = document.getElementById('emailAliasOptions');
    if (!modeSelect || !randomOpts || !aliasOpts) return;

    const isAlias = modeSelect.value === 'alias';
    randomOpts.classList.toggle('d-none', isAlias);
    aliasOpts.classList.toggle('d-none', !isAlias);
}

function generateClientSideUsername() {
    const modeSelect = document.getElementById('usernameMode');
    const mode = modeSelect ? modeSelect.value : 'random';

    if (mode === 'alias') {
        const baseEmailEl = document.getElementById('baseEmail');
        const aliasTagEl = document.getElementById('aliasTag');
        const baseEmail = baseEmailEl ? baseEmailEl.value.trim() : '';
        const aliasTag = aliasTagEl ? aliasTagEl.value.trim().toLowerCase().replace(/[^a-z0-9_-]/g, '') : '';

        if (!baseEmail || !baseEmail.includes('@')) {
            if (baseEmailEl) baseEmailEl.focus();
            alert('Bitte geben Sie zuerst eine gültige Basis-E-Mail-Adresse (z. B. name@domain.de) ein.');
            return null;
        }

        const parts = baseEmail.split('@');
        const localPart = parts[0].split('+')[0];
        const domainPart = parts.slice(1).join('@');
        const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
        let token = '';
        for (let i = 0; i < 6; i++) {
            token += chars.charAt(secureRandomInt(chars.length));
        }

        const plusPart = aliasTag ? `${aliasTag}-${token}` : token;
        return `${localPart}+${plusPart}@${domainPart}`;
    }

    const sepEl = document.getElementById('usernameSeparator');
    const numEl = document.getElementById('usernameNumbers');
    const capEl = document.getElementById('usernameCapitalize');

    const sep = sepEl ? sepEl.value : '-';
    const includeNumbers = numEl ? numEl.checked : true;
    const capitalize = capEl ? capEl.checked : false;

    let adj = USERNAME_ADJECTIVES[secureRandomInt(USERNAME_ADJECTIVES.length)];
    let noun = USERNAME_NOUNS[secureRandomInt(USERNAME_NOUNS.length)];

    if (capitalize) {
        adj = adj.charAt(0).toUpperCase() + adj.slice(1);
        noun = noun.charAt(0).toUpperCase() + noun.slice(1);
    }

    let result = `${adj}${sep}${noun}`;
    if (includeNumbers) {
        const num = 100 + secureRandomInt(9900);
        result += `${sep}${num}`;
    }
    return result;
}

function syncTransferModalFields() {
    const pwdResult = document.getElementById('passwordResult');
    const userResult = document.getElementById('usernameResult');
    const aliasTag = document.getElementById('aliasTag');

    const transferPwd = document.getElementById('transferPassword');
    const transferUser = document.getElementById('transferUsername');
    const transferTitle = document.getElementById('transferTitle');

    if (transferPwd && pwdResult) {
        transferPwd.value = pwdResult.value;
    }
    if (transferUser && userResult) {
        transferUser.value = userResult.value;
    }
    if (transferTitle && !transferTitle.value.trim() && aliasTag && aliasTag.value.trim()) {
        transferTitle.value = aliasTag.value.trim();
    }
}

function handleTransferToVault(e) {
    e.preventDefault();
    const vaultSelect = document.getElementById('transferVaultSelect');
    const titleInput = document.getElementById('transferTitle');
    const userInput = document.getElementById('transferUsername');
    const pwdInput = document.getElementById('transferPassword');

    const vaultId = vaultSelect ? vaultSelect.value : '';
    const payload = {
        title: titleInput ? titleInput.value.trim() : '',
        username: userInput ? userInput.value.trim() : '',
        password: pwdInput ? pwdInput.value : '',
        timestamp: Date.now()
    };

    try {
        sessionStorage.setItem('pendingVaultEntry', JSON.stringify(payload));
    } catch (err) {
        console.error('Could not store pending vault entry in sessionStorage:', err);
    }

    if (vaultId) {
        window.location.href = 'vault.php?id=' + encodeURIComponent(vaultId) + '&prefill=1';
    } else {
        window.location.href = 'vault.php?prefill=1';
    }
}

function initPasswordGeneratorUI() {
    const copyBtn = document.getElementById('copyBtn');
    if (copyBtn) {
        copyBtn.addEventListener('click', copyPassword);
    }

    const regenerateBtn = document.getElementById('regenerateBtn');
    if (regenerateBtn) {
        regenerateBtn.addEventListener('click', function() {
            const form = document.getElementById('generatorForm');
            if (form) form.submit();
        });
    }

    const lengthRange = document.getElementById('lengthRange');
    if (lengthRange) {
        lengthRange.addEventListener('input', function() {
            syncLength(this.value);
        });
    }

    const lengthInput = document.getElementById('lengthInput');
    if (lengthInput) {
        lengthInput.addEventListener('input', function() {
            syncLength(this.value);
        });
    }

    const specialCheck = document.getElementById('special');
    const specialCountInput = document.getElementById('specialCountInput');
    if (specialCheck && specialCountInput) {
        specialCheck.addEventListener('change', function() {
            if (this.checked) {
                specialCountInput.removeAttribute('disabled');
            } else {
                specialCountInput.setAttribute('disabled', 'disabled');
                specialCountInput.value = '';
            }
        });
    }

    const copyUsernameBtn = document.getElementById('copyUsernameBtn');
    if (copyUsernameBtn) {
        copyUsernameBtn.addEventListener('click', copyUsername);
    }

    const usernameModeSelect = document.getElementById('usernameMode');
    if (usernameModeSelect) {
        usernameModeSelect.addEventListener('change', toggleUsernameMode);
    }

    const regenerateUsernameBtn = document.getElementById('regenerateUsernameBtn');
    if (regenerateUsernameBtn) {
        regenerateUsernameBtn.addEventListener('click', function() {
            const generated = generateClientSideUsername();
            const usernameResult = document.getElementById('usernameResult');
            if (generated && usernameResult) {
                usernameResult.value = generated;
            }
        });
    }

    const saveToVaultBtn = document.getElementById('saveToVaultBtn');
    if (saveToVaultBtn) {
        saveToVaultBtn.addEventListener('click', syncTransferModalFields);
    }

    const saveBothBtn = document.getElementById('saveUsernameAndPasswordToVaultBtn');
    if (saveBothBtn) {
        saveBothBtn.addEventListener('click', syncTransferModalFields);
    }

    const transferForm = document.getElementById('saveToVaultTransferForm');
    if (transferForm) {
        transferForm.addEventListener('submit', handleTransferToVault);
    }
}

if (typeof document !== 'undefined') {
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initPasswordGeneratorUI);
    } else {
        initPasswordGeneratorUI();
    }
}

if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        syncLength,
        copyPassword,
        showFeedback,
        copyUsername,
        toggleUsernameMode,
        generateClientSideUsername,
        initPasswordGeneratorUI
    };
}
