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
        initPasswordGeneratorUI
    };
}
