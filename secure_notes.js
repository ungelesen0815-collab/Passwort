/**
 * Web Crypto API End-to-End Encryption & UI for Secure Notes & Recovery Codes
 */

const SecureNotesCrypto = {
    bufferToBase64(buffer) {
        const bytes = new Uint8Array(buffer);
        let binary = '';
        for (let i = 0, len = bytes.byteLength; i < len; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return window.btoa(binary);
    },

    base64ToBuffer(base64) {
        const binary = window.atob(base64);
        const len = binary.length;
        const bytes = new Uint8Array(len);
        for (let i = 0; i < len; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes;
    },

    generateSalt() {
        const salt = window.crypto.getRandomValues(new Uint8Array(16));
        return this.bufferToBase64(salt);
    },

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

    async encryptNoteData(key, data) {
        const encoder = new TextEncoder();
        const plaintext = typeof data === 'string' ? data : JSON.stringify(data);
        const plaintextBuffer = encoder.encode(plaintext);
        const iv = window.crypto.getRandomValues(new Uint8Array(12));

        const encryptedBuffer = await window.crypto.subtle.encrypt(
            { name: 'AES-GCM', iv: iv },
            key,
            plaintextBuffer
        );

        return {
            ciphertext: this.bufferToBase64(encryptedBuffer),
            iv: this.bufferToBase64(iv)
        };
    },

    async decryptNoteData(key, ciphertextBase64, ivBase64) {
        const ciphertextBuffer = this.base64ToBuffer(ciphertextBase64);
        const ivBuffer = this.base64ToBuffer(ivBase64);

        const decryptedBuffer = await window.crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: ivBuffer },
            key,
            ciphertextBuffer
        );

        const decoder = new TextDecoder();
        return decoder.decode(decryptedBuffer);
    },

    readFileAsText(file) {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.onload = () => resolve(reader.result);
            reader.onerror = () => reject(reader.error);
            reader.readAsText(file);
        });
    }
};

var notesCsrfToken = '';
var rawNotes = [];
var decryptedNotesCache = new Map();
var notesMasterKey = null;
var notesActiveSalt = null;
var notesMasterPassword = null;
var notesKeysBySalt = new Map();
var currentFilter = 'all';
var currentSearch = '';
var activeViewedNoteId = null;

function escapeNoteHtml(str) {
    if (!str) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

/**
 * Safe lightweight Markdown renderer (escapes HTML first, then formats headings, code blocks, inline code, bold, italic, and lists)
 */
function renderSafeMarkdown(markdownText) {
    const escaped = escapeNoteHtml(markdownText || '');
    const codeBlocks = [];

    // Extract fenced code blocks ```...```
    let processed = escaped.replace(/```([\s\S]*?)```/g, function (_, codeContent) {
        const idx = codeBlocks.length;
        codeBlocks.push('<pre class="bg-dark text-light p-3 rounded font-monospace small my-2"><code>' + codeContent.replace(/^\n+|\n+$/g, '') + '</code></pre>');
        return '@@CODEBLOCK_' + idx + '@@';
    });

    const lines = processed.split(/\r?\n/);
    const htmlLines = [];
    let inList = false;

    for (let i = 0; i < lines.length; i++) {
        let line = lines[i];

        if (/^@@CODEBLOCK_\d+@@$/.test(line.trim())) {
            if (inList) {
                htmlLines.push('</ul>');
                inList = false;
            }
            htmlLines.push(line.trim());
            continue;
        }

        if (/^###\s+(.+)$/.test(line)) {
            if (inList) { htmlLines.push('</ul>'); inList = false; }
            htmlLines.push('<h6 class="fw-bold mt-3 mb-1">' + formatInlineMarkdown(line.replace(/^###\s+/, '')) + '</h6>');
        } else if (/^##\s+(.+)$/.test(line)) {
            if (inList) { htmlLines.push('</ul>'); inList = false; }
            htmlLines.push('<h5 class="fw-bold mt-3 mb-2">' + formatInlineMarkdown(line.replace(/^##\s+/, '')) + '</h5>');
        } else if (/^#\s+(.+)$/.test(line)) {
            if (inList) { htmlLines.push('</ul>'); inList = false; }
            htmlLines.push('<h4 class="fw-bold mt-2 mb-2">' + formatInlineMarkdown(line.replace(/^#\s+/, '')) + '</h4>');
        } else if (/^[-*]\s+(.+)$/.test(line)) {
            if (!inList) {
                htmlLines.push('<ul class="mb-2">');
                inList = true;
            }
            htmlLines.push('<li>' + formatInlineMarkdown(line.replace(/^[-*]\s+/, '')) + '</li>');
        } else if (line.trim() === '') {
            if (inList) {
                htmlLines.push('</ul>');
                inList = false;
            }
            htmlLines.push('<div class="mb-2"></div>');
        } else {
            if (inList) {
                htmlLines.push('</ul>');
                inList = false;
            }
            htmlLines.push('<p class="mb-1">' + formatInlineMarkdown(line) + '</p>');
        }
    }

    if (inList) {
        htmlLines.push('</ul>');
    }

    let finalHtml = htmlLines.join('\n');
    for (let i = 0; i < codeBlocks.length; i++) {
        finalHtml = finalHtml.replace('@@CODEBLOCK_' + i + '@@', codeBlocks[i]);
    }
    return finalHtml;
}

function formatInlineMarkdown(text) {
    return text
        .replace(/`([^`]+)`/g, '<code class="bg-white border px-1 rounded text-danger">$1</code>')
        .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
        .replace(/\*([^*]+)\*/g, '<em>$1</em>');
}

function renderRecoveryCodesHtml(contentText) {
    const rawLines = String(contentText || '')
        .split(/\r?\n/)
        .map(line => line.trim())
        .filter(Boolean);

    if (rawLines.length === 0) {
        return '<p class="text-muted mb-0">Keine Recovery-Codes eingetragen.</p>';
    }

    let html = '<div class="row g-2">';
    rawLines.forEach((code, idx) => {
        const escapedCode = escapeNoteHtml(code);
        html += `
            <div class="col-sm-6 col-md-4">
                <div class="d-flex justify-content-between align-items-center bg-white border rounded px-3 py-2">
                    <span class="font-monospace fw-bold"><small class="text-muted me-2">#${idx + 1}</small>${escapedCode}</span>
                    <button type="button" class="btn btn-outline-primary btn-sm py-0 px-2 btn-copy-code" data-copy="${escapedCode}" title="Code kopieren">📋</button>
                </div>
            </div>
        `;
    });
    html += '</div>';
    return html;
}

async function getNoteKeyForSalt(salt) {
    if (!salt || salt === notesActiveSalt) {
        return notesMasterKey;
    }
    if (notesKeysBySalt.has(salt)) {
        return notesKeysBySalt.get(salt);
    }
    if (!notesMasterPassword) {
        return notesMasterKey;
    }
    const key = await SecureNotesCrypto.deriveMasterKey(notesMasterPassword, salt);
    notesKeysBySalt.set(salt, key);
    return key;
}

async function handleUnlockNotes(e) {
    e.preventDefault();
    const masterPassword = document.getElementById('notes-master-password-input').value;
    if (!masterPassword) return;

    if (rawNotes.length > 0) {
        notesActiveSalt = rawNotes[0].salt;
    } else if (!notesActiveSalt) {
        notesActiveSalt = SecureNotesCrypto.generateSalt();
    }

    try {
        notesMasterKey = await SecureNotesCrypto.deriveMasterKey(masterPassword, notesActiveSalt);
        notesMasterPassword = masterPassword;
        notesKeysBySalt.clear();
        notesKeysBySalt.set(notesActiveSalt, notesMasterKey);

        if (rawNotes.length > 0) {
            try {
                await SecureNotesCrypto.decryptNoteData(notesMasterKey, rawNotes[0].encrypted_data, rawNotes[0].iv);
            } catch (err) {
                alert('Entschlüsselung fehlgeschlagen! Das Master-Passwort ist möglicherweise falsch.');
                notesMasterKey = null;
                notesMasterPassword = null;
                notesKeysBySalt.clear();
                return;
            }
        }

        document.getElementById('notes-master-password-card').classList.add('d-none');
        document.getElementById('notes-content').classList.remove('d-none');
        document.getElementById('lock-notes-btn').classList.remove('d-none');

        await decryptAllNotesAndRender();
    } catch (err) {
        alert('Fehler beim Entschlüsseln: ' + err.message);
    }
}

function lockNotes() {
    notesMasterKey = null;
    notesMasterPassword = null;
    notesKeysBySalt.clear();
    decryptedNotesCache.clear();
    document.getElementById('notes-master-password-input').value = '';
    document.getElementById('notes-master-password-card').classList.remove('d-none');
    document.getElementById('notes-content').classList.add('d-none');
    document.getElementById('lock-notes-btn').classList.add('d-none');
}

async function decryptAllNotesAndRender() {
    decryptedNotesCache.clear();

    const uniqueSalts = new Set(rawNotes.map(n => n.salt).filter(Boolean));
    for (const salt of uniqueSalts) {
        await getNoteKeyForSalt(salt);
    }

    await Promise.all(rawNotes.map(async (note) => {
        try {
            const key = await getNoteKeyForSalt(note.salt);
            const jsonStr = await SecureNotesCrypto.decryptNoteData(key, note.encrypted_data, note.iv);
            const parsed = JSON.parse(jsonStr);
            decryptedNotesCache.set(Number(note.id), {
                content: parsed.content || '',
                tags: parsed.tags || ''
            });
        } catch (e) {
            decryptedNotesCache.set(Number(note.id), {
                content: '',
                tags: '',
                error: true
            });
        }
    }));

    renderNotesGrid();
}

function renderNotesGrid() {
    const grid = document.getElementById('notes-grid');
    if (!grid) return;

    let countAll = rawNotes.length;
    let countNote = rawNotes.filter(n => n.note_type === 'note').length;
    let countRecovery = rawNotes.filter(n => n.note_type === 'recovery').length;

    const countAllEl = document.getElementById('count-all');
    const countNoteEl = document.getElementById('count-note');
    const countRecoveryEl = document.getElementById('count-recovery');
    if (countAllEl) countAllEl.textContent = String(countAll);
    if (countNoteEl) countNoteEl.textContent = String(countNote);
    if (countRecoveryEl) countRecoveryEl.textContent = String(countRecovery);

    const searchLower = currentSearch.trim().toLowerCase();

    const filtered = rawNotes.filter((note) => {
        if (currentFilter !== 'all' && note.note_type !== currentFilter) {
            return false;
        }
        if (!searchLower) {
            return true;
        }
        const decrypted = decryptedNotesCache.get(Number(note.id)) || { content: '', tags: '' };
        const haystack = [note.title, decrypted.tags, decrypted.content].join(' ').toLowerCase();
        return haystack.includes(searchLower);
    });

    if (filtered.length === 0) {
        grid.innerHTML = '<div class="col-12 text-center text-muted py-4">Keine passenden sicheren Notizen gefunden.</div>';
        return;
    }

    grid.innerHTML = '';

    filtered.forEach((note) => {
        const decrypted = decryptedNotesCache.get(Number(note.id)) || { content: '', tags: '' };
        const isRecovery = note.note_type === 'recovery';
        const typeBadge = isRecovery
            ? '<span class="badge bg-warning text-dark">🛟 Recovery-Codes</span>'
            : '<span class="badge bg-primary">📄 Markdown-Notiz</span>';

        const tagsList = String(decrypted.tags || '')
            .split(',')
            .map(t => t.trim())
            .filter(Boolean)
            .map(t => `<span class="badge bg-secondary me-1">${escapeNoteHtml(t)}</span>`)
            .join('');

        let previewText = '';
        if (decrypted.error) {
            previewText = '<span class="text-danger">Entschlüsselungsfehler</span>';
        } else if (isRecovery) {
            const codeCount = String(decrypted.content || '').split(/\r?\n/).map(l => l.trim()).filter(Boolean).length;
            previewText = `<span class="text-muted">🔒 ${codeCount} Recovery-Code(s) hinterlegt</span>`;
        } else {
            const snippet = String(decrypted.content || '').replace(/\s+/g, ' ').trim().slice(0, 120);
            previewText = escapeNoteHtml(snippet) + (snippet.length >= 120 ? '…' : '');
        }

        const col = document.createElement('div');
        col.className = 'col-md-6 col-lg-4';
        col.innerHTML = `
            <div class="card h-100 shadow-sm">
                <div class="card-body d-flex flex-column">
                    <div class="d-flex justify-content-between align-items-start mb-2">
                        <h5 class="card-title mb-0 text-truncate" title="${escapeNoteHtml(note.title)}">${escapeNoteHtml(note.title)}</h5>
                        ${typeBadge}
                    </div>
                    ${tagsList ? `<div class="mb-2">${tagsList}</div>` : ''}
                    <p class="card-text small text-secondary flex-grow-1 mb-3">${previewText}</p>
                    <div class="d-flex flex-wrap gap-1 justify-content-between align-items-center mt-auto pt-2 border-top">
                        <div class="btn-group btn-group-sm">
                            <button type="button" class="btn btn-outline-primary btn-view-note" data-id="${note.id}">👁️ Öffnen</button>
                            <button type="button" class="btn btn-outline-secondary btn-edit-note" data-id="${note.id}">✏️</button>
                            <button type="button" class="btn btn-outline-secondary btn-copy-note" data-id="${note.id}" title="Inhalt kopieren">📋</button>
                            <button type="button" class="btn btn-outline-secondary btn-download-note" data-id="${note.id}" title="Herunterladen">📥</button>
                        </div>
                        <button type="button" class="btn btn-outline-danger btn-sm btn-delete-note" data-id="${note.id}">🗑️</button>
                    </div>
                </div>
            </div>
        `;
        grid.appendChild(col);
    });
}

function openNewNoteModal() {
    document.getElementById('edit_note_id').value = '';
    document.getElementById('note-editor-form').reset();
    document.getElementById('noteEditorModalLabel').textContent = 'Neue sichere Notiz erstellen';
    updateNoteTypePlaceholders();
}

function openEditNoteModal(noteId) {
    const note = rawNotes.find(n => Number(n.id) === Number(noteId));
    if (!note) return;
    const decrypted = decryptedNotesCache.get(Number(note.id)) || { content: '', tags: '' };

    document.getElementById('edit_note_id').value = String(note.id);
    document.getElementById('note_type').value = note.note_type || 'note';
    document.getElementById('note_title').value = note.title || '';
    document.getElementById('note_tags').value = decrypted.tags || '';
    document.getElementById('note_content').value = decrypted.content || '';
    document.getElementById('noteEditorModalLabel').textContent = 'Sichere Notiz bearbeiten';
    updateNoteTypePlaceholders();

    const modalEl = document.getElementById('noteEditorModal');
    if (typeof bootstrap !== 'undefined' && bootstrap.Modal) {
        const modal = bootstrap.Modal.getOrCreateInstance(modalEl);
        modal.show();
    }
}

function openViewNoteModal(noteId) {
    const note = rawNotes.find(n => Number(n.id) === Number(noteId));
    if (!note) return;
    const decrypted = decryptedNotesCache.get(Number(note.id)) || { content: '', tags: '' };
    activeViewedNoteId = Number(note.id);

    document.getElementById('noteViewModalLabel').textContent = note.title;
    document.getElementById('noteViewMeta').textContent = note.note_type === 'recovery'
        ? '🛟 Recovery-Codes (Ende-zu-Ende verschlüsselt)'
        : '📄 Freitext / Markdown-Notiz (Ende-zu-Ende verschlüsselt)';

    const tagsContainer = document.getElementById('noteViewTags');
    const tagsList = String(decrypted.tags || '')
        .split(',')
        .map(t => t.trim())
        .filter(Boolean)
        .map(t => `<span class="badge bg-secondary me-1">${escapeNoteHtml(t)}</span>`)
        .join('');
    tagsContainer.innerHTML = tagsList;

    const renderedContainer = document.getElementById('noteViewRendered');
    if (note.note_type === 'recovery') {
        renderedContainer.innerHTML = renderRecoveryCodesHtml(decrypted.content);
    } else {
        renderedContainer.innerHTML = renderSafeMarkdown(decrypted.content);
    }

    const modalEl = document.getElementById('noteViewModal');
    if (typeof bootstrap !== 'undefined' && bootstrap.Modal) {
        const modal = bootstrap.Modal.getOrCreateInstance(modalEl);
        modal.show();
    }
}

function updateNoteTypePlaceholders() {
    const typeSelect = document.getElementById('note_type');
    const contentLabel = document.getElementById('note_content_label');
    const contentArea = document.getElementById('note_content');
    if (!typeSelect || !contentLabel || !contentArea) return;

    if (typeSelect.value === 'recovery') {
        contentLabel.innerHTML = 'Recovery-Codes / Backup-Codes <small class="text-muted">(ein Code pro Zeile)</small>';
        contentArea.placeholder = 'ABCD-1234-EFGH\nIJKL-5678-MNOP\nQRST-9012-UVWX';
    } else {
        contentLabel.innerHTML = 'Inhalt (Markdown unterstützt: <code># Titel</code>, <code>**fett**</code>, <code>`code`</code>, Listen)';
        contentArea.placeholder = '# Server-Zugang / Notiz\n\n- Wichtiger Hinweis\n- Konfiguration...';
    }
}

async function handleSaveNote(e) {
    e.preventDefault();
    if (!notesMasterKey) {
        alert('Bitte entsperren Sie zuerst Ihre Notizen mit dem Master-Passwort.');
        return;
    }

    const editId = document.getElementById('edit_note_id').value.trim();
    const noteType = document.getElementById('note_type').value;
    const title = document.getElementById('note_title').value.trim();
    const tags = document.getElementById('note_tags').value.trim();
    const content = document.getElementById('note_content').value;

    if (!title || !content) {
        alert('Bitte Titel und Inhalt ausfüllen.');
        return;
    }

    if (!notesActiveSalt) {
        notesActiveSalt = rawNotes.length > 0 ? rawNotes[0].salt : SecureNotesCrypto.generateSalt();
    }
    const salt = notesActiveSalt;
    const key = await getNoteKeyForSalt(salt);
    const payload = { content: content, tags: tags };
    const encrypted = await SecureNotesCrypto.encryptNoteData(key, payload);

    const formData = new FormData();
    formData.append('action', editId ? 'update' : 'add');
    if (editId) {
        formData.append('note_id', editId);
    }
    formData.append('csrf_token', notesCsrfToken);
    formData.append('note_type', noteType);
    formData.append('title', title);
    formData.append('encrypted_data', encrypted.ciphertext);
    formData.append('iv', encrypted.iv);
    formData.append('salt', salt);
    formData.append('ajax', '1');

    try {
        const response = await fetch('secure_notes.php', {
            method: 'POST',
            body: formData,
            headers: { 'X-Requested-With': 'XMLHttpRequest' }
        });
        const res = await response.json();
        if (res.success) {
            if (editId) {
                const idx = rawNotes.findIndex(n => Number(n.id) === Number(editId));
                if (idx !== -1) {
                    rawNotes[idx].note_type = noteType;
                    rawNotes[idx].title = title;
                    rawNotes[idx].encrypted_data = encrypted.ciphertext;
                    rawNotes[idx].iv = encrypted.iv;
                    rawNotes[idx].salt = salt;
                }
                decryptedNotesCache.set(Number(editId), { content: content, tags: tags });
            } else {
                const newId = Number(res.id);
                rawNotes.unshift({
                    id: newId,
                    note_type: noteType,
                    title: title,
                    encrypted_data: encrypted.ciphertext,
                    iv: encrypted.iv,
                    salt: salt,
                    created_at: new Date().toISOString()
                });
                decryptedNotesCache.set(newId, { content: content, tags: tags });
            }

            const modalEl = document.getElementById('noteEditorModal');
            if (typeof bootstrap !== 'undefined' && bootstrap.Modal) {
                const modal = bootstrap.Modal.getInstance(modalEl);
                if (modal) modal.hide();
            }
            document.getElementById('note-editor-form').reset();
            document.getElementById('edit_note_id').value = '';
            renderNotesGrid();
        } else {
            alert('Fehler beim Speichern: ' + (res.error || 'Unbekannter Fehler'));
        }
    } catch (err) {
        alert('Netzwerkfehler beim Speichern.');
    }
}

async function deleteNoteById(noteId) {
    if (!confirm('Möchten Sie diese sichere Notiz wirklich unwiderruflich löschen?')) return;

    const formData = new FormData();
    formData.append('action', 'delete');
    formData.append('csrf_token', notesCsrfToken);
    formData.append('note_id', noteId);
    formData.append('ajax', '1');

    try {
        const response = await fetch('secure_notes.php', {
            method: 'POST',
            body: formData,
            headers: { 'X-Requested-With': 'XMLHttpRequest' }
        });
        const res = await response.json();
        if (res.success) {
            const idx = rawNotes.findIndex(n => Number(n.id) === Number(noteId));
            if (idx !== -1) rawNotes.splice(idx, 1);
            decryptedNotesCache.delete(Number(noteId));
            renderNotesGrid();
        } else {
            alert('Fehler beim Löschen: ' + (res.error || 'Unbekannter Fehler'));
        }
    } catch (err) {
        alert('Netzwerkfehler beim Löschen.');
    }
}

function copyNoteText(text) {
    navigator.clipboard.writeText(text).then(() => {
        alert('In die Zwischenablage kopiert!');
    }).catch(() => {
        alert('Kopieren fehlgeschlagen.');
    });
}

function downloadNoteFile(note) {
    const decrypted = decryptedNotesCache.get(Number(note.id)) || { content: '' };
    const ext = note.note_type === 'recovery' ? '.txt' : '.md';
    const safeTitle = String(note.title || 'notiz').replace(/[^a-zA-Z0-9_-]+/g, '_');
    const filename = safeTitle + ext;

    const element = document.createElement('a');
    if (typeof Blob !== 'undefined' && typeof URL !== 'undefined' && URL.createObjectURL) {
        const blob = new Blob([decrypted.content || ''], { type: 'text/plain;charset=utf-8' });
        const url = URL.createObjectURL(blob);
        element.setAttribute('href', url);
        element.setAttribute('download', filename);
        element.hidden = true;
        document.body.appendChild(element);
        element.click();
        document.body.removeChild(element);
        setTimeout(() => URL.revokeObjectURL(url), 100);
    }
}

function initSecureNotesUI() {
    const dataEl = document.getElementById('secure-notes-data');
    if (dataEl) {
        try {
            const rawJson = dataEl.dataset && dataEl.dataset.json ? dataEl.dataset.json : (dataEl.getAttribute('data-json') || dataEl.textContent);
            const parsed = JSON.parse(rawJson);
            notesCsrfToken = parsed.csrfToken || '';
            rawNotes = parsed.notes || [];
        } catch (e) {
            console.error('Failed to parse secure notes data:', e);
        }
    }

    const unlockForm = document.getElementById('notes-master-password-form');
    if (unlockForm) unlockForm.addEventListener('submit', handleUnlockNotes);

    const lockBtn = document.getElementById('lock-notes-btn');
    if (lockBtn) lockBtn.addEventListener('click', lockNotes);

    const newNoteBtn = document.getElementById('btn-new-note');
    if (newNoteBtn) newNoteBtn.addEventListener('click', openNewNoteModal);

    const noteTypeSelect = document.getElementById('note_type');
    if (noteTypeSelect) noteTypeSelect.addEventListener('change', updateNoteTypePlaceholders);

    const editorForm = document.getElementById('note-editor-form');
    if (editorForm) editorForm.addEventListener('submit', handleSaveNote);

    const fileImport = document.getElementById('note_file_import');
    if (fileImport) {
        fileImport.addEventListener('change', async function () {
            if (this.files && this.files[0]) {
                try {
                    const text = await SecureNotesCrypto.readFileAsText(this.files[0]);
                    document.getElementById('note_content').value = text;
                    const titleInput = document.getElementById('note_title');
                    if (titleInput && !titleInput.value.trim()) {
                        titleInput.value = this.files[0].name.replace(/\.[^.]+$/, '');
                    }
                } catch (e) {
                    alert('Datei konnte nicht gelesen werden.');
                }
            }
        });
    }

    const searchInput = document.getElementById('notes-search-input');
    if (searchInput) {
        searchInput.addEventListener('input', function () {
            currentSearch = this.value || '';
            renderNotesGrid();
        });
    }

    const filterTabs = document.getElementById('notesFilterTabs');
    if (filterTabs) {
        filterTabs.addEventListener('click', function (e) {
            const btn = e.target.closest('button[data-filter]');
            if (!btn) return;
            filterTabs.querySelectorAll('.nav-link').forEach(el => el.classList.remove('active'));
            btn.classList.add('active');
            currentFilter = btn.getAttribute('data-filter') || 'all';
            renderNotesGrid();
        });
    }

    const notesGrid = document.getElementById('notes-grid');
    if (notesGrid) {
        notesGrid.addEventListener('click', function (e) {
            const viewBtn = e.target.closest('.btn-view-note');
            if (viewBtn) {
                openViewNoteModal(viewBtn.dataset.id);
                return;
            }
            const editBtn = e.target.closest('.btn-edit-note');
            if (editBtn) {
                openEditNoteModal(editBtn.dataset.id);
                return;
            }
            const copyBtn = e.target.closest('.btn-copy-note');
            if (copyBtn) {
                const decrypted = decryptedNotesCache.get(Number(copyBtn.dataset.id));
                if (decrypted) copyNoteText(decrypted.content || '');
                return;
            }
            const downloadBtn = e.target.closest('.btn-download-note');
            if (downloadBtn) {
                const note = rawNotes.find(n => Number(n.id) === Number(downloadBtn.dataset.id));
                if (note) downloadNoteFile(note);
                return;
            }
            const deleteBtn = e.target.closest('.btn-delete-note');
            if (deleteBtn) {
                deleteNoteById(deleteBtn.dataset.id);
            }
        });
    }

    const viewModal = document.getElementById('noteViewModal');
    if (viewModal) {
        viewModal.addEventListener('click', function (e) {
            const copyCodeBtn = e.target.closest('.btn-copy-code');
            if (copyCodeBtn) {
                copyNoteText(copyCodeBtn.dataset.copy || '');
            }
        });
    }

    const btnViewCopy = document.getElementById('btn-view-copy');
    if (btnViewCopy) {
        btnViewCopy.addEventListener('click', function () {
            if (activeViewedNoteId !== null) {
                const decrypted = decryptedNotesCache.get(Number(activeViewedNoteId));
                if (decrypted) copyNoteText(decrypted.content || '');
            }
        });
    }

    const btnViewDownload = document.getElementById('btn-view-download');
    if (btnViewDownload) {
        btnViewDownload.addEventListener('click', function () {
            if (activeViewedNoteId !== null) {
                const note = rawNotes.find(n => Number(n.id) === Number(activeViewedNoteId));
                if (note) downloadNoteFile(note);
            }
        });
    }

    const btnViewEdit = document.getElementById('btn-view-edit');
    if (btnViewEdit) {
        btnViewEdit.addEventListener('click', function () {
            if (activeViewedNoteId !== null) {
                const viewModalEl = document.getElementById('noteViewModal');
                if (typeof bootstrap !== 'undefined' && bootstrap.Modal) {
                    const m = bootstrap.Modal.getInstance(viewModalEl);
                    if (m) m.hide();
                }
                openEditNoteModal(activeViewedNoteId);
            }
        });
    }
}

if (typeof window !== 'undefined') {
    window.SecureNotesCrypto = SecureNotesCrypto;
    window.renderSafeMarkdown = renderSafeMarkdown;
    window.renderRecoveryCodesHtml = renderRecoveryCodesHtml;
}

if (typeof document !== 'undefined') {
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initSecureNotesUI);
    } else {
        initSecureNotesUI();
    }
}

if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        SecureNotesCrypto,
        renderSafeMarkdown,
        renderRecoveryCodesHtml,
        initSecureNotesUI
    };
}
