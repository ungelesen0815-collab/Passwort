function updateThemeButton(isDark) {
    const btn = document.getElementById('theme-toggle-btn');
    if (btn) {
        btn.textContent = isDark ? '☀️ Light' : '🌙 Dark';
    }
}

function toggleTheme() {
    const body = document.body;
    body.classList.toggle('dark-mode');
    const isDark = body.classList.contains('dark-mode');
    localStorage.setItem('theme', isDark ? 'dark' : 'light');

    // Update button text/icon
    updateThemeButton(isDark);
}

function initTheme() {
    const theme = localStorage.getItem('theme');
    const isDark = theme === 'dark';
    if (isDark) {
        document.body.classList.add('dark-mode');
    }

    // Ensure button reflects current state
    updateThemeButton(isDark);

    // Attach event listener dynamically
    const themeBtn = document.getElementById('theme-toggle-btn');
    if (themeBtn) {
        themeBtn.addEventListener('click', toggleTheme);
    }
}

// Apply theme on load
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initTheme);
} else {
    initTheme();
}