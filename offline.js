(function() {
    'use strict';

    // Apply dark mode if stored
    if (localStorage.getItem('theme') === 'dark') {
        document.body.classList.add('dark-mode');
    }

    const retryBtn = document.getElementById('offline-retry-btn');
    if (retryBtn) {
        retryBtn.addEventListener('click', function() {
            window.location.reload();
        });
    }

    // Automatically reload when network returns
    window.addEventListener('online', function() {
        window.location.reload();
    });
})();
