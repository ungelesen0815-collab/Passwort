/**
 * Progressive Web App (PWA) client controller:
 * - Registers Service Worker
 * - Manages offline/online connection status indicators
 * - Handles standalone install prompts
 */

let deferredInstallPrompt = null;

function registerServiceWorker() {
    if (typeof window === 'undefined' || !('serviceWorker' in navigator)) {
        return Promise.resolve(null);
    }

    return navigator.serviceWorker.register('sw.js', { scope: './' })
        .then((registration) => {
            console.log('[PWA] Service Worker registered with scope:', registration.scope);
            return registration;
        })
        .catch((error) => {
            console.warn('[PWA] Service Worker registration failed:', error);
            return null;
        });
}

function updateOnlineStatus(isOnline) {
    if (typeof document === 'undefined') return;

    let banner = document.getElementById('pwa-offline-banner');

    if (!isOnline) {
        if (!banner) {
            banner = document.createElement('div');
            banner.id = 'pwa-offline-banner';
            banner.className = 'pwa-offline-banner alert alert-warning text-center m-0 py-1 px-3 fixed-top shadow-sm';
            banner.setAttribute('role', 'status');
            banner.textContent = '⚠️ Offline-Modus aktiv: Änderungen werden lokal zwischengespeichert';
            document.body.prepend(banner);
        }
        banner.classList.remove('d-none');
    } else if (banner) {
        banner.className = 'pwa-offline-banner alert alert-success text-center m-0 py-1 px-3 fixed-top shadow-sm';
        banner.textContent = '✅ Verbindung wiederhergestellt';
        setTimeout(() => {
            if (banner && banner.parentNode) {
                banner.classList.add('d-none');
            }
        }, 3000);
    }
}

function setupPWAEvents() {
    if (typeof window === 'undefined') return;

    window.addEventListener('online', () => updateOnlineStatus(true));
    window.addEventListener('offline', () => updateOnlineStatus(false));

    // If already offline when page loads
    if (typeof navigator !== 'undefined' && !navigator.onLine) {
        updateOnlineStatus(false);
    }

    window.addEventListener('beforeinstallprompt', (e) => {
        // Prevent default browser mini-infobar on mobile
        e.preventDefault();
        deferredInstallPrompt = e;

        // If an install button exists on the page, display it
        const installBtn = document.getElementById('pwa-install-btn');
        if (installBtn) {
            installBtn.classList.remove('d-none');
            installBtn.addEventListener('click', promptInstall);
        }
    });

    window.addEventListener('appinstalled', () => {
        deferredInstallPrompt = null;
        const installBtn = document.getElementById('pwa-install-btn');
        if (installBtn) {
            installBtn.classList.add('d-none');
        }
        console.log('[PWA] Application successfully installed.');
    });
}

function promptInstall() {
    if (!deferredInstallPrompt) return Promise.resolve(null);

    return deferredInstallPrompt.prompt().then(() => {
        return deferredInstallPrompt.userChoice;
    }).then((choiceResult) => {
        deferredInstallPrompt = null;
        return choiceResult;
    });
}

if (typeof window !== 'undefined') {
    if (document.readyState === 'complete' || document.readyState === 'interactive') {
        registerServiceWorker();
        setupPWAEvents();
    } else {
        window.addEventListener('DOMContentLoaded', () => {
            registerServiceWorker();
            setupPWAEvents();
        });
    }
}

if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        registerServiceWorker,
        updateOnlineStatus,
        setupPWAEvents,
        promptInstall,
        getDeferredInstallPrompt: () => deferredInstallPrompt
    };
}
