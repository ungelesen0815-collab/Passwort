/* Service Worker for Passwort & Vault Manager PWA */
const CACHE_VERSION = 'passwort-pwa-v1';
const PRECACHE_ASSETS = [
    './',
    'index.php',
    'manifest.json',
    'icon.svg',
    'style.css',
    'theme.js',
    'pwa.js',
    'offline.html',
    'offline.js',
    'https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css',
    'https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js'
];

// Install: Precache core static assets for offline resilience
self.addEventListener('install', (event) => {
    event.waitUntil(
        caches.open(CACHE_VERSION).then((cache) => {
            return Promise.allSettled(
                PRECACHE_ASSETS.map((asset) =>
                    cache.add(asset).catch((err) => {
                        console.warn('[PWA SW] Precache failed for:', asset, err);
                    })
                )
            );
        }).then(() => self.skipWaiting())
    );
});

// Activate: Clean up outdated caches and claim clients immediately
self.addEventListener('activate', (event) => {
    event.waitUntil(
        caches.keys().then((keys) => {
            return Promise.all(
                keys.filter((key) => key !== CACHE_VERSION).map((key) => {
                    console.log('[PWA SW] Removing old cache:', key);
                    return caches.delete(key);
                })
            );
        }).then(() => self.clients.claim())
    );
});

// Fetch: Strategy dispatch based on request type
self.addEventListener('fetch', (event) => {
    const request = event.request;

    // Only handle GET requests
    if (request.method !== 'GET') {
        return;
    }

    const url = new URL(request.url);

    // Only handle http and https schemes
    if (!['http:', 'https:'].includes(url.protocol)) {
        return;
    }

    // Navigation requests (HTML pages): Network-First with cache and offline fallback
    if (request.mode === 'navigate') {
        event.respondWith(
            fetch(request)
                .then((networkResponse) => {
                    if (networkResponse && networkResponse.status === 200) {
                        const responseClone = networkResponse.clone();
                        caches.open(CACHE_VERSION).then((cache) => {
                            cache.put(request, responseClone);
                        });
                    }
                    return networkResponse;
                })
                .catch(async () => {
                    const cachedResponse = await caches.match(request);
                    if (cachedResponse) {
                        return cachedResponse;
                    }
                    const offlinePage = await caches.match('offline.html');
                    return offlinePage || new Response('Offline', {
                        status: 503,
                        statusText: 'Service Unavailable',
                        headers: { 'Content-Type': 'text/plain' }
                    });
                })
        );
        return;
    }

    // Static assets (CSS, JS, images, SVG, fonts): Stale-While-Revalidate
    const isStaticAsset =
        ['style', 'script', 'image', 'font'].includes(request.destination) ||
        /\.(css|js|svg|png|jpg|jpeg|gif|webp|ico|woff2?|ttf|eot)(\?.*)?$/i.test(url.pathname);

    if (isStaticAsset) {
        event.respondWith(
            caches.match(request).then((cachedResponse) => {
                const fetchPromise = fetch(request)
                    .then((networkResponse) => {
                        if (networkResponse && (networkResponse.status === 200 || networkResponse.type === 'opaque')) {
                            const responseClone = networkResponse.clone();
                            caches.open(CACHE_VERSION).then((cache) => {
                                cache.put(request, responseClone);
                            });
                        }
                        return networkResponse;
                    })
                    .catch((err) => {
                        // Network error: if cachedResponse exists, it was already returned
                        return cachedResponse;
                    });

                return cachedResponse || fetchPromise;
            })
        );
        return;
    }

    // Default strategy for other GET requests: Cache-First with Network fallback
    event.respondWith(
        caches.match(request).then((cachedResponse) => {
            return cachedResponse || fetch(request).then((networkResponse) => {
                if (networkResponse && networkResponse.status === 200) {
                    const responseClone = networkResponse.clone();
                    caches.open(CACHE_VERSION).then((cache) => {
                        cache.put(request, responseClone);
                    });
                }
                return networkResponse;
            });
        })
    );
});
