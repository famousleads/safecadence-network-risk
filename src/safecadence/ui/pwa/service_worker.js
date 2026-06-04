/* SafeCadence NetRisk — service worker (v11.1.0)
 *
 * Strategy:
 *   - Static assets (manifest, responsive.css, /sw.js, icons): cache-first.
 *   - API (/api/*): network-first with a stale-cache fallback.
 *   - Everything else: network-first.
 *
 * Cache is versioned so a release bump invalidates old assets automatically.
 */

const CACHE_VERSION = 'sc-v16.0.1-mobile';
const STATIC_CACHE = `${CACHE_VERSION}-static`;
const RUNTIME_CACHE = `${CACHE_VERSION}-runtime`;

const STATIC_ASSETS = [
  '/manifest.webmanifest',
  '/static/responsive.css',
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(STATIC_CACHE).then((cache) => {
      // Best-effort: don't fail install if any one URL 404s.
      return Promise.all(
        STATIC_ASSETS.map((url) =>
          cache.add(url).catch(() => null)
        )
      );
    }).then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(
        keys
          .filter((k) => !k.startsWith(CACHE_VERSION))
          .map((k) => caches.delete(k))
      )
    ).then(() => self.clients.claim())
  );
});

function isStatic(url) {
  return (
    url.pathname === '/manifest.webmanifest' ||
    url.pathname === '/sw.js' ||
    url.pathname.startsWith('/static/') ||
    url.pathname.endsWith('.css') ||
    url.pathname.endsWith('.svg') ||
    url.pathname.endsWith('.png') ||
    url.pathname.endsWith('.ico')
  );
}

function isApi(url) {
  return url.pathname.startsWith('/api/');
}

self.addEventListener('fetch', (event) => {
  const req = event.request;
  if (req.method !== 'GET') return;
  const url = new URL(req.url);
  if (url.origin !== self.location.origin) return;

  if (isStatic(url)) {
    // Cache-first.
    event.respondWith(
      caches.match(req).then((cached) =>
        cached || fetch(req).then((resp) => {
          const copy = resp.clone();
          caches.open(STATIC_CACHE).then((c) => c.put(req, copy));
          return resp;
        }).catch(() => cached)
      )
    );
    return;
  }

  if (isApi(url)) {
    // Network-first; fall back to whatever we last saw.
    event.respondWith(
      fetch(req).then((resp) => {
        const copy = resp.clone();
        caches.open(RUNTIME_CACHE).then((c) => c.put(req, copy));
        return resp;
      }).catch(() => caches.match(req))
    );
    return;
  }

  // Default: network-first with cache fallback.
  event.respondWith(
    fetch(req).then((resp) => {
      const copy = resp.clone();
      caches.open(RUNTIME_CACHE).then((c) => c.put(req, copy));
      return resp;
    }).catch(() => caches.match(req))
  );
});
