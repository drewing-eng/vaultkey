// Service worker VaultKey — PRD §4 : mitige le risque "code re-servi à
// chaque chargement" (§7.H) en mettant en cache le code de l'app (page,
// module WASM) plutôt qu'en le refaisant transiter par le réseau à chaque
// ouverture. Ne met en cache QUE le code de l'app, jamais les appels API
// (/vaults/...) : ceux-ci restent gérés par la logique OPFS déjà en place
// dans web/index.html (réseau-d'abord avec repli cache, ou cache-d'abord
// selon la donnée — voir CLAUDE.md, étape 6).
//
// Placé à la racine du dépôt (pas dans web/) pour que sa portée par défaut
// (le répertoire du script) couvre aussi /wasm/pkg/, servi en frère de
// /web/ dans la disposition actuelle du dépôt.

const CACHE_VERSION = 'vaultkey-shell-v1';

const APP_SHELL = [
  '/web/index.html',
  '/web/manifest.webmanifest',
  '/web/icons/icon-192.png',
  '/web/icons/icon-512.png',
  '/web/icons/icon-512-maskable.png',
  '/web/icons/apple-touch-icon.png',
  '/wasm/pkg/vaultkey_wasm.js',
  '/wasm/pkg/vaultkey_wasm_bg.wasm',
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_VERSION).then((cache) => cache.addAll(APP_SHELL))
  );
  // Pas de self.skipWaiting() ici : une mise à jour installée reste "en
  // attente" tant que l'utilisateur ne l'a pas explicitement demandée
  // (bouton "Vérifier les mises à jour" dans web/index.html), conformément
  // au PRD §4 ("revérification des mises à jour uniquement sur action
  // explicite plutôt qu'à chaque ouverture").
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((names) =>
      Promise.all(names.filter((n) => n !== CACHE_VERSION).map((n) => caches.delete(n)))
    ).then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (event) => {
  const req = event.request;
  if (req.method !== 'GET') return; // laisse passer tel quel (écritures API notamment)

  const url = new URL(req.url);
  if (url.origin !== self.location.origin) return; // jamais l'API (autre origine en dev)
  if (!APP_SHELL.includes(url.pathname)) return; // tout le reste (API same-origin en prod, etc.) : réseau normal, non intercepté

  event.respondWith(
    caches.match(req).then((cached) => cached || fetch(req))
  );
});

// Déclenché par web/index.html après que l'utilisateur a explicitement
// confirmé vouloir appliquer une mise à jour détectée.
self.addEventListener('message', (event) => {
  if (event.data === 'SKIP_WAITING') self.skipWaiting();
});
