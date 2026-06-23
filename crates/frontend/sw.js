// Service worker (spec §10.4). Caches ONLY the static app shell (no offline
// data) and handles push + notificationclick. API calls are never cached, so
// they fail cleanly when offline.
//
// IMPORTANT update strategy: the page document (index.html) is served
// NETWORK-FIRST so new deployments are picked up immediately (it is not
// content-hashed, so caching it cache-first would pin users to a stale build
// that references old hashed assets). Content-hashed assets (the WASM/JS/CSS
// bundles) are immutable, so they are served cache-first. Bump SHELL_CACHE to
// invalidate old caches on activate.
const SHELL_CACHE = "okr-shell-v2";

self.addEventListener("install", (event) => {
  event.waitUntil(caches.open(SHELL_CACHE).then((c) => c.add("/")));
  self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches
      .keys()
      .then((keys) =>
        Promise.all(keys.filter((k) => k !== SHELL_CACHE).map((k) => caches.delete(k)))
      )
      .then(() => self.clients.claim())
  );
});

function isDocument(request) {
  return (
    request.mode === "navigate" ||
    (request.headers.get("accept") || "").includes("text/html")
  );
}

self.addEventListener("fetch", (event) => {
  const url = new URL(event.request.url);
  // Never cache the API; let it fail cleanly offline (§10.4).
  if (url.pathname.startsWith("/api/")) return;
  if (event.request.method !== "GET") return;

  // Page document: network-first so new deploys are picked up; fall back to the
  // cached shell only when offline.
  if (isDocument(event.request)) {
    event.respondWith(
      fetch(event.request)
        .then((resp) => {
          if (resp.ok && url.origin === self.location.origin) {
            const copy = resp.clone();
            caches.open(SHELL_CACHE).then((c) => c.put("/", copy));
          }
          return resp;
        })
        .catch(() => caches.match("/"))
    );
    return;
  }

  // Content-hashed, immutable assets: cache-first.
  event.respondWith(
    caches.match(event.request).then((hit) => {
      if (hit) return hit;
      return fetch(event.request).then((resp) => {
        if (resp.ok && url.origin === self.location.origin) {
          const copy = resp.clone();
          caches.open(SHELL_CACHE).then((c) => c.put(event.request, copy));
        }
        return resp;
      });
    })
  );
});

// Tickle push (spec §8): no payload — wake up and show a generic notification.
self.addEventListener("push", (event) => {
  event.waitUntil(
    self.registration.showNotification("OKR Tracker", {
      body: "You have a new notification.",
      icon: "/icon.svg",
      badge: "/icon.svg",
      data: { url: "/" },
    })
  );
});

self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  event.waitUntil(self.clients.openWindow((event.notification.data || {}).url || "/"));
});
