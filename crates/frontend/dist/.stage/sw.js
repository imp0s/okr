// Service worker (spec §10.4). Caches ONLY the static app shell (no offline
// data) and handles push + notificationclick. API calls are never cached, so
// they fail cleanly when offline.
const SHELL_CACHE = "okr-shell-v1";

self.addEventListener("install", (event) => {
  // Pre-cache the root document; hashed assets are cached on first fetch.
  event.waitUntil(caches.open(SHELL_CACHE).then((c) => c.add("/")));
  self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((k) => k !== SHELL_CACHE).map((k) => caches.delete(k)))
    )
  );
  self.clients.claim();
});

self.addEventListener("fetch", (event) => {
  const url = new URL(event.request.url);
  // Never cache the API; let it fail cleanly offline (§10.4).
  if (url.pathname.startsWith("/api/")) return;
  if (event.request.method !== "GET") return;

  event.respondWith(
    caches.match(event.request).then((hit) => {
      if (hit) return hit;
      return fetch(event.request)
        .then((resp) => {
          // Cache successful same-origin shell responses.
          if (resp.ok && url.origin === self.location.origin) {
            const copy = resp.clone();
            caches.open(SHELL_CACHE).then((c) => c.put(event.request, copy));
          }
          return resp;
        })
        .catch(() => caches.match("/"));
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
