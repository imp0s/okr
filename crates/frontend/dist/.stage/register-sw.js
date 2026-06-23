// Registers the service worker (spec §10.4). External module so the strict CSP
// (no inline scripts) is respected.
if ("serviceWorker" in navigator) {
  window.addEventListener("load", () => {
    navigator.serviceWorker.register("/sw.js").catch(() => {
      /* offline registration failure is non-fatal */
    });
  });
}
