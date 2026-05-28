const CACHE_NAME = "phishguard-v1";
const URLS_TO_CACHE = [
  "/",
  "/static/manifest.json",
];

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(URLS_TO_CACHE))
  );
});

self.addEventListener("fetch", (event) => {
  event.respondWith(
    caches.match(event.request).then((response) => {
      return response || fetch(event.request).catch(() => {
        return caches.match("/");
      });
    })
  );
});

self.addEventListener("push", (event) => {
  const data = event.data?.json() || { title: "PhishGuard Alert", body: "New threat detected" };
  const options = {
    body: data.body,
    icon: "/static/icons/icon-192x192.png",
    badge: "/static/icons/icon-192x192.png",
    data: { url: data.url || "/" },
  };
  event.waitUntil(self.registration.showNotification(data.title, options));
});

self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  event.waitUntil(clients.openWindow(event.notification.data?.url || "/"));
});
