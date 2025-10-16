// -------------------------------------------------------------
// 🌟 VIDYARI - Firebase Messaging Service Worker
// Supports: logo.svg, banner image, deep-link redirects
// -------------------------------------------------------------

importScripts("https://www.gstatic.com/firebasejs/12.4.0/firebase-app-compat.js");
importScripts("https://www.gstatic.com/firebasejs/12.4.0/firebase-messaging-compat.js");

// ✅ Initialize Firebase (same as frontend)
firebase.initializeApp({
  apiKey: "AIzaSyCewKKaSGXDAiBPQRYqOtFJ_DV6A-OborA",
  authDomain: "vidyari-notification.firebaseapp.com",
  projectId: "vidyari-notification",
  storageBucket: "vidyari-notification.firebasestorage.app",
  messagingSenderId: "1061582963767",
  appId: "1:1061582963767:web:f97da1a865022e6d172bb2",
});

const messaging = firebase.messaging();

// -------------------------------------------------------------
// 📩 Handle background notifications
// -------------------------------------------------------------
messaging.onBackgroundMessage((payload) => {
  console.log("📨 Background message received:", payload);

  const n = payload.notification || {};
  const d = payload.data || {};

  // 🔹 Extract message fields safely
  const title = n.title || d.title || "Vidyari Notification";
  const body = n.body || d.body || "You have a new update!";
  const icon = "https://www.vidyari.com/images/logo.png"; // ✅ Your Vidyari logo (SVG)
  const badge = "https://www.vidyari.com/images/logo.png"; // ✅ Shown on Android notification bar
  const image = n.image || d.image || d.imageUrl || ""; // Optional banner
  const clickUrl = d.url || d.target_link || "/"; // Destination page

  // 🔹 Notification UI
  const notificationOptions = {
    body,
    icon,
    badge,
    image,
    vibrate: [100, 50, 100],
    requireInteraction: false,
    data: {
      url: clickUrl,
      ...d,
    },
  };

  self.registration.showNotification(title, notificationOptions);
});

// -------------------------------------------------------------
// 🖱️ Handle clicks on notification
// -------------------------------------------------------------
self.addEventListener("notificationclick", (event) => {
  event.notification.close();

  const urlToOpen = new URL(event.notification.data?.url || "/", self.location.origin).href;

  event.waitUntil(
    (async () => {
      const allClients = await clients.matchAll({ type: "window", includeUncontrolled: true });

      // Focus if already open
      for (const client of allClients) {
        if (client.url === urlToOpen) return client.focus();
      }

      // Otherwise, open a new tab
      if (clients.openWindow) await clients.openWindow(urlToOpen);
    })()
  );
});

