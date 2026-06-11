// Firebase Cloud Messaging Service Worker
importScripts('https://www.gstatic.com/firebasejs/12.14.0/firebase-app-compat.js');
importScripts('https://www.gstatic.com/firebasejs/12.14.0/firebase-messaging-compat.js');

firebase.initializeApp({
  apiKey: "AIzaSyD0xsiPu7wPLvTaS0LWpYqW_4FV0dZJAK4",
  authDomain: "esmil-vision-cs.firebaseapp.com",
  projectId: "esmil-vision-cs",
  storageBucket: "esmil-vision-cs.firebasestorage.app",
  messagingSenderId: "614844430959",
  appId: "1:614844430959:web:44469ac3e8de0b4ca9ab9a",
});

const messaging = firebase.messaging();

// Background message handler
messaging.onBackgroundMessage(function(payload) {
  console.log('[SW] Background message:', payload);
  const data = payload.data || {};
  const notif = payload.notification || {};
  
  self.registration.showNotification(notif.title || '🔔 ESMIL Vision CS', {
    body: notif.body || data.body || 'New CS entry registered.',
    icon: '/static/icon-192.png',
    badge: '/static/icon-96.png',
    tag: 'esmil-cs-' + (data.entryId || Date.now()),
    data: { url: '/', entryId: data.entryId },
    vibrate: [200, 100, 200],
    requireInteraction: false,
  });
});

// Click → open app
self.addEventListener('notificationclick', function(event) {
  event.notification.close();
  const url = (event.notification.data && event.notification.data.url) || '/';
  event.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then(function(list) {
      for (var c of list) {
        if (c.url.includes(self.location.origin)) { c.focus(); return; }
      }
      return clients.openWindow(url);
    })
  );
});
