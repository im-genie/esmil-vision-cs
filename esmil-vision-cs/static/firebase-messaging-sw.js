/* Firebase Cloud Messaging service worker — handles background push */
importScripts('https://www.gstatic.com/firebasejs/10.12.0/firebase-app-compat.js');
importScripts('https://www.gstatic.com/firebasejs/10.12.0/firebase-messaging-compat.js');

firebase.initializeApp({
  apiKey: "AIzaSyD0xsiPu7wPLvTaS0LWpYqW_4FV0dZJAK4",
  authDomain: "esmil-vision-cs.firebaseapp.com",
  projectId: "esmil-vision-cs",
  storageBucket: "esmil-vision-cs.firebasestorage.app",
  messagingSenderId: "614844430959",
  appId: "1:614844430959:web:44469ac3e8de0b4ca9ab9a",
});

var messaging = firebase.messaging();

// Background (app closed / phone locked) — data-only messages build the notification here
messaging.onBackgroundMessage(function (payload) {
  var d = payload.data || {};
  var title = d.title || '\uD83D\uDD14 New Entry';
  var body  = d.body  || '';
  self.registration.showNotification(title, {
    body: body,
    icon: '/static/icon-192.png',
    badge: '/static/icon-192.png',
    tag: d.entryId || 'vision-cs',
    vibrate: [200, 100, 200],
    data: d,
  });
});

// Tap notification → focus or open the app
self.addEventListener('notificationclick', function (event) {
  event.notification.close();
  event.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then(function (list) {
      for (var i = 0; i < list.length; i++) {
        if ('focus' in list[i]) return list[i].focus();
      }
      if (clients.openWindow) return clients.openWindow('/');
    })
  );
});
