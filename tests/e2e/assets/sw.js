
self.addEventListener('install', function (event) {
    console.log('Sovereign Test Worker Installing');
});

self.addEventListener('fetch', function (event) {
    console.log('Fetching:', event.request.url);
});
