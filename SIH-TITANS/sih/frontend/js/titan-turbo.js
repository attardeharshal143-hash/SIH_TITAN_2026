// sih/frontend/js/titan-turbo.js
// High-Performance Instant SPA Page Transition Engine for TITAN

(function() {
    // Cache for preloaded HTML pages
    var pageCache = new Map();

    // Prefetch page on hover / touchstart for 0ms perceived latency
    function prefetchPage(url) {
        if (!url || pageCache.has(url) || url.startsWith('#') || url.startsWith('javascript:')) return;
        try {
            var target = new URL(url, window.location.origin);
            if (target.origin !== window.location.origin) return;
            if (!target.pathname.endsWith('.html') && target.pathname !== '/') return;

            fetch(target.href, { priority: 'low' })
                .then(function(r) { return r.text(); })
                .then(function(html) { pageCache.set(target.href, html); })
                .catch(function() {});
        } catch(e) {}
    }

    // Instant Page Swap without full browser teardown
    function navigateTo(url, pushState) {
        if (pushState === undefined) pushState = true;
        var target = new URL(url, window.location.origin);

        // If cached, render in 0ms!
        if (pageCache.has(target.href)) {
            renderPage(pageCache.get(target.href), target.href, pushState);
            return;
        }

        // Show subtle top loading indicator
        var loader = document.getElementById('titan-top-loader');
        if (loader) loader.style.width = '60%';

        fetch(target.href)
            .then(function(r) { return r.text(); })
            .then(function(html) {
                pageCache.set(target.href, html);
                renderPage(html, target.href, pushState);
            })
            .catch(function() {
                window.location.href = url; // Fallback to normal navigation
            });
    }

    function renderPage(html, url, pushState) {
        try {
            var parser = new DOMParser();
            var doc = parser.parseFromString(html, 'text/html');

            var newMain = doc.querySelector('main');
            var currentMain = document.querySelector('main');

            if (!newMain || !currentMain) {
                window.location.href = url;
                return;
            }

            // Update document title
            if (doc.title) document.title = doc.title;

            // Fade transition
            currentMain.style.transition = 'opacity 0.08s ease-out';
            currentMain.style.opacity = '0';

            setTimeout(function() {
                currentMain.innerHTML = newMain.innerHTML;
                currentMain.className = newMain.className;
                currentMain.id = newMain.id;
                currentMain.style.opacity = '1';

                // Scroll to top
                window.scrollTo({ top: 0, behavior: 'instant' });

                // Update active link states in desktop & mobile navs
                updateActiveNavLinks(url);

                if (pushState) {
                    history.pushState({ url: url }, doc.title, url);
                }

                // Execute scripts in the new content
                var scripts = doc.querySelectorAll('script:not([src*="tailwindcss"]):not([src*="titan-turbo"])');
                scripts.forEach(function(s) {
                    var newScript = document.createElement('script');
                    if (s.src) newScript.src = s.src;
                    else newScript.textContent = s.textContent;
                    document.body.appendChild(newScript);
                });

                // Dispatch DOMContentLoaded event so page scripts execute
                document.dispatchEvent(new Event('DOMContentLoaded'));

                var loader = document.getElementById('titan-top-loader');
                if (loader) {
                    loader.style.width = '100%';
                    setTimeout(function() { loader.style.width = '0%'; }, 200);
                }
            }, 80);

        } catch(e) {
            window.location.href = url;
        }
    }

    function updateActiveNavLinks(url) {
        var path = new URL(url, window.location.origin).pathname;
        if (path === '/' || path === '') path = '/index.html';

        document.querySelectorAll('a').forEach(function(a) {
            try {
                var aPath = new URL(a.href, window.location.origin).pathname;
                if (aPath === '/' || aPath === '') aPath = '/index.html';
                
                // Desktop nav pill
                if (a.classList.contains('titan-nav-link')) {
                    if (aPath === path) {
                        a.classList.add('text-primary', 'font-bold', 'bg-primary/10');
                        a.classList.remove('text-on-surface-variant');
                    } else {
                        a.classList.remove('text-primary', 'font-bold', 'bg-primary/10');
                        a.classList.add('text-on-surface-variant');
                    }
                }
            } catch(e) {}
        });
    }

    // Attach click and hover listeners globally
    document.addEventListener('mouseover', function(e) {
        var a = e.target.closest('a');
        if (a && a.href) prefetchPage(a.href);
    });

    document.addEventListener('touchstart', function(e) {
        var a = e.target.closest('a');
        if (a && a.href) prefetchPage(a.href);
    }, { passive: true });

    document.addEventListener('click', function(e) {
        var a = e.target.closest('a');
        if (!a || !a.href) return;
        if (a.target === '_blank' || a.hasAttribute('download') || a.href.includes('/api/')) return;

        try {
            var target = new URL(a.href, window.location.origin);
            if (target.origin !== window.location.origin) return;
            if (target.pathname === window.location.pathname && target.hash) return; // Anchor link

            e.preventDefault();
            navigateTo(a.href, true);
        } catch(err) {}
    });

    window.addEventListener('popstate', function(e) {
        if (e.state && e.state.url) {
            navigateTo(e.state.url, false);
        } else {
            navigateTo(window.location.href, false);
        }
    });

    // Cache current page on startup
    pageCache.set(window.location.href, document.documentElement.outerHTML);
})();
