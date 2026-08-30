// sih/frontend/js/api.js
// Universal API Endpoint Resolver for Vercel + Render Deployment

(function() {
    // 1. Explicit custom URL if injected
    // 2. Saved URL from localStorage
    // 3. If running on Vercel / standalone frontend without backend:
    //    Use configured Render backend or fallback to relative /api
    var savedUrl = localStorage.getItem('TITAN_API_URL');
    
    // Auto-detect environment:
    var isLocalDev = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1';
    var isVercel = window.location.hostname.includes('vercel.app');
    
    var defaultUrl = isLocalDev 
        ? (window.location.origin.includes(':5000') ? window.location.origin : 'http://127.0.0.1:5000')
        : (isVercel ? (savedUrl || window.TITAN_RENDER_BACKEND_URL || window.location.origin) : window.location.origin);

    window.API_BASE_URL = window.CUSTOM_API_URL || savedUrl || defaultUrl;

    window.getApiUrl = function(endpoint) {
        var base = (window.API_BASE_URL || '').replace(/\/+$/, '');
        var path = (endpoint || '').replace(/^\/+/, '');
        return base + '/' + path;
    };

    console.log('[TITAN Core] Active API Base URL:', window.API_BASE_URL);
})();
