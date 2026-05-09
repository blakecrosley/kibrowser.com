// Theme toggle. Initial value is set inline in the document <head>
// (before CSS) so the page paints in the correct mode with no FOUC.
// This file handles the click + the system-preference listener only.

function toggleTheme() {
    var html = document.documentElement;
    var current = html.getAttribute('data-theme') || 'light';
    var next = current === 'dark' ? 'light' : 'dark';
    html.setAttribute('data-theme', next);
    try { localStorage.setItem('theme', next); } catch (e) {}
}

// Track system preference only when the user has not made an explicit choice.
if (window.matchMedia) {
    window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', function (e) {
        try {
            if (localStorage.getItem('theme')) return;
        } catch (err) { return; }
        document.documentElement.setAttribute('data-theme', e.matches ? 'dark' : 'light');
    });
}
