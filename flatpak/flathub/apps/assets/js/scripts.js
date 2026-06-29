// Flatpak installation handler
function installFlatpak(appId) {
    // Try the flatpak: protocol first
    window.location.href = 'flatpak:' + appId;

    // Fallback: show manual installation instructions, pinned to the current
    // stable version when it is known (see version injection below).
    setTimeout(function () {
        var ref = (typeof window.latestStableRef === 'function')
            ? window.latestStableRef(appId)
            : appId;
        alert('If the automatic installation didn\'t work, run this command:\n\nflatpak install openssl-encrypt ' + ref);
    }, 1000);
}

// Pin the flatpak install commands to the current stable version.
// The version is derived at runtime from the changelog page's
// "Latest: X.Y.Z (Stable)" line, so the commands stay correct with no manual
// edits each release. If the changelog cannot be fetched (e.g. the page is
// opened via file://), the commands gracefully stay unversioned, which still
// installs the latest build.
(function () {
    var APP_ID = 'com.opensslencrypt.OpenSSLEncrypt';
    var BRANCH_SUFFIX = '-stable';

    function makeRef(version, appId) {
        return (appId || APP_ID) + '//' + version + BRANCH_SUFFIX;
    }

    function parseVersion(html) {
        var m = html.match(/Latest:<\/strong>\s*([0-9]+\.[0-9]+\.[0-9]+)\s*\(Stable\)/i);
        return m ? m[1] : null;
    }

    function inject(version) {
        if (!version) { return; }
        // Expose a helper the install-button fallback alert can use.
        window.latestStableRef = function (appId) { return makeRef(version, appId); };
        // Rewrite any flatpak install command that targets the app id and is
        // not already versioned.
        var pres = document.getElementsByTagName('pre');
        for (var i = 0; i < pres.length; i++) {
            var text = pres[i].textContent;
            if (text.indexOf('flatpak install') !== -1 &&
                text.indexOf(APP_ID) !== -1 &&
                text.indexOf(APP_ID + '//') === -1) {
                pres[i].textContent = text.replace(APP_ID, makeRef(version));
            }
        }
    }

    function tryFetch(paths, idx) {
        if (idx >= paths.length || typeof fetch !== 'function') { return; }
        fetch(paths[idx])
            .then(function (resp) { return resp.ok ? resp.text() : Promise.reject(); })
            .then(function (html) {
                var v = parseVersion(html);
                if (v) { inject(v); } else { tryFetch(paths, idx + 1); }
            })
            .catch(function () { tryFetch(paths, idx + 1); });
    }

    function start() {
        // changelog.html is a sibling on the app page, and under
        // apps/openssl-encrypt/ from the landing page.
        tryFetch(['changelog.html', 'apps/openssl-encrypt/changelog.html'], 0);
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', start);
    } else {
        start();
    }
})();
