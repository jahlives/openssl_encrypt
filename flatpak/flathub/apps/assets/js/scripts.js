// Shared by BOTH Flatpak apps' pages (CLI-only and GUI+CLI) and the landing
// page. This file is deployed from both the openssl_encrypt and
// openssl_encrypt_gui repositories into the same server directory — keep the
// two copies identical.

// Per-app config: remote (repo) name, changelog location relative to the site
// root, and the flatpak-branch scheme derived from the changelog's
// "Latest: <version> (Stable)" line:
//   suffix '-stable': CLI releases use branch <version>-stable
//   suffix '':        the GUI app's branch IS the pairing version (X.Y.Z-cliA.B.C)
var FLATPAK_APPS = {
    'com.opensslencrypt.OpenSSLEncrypt': {
        repo: 'openssl-encrypt',
        changelog: 'apps/openssl-encrypt/changelog.html',
        suffix: '-stable'
    },
    'com.opensslencrypt.OpenSSLEncryptGui': {
        repo: 'openssl-encrypt-gui',
        changelog: 'apps/openssl-encrypt-gui/changelog.html',
        suffix: ''
    }
};

// Flatpak installation handler
function installFlatpak(appId) {
    // Try the flatpak: protocol first
    window.location.href = 'flatpak:' + appId;

    // Fallback: show manual installation instructions, pinned to the current
    // stable version when it is known (see version injection below).
    setTimeout(function () {
        var app = FLATPAK_APPS[appId] || {};
        var ref = app.latestRef || appId;
        var repo = app.repo || 'openssl-encrypt';
        alert('If the automatic installation didn\'t work, run this command:\n\nflatpak install ' + repo + ' ' + ref);
    }, 1000);
}

// Pin the flatpak install commands to the current stable version.
// The version is derived at runtime from each app's changelog page
// "Latest: X.Y.Z (Stable)" line, so the commands stay correct with no manual
// edits each release. If a changelog cannot be fetched (e.g. the page is
// opened via file://), the commands gracefully stay unversioned, which still
// installs the latest build.
(function () {
    // Match the app id NOT followed by more id characters, so the CLI id
    // (a prefix of the GUI id) never matches the GUI id's occurrences.
    function idPattern(appId) {
        return new RegExp(appId.replace(/\./g, '\\.') + '(?![A-Za-z0-9])');
    }

    function makeRef(appId, version) {
        return appId + '//' + version + FLATPAK_APPS[appId].suffix;
    }

    function parseVersion(html) {
        // Accepts plain versions (1.4.8) and pairing versions (1.0.0-cli1.4.9).
        var m = html.match(/Latest:<\/strong>\s*([0-9][^<\s]*?)\s*\(Stable\)/i);
        return m ? m[1] : null;
    }

    function inject(appId, version) {
        if (!version) { return; }
        // Remember the versioned ref for the install-button fallback alert.
        FLATPAK_APPS[appId].latestRef = makeRef(appId, version);
        // Rewrite any flatpak install command that targets the app id and is
        // not already versioned.
        var pattern = idPattern(appId);
        var pres = document.getElementsByTagName('pre');
        for (var i = 0; i < pres.length; i++) {
            var text = pres[i].textContent;
            if (text.indexOf('flatpak install') !== -1 &&
                pattern.test(text) &&
                text.indexOf(appId + '//') === -1) {
                pres[i].textContent = text.replace(pattern, makeRef(appId, version));
            }
        }
    }

    function changelogCandidates(appId) {
        // On the app's own page its changelog is a sibling; from the landing
        // page (site root) the root-relative path works; from the OTHER app's
        // page fall back to stepping out of apps/<name>/.
        var app = FLATPAK_APPS[appId];
        var dir = app.changelog.slice(0, app.changelog.lastIndexOf('/'));
        if (window.location.pathname.indexOf('/' + dir + '/') !== -1) {
            return ['changelog.html'];
        }
        return [app.changelog, '../../' + app.changelog];
    }

    function pageMentions(appId) {
        var pattern = idPattern(appId);
        var pres = document.getElementsByTagName('pre');
        for (var i = 0; i < pres.length; i++) {
            if (pattern.test(pres[i].textContent)) { return true; }
        }
        return false;
    }

    function tryFetch(appId, paths, idx) {
        if (idx >= paths.length || typeof fetch !== 'function') { return; }
        fetch(paths[idx])
            .then(function (resp) { return resp.ok ? resp.text() : Promise.reject(); })
            .then(function (html) {
                var v = parseVersion(html);
                if (v) { inject(appId, v); } else { tryFetch(appId, paths, idx + 1); }
            })
            .catch(function () { tryFetch(appId, paths, idx + 1); });
    }

    function start() {
        for (var appId in FLATPAK_APPS) {
            // Only resolve versions for apps actually offered on this page.
            if (pageMentions(appId)) {
                tryFetch(appId, changelogCandidates(appId), 0);
            }
        }
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', start);
    } else {
        start();
    }
})();
