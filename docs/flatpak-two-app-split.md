# Plan: split the Flatpak into two apps — CLI-only and GUI+CLI

Status: done
Created: 2026-08-12

## Goal

The desktop GUI and its Flatpak already moved to their own repo
(`openssl_encrypt_gui`) as a combined GUI+CLI Flatpak, but that Flatpak currently
REUSES the CLI's Flatpak identity (`app-id com.opensslencrypt.OpenSSLEncrypt`,
repo path `apps/openssl-encrypt/`), so their metainfo / changelog / versioning
mix. Split into TWO distinct Flatpak apps: (1) a **CLI-only** Flatpak that
encapsulates liboqs + liboqs-python + all build deps (so CLI users don't build
from source — the main reason to ship it even though most CLI users pip-install),
keeping the original id/path; (2) the **GUI+CLI** Flatpak under a NEW app-id and
its own repo path. Distinct ids give each app its own metainfo/changelog, which
is the cleanup that motivated this.

Decision (2026-08-12): going with two apps. CLI-only stays the original identity;
the GUI app takes a new identity.

## Steps

### App 1 — CLI-only Flatpak (stays in `openssl_encrypt`)

- [x] P1: Confirm the CLI-repo manifest is a complete CLI-only app after the P14
  GUI-module removal (builds the CLI + liboqs/pcsc/python deps + Threefish; no
  Flutter; `command` is the CLI) and builds/runs standalone.
  target: openssl_encrypt/flatpak/com.opensslencrypt.OpenSSLEncrypt.json
  DONE 2026-08-12 (1.4.x ac59c451 / 1.5.x c8ba14b1, gitlab#267 gh#142): manifest
  confirmed CLI-only and CLEANED: dropped GUI-only finish-args (x11/wayland/dri/
  ipc/at-spi/a11y/talk-names/GDK_BACKEND — CLI never touches a display) + the
  no-op x11-tools module; launcher --gui now points at the GUI app instead of
  exec'ing a missing bundle; desktop entry runs the CLI in a terminal;
  build-flatpak.sh no longer advertises --build-flutter. VALIDATED 2026-08-13
  (user, real flatpak-builder, 1.5.x line / branch 1.5.0-dev): builds, runs
  under the old id, and --gui prints the pointer to the separate GUI app.
- [x] P2: Revive the CLI-repo Flatpak build+deploy that P14 removed — restore the
  CI `flatpak-build`/`flatpak-publish` jobs (CLI-only, no Flutter step); the
  `build-flatpak.sh` / `build-remote.sh` in that repo already target the CLI-only
  manifest (build-flatpak's `--build-flutter` correctly errors there).
  target: openssl_encrypt/.gitlab-ci.yml, openssl_encrypt/flatpak/build-*.sh
  DONE 2026-08-12 (same commits): flatpak-build[:clean]/flatpak-publish[:clean]
  restored from the P14 removal, minus the Flutter toolchain; rules/caches/
  signing/rsync flow unchanged.
- [x] P3: Keep `app-id com.opensslencrypt.OpenSSLEncrypt`, repo path
  `apps/openssl-encrypt/`, and the existing CLI-centric metainfo + flathub
  changelog (now correct, since this app IS the CLI). Existing installs upgrade
  in place; no id change.
  target: openssl_encrypt/flatpak/ (metainfo.xml, .desktop, flathub/)
  DONE 2026-08-12 (same commits): id/path kept; shared landing index.html +
  apps/assets mirrored BYTE-IDENTICAL from this repo (they list both apps —
  keep them in sync across repos on every change); CLI app page made
  CLI-centric with a pointer to the GUI app; four changelog files updated
  (1.4.10 / 1.5.0).

### App 2 — GUI+CLI Flatpak (in `openssl_encrypt_gui`)

- [x] P4: Pick the GUI app-id (see Open questions) and rename to it: the manifest
  file, the `.desktop`, the `.metainfo.xml`, the `.svg` icon, and the
  `openssl-encrypt-gui-launcher` install paths / desktop `Icon=`.
  target: openssl_encrypt_gui/flatpak/
- [x] P5: Point the GUI Flatpak at its own repo path/name in the deploy script:
  `REPO_NAME` (openssl-encrypt-gui), `SERVER_REPO` (`apps/openssl-encrypt-gui`),
  the generated `.flatpakrepo` Title/Url, and any app-id references in
  `pairing-version.sh` (the manifest filename it parses) and both build scripts.
  target: openssl_encrypt_gui/flatpak/build-remote.sh, build-flatpak.sh, pairing-version.sh
  NOTE (done 2026-08-12): `SERVER_REPO` in the actual script is the server's
  shared ostree repo `/var/www/flatpak-repo`, not an `apps/...` path — left
  unchanged (shared-repo open question below). The `apps/openssl-encrypt/`
  path exists only in the flathub web files (`flathub/index.html`,
  `apps/assets/js/scripts.js` APP_ID + changelog fetch path), which still
  advertise the OLD id — folded into the deferred P7 web/changelog decision.
  `.flatpakrepo` Url also unchanged (same shared repo); Title now
  "OpenSSL Encrypt GUI Repository".
- [x] P6: Update the manifest internals that embed the app-id: `app-id`,
  `command`, `finish-args` (PYTHONPATH is fine), the GUI/CLI module `post-install`
  install targets, and the desktop/metainfo/icon install lines.
  target: openssl_encrypt_gui/flatpak/<new-id>.json (renamed)
  NOTE (done 2026-08-12): only `app-id` was left to change — `command` is the
  id-free `openssl-encrypt-gui-launcher`, finish-args/post-install embed no id,
  and the desktop/metainfo/icon install lines were already updated in P4.
  flatpak/README.md references updated alongside. The renamed app has NOT yet
  been rebuilt/validated with flatpak-builder under the new id.
- [x] P7: The metainfo `<releases>` is already reset to a pairing entry
  (`1.0.0-cli1.4.9`). The flathub `changelog.html` (still the copied CLI
  changelog) becomes GUI-app-specific under the new id — reset/repoint it.
  DECIDED+DONE 2026-08-12: dedicated GUI-only changelog (pairing-versioned,
  starts fresh at 1.0.0-cli1.4.9; links to the CLI changelog for the bundled
  CLI's history). Web dir renamed apps/openssl-encrypt/ → apps/openssl-encrypt-gui/;
  app index.html rewritten for the GUI app (version, install commands, features,
  migration section, GUI-repo service desk issue+world-openssl-encrypt-gui-28-…).
  SHARED-FILES RULE: the landing index.html + apps/assets/* are deployed by BOTH
  repos into the same server dir (last writer wins) — they now list BOTH apps
  and must be kept byte-identical in the CLI repo (mirrored there in P3);
  scripts.js is two-app aware (per-app repo name, changelog path, branch scheme:
  CLI `<ver>-stable` vs GUI pairing-as-branch).
  target: openssl_encrypt_gui/flatpak/flathub/
- [x] P8: Record the migration note: the current GUI Flatpak (installed under
  `com.opensslencrypt.OpenSSLEncrypt`) is orphaned by the id change — users
  reinstall the new id once; the CLI-only app takes over the old id/path.
  DONE 2026-08-12: recorded in flatpak/README.md ("App identity & migration"),
  on the landing page's GUI card, and as a "Migrating from the old combined
  package" section on the GUI app page (uninstall old id → install new id).

## Open questions

- **GUI app-id: DECIDED 2026-08-12** — `com.opensslencrypt.OpenSSLEncryptGui`
  (repo path `apps/openssl-encrypt-gui/`, `.flatpakrepo` name `openssl-encrypt-gui`).
  This choice drives P4–P6. Tracked as gitlab openssl_encrypt_gui#2 /
  github openssl_encrypt#141.
- Revive the CLI-only Flatpak deploy (App 1 / P2) now, or later? It is
  independent of App 2.
- Reset the flathub `changelog.html` for the GUI app (P7) — deferred; user wants
  to think about the changelog approach more deeply.
- ~~Share the same GPG signing key and `LOCAL_REPO` for both apps, or separate
  per-app repos/keys?~~ **DECIDED 2026-08-13: shared** — one GPG key and one
  shared LOCAL_REPO/server ostree repo for both apps (the current script
  state; both `.flatpakrepo` files point at the same signed repo).

## Context / current state (2026-08-12)

- GUI split plan P1–P15 is complete on both CLI lines; see
  `gui-split-unified-plan.md`.
- The GUI+CLI Flatpak builds and runs end-to-end from `openssl_encrypt_gui`
  (validated on a real flatpak-builder); it pins the CLI via git tag `v1.4.9`
  (commit a9838a0b) and bundles this repo's Flutter build.
- The Flatpak build/deploy scripts were ported to `openssl_encrypt_gui/flatpak/`
  (`pairing-version.sh`, `build-flatpak.sh`, `build-remote.sh`, `flathub/`);
  version tracks the CLI×GUI pairing (branch + metainfo `1.0.0-cli1.4.9`).
- The CLI-side touch-prompt-to-stderr fix is on both CLI dev lines
  (1.4.x c97e32de → 1.4.10, 1.5.x 5463f0de → 1.5.0); the GUI Flatpak on `main`
  still pins released `v1.4.9`, with a throwaway `test/cli-1.4.x-dev-pin` branch
  pinning the dev CLI for previewing the touch prompt.
