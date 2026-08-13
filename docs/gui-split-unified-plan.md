# Plan: split the desktop GUI into its own project + unify it (capability-gated)

Status: draft
Created: 2026-08-12

## Goal

The Flutter desktop GUI (`desktop_gui/`) is maintained per CLI branch and the two
copies have diverged, features drift (1.4.9 GUI is missing the encrypt-metadata
options and the second-password path for decrypting metadata), and GUI readiness
gates otherwise-ready CLI releases. Move the GUI into its own repository as one
unified codebase that adapts to whatever CLI it is paired with via runtime
capability detection (a `crypt capabilities --json` manifest; version-string
sniffing only as a fallback). This lets CLI security/patch releases ship on their
own cadence, hides features a CLI line no longer advertises without a per-version
GUI fork, and collapses two divergent GUIs into one. The runtime coupling is
already a clean subprocess boundary, `--gui` is already a launcher for a pre-built
bundle, and the Flatpak is already multi-module consuming a pre-built GUI, so the
split formalizes a separation that half-exists.

## Steps

- [x] P1: Add a `crypt capabilities --json` subcommand emitting a stable
  `{schema_version, cli_version, line, commands[], features{}, json_endpoints[]}`
  document that carries no secret-valued fields.
  target: openssl_encrypt/modules/crypt_cli.py, openssl_encrypt/modules/capabilities.py (new)
- [x] P2: Derive the manifest's `commands`/`features` from the CLI's actually
  registered subcommands/flags (plus a small curated feature overlay) so it cannot
  drift from what the CLI really supports.
  target: openssl_encrypt/modules/capabilities.py
- [x] P3: TDD the manifest: lists exactly the registered commands, is valid JSON,
  contains no secret-valued fields, and reflects line-specific feature removal
  (e.g. stego absent on 1.5.x, present on 1.4.x).
  target: openssl_encrypt/unittests/test_capabilities_manifest.py (new)
- [x] P4: Land the capability endpoint on BOTH branches with the full workflow
  (public feature issue, four changelog files, security-reviewer secret-leak lens,
  commit + push origin) — it is useful and backportable regardless of the split.
  DONE 2026-08-12: feature/v1.4.x-development a2918f19 (targets 1.4.10; 1.4.9
  releases as-is) and feature/v1.5.x-development e963c32b (targets 1.5.0);
  gitlab#265 / github#140; four changelog files each line; security-reviewer
  clean on both (no secret-leak/crypto findings). Verified: line=1.4.x stego
  present, line=1.5.x stego absent. The GUI-repo plan doc was NOT copied onto the
  maintenance branches (working-tracking artifact stays on this branch/main).
  target: openssl_encrypt/ (both branches)
- [x] P5: Extract `desktop_gui/` from feature/v1.4.x-development (the superset copy)
  into a new `openssl_encrypt_gui` repo via `git subtree split --prefix=desktop_gui`,
  preserving commit history. DONE 2026-08-12: world/openssl_encrypt_gui main @ d1f2eccb,
  142 commits preserved. NOTE: a pre-existing nested `desktop_gui/desktop_gui/linux`
  cruft dir came across faithfully — clean it during unification (P9/P10), not by
  rewriting history.
  target: new repo openssl_encrypt_gui
- [x] P6: Stand up GUI-repo CI: `flutter analyze`, `flutter test`, and a Linux
  release build that produces the bundle artifact.
  target: openssl_encrypt_gui/.gitlab-ci.yml (or equivalent)
- [x] P7: Produce a divergence audit listing every screen/widget/flag present in the
  1.4.x GUI and not the 1.5.x GUI (and vice versa), written down BEFORE either copy
  is deleted from the CLI repo.
  target: docs/ (audit note)
- [x] P8: In the unified GUI, query the P1 capability manifest once at startup, cache
  it, and gate each screen/option on a feature flag (unknown/absent → hidden).
  target: openssl_encrypt_gui/lib/cli_service.dart (+ screen widgets)
- [x] P9: Fold every feature from the P7 divergence audit into the unified GUI as the
  gated superset (stego panel only when `features.stego`, recovery-slots only when
  `features.recovery_slots`, dek-slot-binding-aware messaging when
  `features.dek_slot_binding`, etc.). DONE: A-only screens nav-gated in P8;
  stego Encrypt-block + Decrypt extract-card gated on `features.steganography`
  (GUI 2abb5e3); `identity import` protocol reconciled via a capability-gated
  argv builder — stdin+alias (1.4.x, `--data-stdin`) vs 0600 temp-file `--file`
  (1.5.x), private-key pre-check, fail-open to stdin (GUI faa5f25). Batch
  remote-pepper was already present on base=A (no regression to reconcile).
  target: openssl_encrypt_gui/lib/
- [x] P10: Build the currently-missing features once in the unified GUI: the
  encrypt-metadata options and the second-password path for decrypting metadata
  (plus anything else P7 surfaces).
  target: openssl_encrypt_gui/lib/tabs/ (+ related screens)
- [x] P11: Replace the hardcoded CLI paths in the GUI with a discovery routine:
  Flatpak `/app/bin/openssl-encrypt` → `$OPENSSL_ENCRYPT_CLI` → PATH → configured
  path → dev fallback, surfacing a clear "CLI not found / too old" state. DONE
  (GUI deffb47): `resolveCliInvocation()` with priority `$OPENSSL_ENCRYPT_CLI` →
  Flatpak `/app/bin/openssl-encrypt` → PATH → dev `python -m openssl_encrypt.cli`
  from `$OPENSSL_ENCRYPT_DEV_DIR`; hardcoded `/home/work/...` paths removed.
  target: openssl_encrypt_gui/lib/cli_service.dart
- [x] P12: Update the CLI-side `--gui` launcher to resolve an INSTALLED GUI (Flatpak
  app, known install dir, `$OPENSSL_ENCRYPT_GUI`, PATH) and, when absent, print
  "install the separate GUI app / Flatpak" instead of pointing at `desktop_gui/build`.
  target: openssl_encrypt/cli.py (`_resolve_gui_command`)
- [x] P13: Move the Flatpak manifest into the GUI repo; its GUI module pulls the GUI
  repo's released bundle artifact and its CLI module pins a specific CLI release, so
  the Flatpak tag is the CLI×GUI pairing record.
  target: openssl_encrypt_gui/flatpak/ (moved from CLI repo)
- [x] P14: Remove the in-tree pre-built-GUI copy step from the CLI repo's Flatpak
  manifest and update CLI-repo docs/references to point at the GUI repo as the source
  of the GUI + Flatpak.
  target: flatpak/com.opensslencrypt.OpenSSLEncrypt.json, CLI repo docs
- [x] P15: Add a contract-test matrix in the GUI repo running the CLIService
  integration tests against pinned CLI releases {latest 1.4.x, latest 1.5.x, and a
  pre-capabilities "too old" CLI}, plus a CI check that fails a CLI change dropping a
  manifest field without a corresponding capability flag.
  target: openssl_encrypt_gui/ (contract tests), CLI repo CI

## Open questions

- Capability-manifest granularity: coarse command + feature booleans to start, or a
  richer schema also carrying per-flag support and JSON-endpoint field lists?
  (`schema_version` allows later growth.)
- How much of the manifest can be introspected from the CLI's parser registration vs.
  a curated overlay — confirm the parser is introspectable enough that the manifest
  cannot lie.
- Minimum CLI version the unified GUI supports (the first release carrying
  `crypt capabilities --json`) and the fallback below it (version-string heuristic vs.
  a hard "please upgrade the CLI" screen).
- Whether the Flatpak lives in the GUI repo (plan's assumption) or a dedicated
  packaging repo if CLI-pinning logic grows.
- Keep the legacy tkinter `--gui-legacy` in the CLI (in-tree Python) or retire it as
  part of this work.
- Whether the split also formalizes Windows/macOS GUI builds or stays Linux-first for
  now.

## Status log

- **P12** DONE 2026-08-12 (CLI f1cb0231): `_resolve_gui_command` resolves an INSTALLED GUI (override -> known install path incl. in-Flatpak -> Flatpak app -> `openssl-encrypt-gui` on PATH); not-found points at the separate app/Flatpak; in-tree bundle path dropped. TDD test_gui_launch.py.
- **P13** DONE 2026-08-12 (GUI 6621d9a): flatpak/ in the GUI repo — manifest with a PyPI-pinned CLI module (openssl_encrypt==1.4.9) + GUI module from build-linux bundle; launcher/desktop/metainfo; `package`-stage flatpak-build CI job. NOT built end-to-end here (needs real flatpak-builder pass — see flatpak/README.md).
- **P14** DONE 2026-08-12 (CLI 70d5b412): removed desktop_gui/ (91 files), the flatpak flutter-desktop-gui module, the two CLI-repo GUI-lint tests + gui_test_utility, the CI flatpak build/publish jobs, and the build-flatpak.sh --build-flutter path; docs point at the GUI repo. CLI repo builds the CLI only.
- **P15** DONE 2026-08-12: CLI-repo drift guard pins the manifest top-level + feature vocabularies (test_capabilities_manifest.py, CLI 0f548766); GUI-repo contract test runs the REAL CLI + CI matrix over pinned releases 1.4.9/1.4.8 (GUI 32d4dee).

## Real-flatpak validation + follow-up fixes (2026-08-12)

The Flatpak (P13) was built end-to-end on a real `flatpak-builder` and the GUI run,
which surfaced issues the sandbox could not:

- **CLI source PyPI -> git tag** (GUI b4e2ff0): 1.4.9 was never uploaded to public
  PyPI (latest there is 1.4.8), so the `openssl_encrypt==1.4.9` pin did not resolve.
  The `openssl-encrypt` module now sources the CLI from the git **tag `v1.4.9`**
  (commit `a9838a0b`) and builds it (maturin Threefish + `pip install --no-deps .`).
- **App icon** (GUI 1bdced8): `appstreamcli compose` failed `icon-not-found`; added
  `flatpak/com.opensslencrypt.OpenSSLEncrypt.svg` and install it unconditionally.
- **Decrypt of hidden-header/binary files** (GUI c3d1e71): the GUI read the encrypted
  file via `File.readAsString()` (UTF-8), which threw "Could not read file" for a
  whitened (binary) file. Decrypt now hands the CLI the real file path (`-i <path>`),
  binary-safe; the CLI self-resolves the HSM plugin + slot from metadata.
- **YubiKey touch prompt in the GUI** — two fixes: (A) CLI-side, the CR plugin now
  echoes "Touch your Yubikey" to stderr when `tty_write` reaches a real terminal
  (openssl_encrypt 1.4.x `c97e32de` -> 1.4.10, 1.5.x `5463f0de` -> 1.5.0;
  security-reviewer CLEAN); (B) GUI-side, file-mode decrypt now enables the stderr
  touch-prompt detection (GUI 657611a) that the binary-safe change had disabled.
  Verified end-to-end: "Please touch your YubiKey..." now shows in the GUI.

## Post-release cleanup (do when 1.4.10 ships)

- **Repin the Flatpak CLI** on `openssl_encrypt_gui` `main`:
  `flatpak/com.opensslencrypt.OpenSSLEncrypt.json` -> change the `openssl-encrypt`
  module's git source from `tag v1.4.9` / `commit a9838a0b` to `v1.4.10` (tag +
  commit). That is the released CLI carrying the touch-prompt echo, so the whole
  flow works from `main` with no dev pin.
- **Delete the throwaway test branch** used to preview the touch prompt before 1.4.10:
  `git push origin --delete test/cli-1.4.x-dev-pin` (GUI repo). It pins the CLI to
  the 1.4.x dev commit `c97e32de` and merges `main`'s GUI fix; `main` was never
  changed to a dev pin.
- **Add latest 1.5.x** to the GUI contract-test matrix (`.gitlab-ci.yml` `contract:`)
  once 1.5.0 is published.
