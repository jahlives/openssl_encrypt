# Plan: Flutter GUI ↔ CLI Feature Sync

Status: draft
Created: 2026-07-24

## Goal

Bring the Flutter desktop GUI (`desktop_gui/`) into feature parity with the live
`openssl-encrypt` CLI. The GUI shells out to the CLI via `lib/cli_service.dart`
(bundled Flatpak binary or `python -m openssl_encrypt.cli`), so each gap is
either UI-only (flag already emitted by `CLIService`) or UI + new `CLIService`
plumbing. This plan covers all three priority tiers agreed in analysis: the
cheap decrypt dead-field fix, missing top-level features (password generation,
secure shred, strength meter, rekey, recovery slots, sign/verify), per-tab flag
gaps (encrypt-tab options, batch-tab parity), and remaining nice-to-haves
(identity flags, analysis/recommendation commands, telemetry opt-out). Only the
*live* CLI surface is targeted — the dead `keystore_cli.py` / `hsm_cli.py` /
`cli_aliases.py` / `create-usb`/`verify-usb`/plugin-mgmt surfaces are excluded.

## Steps

### Tier 1 — highest value-to-effort

- [ ] P1: Decrypt tab exposes widgets for `--with-key` (recipient identity),
      `--verify-from` (signer identity), and `--no-verify` (skip signature,
      behind a warning) — the three fields already passed to `CLIService` but
      never set by any widget become reachable.
      target: desktop_gui/lib/tabs/decrypt_tab.dart
- [ ] P2: `CLIService.generatePassword()` emits the `generate-password`
      char-mode flags (`length`, `--use-lowercase/-uppercase/-digits/-special`).
      target: desktop_gui/lib/cli_service.dart
- [ ] P3: `CLIService.generatePassword()` also supports diceware mode
      (`--dice`, `--dice-count`, `--dice-sep`, `--dice-list`, `--force-wordlist`).
      target: desktop_gui/lib/cli_service.dart
- [ ] P4: New Password Generator screen with char/diceware toggle and a
      NavigationRail entry, calling P2/P3.
      target: desktop_gui/lib/ (new password_generator_screen.dart) + lib/main.dart
- [ ] P5: Generated password can be inserted into the Encrypt and Decrypt
      password fields (copy-to-field action).
      target: desktop_gui/lib/tabs/encrypt_tab.dart, desktop_gui/lib/tabs/decrypt_tab.dart
- [ ] P6: `CLIService.shred()` emits the `shred` command
      (`--input` incl. glob, `--shred-passes`, `--recursive`).
      target: desktop_gui/lib/cli_service.dart
- [ ] P7: New Secure Shred screen (file/glob picker, passes, recursive) with a
      NavigationRail entry and a mandatory irreversible-action confirmation.
      target: desktop_gui/lib/ (new shred_screen.dart) + lib/main.dart
- [ ] P8: `CLIService.checkPassword()` emits `check-password`
      (`--password-policy`, `--strict-strength`, `--json`) and parses the JSON
      strength result.
      target: desktop_gui/lib/cli_service.dart
- [ ] P9: Live password-strength indicator widget driven by P8, shown under the
      password fields in the Encrypt tab, Decrypt tab, and Password Generator.
      target: desktop_gui/lib/ (new strength_meter widget) + encrypt_tab.dart / decrypt_tab.dart

### Tier 2 — parity gaps

- [ ] P10: `CLIService.rekey()` emits the `rekey` command (old-password vs
      `--rekey-password*`, optional `--algorithm`, cascade flags, full hash/KDF
      group, `--password-policy` group).
      target: desktop_gui/lib/cli_service.dart
- [ ] P11: New Rekey screen (change password and/or algorithm on an existing
      file) with a NavigationRail entry, calling P10.
      target: desktop_gui/lib/ (new rekey_screen.dart) + lib/main.dart
- [ ] P12: `CLIService` gains methods for envelope recovery slots:
      `list-recovery`, `add-recovery` (`--add-code`/`--add-passphrase`),
      `recover` (`--recovery-code`/`--recovery-passphrase`), and
      `remove-recovery` (`--slot-id`).
      target: desktop_gui/lib/cli_service.dart
- [ ] P13: New Recovery Slots screen listing/adding/removing recovery slots and
      recovering a file, calling P12.
      target: desktop_gui/lib/ (new recovery_screen.dart) + lib/main.dart
- [ ] P14: Encrypt tab exposes `--shred` + `--shred-passes` to securely wipe the
      source file after a successful encrypt.
      target: desktop_gui/lib/tabs/encrypt_tab.dart, desktop_gui/lib/cli_service.dart
- [ ] P15: Encrypt tab exposes `--random LENGTH` for inline random-password
      generation instead of a typed password.
      target: desktop_gui/lib/tabs/encrypt_tab.dart, desktop_gui/lib/cli_service.dart
- [ ] P16: Encrypt tab exposes OS-keyring store/load (`--keyring-store`,
      `--keyring-load`) with matching `CLIService` plumbing.
      target: desktop_gui/lib/tabs/encrypt_tab.dart, desktop_gui/lib/cli_service.dart
- [ ] P17: Encrypt tab exposes `--pqc-keyfile` and `--pqc-store-key`.
      target: desktop_gui/lib/tabs/encrypt_tab.dart, desktop_gui/lib/cli_service.dart
- [ ] P18: Encrypt tab exposes the hidden/whitened header format
      (`--hidden-header`, `--second-password*` inputs).
      target: desktop_gui/lib/tabs/encrypt_tab.dart, desktop_gui/lib/cli_service.dart
- [ ] P19: Encrypt tab exposes the format-version / KDF-parallelism controls
      (`--independent-xor` vs `--use-xor-composition`, `--parallel-kdf`,
      `--kdf-workers`).
      target: desktop_gui/lib/tabs/encrypt_tab.dart, desktop_gui/lib/cli_service.dart
- [ ] P20: Batch Operations tab gains the KDF config panel present in the
      single-file Encrypt tab.
      target: desktop_gui/lib/main.dart (BatchOperationsTab)
- [ ] P21: Batch Operations tab gains the hash-chain config controls.
      target: desktop_gui/lib/main.dart (BatchOperationsTab)
- [ ] P22: Batch Operations tab gains the HSM/YubiKey config controls.
      target: desktop_gui/lib/main.dart (BatchOperationsTab)
- [ ] P23: Batch Operations tab gains the pepper config controls.
      target: desktop_gui/lib/main.dart (BatchOperationsTab)
- [ ] P24: Batch Operations tab gains the steganography config controls.
      target: desktop_gui/lib/main.dart (BatchOperationsTab)

### Tier 3 — nice-to-have

- [ ] P25: `CLIService.sign()` emits `sign` (`--input`, `--output`,
      `--sign-with`, `--no-armor`) and a standalone Sign screen uses it.
      target: desktop_gui/lib/cli_service.dart + lib/ (new sign_screen.dart)
- [ ] P26: `CLIService.verifySignature()` emits `verify-signature`
      (`--input`, `--signature`, `--signer`, `--json`) and a Verify Signature
      screen uses it.
      target: desktop_gui/lib/cli_service.dart + lib/ (new verify_signature_screen.dart)
- [ ] P27: Create-Identity dialog exposes `--no-touch` (disable HSM touch,
      behind a warning).
      target: desktop_gui/lib/identity_management_screen.dart
- [ ] P28: Import-Contact/identity flow exposes `--allow-key-change` (TOFU
      key-substitution override, behind a warning).
      target: desktop_gui/lib/identity_management_screen.dart
- [ ] P29: Identity/HSM config exposes the PIV slot selector (`--hsm-piv-slot`
      {9a,9c,9d,9e}) alongside the existing YubiKey slot field.
      target: desktop_gui/lib/identity_management_screen.dart, crypto_widgets.dart
- [ ] P30: `CLIService` + new screen for `analyze-security` (hash/KDF/PQC
      parameter analysis, `--output-format`).
      target: desktop_gui/lib/cli_service.dart + lib/ (new analyze_security_screen.dart)
- [ ] P31: `CLIService` + new screen for `analyze-config`
      (`--use-case`, `--compliance-frameworks`, `--output-format`).
      target: desktop_gui/lib/cli_service.dart + lib/ (new analyze_config_screen.dart)
- [ ] P32: `CLIService` + management UI for `template`
      (`list`/`create`/`analyze`/`compare`/`recommend`/`delete`).
      target: desktop_gui/lib/cli_service.dart + lib/ (new templates_screen.dart)
- [ ] P33: `CLIService` + UI for `smart-recommendations` (`get`/`quick`),
      superseding or feeding the existing Recommendation Wizard.
      target: desktop_gui/lib/cli_service.dart + lib/main.dart (InfoTab wizard)
- [ ] P34: Settings gains a telemetry opt-out toggle backed by
      `telemetry status` / `telemetry opt-out`.
      target: desktop_gui/lib/settings_screen.dart, desktop_gui/lib/cli_service.dart

## Open questions

- Security-sensitive flags surfaced here (`--no-verify`, `--no-touch`,
  `--allow-key-change`, `--allow-high-kdf-cost`, `--force-password`,
  `--unsafe-show-secrets`) must carry explicit warnings and route through the
  `security-reviewer` subagent before their commits land. `--unsafe-show-secrets`
  and `--allow-high-kdf-cost` are not in this plan — confirm they should stay
  out of the GUI entirely.
- Per-feature issue tracking + TDD are gated by CLAUDE.md (issue-tracking,
  tdd-workflow, changelog skills). Confirm whether each Pn is one issue/commit,
  or whether tiers are grouped.
- Out-of-scope defects found during analysis, to be filed separately (not GUI
  work): CLI routing table references non-existent parsers for
  `create-usb`/`verify-usb`/plugin-mgmt (`--help` errors); keystore docs point
  to a non-existent `openssl_encrypt.keystore_cli_main` module; stale
  `desktop_gui/TODO.md` (done features listed PENDING) and a leftover 424 KB
  `desktop_gui/lib/main.dart.backup`. Confirm these should become issues.
- P32/P33 (`template`, `smart-recommendations`) are heavy CLI surfaces with many
  subcommands — confirm whether full management UI is wanted or a read-only
  "recommend/get" view is sufficient.
