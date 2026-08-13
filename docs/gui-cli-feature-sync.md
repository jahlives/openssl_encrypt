# Plan: Flutter GUI ↔ CLI Feature Sync

Status: draft
Created: 2026-07-24

## Progress (autonomous run, 2026-07-24)

Branches: `feature/gui-decrypt-asym-fields` (P1), `feature/generate-password-json`
(CLI enabler for P2), `feature/gui-cli-sync` (P4+ GUI features, stacked one
commit per feature off the P1 branch). All Dart is committed but **not compiled
or tested here** (no Flutter toolchain) — run `flutter analyze && flutter test`.

- **P1 — DONE** (`feature/gui-decrypt-asym-fields`): decrypt asymmetric fields wired; security review MEDIUM+2 LOW fixed. gitlab#137/gh#55.
  **Correction (2026-08-07):** the identity selector this delivered could
  never have populated — `CLIService.listIdentities()` called
  `identity list --json`, a flag that did not exist, and swallowed the
  failure into an empty list (gitlab#183, fixed). The widgets were right;
  the data never arrived. A GUI feature is not verified until it has been
  driven against the real CLI, which is also why nothing in this plan was
  ever compiled or run — see the stopping-point note.
- **P2 — DONE, scope grew to a CLI change**: `generate-password` had no machine-readable output (password only on stderr behind a 10s timeout), so added `generate-password --json` on `feature/generate-password-json` (gitlab#138/gh#59… gh#56), then `CLIService.generatePassword()` consumes it. Full pytest run: no regressions.
- **P3 — DONE**: diceware supported in `CLIService.generatePassword()` and the generator screen (per explicit user request).
- **P4 — DONE** (gitlab#139/gh#57): Password Generator screen. **Remark:** added to **Pro mode only**; not added to Simple mode (kept deliberately minimal). Security review MEDIUM (password leaked to debug log via `_runCLICommand` dev-path stdout dump) + LOW fixed.
- **P5 — PARTIAL**: generated password gets **copy-to-clipboard**. **Remark/deferred:** direct insertion into the Encrypt/Decrypt password fields (cross-tab) not done — needs shared-state plumbing across independent tab widgets; clipboard covers the immediate need. Optional future: clipboard auto-clear timer.
- **P6/P7 — DONE** (gitlab#140/gh#58): Secure Shred screen + `CLIService.shred()`, mandatory confirmation. Security review MEDIUM fixed: CLI globs `-i`, so GUI now escapes glob metacharacters (glob.escape equivalent) so confirmed target == deleted target. **Remark:** a durable CLI-side `shred --no-glob`/literal mode is recommended future hardening for all callers.
- **P8/P9 — DONE** (gitlab#141/gh#59): `CLIService.checkPassword()` (password via stdin) + live strength meter widget. **Remark/deviation from plan:** meter placed on the **Encrypt tab only**. Decrypt tab omitted (entering an existing password — strength is not meaningful); Password Generator omitted (already displays entropy/strength). Security review pending at time of writing.
- **P10/P11 (Rekey) — DONE** (gitlab#142/gh#60): Rekey screen re-encrypts a file with a new password/algorithm. Old password via `CRYPT_PASSWORD`, new via `OPENSSL_ENCRYPT_REKEY_PASSWORD` (env, CLI clears after read). Security review LOW fixed (refuse output==input; confirm overwrite). **Remark:** password/algorithm only — full KDF/hash reconfiguration during rekey is deferred (the Encrypt tab already exposes full KDF config for new files).
- **P12/P13 (Recovery slots) — DONE** (gitlab#145/gh#63), but scope grew to **two**
  CLI enablers first, both landed:
  - gitlab#144/gh#62 — recovery credentials via the environment. `--recovery-code`
    was argv-only (visible in the world-readable `/proc/PID/cmdline`, and unlike
    `--password` it carried no warning), and passphrases were reachable only
    through a `getpass()` prompt on `/dev/tty` that no GUI subprocess can answer.
    Four security-review passes; two MEDIUMs were designs I had got wrong, not
    omissions — an env var could *select* the credential path (a planted variable
    silently wrapping the DEK under an attacker's passphrase), and my log-redaction
    registration was inert by construction while my test asserted only tuple
    membership.
  - gitlab#146/gh#64 — `--json` output plus `--recovery-code-out`. The first design
    put the generated code on stdout, justified by a GUI redaction gate that does
    not exist: `logStdout` defaulted to on, the streaming helper had no such
    parameter, and stdout was logged and embedded in the exception on any non-zero
    exit. Three passes.
  - **Remark:** the screen also fixed gitlab#148 (same-file rewrites took the
    envelope writer's truncating path; `in_place` existed but no CLI caller set
    it). Identity is tested with `samestat`, and symlinks are excluded — `os.replace`
    would swap the link for a regular file and leave the real file carrying its old
    header, which for `remove-recovery` is a silent revocation failure reported as
    success.

- **P14 (encrypt-tab `--shred`) — IN PROGRESS** (gitlab#151/gh#69). Pure GUI over
  flags that already exist.

- **P15 (encrypt-tab `--random`) — BLOCKED on gitlab#152/gh#70.** Not skipped for
  lack of a decision: `--random` prints the file's password to **stderr**
  (`crypt_cli.py:9522`) and then blocks 10 seconds on a countdown
  (`:9532-9547`). The GUI streams stderr into its persistent debug log, so
  exposing this as-is would write the encryption password to disk, and every such
  encryption would stall with no visible reason. Needs the same
  `--json` + `--generated-password-out` treatment as gitlab#146 first.

- **P16/P17/P19 — DONE, narrower than specified** (gitlab#153/gh#71). Review found
  **three of the four flags inert on the GUI's path**, so they were removed rather
  than shipped as controls that do not control anything: `--keyring-store`/`-load`
  are gated on the `-p` value while the GUI passes `CRYPT_PASSWORD`, so the store
  never runs *and* its confirmation never prints (gitlab#156) — a user could
  discard the only copy of a password that was never saved; `--pqc-store-key` is
  already emitted unconditionally (gitlab#157). **Remark:** "Sequential XOR" was
  first presented as a neutral third option; it pins legacy format v13 and drops
  four hardening measures, so it is now an off-by-default switch labelled as the
  downgrade it is.

- **P20–P24 — DONE except P24** (gitlab#155/gh#73). Hash/KDF panels extracted into
  a shared widget rather than duplicated. **Remark:** two review passes, and both
  of my fixes were wrong in opposite directions — seeding only argon2 dropped the
  CLI's STANDARD template (weaker than the `null` it replaced), then sending the
  config unconditionally suppressed that template for asymmetric/cascade. The
  Encrypt tab's existing rule (symmetric only) was right all along. Also: the
  symmetric branch displayed HSM/pepper controls it never sent.

- **P25 — BLOCKED on gitlab#159/gh#77** (`sign` unlocks the identity via
  `getpass()`; no environment path).

- **P26 — DONE** (gitlab#158/gh#76). **Remark:** review found a pinned-signer
  mismatch rendering in the "could not check — not a verdict either way" card,
  i.e. the strongest negative result shown in the most reassuring style. Component
  names are not covered by the signature (gitlab#160).

- **P27/P28/P29 — IMPLEMENTED, THEN ABANDONED UNSHIPPED.** The branch was deleted
  rather than merged, because security review established that all three flags are
  inert or misdescribed:
  - `--no-touch` disables **nothing**. `require_touch`'s only consumer is
    `identity_protection.py:363`, which prints "👆 Touch your Yubikey to
    continue..."; it is never passed to a plugin. The real touch requirement lives
    in the device's OTP slot config, which this tool never touches. My warning
    dialog stated the opposite in confident, specific language — a control whose
    warning is wrong is worse than no control (gitlab#163).
  - `--hsm-piv-slot` is accepted by `identity create` and then discarded unread
    (`cmd_create` never reads it), and `piv` is not even an `--hsm` choice there.
  - `--allow-key-change` could never execute: `importContact` sends `--data`/
    `--alias`, which do not exist, so **GUI contact import has never worked** —
    pre-existing, gitlab#164. **FIXED**: `identity import` now takes `--file` /
    `--data-stdin` (mutually exclusive, one required) plus `--alias`, and the
    GUI pipes the document over stdin rather than argv. The document is *not*
    passable as a command-line value by design — `/proc/PID/cmdline` is
    world-readable and the GUI field is a free-text paste box, so an inline
    flag would expose a mis-pasted private key or passphrase at `execve`.
  - **Remaining gap (deliberate, not a regression):** the GUI still has no way
    to accept a *legitimate* re-key. `importContact` never passes
    `--allow-key-change` and there is no UI for it, so a contact who genuinely
    rotates keys cannot be re-imported from the GUI. This fails closed, which
    is the right default, but the user is stuck with a clear error and no
    remedy inside the app. Per the remark below, the fix is **not** a
    confirmation dialog: hold it to the `plugin trust-key
    --trust-fingerprint` pattern (typed out-of-band fingerprint, fails closed
    on mismatch) before exposing it. Not attempted here — it is a new trust
    UI, not a wiring fix.
  - **Remark:** review also judged a confirmation dialog insufficient for
    `--allow-key-change` regardless. This repo already has the right pattern in
    `plugin trust-key --trust-fingerprint`: a typed out-of-band fingerprint that
    fails closed on mismatch. Hold `identity import` to that before exposing it.

- **P30–P34 — triaged; mostly blocked on gitlab#162/gh#80.** Verified per command:
  - **P31 (`analyze-config`) — IMPLEMENTED, THEN ABANDONED UNSHIPPED** (gitlab#166).
    It has `--output-format json`, but the command analyses `vars(args)`, i.e. the
    argparse defaults — there is no way to submit a configuration, so the score is
    not about anything the user has set. Worse, `--pqc-algorithm` defaults to the
    *string* `"none"`, which is truthy, so the report asserts
    `post_quantum_enabled: true` when PQC is off *and* suppresses the
    recommendation to enable it. A security readout that is neither about the
    user's configuration nor internally truthful must not be rendered in a GUI.
  - **P34 opt-out — IMPLEMENTED, THEN ABANDONED UNSHIPPED** (gitlab#166). The
    `telemetry` command ends in an unconditional `sys.exit(0)`, so a failed
    opt-out is indistinguishable from a successful one: the GUI would report that
    a user's telemetry data had been deleted when it had not. Opt-out also writes
    no persistent flag, so a config- or env-enabled install re-enables collection
    on the next run.
  - **P34 opt-out action — buildable** (`--force` behind a GUI confirmation); its
    *state display* is blocked, since `telemetry status` has no JSON and a toggle
    that can show the wrong state is worse than none.
  - **P30 / P33 — blocked**: no machine-readable output at all. Parsing free text
    is worse than not building it — a misparsed security analysis is a reassuring
    screen derived from text the parser did not understand.
  - **P32/P33 scope — resolved: read-only views** (user decision, 2026-07-25).

### Note on the "no CLI change needed" classification

The plan states P12–P34 are "pure GUI work shelling to **existing** CLI commands
(no CLI change needed, unlike P2)". That was wrong for **P12/P13, P15, P18, P25,
P27–P29, P30, P33 and part of P34** — most of the plan. Four separate
credential-input gaps (gitlab#144, #152, #154, #159) suggest one shared resolver
rather than five one-off additions. Verify each command's surface, and that each
flag is actually consumed, before starting an item.: recovery slots (P12/P13), encrypt-tab flag gaps (P14–P19), batch-tab parity (P20–P24), sign/verify screens (P25/P26), identity flag gaps (P27–P29), analysis/templates/recommendations/telemetry (P30–P34). All are pure GUI work shelling to **existing** CLI commands (no CLI change needed, unlike P2). Each still needs the full gate treatment: GitLab+GitHub issue → TDD (Dart widget test) → security review for the sensitive ones (P27/P28 `--no-touch`/`--allow-key-change`, P25/P26 signing) → 4-file changelog → one commit per feature on `feature/gui-cli-sync`.

### Autonomous-run stopping point (2026-07-24)

Stopped after P10/P11 to keep the delivered work at full quality rather than leave a feature half-done. All six delivered features (P1, P2-CLI, P3/P4/P5-partial, P6/P7, P8/P9, P10/P11) are committed with tests, security reviews addressed, and changelogs. **No Dart was compiled or tested** in this environment (no Flutter toolchain) — the very first follow-up must be `cd desktop_gui && flutter analyze && flutter test`. P12–P34 remain for a future run.

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

Checkbox state was audited against the code on 2026-08-08 rather than trusted:
`[x]` means the emitting method AND a widget that reaches it both exist. Three
items are annotated because only half of that is true — a service method with
no consumer is dead surface, which is the same defect class as the
emitted-but-nonexistent flags the argv lint now catches.

### Tier 1 — highest value-to-effort

- [x] P1: Decrypt tab exposes widgets for `--with-key` (recipient identity),
      `--verify-from` (signer identity), and `--no-verify` (skip signature,
      behind a warning) — the three fields already passed to `CLIService` but
      never set by any widget become reachable.
      target: desktop_gui/lib/tabs/decrypt_tab.dart
- [x] P2: `CLIService.generatePassword()` emits the `generate-password`
      char-mode flags (`length`, `--use-lowercase/-uppercase/-digits/-special`).
      target: desktop_gui/lib/cli_service.dart
- [x] P3: `CLIService.generatePassword()` also supports diceware mode
      (`--dice`, `--dice-count`, `--dice-sep`, `--dice-list`, `--force-wordlist`).
      target: desktop_gui/lib/cli_service.dart
- [x] P4: New Password Generator screen with char/diceware toggle and a
      NavigationRail entry, calling P2/P3.
      target: desktop_gui/lib/ (new password_generator_screen.dart) + lib/main.dart
- [x] P5: Generated password can be inserted into the Encrypt and Decrypt
      password fields (copy-to-field action).
      target: desktop_gui/lib/tabs/encrypt_tab.dart, desktop_gui/lib/tabs/decrypt_tab.dart
  - **DONE 2026-08-13 in the GUI repo** (post-split home: world/openssl_encrypt_gui
    35267db, gitlab gui#4 / gh#147): "Use for Encrypt/Decrypt" actions on the
    generator + one-shot TARGET-BOUND PasswordHandoff slot consumed by the tab's
    initState; fail-closed navigation by entry identity. Security-reviewed
    (Medium fixed: obscured fields made the handed-off password write-only →
    both password fields gained reveal toggles; 30s clipboard auto-clear on the
    generator). The optional clipboard-auto-clear idea from the original remark
    is included.
- [x] P6: `CLIService.shred()` emits the `shred` command
      (`--input` incl. glob, `--shred-passes`, `--recursive`).
      target: desktop_gui/lib/cli_service.dart
- [x] P7: New Secure Shred screen (file/glob picker, passes, recursive) with a
      NavigationRail entry and a mandatory irreversible-action confirmation.
      target: desktop_gui/lib/ (new shred_screen.dart) + lib/main.dart
- [x] P8: `CLIService.checkPassword()` emits `check-password`
      (`--password-policy`, `--strict-strength`, `--json`) and parses the JSON
      strength result.
      target: desktop_gui/lib/cli_service.dart
- [ ] P9: Live password-strength indicator widget driven by P8, shown under the
      password fields in the Encrypt tab, Decrypt tab, and Password Generator.
      target: desktop_gui/lib/ (new strength_meter widget) + encrypt_tab.dart / decrypt_tab.dart

### Tier 2 — parity gaps

  - **Service method exists, no consumer**: `CLIService.checkPassword()` is implemented (P8) but nothing calls it, so there is no live indicator. Dead surface in the same class as the emitted-but-nonexistent flags.
- [x] P10: `CLIService.rekey()` emits the `rekey` command (old-password vs
      `--rekey-password*`, optional `--algorithm`, cascade flags, full hash/KDF
      group, `--password-policy` group).
      target: desktop_gui/lib/cli_service.dart
- [x] P11: New Rekey screen (change password and/or algorithm on an existing
      file) with a NavigationRail entry, calling P10.
      target: desktop_gui/lib/ (new rekey_screen.dart) + lib/main.dart
- [x] P12: `CLIService` gains methods for envelope recovery slots:
      `list-recovery`, `add-recovery` (`--add-code`/`--add-passphrase`),
      `recover` (`--recovery-code`/`--recovery-passphrase`), and
      `remove-recovery` (`--slot-id`).
      target: desktop_gui/lib/cli_service.dart
- [x] P13: New Recovery Slots screen listing/adding/removing recovery slots and
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
  - **Partly**: `cli_service.dart` emits `--pqc-keyfile`/`--pqc-store-key`, but `main.dart` never passes them, so no widget reaches them.
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
- [x] P26: `CLIService.verifySignature()` emits `verify-signature`
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

### Second autonomous-run stopping point (2026-07-25)

Delivered and merged: P1-P14, P16-P24 (less P24), P26. Two branches were
**implemented, reviewed, and then deleted rather than merged** — P27-P29
(gitlab#163, #164) and P31/P34-opt-out (gitlab#166) — because in both cases
review established that the controls did not do what their UI said. That is the
right outcome, not a failure of the run: a control that misreports is worse than
an absent one.

Every remaining plan item is blocked on a CLI change, all filed:
gitlab#152 (P15), #154 (P18), #159 (P25), #162 (P30/P33/P34-state),
#163/#164 (P27-P29), #166 (P31/P34-opt-out). **Nothing is buildable without a CLI change.** P24 and P32 were the last two
candidates and both turned out to be blocked (gitlab#167):

- **P32** — `template list`/`compare` accept `--format json` and never read it
  (0 references to `args.format` in either handler); they emit human text
  unconditionally. `template` is also dispatched with an unconditional
  `sys.exit(0)`, so failures are invisible. Third accepted-then-discarded flag
  in this plan, after `--hsm-piv-slot` and the analyse/telemetry defects.
- **P24** — the GUI already emits `--no-video-temporal-spread`, which does not
  exist (the CLI has `--video-temporal-spread`), so steganography with that
  option off fails outright today. Separately, steganography hides a payload
  inside a *carrier image*, so a batch of N files needs a carrier-to-file
  mapping that the batch tab has no concept of — a design decision, not wiring.

Eleven security reviews ran across this session and every one found something
that would otherwise have shipped, including three cases where the defect was
introduced by the fix to the previous finding. Treat "the CLI flag exists" as
the start of verification, not the end: check that the flag is *consumed*, that
the command *exits non-zero on failure*, and that what the UI says about it is
true.

---

## Outstanding issue register (added 2026-07-26, updated 2026-08-07)

The body of this plan tracks GUI parity items (P-numbers) and the CLI blockers
found while triaging them. It did **not** track the CLI issues found by reading
CLI surface directly, nor the follow-ups raised by the security reviews — 16
issues in total. They are all filed on GitLab (and mirrored to GitHub except
where confidential), but this plan is the resumption record, so they are listed
here too.

### Landed this session

| Issue | Was |
|---|---|
| gitlab#164 / gh#82 | GUI contact import had never worked (`--data`/`--alias` did not exist). Now `--file` / `--data-stdin` + `--alias`. |
| gitlab#171 / gh#89 | Global flags after a subcommand rejected for 22 of 42 subcommands (drifted command list). Also fixed two credential leaks it made reachable. |
| gitlab#154 / gh#72, gitlab#159 / gh#77 | Second password and signer passphrase had no non-interactive input path. Shared `modules/credential_env.py`. |
| gitlab#152 / gh#70, gitlab#181 / gh#96 | `--random` had no safe delivery channel — and crashed with `AttributeError` before ever reaching it. |

### Landed 2026-08-07

| Issue | Was |
|---|---|
| gitlab#172 (confidential) | Imported identity `email` printed raw above the `Fingerprint:` line — ANSI escapes could forge the only authenticity readout this design has. Four review rounds; scope grew to the keyserver TOFU prompt (remote bundles), `identity create --email`, stored identity files, the signature sidecar (incl. the unsigned `component` field) and keyserver HTTP error bodies. Draft **GHSA-qjr2-x6mr-8xgf** + SECURITY.md ADVISORY 2026-14 **held until release**. |
| gitlab#183 / gh#100 | **GUI identity listing had never worked**: `CLIService.listIdentities()` emitted `identity list --json`, a flag that did not exist, and swallowed the argparse failure into empty lists. Now `identity list --json` (+ `skipped`), GUI sanitizes at the decode boundary, and a failed listing raises instead of returning empty. |
| gitlab#148 | **Envelope rewrites could destroy the ciphertext they manage.** The writer chose its atomic vs. truncating path from a caller-supplied flag; it now derives eligibility itself immediately before the write. Identity ("does this write land on its own input") and atomicity ("can `os.replace` be used") are separate predicates — conflating them made the recoverable path unreachable for exactly the cases it was written for, caught in review. Symlinked and multiply-linked targets must be written *through*, so they get a fsynced backup + restore instead of an unprotected truncate. `_rekey_envelope_fast` carried a second, weaker copy and now delegates. Residual: `rekey_file`/`decrypt_file` with `-o` equal to `-i` → **gitlab#195 / gh#112**. |

### Landed 2026-08-08

| Issue | Was |
|---|---|
| gitlab#196 / gh#113 | **Malformed OpenPGP input escaped the module's error taxonomy** (1.5.x only — `interop/` does not exist on 1.4.x). Truncated packets raised raw `IndexError`/`struct.error` past the documented `OpenPGPError`, on untrusted input. Bounds checks at every length read, the same treatment for the **public-key** path (authored by anyone holding the recipient's public key — no shared secret needed), and `InvalidTag`/`UnsupportedAlgorithm` mapped by name so a later catch-broadening cannot downgrade tamper to malformed. Found via a test that failed ~2% of runs; the first two corpora reached none of the fixed code, which a line-trace assertion now prevents. |
| gitlab#178 (confidential) | `keyserver show-token` printed the first 8 and last 4 characters of the bearer token outside `debug_secret()`. Now redacted by default, revealed only under `--debug --unsafe-show-secrets`. |
| gitlab#184 | The 1.5.x stdout-leak lint matched a **prefix** against a call's first line; 9 of 22 entries were bare prefixes, so one entry authorized every `json.dumps` print in its file and left everything after the prefix unconstrained. Ported the 1.4.x call-anchored matcher: 22 loose entries → 29 exact ones. |
| gitlab#191 | The argv lint checked every argv the GUI **executes** but neither builder that renders a copy-pasteable command to the user. Widening the anchor immediately found `--pbkdf2-iterations` in the 1.5.x encrypt preview, closing the last flag item of gitlab#192. |
| gitlab#185 | GUI `identity delete` sent `--contact`, a flag that has never existed, so contact deletion had never worked; and without `--force` the CLI's confirmation `input()` raised EOFError on a pipe. Now `--kind own\|contact` + `--force`. |
| gitlab#190 | GUI steganographic encryption sent `-a <algorithm>`, but `-a` is `--armor`, a `store_true` — the algorithm became a stray positional and the command exited 2. **The lint could not have caught this**: it checked flag *existence*, not arity. It now checks both, which required reading argv *elements* rather than string literals, because the value is a Dart variable. |
| gitlab#157 | **A duplicate implementation wrote the post-quantum private key in the clear.** Reintroduced by a file-reconstruction commit *after* the wrapping fix landed, and missed by the Argon2id upgrade whose message says it touched "the one write site"; its loader also read `private_key` unconditionally, so a wrapped keyfile would have had its AES-GCM ciphertext used as the key. Deleted. Separately `--pqc-keyfile` could not save by **any** invocation (`--pqc-gen-key` lived only on a parser `main()` never routes to), so naming a new path was silently ignored. Now reachable, refused when missing, and written 0600 via `create_secure_file(exclusive=True)`. **SECURITY.md ADVISORY 2026-16**. |

### Open CLI work (blocks GUI items)

- **gitlab#162 / gh#80** — no machine-readable output for `analyze-security`,
  `smart-recommendations`, `telemetry status`. Blocks P30/P33.
- **gitlab#163 / gh#81** — `--no-touch` only suppresses a prompt;
  `--hsm-piv-slot` discarded on create. Blocks P27–P29.
- **gitlab#167 / gh#85 (remainder)** — `template compare --format json` still
  ignored (`template list` was fixed).
- **gitlab#168 / gh#86** — `analyze-config` reads KDF/cipher keys its own
  parser never sets.
- **gitlab#169 / gh#87** — template self-asserted security score is the sort
  key; unbounded `hash_config`; secret-to-disk in create.
- **gitlab#170 / gh#88** — video steganography options are dead surface; MP4
  support advertised but absent. Blocks P24.

### Open follow-ups from security reviews

(Confidential entries have all been fixed and made public; see the register.)

Public:

- **gitlab#174 / gh#90** — interactive confirmation prompts go to stdout while
  their warning text goes to stderr, so a redirected stdout hides the question.
- **gitlab#175 / gh#91** — GUI `_runCLICommandWithStdin` writes and closes
  stdin before draining stdout/stderr.
- **gitlab#176 / gh#92** — `install-dependencies --yes` still rejected;
  `main()`'s routing skip-set is still a hand-maintained duplicate.
- **gitlab#177 / gh#93** — global-flag preprocessing ignores `--` and can take
  an option value as the command position.
- **gitlab#179 / gh#94** — seven documented commands (`create-usb`,
  `verify-usb`, the five `*-plugin`) route to a subparser that does not exist.
  Verified pre-existing.
- **gitlab#180 / gh#95** — credential-channel follow-ups: late consume on the
  encrypt path, `info` has no way to *request* the credential, the fd blank
  check duplicates the rule.
- **gitlab#182 / gh#97** — `generate-password` still claims to clear the
  screen; the orphan-password NOTE misses the `return 1` paths; `realpath`
  does not resolve hardlinks.
- **gitlab#147, gitlab#149** — earlier follow-ups. (#150, the stdout-leak
  lint's ±50 line tolerance, is fixed on both lines.) #149 is the one with
  teeth: recovery passphrases bypass the password-strength policy, and a
  recovery slot is an additional wrapping of the same file key, so a weak one
  is a weak key for the whole file.
- **gitlab#195 / gh#112** — the same-file truncating write that gitlab#148
  fixed in the envelope header writer still exists on the slow paths:
  `rekey -i f -o f` and `decrypt -i f -o f` hand the input path straight to
  a `"wb"` open. Filed with the two predicates the fix should reuse.

### A defect class worth a lint

`--hsm-piv-slot`, `template --format`, the `analyze-config` KDF keys, the video
steganography group, and `encrypt --random`'s character-class flags were all
the same shape: surface that is accepted or advertised but that no handler can
service. A test asserting that every `args.<attr>` read in a subcommand handler
is declared on that subcommand's parser would catch the whole class at once —
it would have caught gitlab#181 immediately.

**The mirror image is worth a lint too** (gitlab#183, 2026-08-07): the GUI
*emits* flags the CLI does not declare. `identity list --json` had never
existed, so GUI identity listing never worked at all — the third instance
after `--data`/`--alias` (gitlab#164) and `encrypt --random` (gitlab#181). A
test that extracts every argv list `CLIService` builds and parses it against
the real parser would catch that direction, and the two lints together close
the whole "flag exists on one side only" class.

Two habits made these invisible for so long, both now fixed in the GUI but
worth checking wherever else they appear:

- **`CLIService` swallowed non-zero exits into empty results.** An empty
  identity list is indistinguishable from an empty store, so an argparse
  error looked exactly like a fresh install. `listIdentities` now raises;
  the Identity screen's error banner had been dead code until then.
- **Absent entries were reported as absence, not as failure.** A store entry
  that fails to load simply vanished from the listing. Presenting a short
  list as complete silently drops a recipient, or makes an own identity look
  deleted, so `list_identities` now collects skipped entries and every
  consumer surfaces them.

### Display safety after gitlab#172/#183

The rule these two settled, since it constrains every future GUI feature that
renders CLI output: **`--json` channels stay unsanitized** (machine-readable,
`ensure_ascii` pinned, the consumer renders), and display safety belongs to
the renderer — in the GUI that means the **decode boundary** in `CLIService`,
not the individual widget. A per-widget pass had already missed the recipient
picker and the signature-verification picker, the two controls that decide who
can read the plaintext and whose signature is trusted. Never sanitize `name`
or `fingerprint` there: both are passed back to the CLI as argument values.
