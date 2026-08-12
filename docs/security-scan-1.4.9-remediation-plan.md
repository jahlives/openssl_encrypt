# Plan: 1.4.9 / 1.5.0 pre-release security-scan remediation

Status: draft
Created: 2026-08-11

## Goal

The `claude-security:scan` run on 1.4.9 produced 36 findings (1 HIGH, 35 MEDIUM)
and a NO-GO recommendation. The agreed release-gate blocker set —
F1, F5, F6, F7, F10, F36, and the pre-auth DoS cluster F9/F16/F28/F29 — is
already fixed on both maintenance branches (see "Already done" below). This plan
covers the **remaining** work: F17/F18 (deferred as a focused follow-up) plus
the ~24 non-gate findings the scan said to "triage against the release
timeline." The full per-finding detail lives in
`security-scans/scan-1.4.9-findings.md` (git-ignored, in the working tree);
this plan is the checkable work-list built from it.

## Ground rules (apply to EVERY step below)

- **Two branches.** Fix on `feature/v1.4.x-development` first, then port to
  `feature/v1.5.x-development` (unless marked *1.4.x-only*). Keep changelog text
  byte-identical across branches; use line-appropriate "Fixed in" versions
  (1.4.9 / 1.5.0). The D-Bus service is **removed on 1.5.x**, so D-Bus findings
  are 1.4.x-only.
- **Workflow gates per fix** (project skills): `issue-tracking` (confidential
  GitLab issue for a security bug + draft GHSA; public GitLab issue + closed
  GitHub mirror for pure hardening once landed) → `tdd-workflow` (red→green) →
  mandatory `security-reviewer` subagent pass → `changelog` (CHANGELOG.md +
  SECURITY.md advisory for user-relevant bugs; the three per-version summary
  files are deferred to release finalization, matching this batch's precedent)
  → commit + push to **origin (GitLab)** → comment the commit on the trackers.
- **Advisories/GHSAs are HELD** (draft) until the 1.4.9/1.5.0 release; do not
  publish mid-work.
- **Sandbox commits:** run black 26.3.1 (`--line-length=100`) + isort + bandit
  manually, then `git commit --no-verify` and `git push --no-verify` (a pre-push
  hook invokes pre-commit, which isn't installed here).
- Advisory numbering continues from **2026-25** (last used). GitLab issues
  continue from **#233** (last used); GitHub uses draft GHSAs, not issues, for
  security bugs.

## Already done (both branches unless noted) — do NOT redo

- F1  HIGH CWE-916  D-Bus key-stretching collapse — gitlab#228, GHSA-v9r6-grch-fxw7, ADVISORY 2026-20 (**1.4.x-only**)
- F5  MED  CWE-287  unencrypted embedded PQC key decrypts under any password — gitlab#229, GHSA-qqfq-g2cv-j7v3, 2026-21
- F6/F7 MED CWE-345 silent identity key substitution — gitlab#230, GHSA-q8p3-7h6h-ghfr, 2026-22
- F10 MED  CWE-347  plugin trust denylist→allowlist — gitlab#231, GHSA-wxx9-p55f-wm34, 2026-23
- F36 MED  CWE-347  revoked/expired GPG keys accepted — gitlab#232, GHSA-x38r-8wf3-q9hq, 2026-24
- F9/F16/F28/F29 MED CWE-770/405/1284 pre-auth KDF-cost DoS — gitlab#233, GHSA-phmr-p567-q5g6, 2026-25

## Steps

### F17/F18 — authenticate recovery-slot presence in the bulk AAD (the agreed follow-up)

Decision taken (2026-08-11): full crypto fix. SUPERSEDED 2026-08-12: implemented as **Option B (wrapped_dek AAD binding)** instead of the bulk re-tag — DONE both lines (gitlab#264, GHSA-grhj-cpmg-f5mx, advisory 2026-44). The count commitment (encryption.dek_slot_count) is bound into the wrapped_dek AEAD (not the bulk), so slot ops stay O(header); decrypt fails closed on strip/downgrade/tamper on both paths; slot management now requires the primary password. security-reviewer: core sound, F1 hardening applied (authenticate incoming set), F2 documented residual. Original bulk-re-tag plan (P1 primitive extraction) NOT needed and not done. Original text below for history:

Decision taken (2026-08-11): **full crypto fix (re-tag bulk)**. Root tension:
`dek_slots`/`dek_slots_mac` are deliberately excluded from `envelope_aad` so
slots can be added/removed post-hoc without re-encrypting the bulk
(`remove_recovery_slot` even removes the last slot and asserts the AAD is
unchanged). Detecting wholesale deletion requires an **authenticated** commitment
to slot presence, which forces every slot add/remove to recompute the bulk AEAD
tag. There is currently **no reusable bulk-cipher primitive**: the logic lives
in nested closures `do_encrypt` (crypt_core.py:7786) and `do_decrypt`
(crypt_core.py:12242) that capture dozens of locals across GCM / GCM-SIV / OCB3 /
ChaCha20 / XChaCha20 / cascade / streaming. So this is a refactor, not an edit.

- [x] P1: Extract reusable bulk-cipher primitives `bulk_encrypt(dek, nonce, plaintext, aad, *, algorithm, cascade_cfg, streaming_cfg, format_version, xchacha_nonce_format)` and `bulk_decrypt(...)` from the `do_encrypt`/`do_decrypt` closures, covering every mode (GCM, GCM-SIV, OCB3, ChaCha20-Poly1305, XChaCha20-Poly1305, cascade chains, streaming chunks). `encrypt_file`/`decrypt_file` call the new primitives so behavior is byte-for-byte unchanged (regression: full encrypt/decrypt round-trip suite stays green for every algorithm).
  target: openssl_encrypt/modules/crypt_core.py (new module-level functions, or openssl_encrypt/modules/envelope.py)
- [x] P2: Add an AAD-covered slot-presence commitment `encryption.dek_slot_count` (int). Remove `dek_slots`/`dek_slots_mac` handling as-is but ADD `dek_slot_count` to the authenticated subset (i.e. NOT in `_AAD_EXCLUDED_ENCRYPTION`). `encrypt_file` writes `dek_slot_count = len(dek_slots)` (0/absent when none).
  target: openssl_encrypt/modules/envelope.py (`_AAD_EXCLUDED_ENCRYPTION`, `envelope_aad`), openssl_encrypt/modules/crypt_core.py (encrypt_file metadata build ~7587/8454/8757)
- [x] P3: Fail closed on decrypt when the AAD-committed count disagrees with the slots present: in `decrypt_file` (recovery + password envelope paths, ~11850-11930) and `_recover_envelope_dek` (~9894), require `dek_slots` present with `len == dek_slot_count` AND the slot-set MAC to verify whenever `dek_slot_count > 0`. Because `dek_slot_count` is AAD-covered, an attacker cannot silently set it to 0 (bulk tag fails).
  target: openssl_encrypt/modules/crypt_core.py
- [x] P4: Re-tag the bulk in `add_recovery_slots` (crypt_core.py:10331) and `remove_recovery_slot` (crypt_core.py:10386): recover the DEK (already done), `bulk_decrypt` the payload under the OLD aad, update `dek_slots` + `dek_slot_count` + `dek_slots_mac`, `bulk_encrypt` under the NEW aad, write. DROP the `envelope_aad(meta) == aad_before` assertion (it is now intentionally violated). Handle SIV modes (whole-ciphertext changes) and streaming/cascade correctly via P1's primitives.
  target: openssl_encrypt/modules/crypt_core.py
- [x] P5: TDD across cipher modes: (a) encrypt with recovery slots, delete `dek_slots`+`dek_slots_mac`, assert decrypt now FAILS closed (F17/F18); (b) add/remove a slot, assert the file still decrypts by password AND by the surviving recovery credential (bulk re-tag correct) for GCM, GCM-SIV, OCB3, ChaCha, XChaCha, cascade, and streaming; (c) legitimate remove-last-slot still yields a decryptable file with `dek_slot_count == 0`.
  target: openssl_encrypt/unittests/test_recovery_slot_aad_commitment_234.py (new)
- [x] P6: issue-tracking (confidential gitlab#234 + draft GHSA, CWE-354/347), changelog (CHANGELOG.md + SECURITY.md ADVISORY 2026-26), security-reviewer pass, commit + push both lines. Note the behavior change in the advisory: post-hoc recovery-slot management now re-tags (touches) the bulk.

### Pull-forward-worthy non-gate findings (real user-facing risk; do first)

- [x] P7: F2 (MED, CWE-916) — remote pepper wrap key is HKDF(password, salt=None) — server-side offline password guessing at ~2 SHA-256/guess, no salt = fleet-wide precompute. Derive the wrapping key from the file's memory-hard chain (or Argon2id + fresh per-blob random salt stored alongside) and bind pepper name/file-id into the AEAD AAD. Both lines. Format-compat: keep reading old-format wrapped peppers.
  target: openssl_encrypt/modules/crypt_core.py:6559 `_derive_pepper_key`
- [x] P8: F8 (MED, CWE-311) — unkeyed `sha256(plaintext)` stored as `hashes.original_hash` in every file's cleartext header (confirmation/brute-force oracle). Stop writing it; if a redundant check is wanted, HMAC over an HKDF-separated subkey of the file key. Keep decrypt tolerant of old files that still carry it. Both lines. NOTE: interacts with F17/F18 P2 (both touch header/hashes) — sequence after P2 or coordinate.
  target: openssl_encrypt/modules/crypt_core.py:7692 `encrypt_file`
- [x] P9: F35 (MED, CWE-78) — `info`'s "Reconstructed CLI" block interpolates untrusted `pepper_name`/`hsm_plugin`/`algorithm`/`kdf_config.hkdf.info` unquoted; a `pepper_name` of `work; curl …|sh #` runs when the user pastes the block. `shlex.quote()` every interpolated value and allow-list per flag. Both lines.
  target: openssl_encrypt/modules/crypt_core.py:9474 `_append_pepper_flags` (+ `_reconstruct_cli_from_metadata`)
- [x] P10: F34 (MED, CWE-426) — legacy GUI `CONFIG_FILE` reassigned at crypt_settings.py:84 to bare relative `crypt_settings.json`, so a planted CWD config (`sha256:1`, KDFs off) silently weakens every file that session. Delete the line-84 reassignment (resolve to the absolute per-user path) and validate loaded values against the template schema; refuse/warn when no memory-hard/iterated KDF. Both lines.
  target: openssl_encrypt/modules/crypt_settings.py:84, :1259 `SettingsTab.load_settings`

### Display sanitization / ANSI-escape cluster (CWE-117/116) — forged authenticity readouts

- [x] P11: F3 (MED, CWE-117) — `main_with_args` prints attacker `asymmetric.recipients[].key_id` unescaped during decrypt auto-detect; forges a `Fingerprint:` block. Route through `sanitize_for_display()`, validate `key_id` against the fingerprint regex, bound recipient count, replace the bare `json.loads` in `detect_encryption_type` with `secure_metadata_loads`. Both lines.
  target: openssl_encrypt/modules/crypt_cli.py:7784 `main_with_args`; `detect_encryption_type`
- [x] P12: F4 (MED, CWE-117) — `print_file_info` prints metadata fields (`hsm_plugin`, `pepper_plugin`, `pepper_name`, `layer_info[].cipher`, kdf pairs; all v1/v2 fields) unsanitized. Wrap every metadata-derived value in `sanitize_for_display()`; constrain free-form fields with the write-path regex. Both lines.
  target: openssl_encrypt/modules/crypt_core.py:9211 `print_file_info`
- [x] P13: F25 (MED, CWE-117) — `verify-usb` echoes `added_file_list` (raw `rglob` names off the untrusted drive) unsanitized under the FAILED banner; repaints a forged PASSED. `sanitize_for_display()` at crypt_cli.py:6663/6665/6667 (or where appended in `_verify_integrity_file`). Both lines.
  target: openssl_encrypt/modules/crypt_cli.py:6667 `main` (verify-usb branch)
- [x] P14: F19 (MED, CWE-116, GUI/Dart) — recovery-slot `id`/`type` from unauthenticated `list-recovery --json` rendered with bare `Text(...)` inside the irreversible removal dialog; `U+2029` forges a line under the warning. Run every field through `sanitizeForDisplay` at the decode boundary in `RecoverySlot.fromJson`/`CLIService.listRecoverySlots`; keep the raw value only for the `--slot-id` argument. GUI — both lines (1.5.x GUI may lag; verify).
  target: desktop_gui/lib/recovery_slots_screen.dart:459; RecoverySlot.fromJson / CLIService.listRecoverySlots

### Argv / SharedPreferences secret exposure (CWE-214/312) — GUI

- [x] P15: F21+F22 (MED, CWE-214, GUI/Dart) — stego password appended to child argv (`--stego-password`) on encrypt (cli_service.dart:2148) AND decrypt (cli_service.dart:2390), exposed in `/proc/<pid>/cmdline`, while the main password correctly uses `CRYPT_PASSWORD`. Add a CLI env channel for the stego secret and pass it in the environment map; fix both sides in one change. GUI + CLI (add the env read on the CLI side). Both lines.
  target: desktop_gui/lib/cli_service.dart:2148 & :2390; CLI stego arg parsing (openssl_encrypt/modules/crypt_cli.py stego options)
- [x] P16: F20 (MED, CWE-312, GUI/Dart) — mTLS client private-key PEM pasted in Settings written to plaintext SharedPreferences (0644). Never store private-key PEM there; write to a dedicated 0600 file and persist only the path; same for `setIntegrityClientCertPem`; delete the unused `*ClientKeyPem` accessors (the paste-PEM value is never even used by `testPepperConnection`). GUI — both lines.
  target: desktop_gui/lib/settings_service.dart:393 `setPepperClientCertPem` (+ `setIntegrityClientCertPem`)
- [x] P17: F23 (MED, CWE-276, GUI/Dart) — GUI writes decrypted plaintext with `File.writeAsString` (0644), unlike the CLI's 0600. Create output owner-only before writing (or chmod 0600 immediately after), or route the write through the CLI so `file_permissions` applies. GUI — both lines.
  target: desktop_gui/lib/file_manager.dart:323 `FileManager.writeFileText`
- [x] P18: F32 (MED, CWE-214) — `tools/list_keystore_keys.py` makes `--password required=True` (keystore master password on argv). Make it optional with `getpass.getpass()` fallback; env/fd for non-interactive. LOW reachability (script not in MANIFEST.in — source-checkout only). Both lines.
  target: tools/list_keystore_keys.py:15 `main`

### Resource-exhaustion / DoS (CWE-789/400) — non-KDF paths

- [x] P19: F14 (MED, CWE-789) — FLAC `total_samples` (36-bit, attacker STREAMINFO) drives `np.random.randint(size=(total_samples, channels))`; ~50-byte file → OOM. Bound by `audio_byte_count / (channels * bytes_per_sample)` and reject out-of-range; use numpy index arrays. Both lines (steganography removed? verify present on 1.5.x — steganography dir still ships).
  target: openssl_encrypt/plugins/steganography/formats/flac.py:513 `_decode_flac_samples`
- [x] P20: F24 (MED, CWE-789) — QR `total_parts` taken verbatim before `set(range(1, total+1))`; two QR images with `total=10**12` OOM `import-qr`. Validate `part`/`total` as ints in 1..99 right after parsing; compute the missing set from parts present. Both lines.
  target: openssl_encrypt/modules/portable_media/qr_distribution.py:442 `_parse_multi_qr_data`
- [x] P21: F30 (MED, CWE-400) — `enforce_memory_ceiling` gates only `peak_memory_kb`, never `total_time_seconds`; a v14 file with `argon2.rounds=2**31` + tiny memory wedges CPU at 100% pre-auth (silent under `--quiet`/`--no-estimate`). Add a hard `total_time_seconds` ceiling enforced independently of the display flags; bound the iteration-count fields (argon2 rounds, balloon time_cost, pbkdf2 rounds, scrypt work factor) in the v14 schema. Both lines. (2/3 confidence: local user can Ctrl-C — but not in unattended mode.)
  target: openssl_encrypt/modules/decryption_estimator.py:434 `enforce_memory_ceiling`; v14 schema

### D-Bus authorization (CWE-20/862) — 1.4.x ONLY (service removed on 1.5.x)

- [x] P22: F11 (MED, CWE-916) — D-Bus `_encrypt_worker` maps options into keys `crypt_core` never reads; same root cause as F1, reported at the mapping site. Largely subsumed by the F1 fix (dbus_kdf_config.py); VERIFY the mapping site is fully covered by F1 or add the remaining validation (fail closed when the resulting config yields no hash rounds and no KDF). **1.4.x only.**
  target: openssl_encrypt/modules/dbus_service.py:589 `_encrypt_worker`
- [x] P23: F12+F13 (MED, CWE-20/862) — `Properties.Set` has no `sender_keyword`/`_authorize_caller`; any local UID sets `MaxConcurrentOperations` to 0/negative (DoS) or huge (removes the limit) on the root system-bus daemon, no polkit prompt. Add `sender_keyword` + `_authorize_caller` (+ a dedicated polkit action) to Get/Set/GetAll, validate/clamp `>=1`, or make properties read-only on the wire and add a `<deny>` for Properties writes in the bus policy. **1.4.x only.**
  target: openssl_encrypt/modules/dbus_service.py:1211 `CryptoService.Set`

### USB / portable-media integrity (CWE-59/311)

- [x] P24: F26 (MED, CWE-59) — `verify-usb` allowlist uses `rglob('*')` (never descends symlinked dirs; `O_NOFOLLOW` binds only the final component); an evil-maid symlink to a copy with a planted `__pycache__/*.pyc` verifies PASSED → code execution on the portable install. Walk with `os.walk(followlinks=False)` + `os.lstat`, record directory entries in the manifest at creation, treat any symlinked path component at verify time as tampering. Both lines.
  target: openssl_encrypt/modules/portable_media/usb_creator.py:1033 `_verify_integrity_file`
- [x] P25: F27 (MED, CWE-311) — DONE both lines (gitlab#263, GHSA-2jv6-qqfm-m46m, advisory 2026-43, held to release). Decision: IMPLEMENT real encryption. `_create_encrypted_workspace` now seals the workspace into a genuine AES-256-GCM vault (`data/workspace.vault`) using the derived key; new `_seal_workspace_vault`/`_unlock_workspace_vault` + portable `crypt.py seal`/`unlock` (key re-derived from CRYPT_PASSWORD/prompt + stored salt + bounded/validated hash_config, O_EXCL/O_NOFOLLOW 0600 temp + atomic rename, path-traversal-guarded, zeroized). Marker/README + `auto_encrypt_workspace`/`secure_deletion_on_exit` flags corrected to honest. TDD test_workspace_vault_263.py; security-reviewer 5 findings all resolved. 1.4.x 2b09b2ff / 1.5.x f39cbc9e.
  target: openssl_encrypt/modules/portable_media/usb_creator.py:660 `_create_encrypted_workspace`

### Keyserver transport (CWE-319)

- [x] P26: F15 (MED, CWE-319) — `keyserver login` (unlike `register`) accepts `http://` and any host; cert pinning only mounts for https. One shared validator requiring `https://` + membership of `config.servers`, used by `login`/`register`/`register_with_email` and every per-request URL build; don't persist tokens from a response that failed the check. Both lines. (2/3: needs the victim to type a bad URL.)
  target: openssl_encrypt/plugins/keyserver/keyserver_plugin.py:640 `KeyserverPlugin.login`

### Supply-chain build pinning (CWE-494)

- [x] P27: F31+F33 (MED, CWE-494) — `build_local_deps.sh` clones liboqs from a mutable `--branch ${LIBOQS_VERSION}` and pip-installs liboqs-python from a mutable tag, both with no SHA/signature/hash pin (only a self-reported version check); runs on end-user machines via the import-time prompt (`__init__.py:107`) and `install-dependencies`. A moved tag = code execution + PQC-implementation substitution. Pin both to immutable commit SHAs (or verify a signed release tarball), fail closed on mismatch; apply to the `.ps1` and the inline fallbacks in `crypt_cli.py`. Both lines. (2/3: tag pinning is common practice — treat as hardening, public issue.)
  target: scripts/build_local_deps.sh:33 & :76; build_local_deps.ps1; crypt_cli.py inline fallbacks

## Open questions

- **F17/F18 P1 refactor scope:** extract the bulk-cipher primitives into a new
  module (`bulk_cipher.py`) vs. module-level functions in `crypt_core.py`? The
  streaming path (`StreamingEncryptor`/`StreamingDecryptor`) and cascade path
  already have their own classes — confirm the primitive can delegate to them
  cleanly rather than duplicating chunk logic.
- **F17/F18 behavior change:** re-tagging on every slot add/remove means those
  ops now read+rewrite the whole bulk (O(filesize), not O(header)). Confirm this
  is acceptable for large files, or add a size warning. (User already chose the
  full fix knowing "slot management is no longer free.")
- **F8 vs F17/F18:** both touch the header/`hashes`. Sequence F8 (P8) after the
  F17/F18 P2 metadata change, or land F17/F18 fully first.
- **F27 (USB workspace):** implement real transparent encryption, or strip the
  false "encrypted" claims? Implementing is a feature; stripping is the safe
  minimum. Needs a product decision.
- **GUI (Dart) findings on 1.5.x:** F19/F20/F21/F22/F23 — the 1.5.x GUI has
  historically lagged the 1.4.x GUI (per project memory). Verify each target
  exists on the 1.5.x desktop_gui before porting; some may need building fresh.
- **Classification per finding (issue-tracking):** decide security-bug (confidential
  issue + GHSA + SECURITY.md advisory) vs. pure hardening (public issue after
  landing, no GHSA/advisory). Suggested bugs: F2, F3, F4, F8, F14, F19, F20,
  F21, F22, F23, F24, F25, F26, F35, F12, F13. Suggested hardening: F15, F27,
  F30, F31, F33, F34, F32, F11 (subsumed).

## Release finalization (when cutting 1.4.9 / 1.5.0)

- Publish the 6 held GHSAs (2026-20…25) + any new ones; make the confidential
  GitLab issues public.
- Fill the three per-version summary files still deferred for the whole batch:
  `version.py.template` VERSION_HISTORY, `flatpak/…metainfo.xml` `<release>`,
  `flatpak/flathub/apps/openssl-encrypt/changelog.html`.
- Bump `__version__`, finalize the metainfo `<release>` date/type.
- Re-sign the source-integrity manifest (`update_manifest`) after all changes.
- Re-run `claude-security:scan` (or targeted re-verify) to confirm the gate is clear.
