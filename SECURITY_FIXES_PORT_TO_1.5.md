# Security fixes on 1.4.x — porting guide for 1.5.x

**Purpose:** This document describes the security fixes committed on
`feature/v1.4.x-development` (2026-06-10) so they can be ported/forward-merged
into the 1.5.x line. Source of findings: `SECURITY_REVIEW_FINDINGS.md`.

**Commits to port (in order):**

| Order | Commit | Finding | Subject |
|-------|--------|---------|---------|
| 1 | `e1969035` | H3 | fix(pqc): fail closed on unresolvable KEM algorithm, no silent downgrade |
| 2 | `b2aeed02` | H5 | fix(usb): use a unique per-drive KDF salt instead of a global fixed salt |
| 3 | `e02ca531` | H6 | chore: gitignore local secrets and tool output artifacts |
| 4 | `de021bf5` | H4 | fix(keystore): authenticate the whole keystore with an HMAC (v2 format) — on branch `feature/h4-keystore-integrity` |
| 5 | `8bb028d0` | (test infra) | fix(tests): collect unittests.py again and repair everything that surfaced — on branch `feature/unittests-collection` |
| 6 | `d0dc0bab` | H7 + L8 | fix(dbus): per-caller authorization — polkit on system bus, UID on session — on branch `feature/h7-dbus-authz` |
| 7 | `c2a7dd6e` | H8 | fix(plugins): enforce sandbox on default path, close AST frame escape, reject writable plugin dirs — on branch `feature/h8-plugin-sandbox` |
| 8 | `6204bff3` | M7 | fix(keystore): stop storing the weak PBKDF2 file-password verifier in metadata — on branch `feature/m7-drop-pbkdf2-verifier` |
| 9 | `335020cd` | M6 | test(keystore): prove H4 store-MAC neutralizes the M6 blob-move attack — on branch `feature/m6-verify-h4-mitigation` |
| 10 | `fd160b73` | M10(b) | fix(secure-memory): secure_memzero must not falsely report success on immutable input — on branch `feature/m10-secure-memzero` |
| 11 | `72d94b23` | M10(a) | fix(kdf): make the password wipe effective and copy-free across backends — on branch `feature/m10a-kdf-wipe` |
| 12 | `3612f24e` | M11 | fix(metadata): register all schemas dynamically + fail closed on unknown format_version — on branch `feature/m11-schema-fail-closed` |
| 13 | `deb4bc09` | M3 | fix(balloon): memory-hard default space_cost, persisted; warn on explicit-low — on branch `feature/m3-balloon-defaults` |
| 14 | `e0ea4be3` | M8 | fix(identity): TOFU key-change detection, full-fingerprint lookup, honest naming — on branch `feature/m8-identity-tofu` |

**Preferred port method:** `git cherry-pick e1969035 b2aeed02 e02ca531 de021bf5 8bb028d0 d0dc0bab c2a7dd6e 6204bff3 335020cd fd160b73 72d94b23 3612f24e deb4bc09 e0ea4be3` onto the
1.5.x branch, then resolve conflicts using the per-fix notes below and re-run the
test suite. If the files diverged substantially in 1.5.x, port by hand using the
"What changed" sections rather than the raw patch.

After porting, run the full suite: `pytest -n auto --dist=worksteal openssl_encrypt/unittests/`.

---

## 1. H3 — PQC: fail closed on unresolvable algorithm (commit `e1969035`)

**Files:** `openssl_encrypt/modules/pqc.py`, `openssl_encrypt/unittests/test_pqc.py`

**Problem:** `PQCipher.__init__` silently fell back to the first available KEM (the
*weakest*, e.g. `Kyber512`) when a requested algorithm name could not be matched,
and used unsupported enum values verbatim ("hope for the best"). A request for
`ML-KEM-1024` on a build lacking it — or any typo — could be served a weaker
algorithm with only an optional stderr line. Demonstrated: a bogus name resolved
to `Kyber512`.

**What changed (in `PQCipher.__init__`):**
- **String path** (`if not matched:` block, ~line 462): replaced the silent
  fallback (`self.algorithm_name = kyber_algs[0]` / `supported[0]`) with a
  `raise ValueError(...)` that lists the available KEM algorithms and explicitly
  refuses to downgrade.
- **Enum path** (the `else: # Use the enum value and hope for the best`, ~line 487):
  now first normalizes legacy enum values to their standard equivalent
  (`normalize_algorithm_name(algorithm.value, use_standard=True)`), then tries the
  normalized-base variant match, and only if all fail does it `raise ValueError(...)`.

**Critical invariant to preserve — legacy ML-KEM names must keep working:**
- Legacy *string* names (`Kyber768`, `Kyber-768`, `MLKEM768`, `kyber768-hybrid`)
  already resolve at the SAME security level via the earlier normalization/level
  matching (lines ~419-460) — do not touch that logic.
- Legacy *enum* values (e.g. `PQCAlgorithm.KYBER768`) now resolve via the added
  `normalize_algorithm_name` step to `ML-KEM-768` (same level) before any raise.
- The fix only converts the *unresolvable* case from "silent downgrade" to "error".

**1.5.x porting notes:**
- If 1.5.x added new KEM families (e.g. more HQC variants), make sure the KEM
  filter in the error message (`["kyber", "ml-kem", "hqc"]`) still lists them — it
  only affects the message text, not correctness.
- If 1.5.x changed `normalize_algorithm_name` or the `LEGACY_TO_STANDARD_ALGORITHM_MAP`,
  re-verify that every legacy name still maps to the same level after the change.
- Exception type is `ValueError` (consistent with other raises in `pqc.py`). Keep it
  so the CLI's existing error handling surfaces it and exits non-zero.

**Tests added (regression):**
- `test_unresolvable_algorithm_raises_no_silent_downgrade` — bogus / `ML-KEM-9999`
  names raise instead of downgrading.
- `test_legacy_names_still_resolve_to_same_level` — `Kyber512`/`Kyber-768`/
  `kyber1024-hybrid`/`ML-KEM-768`/`MLKEM1024` resolve to the correct level.
- Both guarded by `@unittest.skipUnless(LIBOQS_AVAILABLE, ...)`.

---

## 2. H5 — USB: unique per-drive KDF salt (commit `b2aeed02`)

**Files:** `openssl_encrypt/modules/portable_media/usb_creator.py`,
`openssl_encrypt/unittests/test_portable_media.py`

**Problem:** Every portable USB drive derived its master key with the same
hardcoded salt `b"openssl_encrypt_usb_v1.0_salt_2024"` (in both the multi-hash and
PBKDF2 paths), despite a comment claiming it was "unique per USB". A single
precomputed dictionary could crack the master password of ANY drive, and two drives
with the same password shared a key.

**What changed (`USBDriveCreator`):**
- New constants: `SALT_FILE = "salt.bin"` and
  `_LEGACY_FIXED_SALT = b"openssl_encrypt_usb_v1.0_salt_2024"` (retained ONLY for
  reading pre-fix drives). Added `import secrets` at module top.
- New method `_load_or_create_salt(portable_root, create=False)`:
  - reads `config/salt.bin` if present (>=16 bytes);
  - if `create=True` and absent, generates `secrets.token_bytes(SALT_LENGTH)` (32),
    writes it to `config/salt.bin` (plaintext — salts are not secret), returns it;
  - if `create=False` and absent (pre-fix drive), returns `_LEGACY_FIXED_SALT`.
- `_derive_encryption_key(password, hash_config=None, salt=None)` and
  `_derive_key_pbkdf2_fallback(password, salt=None)` now take an explicit `salt`
  (default `None` → `_LEGACY_FIXED_SALT` as a safety net); the hardcoded literals
  inside them were removed.
- Call sites threaded the salt through:
  - `create_portable_usb`: `salt = self._load_or_create_salt(portable_root, create=True)`
    then `_derive_encryption_key(secure_password, hash_config, salt)`.
  - `verify_usb_integrity`: `salt = self._load_or_create_salt(portable_root, create=False)`
    then `_derive_encryption_key(...)`.
  - `_read_hash_config_from_integrity`: loads the salt and passes it to
    `_derive_key_pbkdf2_fallback`.

**Backward compatibility (important):** pre-fix drives have no `salt.bin`; they
transparently fall back to `_LEGACY_FIXED_SALT` and remain verifiable. New drives
never use the legacy salt. `salt.bin` is not in the integrity checksum globs
(`*.conf|*.exe|openssl_encrypt|*.encrypted|*.py|*.bat|*.sh`), which is fine —
tampering with the salt changes the derived key, so AES-GCM decryption of the
integrity file fails and is detected as tamper.

**1.5.x porting notes:**
- If 1.5.x changed the on-disk layout (`CONFIG_DIR`, the directory creation order in
  `create_portable_usb`), keep the salt write happening *after* `config_dir` is
  created and *before* `_derive_encryption_key`.
- If 1.5.x bumps the USB format `VERSION`, consider: you can drop the
  `_LEGACY_FIXED_SALT` fallback ONLY if 1.5.x also drops support for reading
  1.4.x-era drives. Otherwise keep it.
- Consider (optional improvement for 1.5.x, NOT done here): the USB key derivation
  still uses raw multi-hash / PBKDF2; 1.5.x could move it to the same Argon2id-backed
  KDF used elsewhere and store KDF parameters next to the salt. Out of scope for the
  1.4.x fix (kept minimal), but a natural follow-up.

**Tests added (regression):**
- `test_usb_per_drive_salt_is_unique` — two drives, same password → different
  `salt.bin` (32 bytes, ≠ legacy), each still verifies.
- `test_usb_salt_legacy_fallback_and_key_separation` — missing salt file →
  `_LEGACY_FIXED_SALT`; different salts → different derived keys.

---

## 3. H6 — gitignore local secrets / artifacts (commit `e02ca531`)

**File:** `.gitignore`

**Problem (scope corrected during review):** a local `.gh_token` (GitHub `gho_`
OAuth token) sat world-readable in the repo root with no ignore rule. It was
**never tracked, never committed on any branch/ref, and its value never appeared in
history** (verified via `git ls-files`, `git log --all`, pickaxe `-S`,
`git diff --cached`). So there was **no git leak** — the fix is purely preventive
against a future accidental `git add .`. Token rotation was left to the owner's
judgment about the environment, not forced.

**What changed:** appended to `.gitignore`:
```
# Secrets / credentials (never commit)
.gh_token
*.token
.env
.env.*

# Local tool/test output artifacts
output.txt
precommit_output.txt
```
(`.coverage*` was already ignored.)

**1.5.x porting notes:** trivial — just ensure these patterns exist in the 1.5.x
`.gitignore`. No code impact.

---

## 4. H4 — keystore: whole-store integrity MAC, format v2 (commit `de021bf5`)

**Branch:** `feature/h4-keystore-integrity` (cherry-pick from there, or merge the
branch into `feature/v1.4.x-development` first).

**Files:** `openssl_encrypt/modules/keystore_cli.py`,
`openssl_encrypt/modules/crypt_errors.py`,
`openssl_encrypt/schemas/keystore_schema.json`,
`openssl_encrypt/unittests/test_keystore_integrity.py` (new)

**Problem:** The production keystore (`keystore_cli.py`) was plaintext JSON where
only per-key `private_key` fields were encrypted. `public_key`, `algorithm`,
`defaults`, `dual_encryption` flags etc. were unauthenticated — anyone with write
access could swap a public key for their own (undetectable), repoint defaults,
delete entries or strip dual-encryption flags. The `test_key` check authenticates
the password, not the file.

**What changed:**
- `KEYSTORE_VERSION` 1 → 2; `SUPPORTED_KEYSTORE_VERSIONS = (1, 2)`.
- `save_keystore()` now (a) refuses to save without the master key, (b) always
  stamps the current version, (c) writes
  `integrity: {alg: "HMAC-SHA256", mac: <b64>}` computed over the canonical JSON
  (`sort_keys=True`, `separators=(",", ":")`, `integrity` field excluded) of the
  whole structure, keyed by
  `HMAC(master_key, b"openssl_encrypt.keystore.integrity.v2")` (domain-separated
  subkey — the master key itself stays the AES-GCM private-key wrap key).
- `load_keystore()` verifies the MAC for v2 **before trusting any field**
  (`_verify_integrity`, called right after master-key derivation). On mismatch it
  uses `test_key` to disambiguate: test_key decrypt fails → `KeystorePasswordError`
  (wrong password); succeeds (or absent) → new `KeystoreIntegrityError`. Master key
  and keystore_data are cleared before raising.
- Legacy v1: loads with `logger.warning`, then auto-upgrades to v2 by calling
  `save_keystore()` — only if a `test_key` verified the password (otherwise the
  upgrade is skipped with a warning so a mistyped password can never seal the
  store); a failed upgrade write (read-only media) is warned, load still succeeds.
- `crypt_errors.py`: new `KeystoreIntegrityError(KeystoreError)`.
- `keystore_schema.json`: optional top-level `integrity` object (required `alg`
  enum `["HMAC-SHA256"]` + base64 `mac`); v1 files validate unchanged.

**Critical invariants to preserve when porting:**
- The MAC must be computed LAST in `save_keystore()` (after `last_modified`,
  version stamp, and `test_key` creation) so it covers the final structure.
- The MAC must be verified BEFORE any field of a v2 store is trusted on load.
- Canonicalization must be byte-stable: `json.dumps(payload, sort_keys=True,
  separators=(",", ":"))` with default `ensure_ascii` — if 1.5.x changed the
  serializer or stores non-JSON-stable types in `keystore_data`, re-verify.
- Wrong password and tampering MUST remain distinguishable (`KeystorePasswordError`
  vs `KeystoreIntegrityError`) — CLI/D-Bus error handling depends on the former.

**1.5.x porting notes / divergence risks:**
- If 1.5.x already bumped the keystore version or added fields, merge the version
  sets rather than overwriting (`SUPPORTED_KEYSTORE_VERSIONS`).
- **Recommended hardening for 1.5.x (not done on 1.4.x):** refuse v1 keystores
  (or gate behind an explicit flag). On 1.4.x a downgrade attack (strip MAC +
  rewrite `version: 1`) still loads with a warning — accepted for backward
  compatibility on the stable branch; 1.5.x is the right place to close it.
- The dual-encryption no-AAD issue inside the same file is M6 and is NOT part of
  this fix — don't conflate them when resolving conflicts.
- Keystores created by 1.4.x post-fix are v2; pre-fix 1.4.x code rejects them with
  `KeystoreVersionError` ("Unsupported keystore version"). Mixed-version fleets
  should upgrade readers first.

**Tests added (regression, `test_keystore_integrity.py`, 18 tests):** tampered
public_key / algorithm / defaults / dual-encryption flags; deleted and swapped key
entries; stripped `integrity` field; unknown MAC alg (fails closed via schema);
wrong-password vs tamper distinction (v1 and v2); v1 warn + auto-upgrade incl.
write-failure and missing-`test_key` paths; mutating-operation round-trips
(add/set-default/remove/change-master-password); save-without-master-key refusal.
The tests use random bytes as key material, so they run without liboqs.

---

## 5. Test infra — unittests.py was never collected (commit `8bb028d0`)

**Branch:** `feature/unittests-collection`. Not a security finding, but port it:
without it ~90 tests (incl. all `TestKeystoreOperations`/`TestCryptCore`) never
run, and two real `pqc_keystore.py` bugs it fixes stay hidden.

**What changed:**
- `pytest.ini`: `python_files = test_*.py unittests.py` — the file predates the
  `test_*.py` convention and was silently dropped from collection when
  pytest.ini was introduced (2025-12-30).
- `Makefile`: `test-all` runs the whole `unittests/` directory.
- `unittests.py`: removed a module-level global `warnings.warn` monkeypatch that
  leaked into co-resident test modules and broke `pytest.warns()` tests
  (replaced with module-scoped `pytestmark` filterwarnings); flattened
  `TestCryptCore` hash configs (nested `derivation_config` shape produced
  undecryptable files); `TestArgon2KdfVersion` now targets
  `pqc_keystore.PQCKeystore` (was hitting `keystore_cli.PQCKeystore` via the
  name collision); legacy-v1 KDF test rewritten with a deterministic mock plus
  a new test documenting that the real v1 KDF is non-deterministic
  (unrecoverable keystores).
- `pqc_keystore.py` (product fixes): `load_keystore` no longer validates its
  payload against the format-mismatched keystore_cli schema (every load failed
  since MED-8; now `secure_json_loads` generic limits — payload is AEAD-
  authenticated anyway); `save_keystore` now serializes the payload AFTER
  updating `kdf_version`/nonce so the embedded params match the header.

**1.5.x porting notes:** if 1.5.x renamed/split `unittests.py`, only the
`pqc_keystore.py` hunks and the warnings-monkeypatch removal matter. Check
whether 1.5.x's pytest.ini has the same `python_files` gap.

---

## 6. H7 + L8 — D-Bus per-caller authorization (commit `d0dc0bab`)

**Branch:** `feature/h7-dbus-authz`

**Files:** `openssl_encrypt/modules/dbus_service.py`,
`openssl_encrypt/unittests/test_dbus_authz.py` (new),
`openssl_encrypt/dbus/ch.rmrf.openssl_encrypt.conf` (docs/comments),
`openssl_encrypt/dbus/ch.rmrf.openssl_encrypt.policy` (tightened),
`openssl_encrypt/dbus/system-services/ch.rmrf.openssl_encrypt.service` (new),
`systemd/openssl-encrypt-dbus.service` (L8 hardening),
`systemd/openssl-encrypt-dbus-system.service` (new)

**Problem:** No caller authorization on any D-Bus method; system-bus policy
allowed any user; polkit .policy shipped but never enforced.

**Design intent (owner):** the system-bus root service is intentional — it lets a
non-root admin encrypt/decrypt files only root can access. Authorization was
implemented, not removed.

**What changed (invariants to preserve when porting):**
- `_authorize_caller(sender, action_id)` is consulted FIRST in every
  state-touching method and **fails closed** (no sender / UID unresolvable /
  polkit error ⇒ deny + `security_logger` audit event).
- Session bus: caller UID == service UID. System bus (`--system` flag on
  `run_service`/module CLI): polkit `CheckAuthorization`, subject
  `("system-bus-name", {"name": sender})`, flags include
  `AllowUserInteraction` (1).
- Method → action id map: EncryptFile/EncryptData → `…encrypt`,
  DecryptFile/DecryptData → `…decrypt`, SecureShredFile → `…shred`,
  GeneratePQCKey → `…generate_key`, ListPQCKeys → `…keystore`,
  DeletePQCKey → `…delete_key`. Action ids must stay in sync with the
  .policy (there is a test for that).
- Path policy is mode-dependent (`self._allowed_base_directories` /
  `self._blocked_paths` set in `__init__`): system mode = whole filesystem
  minus blocked critical paths with `/root` unblocked; session = home/tmp.
  `_validate_file_path` also catches `OSError` from `stat()` (fail closed).
- polkit .policy: `allow_active` is `auth_admin_keep` for
  encrypt/decrypt/keystore/generate_key; `auth_admin` for shred/delete_key.
  Do NOT regress to `yes` when resolving conflicts.

**1.5.x porting notes:**
- If 1.5.x added/renamed D-Bus methods, every new method MUST get
  `sender_keyword` + an `_authorize_caller` gate with the right action id —
  the gating test class (`TestMethodGating`) should be extended to cover it.
- The tests fake the `dbus` module via `setUpModule`/`tearDownModule`
  (dbus-python not required); keep that pattern — do not let a real dbus
  import sneak in or the module import will `sys.exit(1)` on CI boxes
  without dbus.
- **Manual smoke test required once on a real system-bus install** (polkit
  integration is mock-tested only): install .conf + .policy + system unit,
  call EncryptFile as a non-admin (expect polkit prompt/denial) and as admin.
- L12 (passwords as plain `str` on the bus) is still open and matters more
  now that the system-bus path is real — consider fd-passing in 1.5.x.

---

## 7. H8 — plugin sandbox on the default path (commit `c2a7dd6e`)

**Branch:** `feature/h8-plugin-sandbox`

**Files:** `openssl_encrypt/modules/plugin_system/plugin_sandbox.py`,
`plugin_ast_analyzer.py`, `plugin_manager.py`,
`openssl_encrypt/unittests/test_plugin_sandbox_h8.py` (new)

**Problem:** (1) file/net/process restrictions ran only in threading mode, not the
default `_plugin_worker` process path; (2) AST denylist missed the frame/traceback
escape chain; (3) plugins loadable from group/world-writable locations (import-time
code window).

**What changed:**
- `_plugin_worker`: AST-validate first (real `open()` needed by
  `inspect.getsource`), then run `_setup_restricted_environment()` (full
  capability-honouring sandbox), then `execute()`.
- `DANGEROUS_DUNDER_ATTRIBUTES`: added `__traceback__`, `tb_frame`, `tb_next`,
  `f_back`, `f_globals`, `f_locals`, `f_builtins`, `gi_frame`, `cr_frame`,
  `ag_frame`.
- `plugin_manager._insecure_location_reason()` + a call at the top of
  `_validate_plugin_file` (before the built-in trust shortcut): reject
  group/world-writable file or parent dir; sticky dirs (e.g. `/tmp`) exempt.

**Critical invariants when porting (this fix was subtle):**
- AST validation MUST run before the file restrictions are applied, or
  `inspect.getsource` (which reads the plugin file) fails under the patched
  `open()`. Keep that order.
- `_plugin_worker` mutates PROCESS-WIDE state. It now restores all of it in
  `finally`: resource limits, cwd, patched globals, temp dir. **Resource limits
  must lower only the SOFT limit and preserve the original HARD limit** — an
  unprivileged process cannot raise a hard limit back, so the old `(60,60)`
  `RLIMIT_CPU` was unrestorable and leaked a 60 s CPU cap when the worker runs
  in-process (it killed xdist workers with SIGXCPU). If 1.5.x touches this
  worker, preserve the soft-only pattern and the restore finally.
- The writable-location check is keyed on `stat` bits incl. the sticky bit; do
  not "simplify" it to a plain world-writable check or `/tmp`-based plugin dirs
  (and the test suite) break.

**1.5.x porting notes / follow-ups (not done here):**
- Module top-level code still runs under `exec_module` with only AST + the new
  permission gate — a genuinely restricted-`__builtins__` runtime at load time
  is the larger fix and a good 1.5 item.
- Dynamic `getattr(obj, <computed-name>)` stays severity "high" (warn, not
  block) to avoid false positives; revisit if a stricter policy is acceptable.

**Tests (15, `test_plugin_sandbox_h8.py`):** AST frame/traceback chain (incl.
`getattr`), worker file-denial + sandbox-wiring, writable file/dir rejection +
secure-location acceptance, and explicit cwd / resource-limit preservation
guards (the regression that caused the xdist crashes).

---

## 8. M7 — drop the weak PBKDF2 file-password verifier (commit `6204bff3`)

**Branch:** `feature/m7-drop-pbkdf2-verifier`

**Files:** `openssl_encrypt/modules/keystore_wrapper.py`,
`openssl_encrypt/unittests/test_pqc.py`

**Problem:** dual-encrypted files stored `pqc_dual_encrypt_verify[_salt]` — a
10k-iteration PBKDF2-HMAC-SHA256 hash of the file password in cleartext metadata,
a redundant UX pre-check that doubled as a cheap offline brute-force oracle.

**What changed:** `encrypt_file_with_keystore` no longer writes the verifier
(the AES-GCM tag in `keystore_cli.get_key` already authenticates the file
password). `decrypt_file_with_keystore` still validates the field on legacy files
and otherwise relies on the tag.

**>>> 1.5 ACTION REQUIRED (PBKDF2 removal):** this verifier is a **standalone
`hashlib.pbkdf2_hmac("sha256", ...)`** call in `keystore_wrapper.py` (the decrypt
side still has one for reading legacy files), NOT routed through the KDF registry.
A 1.5 "remove the PBKDF2 KDF option" sweep done via the registry will MISS it.
When PBKDF2 is fully removed in 1.5, explicitly grep for `pbkdf2_hmac` and delete
the remaining legacy-read verifier path in `decrypt_file_with_keystore` too. After
that, 1.5 cannot read the pre-M7 verifier — acceptable since the tag verifies the
password regardless.

**1.5 porting notes:** trivial cherry-pick; if 1.5 changed the dual-encryption
metadata layout, just ensure no code path re-introduces a password-derived value
in cleartext metadata.

---

## 9. M6 — verified H4 neutralizes the keystore blob-move (commit `335020cd`)

**Branch:** `feature/m6-verify-h4-mitigation`. Test-only.

The H4 whole-store HMAC covers every entry's `private_key` field, so moving an
encrypted blob between entries fails the MAC on load (for any attacker without
the master password). Added `test_private_key_blob_move_between_entries_rejected`
to `test_keystore_integrity.py` proving it; M6 downgraded to "largely mitigated
by H4". **Optional 1.5 defense-in-depth (not required):** add `aad=key_id`
(or `algorithm` + hash(public_key)) to the master-key private-key wrap in
`keystore_cli._encrypt_data_with_key`/`_decrypt_data_with_key`, so the binding
holds independent of the store MAC. Depends on H4 being present.

## 10. M10(b) — secure_memzero honesty (commit `fd160b73`)

**Branch:** `feature/m10-secure-memzero`

**Files:** `openssl_encrypt/modules/secure_memory.py`,
`openssl_encrypt/unittests/test_secure_memzero_m10.py`

`secure_memzero` returned `True` ("verified zeroed") for immutable `bytes`/`str`
while only zeroing a throwaway copy. Now returns `False` (or raises with the new
`strict=True`) for immutable input; mutable buffers still wiped in place → `True`.

**M10 part (a) is now DONE — see entry 11 below (commit `72d94b23`).**

---

## 11. M10(a) — effective, copy-free KDF password wipe (commit `72d94b23`)

**Branch:** `feature/m10a-kdf-wipe`

**Files:** `openssl_encrypt/modules/registry/kdf_registry.py`,
`openssl_encrypt/unittests/test_kdf_wipe_m10a.py`

Removed the dead `password_bytes != password` guard + throwaway-copy wipes from
every backend. Copy-free backends (cryptography PBKDF2/Scrypt/HKDF, Balloon,
RandomX) now pass the caller's `password` straight through; Argon2id (Argon2i/d
delegate to it) holds the secret in a wipeable `bytearray` and zeroes it,
feeding argon2 one short-lived `bytes()` copy (its binding requires immutable
bytes).

**Critical invariant when porting:** the derived key MUST stay byte-identical
for `bytes`/`bytearray`/`SecureBytes` input on every backend, and the caller's
`SecureBytes` must never be mutated. If 1.5 changes a backend or its binding,
re-verify with `test_kdf_wipe_m10a.py` (key-equality + caller-intact + wipe
spy) AND `test_cr_cross_backend_determinism.py`. Re-check that each backend
still accepts a `bytearray`/`SecureBytes` (only argon2 needs `bytes`); a binding
that newly rejects bytearray would silently break derivation without these
tests. This is key-derivation code — an error means wrong keys / unrecoverable
data.

---

## 12. M11 — metadata schema fail-closed + dynamic registration (commit `3612f24e`)

**Branch:** `feature/m11-schema-fail-closed`

**Files:** `openssl_encrypt/modules/json_validator.py`,
`openssl_encrypt/unittests/test_metadata_schema_m11.py`

`_load_schemas` now registers every `metadata_v{N}_schema.json` dynamically
(fixes the v9/v12 drift where schemas existed but were never wired up).
`validate_metadata` derives the schema from the version, validates when one is
registered, accepts genuine legacy (missing / v1 / v2) under generic limits, and
**fails closed** on unknown/future/non-integer versions.

**Critical when porting:** `secure_metadata_loads` is on the decrypt path — a
raise aborts decryption. The legacy-accepted set is exactly `{None, 1, 2}`; the
schemaful range is whatever `metadata_v*_schema.json` files ship. If 1.5 adds a
new format version, **ship its schema file** or the dynamic loader won't register
it and files of that version will fail closed. Re-run the format/streaming tests
(v10/v11/v12) plus `test_metadata_schema_m11.py` after porting. If 1.5 retired
v1/v2 support entirely, you may drop them from the legacy-accepted set.

---

## 13. M3 — memory-hard Balloon default (commit `deb4bc09`)

**Branch:** `feature/m3-balloon-defaults`

**Files:** `openssl_encrypt/modules/crypt_core.py`,
`openssl_encrypt/unittests/test_balloon_defaults_m3.py`

The v11 independent-XOR (and `parallel_kdf`) Balloon path defaulted to
`space_cost=16` (~512 B, GPU-trivial) and didn't persist the value. New helper
`_apply_balloon_security_defaults(hash_config)` runs once in `encrypt_file`
(encrypt path ONLY), sets `space_cost=65536` (2 MiB) + `time_cost=3` when unset
and persists them, and warns loudly on an explicit sub-floor value (< 16384 /
512 KiB) without refusing (M4-consistent).

**Critical invariant when porting:** the fix is ENCRYPT-ONLY. The decrypt-side
read-default (`crypt_core.py:2371`, `parallel_kdf`) MUST stay `16` — legacy v11
files stored only `{"enabled": true}` and re-derive with that default; raising
it makes them undecryptable. Keep the legacy-weak-file regression test. If 1.5
moves Balloon to a faster (C) backend, the 2 MiB / 64 MiB tradeoff and the
~1 s time_cost pinning should be re-tuned (pure-Python caps the 1.4 ceiling).
`max_space_cost` left at 1e6 for the same reason. If 1.5 changed the config
shapes, ensure the helper still finds Balloon in both the top-level and
`derivation_config.kdf_config` locations.

---

## 14. M8 — identity TOFU key-change detection (commit `e0ea4be3`)

**Branch:** `feature/m8-identity-tofu`

**Files:** `openssl_encrypt/modules/identity.py`, `identity_cli.py`,
`crypt_cli_subparser.py`, `openssl_encrypt/unittests/test_identity_tofu_m8.py`

`IdentityStore.add_identity` now refuses a fingerprint change for an existing
name (new `IdentityKeyChangedError`) even with `overwrite=True`; the explicit
`allow_key_change=True` is required. `cmd_import` refuses non-interactively and
prompts on a TTY (`--allow-key-change` to script it); `cmd_create` passes
`allow_key_change=True` (own-identity regen). `get_by_fingerprint` requires the
FULL fingerprint (no more `startswith`), errors on empty input and on ambiguous
matches (`IdentityAmbiguousError`). `verify_fingerprint` → renamed
`check_fingerprint_consistency` (alias kept).

**Critical when porting:**
- The full-fingerprint lookup depends on metadata storing the full
  `sender.fingerprint` as `key_id` (verified in 1.4: `crypt_core.py` ~5678). If
  1.5 ever truncates `key_id`, the sender-resolution lookup would break — keep
  them in sync or re-add a (bounded, ambiguity-checked) prefix match.
- The key-change gate is universal in `add_identity` (safe default). Any
  programmatic caller that legitimately rotates an own key must pass
  `allow_key_change=True` (as `cmd_create` does). The keyserver `KeyResolver`
  path refuses key changes by default — consider a trust-callback prompt in 1.5.
- M8 is pinning + change detection, NOT first-contact authenticity (signed
  bundles / web-of-trust) — that remains a larger 1.5 feature.

---

## Related deferred work (1.5.x feature, not a 1.4.x port)

- **XChaCha20 real 192-bit nonce** — deliberately deferred to 1.5.x; 1.4.x left
  as-is (no security defect there: per-file unique keys mean the effective 96-bit
  nonce is never reused). Full analysis and the implementation gotchas (the naive
  "pass the full nonce" fix is a no-op; needs real HChaCha20 via libsodium; backward
  compat needs a `format_version` bump or trial-decrypt fallback) are in
  `SECURITY_REVIEW_FINDINGS.md` under `I-XChaCha`. This is NEW work for 1.5.x, not a
  backport of a 1.4.x commit.

## Findings NOT yet addressed (still open on 1.4.x — port the fixes once made)

These remain open in `SECURITY_REVIEW_FINDINGS.md` and will need their own fixes;
when fixed on 1.4.x, add them to this porting guide:
- Mediums M5, M12 and the Low/Info items.
  (Dispositions so far: M2 mitigated-by-design; M4 & M9 dismissed-by-design;
  M6 mitigated by H4 (verified); M3, M7, M8, M10 (a+b), M11 fixed;
  L8 closed with H7. L12 still open.)

Note: H1/H2 (PQC legacy decrypt shims) were **downgraded to Low** (deprecation-warned
backward-compat code, not reachable for genuine modern files) — see `I-PQC-Legacy`.
If addressed, the recommended approach is an explicit `--allow-legacy-pqc` opt-in
with a sunset version, NOT removal (which would break old files).
