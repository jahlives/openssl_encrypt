# Source-Code Integrity Protection — Implementation Plan

**Status:** DRAFT — awaiting green light. Nothing in this plan has been implemented.
**Author:** drafted with Claude (senior crypto/security engineer hat)
**Date:** 2026-06-17
**Target branches:** `feature/v1.4.x-development` **first**, then forward-port to `feature/v1.5.x-development` (Q7)

---

## 1. Goal & Threat Model

### 1.1 Goal
Detect unauthorized modification ("tampering") of the project's **core cryptographic/security Python source files**. We achieve this by:

1. Maintaining a **manifest** that records a cryptographic hash of each protected file.
2. **PGP-signing** that manifest with a dedicated project signing key (detached signature).
3. Storing manifest + signature **in the repository, per branch and per tag**.
4. Regenerating + re-signing the manifest **automatically before each commit** (local pre-commit hook, developer holds the private key).
5. Providing a **CLI verification command** that re-hashes the files and verifies them against the signed manifest — **with a prominent warning that the CLI verifier is itself bundled code and therefore not a root of trust** (see §7).

### 1.2 What this protects against
- Silent modification of a shipped crypto-core `.py` file (e.g. a backdoored KDF, weakened cascade, leaked key material) in a checkout, a release artifact, or a malicious MR — **detectable** by anyone holding the trusted public key, as long as they verify the signature out-of-band (see §7).

### 1.3 What this explicitly does NOT protect against (documented honestly)
- **Tampering with the verifier itself.** If an attacker can edit `crypt_core.py`, they can also edit the verification code, the manifest, *and* re-sign with a substituted public key. Bundled verification is a tripwire for accidental/unsophisticated tampering, **not** a cryptographic guarantee. The only reliable verification is **manual**, using a public key obtained out-of-band and the `gpg` binary directly (§7).
- **Compromise of the signing private key.** If the dedicated project key leaks, an attacker can forge valid manifests. Key custody (§4) is therefore critical.
- **Runtime / in-memory attacks**, supply-chain compromise of dependencies, or compromise of the build toolchain. Out of scope.
- **Non-Python core** (e.g. the `threefish_native/` Rust crate). See open question Q4.

---

## 2. Confirmed Decisions (from product owner)

| # | Decision | Choice |
|---|----------|--------|
| D1 | Protected file scope | **Crypto/security core only** (explicit list in §3) |
| D2 | Hash/verify mechanism | **Shell out to the system `gpg` binary** (no bundled PGP library as root of trust) |
| D3 | Where signing happens / key custody | **Local pre-commit hook**, signed with the **developer's local copy of the project key**; CI only *verifies* |
| D4 | Signing key | **Dedicated project signing key** (new keypair, public key committed to repo) |

### 2.1 Resolved open questions (all answered 2026-06-17)

| Q | Question | Decision |
|---|----------|----------|
| Q1 | Extra files beyond the 31 core modules | **Include** entry files (`cli.py`, `crypt.py`, `__init__.py`, `__main__.py`) + `crypt_gui.py`, `versions.py`, `post_install.py`. **Exclude** `version.py.template` and the verifier code itself. |
| Q1b | Requirements files | **Include** all 6 tracked requirements files: `requirements.txt`, `requirements-prod.txt`, `requirements-dev.txt`, `requirements-hsm.txt`, `requirements-prod.in`, `requirements-dev.in`. **Exclude** `pyproject.toml`/`setup.py`. |
| Q2 | Hash algorithm | **SHA-512** |
| Q3a | Key algorithm | **Ed25519** (sign-only) |
| Q3b | Hardware token | **Software key now, token-ready** — design/docs allow moving to OnlyKey/YubiKey later without process change |
| Q3c | Signed git tags | **No** — rely on the committed signed manifest each tagged commit carries |
| Q3d | Contributors without the key | **Block via branch protection** — protected branches require a valid current signed manifest |
| Q4 | Rust crate (`threefish_native/`) | **Include now** — `Cargo.toml`, `src/lib.rs`, `src/threefish_aead.rs`, `threefish_native/pyproject.toml` (`Cargo.lock` is gitignored, not tracked → excluded) |
| Q5 | Manifest reproducibility | **Drop** `generated_at_utc`/`git_commit` from the signed payload — fully reproducible manifest |
| Q6a | CLI surface | **`verify-integrity` subcommand** |
| Q6b | `--quiet` and the warning | **Allow shortened** warning under `--quiet` (one-line pointer to docs); full text otherwise; `--json` always keeps the `trust_warning` field |
| Q7 | Rollout order | **1.4.x first**, then forward-port to 1.5.x |
| Q8 | System `gpg` dependency | **Accepted**; `verify-integrity` **fails closed** (clear error, non-zero exit) if `gpg` is absent — never a silent pass |

---

## 3. Protected File Set (D1 — "Crypto/security core only") — FINALIZED

### 3.1 Final list (confirmed via Q1, Q1b, Q4)

**`openssl_encrypt/modules/` — 31 crypto & security modules:**
```
crypt_core.py            crypt_utils.py           crypt_errors.py
crypt_settings.py        secure_memory.py         secure_allocator.py
secure_ops.py            secure_ops_core.py       crypto_secure_memory.py
asymmetric_core.py       pqc.py                   pqc_adapter.py
pqc_liboqs.py            pqc_signing.py           pqc_keystore.py
ml_kem_patch.py          cascade.py               cascade_validator.py
balloon.py               parallel_kdf.py          randomx.py
key_bundle.py            key_resolver.py          keystore_utils.py
keystore_wrapper.py      identity.py              identity_protection.py
password_policy.py       diceware.py              file_permissions.py
security_logger.py
```

**Top-level package — 7 files (Q1):**
```
openssl_encrypt/__init__.py      (package marker / version exposure)
openssl_encrypt/__main__.py      (entry dispatch)
openssl_encrypt/cli.py           (entry point — argument routing)
openssl_encrypt/crypt.py         (high-level orchestration)
openssl_encrypt/crypt_gui.py     (GUI front-end)
openssl_encrypt/versions.py      (dependency-version checker)
openssl_encrypt/post_install.py  (post-install script)
```

**Dependency / requirements files — 6 files (Q1b):**
```
requirements.txt          requirements-prod.txt    requirements-dev.txt
requirements-hsm.txt      requirements-prod.in     requirements-dev.in
```

**Rust crate (`threefish_native/`) — 4 files (Q4):**
```
threefish_native/Cargo.toml
threefish_native/src/lib.rs
threefish_native/src/threefish_aead.rs
threefish_native/pyproject.toml   (maturin build config)
```

**Total: 31 + 7 + 6 + 4 = 48 protected files.**

### 3.2 Explicitly EXCLUDED (with rationale)
- `openssl_encrypt/version.py` — **auto-generated** by `setup.py` (embeds `__git_commit__`, changes every build). Including it would make the manifest unstable.
- `openssl_encrypt/version.py.template` — excluded (Q1).
- The integrity verifier code (`openssl_encrypt/integrity/*.py`) — excluded from the manifest (Q1). It is not self-protecting anyway; trust rests on out-of-band verification (§7).
- `threefish_native/Cargo.lock` — **gitignored / not tracked** (global `.gitignore` ignores `Cargo.lock`), so it cannot be in a committed manifest. Excluded.
- `pyproject.toml` / `setup.py` (repo root) — excluded (Q1b).
- `openssl_encrypt/unittests/**` — tests change frequently; high churn, low attack value.
- `openssl_encrypt/plugins/**` — opt-in, not core. (Could be a *separate* manifest later.)
- `__pycache__/`, data files, schemas, templates.

### 3.3 How the list is maintained
The protected set is stored as an **explicit, version-controlled allowlist** (not a glob), so adding/removing a protected file is a deliberate, reviewable change:
- File: `openssl_encrypt/integrity/protected_files.txt` (one repo-relative path per line, `#` comments allowed).
- Rationale for explicit list over glob: a glob would silently include newly-added files (could mask an injected file being added without review) and silently drop renamed ones. An explicit allowlist forces a human decision and shows up in diffs.
- A guard in the manifest generator (§5) **fails loudly** if a path in the allowlist is missing on disk. It also runs an **advisory** sweep of `openssl_encrypt/modules/*.py` and warns if a module is present but unlisted (so a newly-added crypto module isn't silently left unprotected) — advisory only, never auto-added.

---

## 4. Signing Key (D4 — dedicated project key)

### 4.1 Key generation (one-time, manual, documented — NOT automated)
A new PGP keypair is generated **by you, locally**, e.g.:
```
gpg --quick-generate-key "openssl_encrypt source integrity <jahlives@gmx.ch>" ed25519 sign 2y
```
- Algorithm: **Ed25519** (sign-only) — confirmed (Q3a). Requires gpg ≥ 2.1 (universal today).
- Usage flags: **sign only** (no encryption subkey needed).
- Expiry: 2 years suggested, with documented renewal procedure.
- The key is used **exclusively** for source-integrity signing — never reused for commit signing, email, or release artifact signing, to keep its trust meaning unambiguous.

### 4.2 Public key — committed to repo
- Exported ASCII-armored public key committed at: `openssl_encrypt/integrity/keys/source-integrity-pubkey.asc`
- Its **fingerprint** is recorded in:
  - `openssl_encrypt/integrity/keys/FINGERPRINT` (plain text, the canonical expected fingerprint), and
  - the project `README.md` / `SECURITY.md` (so the fingerprint is also visible out-of-band on the GitLab project page and in mirrors).
- **Trust-on-publish caveat (documented):** committing the public key into the same repo it protects is convenient but circular — an attacker rewriting the repo can swap both. The fingerprint is therefore *also* published out-of-band (SECURITY.md, project description, release notes, and ideally the maintainer's existing web-of-trust). §7 verification instructs users to obtain the fingerprint from an independent channel.

### 4.3 Private key custody (D3)
- The private key lives **only on developer machines** that are authorized to produce signed manifests. It is **never** committed and **never** stored in GitLab CI variables (consistent with D3: CI only verifies).
- **Custody (Q3b — software now, token-ready):** start with a passphrase-protected software key in the developer's gpg keyring. The signer (`gpg_runner.py`) and runbook will be written so the key can later be moved onto an OnlyKey/YubiKey **without any process change** — signing always goes through `gpg --local-user <FPR>`, which works identically for software and on-card keys. The runbook documents the on-card migration as the recommended hardening step.
- Add `*.asc` exceptions carefully: the committed **public** key and the committed **signature** files are `.asc`; ensure `.gitignore` does **not** accidentally ignore them and does **not** allow a private key (`*.key`, `secret*.asc`) to be committed. A `detect-private-key` pre-commit hook already exists — we will extend its scope check.

---

## 5. Manifest Format & Storage

### 5.1 Manifest file
- Path (per branch, lives in the branch itself): `openssl_encrypt/integrity/manifest.json`
- Detached signature: `openssl_encrypt/integrity/manifest.json.asc`
- Format (canonical, deterministic — sorted keys, `\n` line endings, UTF-8, trailing newline) so the same tree always yields a byte-identical manifest:

```json
{
  "schema_version": 1,
  "hash_algorithm": "sha512",
  "key_fingerprint": "<expected signing key fingerprint>",
  "files": {
    "openssl_encrypt/modules/crypt_core.py": "sha512:<hex>",
    "openssl_encrypt/modules/secure_memory.py": "sha512:<hex>"
  }
}
```

- **Hash algorithm: SHA-512** (Q2), recorded in the manifest so it can evolve. `sha512sum` is widely available for the manual out-of-band check.
- **The signature covers the entire `manifest.json` byte-for-byte.** The manifest cannot hash itself; the `.asc` is the integrity anchor for the manifest. The manifest hashes every *other* protected file.
- **Reproducibility (Q5):** `generated_at_utc` and `git_commit` are **dropped from the signed payload** entirely. An identical tree therefore always yields a byte-identical `manifest.json`, so a verifier can independently regenerate it and byte-compare. No timestamp/commit sidecar is produced (branch/ref provenance comes from git itself).

### 5.2 Per-branch vs per-tag
- **Per-branch:** the manifest is a normal tracked file; it travels with the branch and is updated on each commit by the pre-commit hook (§6). Each branch therefore always carries a manifest describing *its own* protected files.
- **Per-tag:** tags are immutable snapshots. Because a tag points at a commit that already contains a committed+signed manifest, **tags inherit the manifest of their commit automatically** — no special action needed at tag time, *provided* the last commit before tagging has an up-to-date signed manifest. The release procedure (§8) will include a verification gate: "manifest is current and signature valid" before tagging.
- **Signed git tags: NOT used (Q3c).** We rely solely on the committed signed manifest that each tagged commit already carries. (`git tag -s` could be added later if desired, but is out of scope now.)

### 5.3 Location rationale
`openssl_encrypt/integrity/` (inside the package) rather than repo root, so the manifest + verifier ship together in the installed package and the CLI can locate them via package resources (`importlib.resources`). The committed scratch-log gitignore work is unaffected.

---

## 6. Automation: Local Pre-Commit Hook (D3)

### 6.1 Mechanism
Add a **`repo: local`** hook to `.pre-commit-config.yaml` (the file already has a `repo: local` block for pip-audit, so the pattern exists):

```yaml
  - repo: local
    hooks:
      - id: source-integrity-manifest
        name: Regenerate & sign source integrity manifest
        entry: python -m openssl_encrypt.integrity.update_manifest --sign
        language: system
        # Only re-run when a protected file (or the allowlist) changes:
        files: '^(openssl_encrypt/integrity/protected_files\.txt|openssl_encrypt/modules/.*\.py|openssl_encrypt/(cli|crypt|__init__|__main__)\.py)$'
        pass_filenames: false
```

### 6.2 What the hook does
1. Read the allowlist (`protected_files.txt`).
2. Hash every listed file → build canonical `manifest.json`.
3. If the manifest content **changed**, write it, then run `gpg --detach-sign --armor --local-user <FPR>` to (re)produce `manifest.json.asc`.
4. `git add` both files so they're part of the commit.
5. If `gpg` is unavailable or the key is absent, **fail the commit with a clear message** (don't silently skip). The standard pre-commit `SKIP=source-integrity-manifest` escape hatch still exists for contributors who don't hold the key — but per Q3d their resulting stale/unsigned manifest **will not pass branch protection** (§6.3), so it cannot be merged to a protected branch.

### 6.3 Why pre-commit and not CI-signing
Per D3, the private key never enters CI. The developer's local hook is the only signer. CI's role is **verification only** (§9). This means: a contributor *without* the key cannot produce a valid signed manifest — by design.

**Branch protection (Q3d):** protected branches (`feature/v1.4.x-development`, `feature/v1.5.x-development`, release tags' source) require the verify-only CI job to pass, which it only does when the manifest is current AND its signature is valid AND verifies against the committed project public key. A stale or unsigned manifest therefore **blocks the merge**. This is the enforcement point that makes the local-signing model meaningful. (Configuring the GitLab branch-protection / "pipeline must succeed" rule is an operational step in the runbook, §8.)

### 6.4 Bootstrapping / chicken-and-egg
- The very first manifest is generated and signed **manually** (documented runbook), committed once. After that, the hook maintains it.
- The hook/verifier code itself (`openssl_encrypt/integrity/*.py`) is **NOT in the protected set** (Q1). It cannot meaningfully protect itself against a local attacker, and the trust model already routes real assurance through out-of-band verification (§7).

---

## 7. CLI Verification Command (with mandatory warning)

### 7.1 Surface
Add a subcommand (consistent with existing `identity`, `hsm`, `keyserver` subparsers in `crypt_cli_subparser.py`):

```
openssl-encrypt verify-integrity [--manifest PATH] [--pubkey PATH] [--json] [--quiet]
```
(Top-level `--verify-integrity` flag is an alternative — Q6. Subcommand recommended for consistency.)

### 7.2 Behavior
1. **Print the trust warning before doing anything** (to stderr). **Default: full warning.** Under `--quiet` (Q6b) it collapses to a single line, e.g. `⚠️ Built-in verification is a tripwire, not proof — see docs/SOURCE_INTEGRITY.md and verify manually with gpg.` In `--json` mode the full caveat is **always** retained in the `"trust_warning"` field regardless of `--quiet`.

   > ⚠️  WARNING: This built-in verification runs code that lives in the same
   >     package it is checking. If an attacker can modify the protected source
   >     files, they can also modify THIS verifier, the manifest, and substitute
   >     the public key — and you would see a "PASS". A green result here is a
   >     convenience tripwire, NOT proof of integrity.
   >
   >     The ONLY reliable verification is MANUAL, using a gpg binary you trust
   >     and a public key fingerprint obtained OUT-OF-BAND (not from this repo):
   >
   >       gpg --verify openssl_encrypt/integrity/manifest.json.asc \
   >                    openssl_encrypt/integrity/manifest.json
   >       # then compare each file hash yourself, e.g.:
   >       sha512sum openssl_encrypt/modules/crypt_core.py
   >
   >     Confirm the signing key fingerprint independently:
   >       <FINGERPRINT> (also published in SECURITY.md and the project page)

2. Locate manifest + signature (package resources by default).
3. **Locate `gpg`. If absent → FAIL CLOSED (Q8):** print a clear error, exit non-zero, do **not** fall back to hash-only and do **not** report success.
4. Shell out to `gpg --verify` (D2) using the **bundled** public key by default, **but** print which key/fingerprint was used and warn if it differs from the out-of-band fingerprint baked into the message.
5. Re-hash each protected file (SHA-512); compare to manifest.
6. Report: per-file `OK` / `MODIFIED` / `MISSING` / `UNLISTED-EXTRA` (a crypto-core file present but not in the manifest), plus signature `VALID` / `INVALID`.
7. Exit codes (distinct per failure class): `0` all-good · `1` hash mismatch/missing file · `2` bad/invalid signature · `3` gpg unavailable · `4` manifest/pubkey not found or malformed.

### 7.3 Honesty constraints
- The command must **never claim cryptographic assurance**. Wording is "consistent with the signed manifest", not "verified authentic".
- `--json` output includes a `"trust_warning"` field repeating the caveat, so automated consumers can't strip it from view by parsing.

---

## 8. Release / Tag Procedure (documented runbook)

`docs/SOURCE_INTEGRITY.md` (new) will document:
1. How the key was generated and where the private key is held.
2. The published fingerprint and out-of-band channels.
3. Pre-tag checklist: run `verify-integrity`, run `gpg --verify` manually, ensure manifest commit is current.
4. Optional `git tag -s` signing.
5. Key rotation / renewal procedure and how verifiers learn the new fingerprint.
6. Contributor instructions (those without the key).

---

## 9. CI Verification (verify-only, no private key)

Add a job to the existing `security` stage in `.gitlab-ci.yml`:
- `gpg --import` the **committed public key**, then `gpg --verify manifest.json.asc manifest.json`.
- Re-hash protected files and compare to manifest (reuse the generator in `--check` mode).
- **Fail the pipeline** on signature failure or hash mismatch.
- Caveat documented in CI logs: CI verifies against the *in-repo* public key, so it catches accidental drift and unsigned/stale manifests, but a full repo rewrite that swaps the key would still pass CI — that case is only caught by out-of-band human verification (§7).
- This job holds **no private key** (per D3).

---

## 10. Module / File Layout (new code)

```
openssl_encrypt/integrity/
  __init__.py
  protected_files.txt            # the allowlist (§3.3)
  manifest.json                  # generated, committed (§5)
  manifest.json.asc             # detached signature, committed (§5)
  manifest_core.py               # canonical manifest build + hashing (pure, testable)
  update_manifest.py             # CLI/hook entry: build, sign (gpg), git add  (§6)
  verify.py                      # verification logic + warning text          (§7)
  gpg_runner.py                  # thin, audited subprocess wrapper around gpg (D2)
  keys/
    source-integrity-pubkey.asc  # committed public key (§4.2)
    FINGERPRINT                  # expected fingerprint (§4.2)
docs/SOURCE_INTEGRITY.md         # runbook (§8)
```
CLI wiring: add `verify-integrity` subparser in `openssl_encrypt/modules/crypt_cli_subparser.py` + dispatch in `crypt_cli.py`.

> ⚠️ Before editing, scan for `# START DO NOT CHANGE` / `# END DO NOT CHANGE` markers in `crypt_cli_subparser.py`, `crypt_cli.py`, and the protected modules. No protected block will be modified.

---

## 11. Test-Driven Development Plan (per CLAUDE.md — tests first)

All tests in `test_*.py` files (per project rule that `unittests.py`-style classes are NOT collected). Candidate: `openssl_encrypt/unittests/test_source_integrity.py`.

**Failing tests written FIRST, covering:**
1. **Manifest determinism:** same tree → byte-identical manifest (sorted keys, fixed newline). 
2. **Hash correctness:** known file content → known SHA-256 (KAT-style fixtures).
3. **Tamper detection (happy + adversarial):**
   - unmodified tree → all `OK`;
   - flip one byte in a protected file → that file reported `MODIFIED`, exit non-zero;
   - delete a protected file → `MISSING`;
   - add an extra crypto-core file not in allowlist → `UNLISTED-EXTRA` warning.
4. **Signature path:** with a throwaway test key in a temp GNUPGHOME, sign a manifest → `gpg --verify` passes; corrupt the `.asc` → verification fails with correct exit code.
5. **gpg-unavailable:** simulate missing `gpg` binary → clear error, non-zero exit, no silent pass.
6. **Warning always printed:** assert the trust-warning text appears on stderr for every invocation incl. `--json` (and in the `"trust_warning"` JSON field).
7. **Allowlist guard:** path in allowlist missing from disk → generator fails loudly.
8. **Boundary/adversarial:** empty file, non-UTF8 bytes, symlink in allowlist (reject), path traversal in allowlist entry (reject).

Tests must not require the real project private key — they use ephemeral keys in `tmp_path` GNUPGHOME. Establish baseline by running the full suite to a `tee` file before and after (per CLAUDE.md unittest workflow), comparing for regressions.

---

## 12. Commit Plan (one feature = one commit, per CLAUDE.md)

Each step: tests first (red) → implement (green) → commit. Targeted-file pytest per cycle; full suite at feature boundaries (per tiered test policy).

1. `integrity` package skeleton + `protected_files.txt` allowlist + tests for allowlist loading.
2. `manifest_core.py` (hashing + canonical manifest) + determinism/hash tests.
3. `verify.py` (hash comparison, no gpg yet) + tamper-detection tests.
4. `gpg_runner.py` + signing/verification tests (ephemeral key).
5. `verify-integrity` CLI subcommand + warning + dispatch + CLI tests.
6. `update_manifest.py` generator/signer + pre-commit hook entry + hook tests.
7. Generate the real project key (manual), commit public key + FINGERPRINT + first signed manifest.
8. `.pre-commit-config.yaml` local hook wiring.
9. `.gitlab-ci.yml` verify-only job.
10. `docs/SOURCE_INTEGRITY.md` runbook + README/SECURITY.md fingerprint.

Implement fully on `feature/v1.4.x-development` first; once green and verified, forward-port the whole feature to `feature/v1.5.x-development` (Q7). The dedicated project key (step 7) is generated once and reused across both branches.

---

## 13. Security Review Checklist (security-first, per CLAUDE.md)
- [ ] `gpg_runner.py` uses `subprocess` with an **argument list (never `shell=True`)**; no untrusted data interpolated into the command line; paths validated.
- [ ] Allowlist entries validated: repo-relative only, no `..`, no absolute paths, no symlinks followed.
- [ ] No private key material ever written to repo, logs, or CI variables; extend `detect-private-key` coverage.
- [ ] Verifier never logs file contents or key material (per code-style rule).
- [ ] Warning text cannot be suppressed to the point of hiding the trust caveat.
- [ ] Manifest parsing is strict (schema-validated, reject unknown/forged fields gracefully).
- [ ] Failure modes fail **closed** (missing gpg / bad sig / missing file ⇒ error, never silent pass).

---

## 14. Open Questions — ALL RESOLVED (2026-06-17)

Every question Q1–Q8 has been answered; decisions are recorded in §2.1 and folded into the relevant sections above. There are **no remaining open questions**. The single remaining gate is your **green light to begin implementation** (starting on `feature/v1.4.x-development`, per Q7).

---

## 15. Effort / Risk Summary
- **Net-new code**, isolated in a new `integrity/` package — low risk of regressing existing crypto paths.
- Touches three existing files only: `crypt_cli_subparser.py` + `crypt_cli.py` (CLI wiring), `.pre-commit-config.yaml`, `.gitlab-ci.yml` — all additive.
- Main *conceptual* risk is over-trusting the bundled verifier; mitigated by the mandatory warning and out-of-band fingerprint publication (§7).
- Estimated: ~6–10 TDD commits as in §12.

---

*End of plan. Awaiting green light + answers to §14 before any implementation.*
