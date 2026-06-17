# Source-Code Integrity Protection

This project maintains a **PGP-signed manifest** of SHA-512 hashes for its core
cryptographic/security source files so that tampering with those files can be
detected. This document is the operational runbook.

> Design background and decisions: see `SOURCE_INTEGRITY_PROTECTION_PLAN.md`.

---

## 1. Trust model — read this first

The built-in verifier (`openssl-encrypt verify-integrity`) runs code that ships in
the **same package it is checking**. If an attacker can modify the protected source
files, they can also modify the verifier, the manifest, and the bundled public key —
and you would still see a green `PASS`.

**A passing built-in check is a convenience tripwire, not cryptographic proof.**

The only reliable verification is **manual**, using a `gpg` you trust and the signing
**fingerprint obtained out-of-band** (not just from this repo). See §3.

### Expected signing-key fingerprint

```
1E5D7995DA9A62CED90354D8F98AAFF3F31FD459
```

This fingerprint is also published in `SECURITY.md` and the GitLab project page.
Confirm it through an independent channel before trusting a verification result.

---

## 2. What is protected

The protected set is the explicit allowlist in
`openssl_encrypt/integrity/protected_files.txt` (48 files: core crypto/security
modules, package entry points, dependency requirements files, and the native
Threefish crate sources). Adding/removing a file is a deliberate, reviewed edit to
that allowlist.

Deliberately **not** protected: the auto-generated `version.py`, the integrity
verifier code itself (it cannot protect itself), tests, plugins, and `Cargo.lock`
(untracked).

There are **two** manifests:

- **Source manifest** (`manifest.json`) — all 48 files. Use it to verify a **source
  checkout** (the files you build from).
- **Installed manifest** (`manifest-installed.json`) — the 38 `openssl_encrypt/` `.py`
  files that survive installation. Use it to verify a **pip/flatpak install**. It
  cannot cover the `requirements*` files, the `threefish_native/` Rust sources, or
  the compiled Threefish `.so` (those aren't present, or aren't reproducible, in an
  installed layout — see §4b).

`verify-integrity` auto-selects the right one (override with `--source` / `--installed`).

Artifacts:
- `openssl_encrypt/integrity/manifest.json[.asc]` — source manifest + signature
- `openssl_encrypt/integrity/manifest-installed.json[.asc]` — installed manifest + signature
- `openssl_encrypt/integrity/keys/source-integrity-pubkey.asc` — signing public key
- `openssl_encrypt/integrity/keys/FINGERPRINT` — expected fingerprint

---

## 3. Manual verification (authoritative)

```bash
# 1. Obtain and confirm the signing key fingerprint OUT-OF-BAND (SECURITY.md,
#    project page, maintainer's web-of-trust) — do not trust only this repo.

# 2. Import the public key and check its fingerprint:
gpg --import openssl_encrypt/integrity/keys/source-integrity-pubkey.asc
gpg --fingerprint 1E5D7995DA9A62CED90354D8F98AAFF3F31FD459

# 3. Verify the manifest signature:
gpg --verify openssl_encrypt/integrity/manifest.json.asc \
             openssl_encrypt/integrity/manifest.json

# 4. Verify each protected file's hash against the manifest, e.g.:
sha512sum openssl_encrypt/modules/crypt_core.py
#   compare the digest to the "files" entry in manifest.json
```

If the signature is good, the fingerprint matches the out-of-band value, and the
file hashes match the manifest, the protected files are intact.

---

## 4. Built-in verification (tripwire convenience)

```bash
openssl-encrypt verify-integrity            # full trust warning + report
openssl-encrypt verify-integrity --quiet    # one-line warning
openssl-encrypt verify-integrity --json     # machine-readable (retains trust_warning)
```

Exit codes:

| Code | Meaning |
|------|---------|
| 0 | all good |
| 1 | one or more protected files modified/missing |
| 2 | manifest signature invalid / unexpected signing key |
| 3 | gpg unavailable (fail closed — never a silent pass) |
| 4 | manifest, signature, or public key not found / malformed |

`gpg` must be installed; if it is absent the command fails closed (exit 3).

---

## 4b. Verifying an installed package (pip / flatpak)

When run from an installed package, `verify-integrity` auto-detects the installed
layout and uses the **installed manifest** (38 `.py` files):

```bash
openssl-encrypt verify-integrity            # auto-detects installed scope
```

**Scope of an installed check (important):** a green result means *"the installed
Python source matches the signed manifest"* — it does **not** cover the native
Threefish `.so` (not reproducible) or the dependencies (`requirements*` — use pip
hash-checking / PyPI attestations for those). Native-code assurance comes only from
verifying the **source tree** (§3) before building.

### Detecting a compromised distribution channel (e.g. a hijacked PyPI)

If someone hijacks the PyPI project and ships tampered files, the manifest, signature
**and** public key *bundled in that package* are also under their control — so the
built-in check (which reads bundled files) would still say PASS. To detect this you
must compare against a reference from a **different trust domain: the GitLab repo.**

1. Note the installed version (it tells you which GitLab tag to use):
   ```bash
   python -c "import openssl_encrypt.version as v; print(v.__version__, v.__git_commit__)"
   ```
2. Download the installed manifest, its signature, and the public key **from GitLab**
   for the **matching tag** (not from the installed package), e.g.:
   ```bash
   base="https://gitlab.rm-rf.ch/world/openssl_encrypt/-/raw/v<VERSION>/openssl_encrypt/integrity"
   curl -O "$base/manifest-installed.json" -O "$base/manifest-installed.json.asc"
   curl -O "$base/keys/source-integrity-pubkey.asc"
   ```
3. Confirm the signing fingerprint **out-of-band** (SECURITY.md / project page), then
   verify the GitLab manifest's signature and compare it to the installed files:
   ```bash
   gpg --import source-integrity-pubkey.asc
   gpg --verify manifest-installed.json.asc manifest-installed.json
   # point the verifier at the GitLab-downloaded reference, against the install:
   openssl-encrypt verify-integrity --installed \
     --manifest manifest-installed.json \
     --signature manifest-installed.json.asc \
     --pubkey source-integrity-pubkey.asc
   ```
   If PyPI was hijacked but GitLab was not, the installed file hashes will not match
   the GitLab manifest → detected.

> Even this is strengthened, not absolute: the verifier code itself comes from the
> (possibly hijacked) install. For full assurance, do the comparison **manually** —
> `gpg --verify` the GitLab manifest, then `sha512sum` the installed files and diff
> against the manifest by hand, using tools that did not come from the package.

---

## 5. Signing (maintainers with the key)

Signing happens **locally**; the private key never enters CI or the repo (D3).

The pre-commit hook `source-integrity-manifest` regenerates and re-signs **both**
manifests (source + installed) automatically whenever a protected file (or the
allowlist) changes, and stages the result:

```bash
pip install pre-commit && pre-commit install
# ...edit a protected file, then `git commit` — the hook updates manifest.json(.asc)
```

Manual regeneration:

```bash
python -m openssl_encrypt.integrity.update_manifest --sign            # regenerate+sign
python -m openssl_encrypt.integrity.update_manifest --sign --git-add  # and stage
python -m openssl_encrypt.integrity.update_manifest --check           # drift check (exit 1 on drift)
```

Regeneration is idempotent: if nothing changed, the manifest and signature are left
untouched (no signature churn).

---

## 6. CI verification

The `source-integrity-verify` job (security stage) verifies the signature, the
expected fingerprint, and all file hashes on every push/MR, and **fails the
pipeline** on any mismatch. It holds **no private key**.

Caveat: CI verifies against the in-repo public key, so it catches drift, stale or
unsigned manifests, and bad signatures — but a full repo rewrite that also swaps the
key would still pass CI. Only the out-of-band manual check (§3) is complete.

---

## 7. Branch protection (policy)

Protected branches require the `source-integrity-verify` job to pass before merge.
A stale, unsigned, or invalid manifest therefore blocks merging — only commits with
a current, validly-signed manifest can land on protected branches (decision Q3d).
Configure this in GitLab: *Settings → Merge requests / Protected branches →
"Pipelines must succeed"*.

Contributors **without** the signing key can still open MRs; a maintainer
regenerates and signs the manifest before the MR is merged.

---

## 8. The signing key

- Algorithm: **Ed25519**, sign-only, 2-year expiry.
- Dedicated to source-integrity signing only — not reused for commit signing,
  email, or release-artifact signing.
- Private key custody: held only on authorized maintainer machines. Designed to be
  movable onto a hardware token (OnlyKey/YubiKey) without process change — signing
  always goes through `gpg --local-user <fingerprint>`.

### ⚠️ Bootstrap key notice

The current key was generated in a development sandbox as a **bootstrap** key. Before
any real public release it MUST be rotated to a key generated on a trusted machine
(ideally hardware-backed). See §9.

---

## 9. Key rotation procedure

1. Generate the new key on a trusted machine:
   ```bash
   gpg --quick-generate-key "openssl_encrypt source integrity <jahlives@gmx.ch>" ed25519 sign 2y
   ```
2. Export and replace `openssl_encrypt/integrity/keys/source-integrity-pubkey.asc`.
3. Update `openssl_encrypt/integrity/keys/FINGERPRINT`, this document, and
   `SECURITY.md` with the new fingerprint.
4. Re-sign the manifest with the new key:
   `python -m openssl_encrypt.integrity.update_manifest --sign`.
5. Announce the new fingerprint through the out-of-band channels.
6. Revoke/retire the old key as appropriate.
