# Hidden ("whitened") file format

The normal encrypted file is `base64(metadata_json) : base64(nonce+ciphertext)`.
The leading base64 metadata blob makes a file trivially identifiable as produced
by this tool and leaks the whole key-derivation profile (KDF choices, costs,
algorithm, format version, …). The **hidden format** wraps that output in an
outer layer so the entire file is indistinguishable from random bytes.

It is **opt-in** (`--hidden-header`) and **fully backward-compatible**: without
the flag, output is byte-for-byte the legacy format, and decryption
auto-detects which format a file uses (there are no magic bytes — that would be
a fingerprint).

## Threat model: what it does and does not do

There are two modes. Choose by your adversary, not by convenience.

| Mode | Outer key source | Property | Resists an analyst who has the tool? |
|------|------------------|----------|--------------------------------------|
| **Keyless** (default for `--hidden-header`) | the **public** per-file salt | anti-fingerprinting / "looks random" | **No** — the transform is public and reversible by anyone |
| **Keyed** (`--second-password…`) | a **second password** via a fixed heavy KDF chain | real **metadata confidentiality** | **Yes** — they would need the second password |

* **Keyless** defeats bulk/passive fingerprinting (`file`, entropy scans, DPI,
  grepping for `base64({`). It does **not** hide that a file is ours from a
  forensic analyst who runs the public un-whitening — there is no secret in the
  outer layer, by design (so it adds no cost to the default path and no
  brute-force oracle).
* **Keyed** gives genuine metadata confidentiality: without the second password
  the metadata cannot be recovered and the file cannot be distinguished from
  random. Use it when the analyst is in your threat model.

In **both** modes the *data* is protected exactly as before — by your primary
password and the inner KDF/cipher. The hidden layer only concerns the
**metadata header**; it is never a substitute for a strong primary password.

## On-disk layout

Both modes use the **same** byte layout, so an observer cannot tell whether a
second password was used:

```
salt(16) | nonce(24) | whitened_len(4) | header_region(L) | auth(16) | raw_body
```

* `salt` — the per-file salt (also used by the inner KDF); needed in the clear
  to derive the outer key.
* `nonce` — random 24-byte XChaCha20 nonce.
* `whitened_len` — the 4-byte header length XOR a keystream derived from a
  **password-derived** subkey, so a keyed file's length decodes to garbage
  without the second password (no length-based distinguisher).
* `header_region` — keyed: XChaCha20-Poly1305 ciphertext of the metadata;
  keyless: the metadata XOR an XChaCha20 keystream.
* `auth` — keyed: the Poly1305 tag (AAD = `salt | nonce | whitened_len`);
  keyless: 16 random decoy bytes (no tag — a tag would be a free "this is our
  file" oracle for anyone, since the keyless key is public).
* `raw_body` — the inner `nonce+ciphertext`, kept raw (not re-encrypted, not
  base64). For streaming files this is the OESC chunk stream verbatim, located
  at a fixed offset rather than after a colon.

Only the (small) header is whitened, so there is no double-encryption of bulk
data and streaming/bounded-memory behavior is preserved.

## Outer key derivation

* **Keyless:** `HKDF-SHA512` over the public salt (cheap — the key is public, so
  memory-hard work would protect nothing and only slow the default path).
* **Keyed:** a fixed, versioned chain over the second password:
  `iterated SHA3-512 → chained Argon2id passes → scrypt → HKDF`.

The chain parameters are **fixed** and pinned to a profile version. They cannot
be stored in the file — they would be needed to open the very layer that
contains them, and storing them would re-introduce a fingerprint. The two modes
are domain-separated so the same salt never yields the same key across modes.

## CLI usage

```sh
# Keyless: looks random, anti-fingerprinting only
openssl_encrypt encrypt -i secret.txt -o secret.enc --password ... --hidden-header

# Keyed: real metadata confidentiality (prompted second password)
openssl_encrypt encrypt -i secret.txt -o secret.enc --password ... \
    --hidden-header --second-password-prompt

# Decrypt: format is auto-detected; supply the second password if it was keyed
openssl_encrypt decrypt -i secret.enc -o secret.txt --password ...
openssl_encrypt decrypt -i secret.enc -o secret.txt --password ... \
    --second-password-prompt

# Force the legacy format / legacy decode
openssl_encrypt encrypt ... --legacy-format
openssl_encrypt decrypt ... --legacy-format

# Armor an EXISTING encrypted file for paste-safe transport (no decryption,
# no password) — e.g. to store a binary/hidden file in a password manager:
openssl_encrypt armor   -i secret.enc -o secret.asc
openssl_encrypt dearmor -i secret.asc -o secret.enc   # reverse; '-o -' / /dev/stdout to stream

# Decrypt straight from a password manager / pipe; the keyed second-password
# prompt is shown on /dev/tty even though the ciphertext is on stdin:
pw-manager show master | openssl_encrypt decrypt -i /dev/stdin -o secret.txt
```

Second-password sources, in priority order: `--second-password-fd FD`,
`--second-password PW` (DEPRECATED — visible in the process list),
`--second-password-prompt`.

`armor`/`dearmor` are a pure, reversible transport transform over the whole
container; `decrypt`/`info`/`verify`/`rekey` auto-de-armor input, so no flag is
needed on the way back in. **Caveat for hidden files:** the armor markers
(`-----BEGIN OPENSSL-ENCRYPT …-----`) are a public fingerprint, so armoring a
hidden file negates its "looks random" property (keyed *confidentiality* is
unaffected). See FORMAT.md §12.

### Interactive second-password fallback

On a bare `decrypt` (no `--second-password*`), the CLI tries keyless first and,
if the file is a hidden file that does **not** peel keyless (i.e. keyed — or
just random/corrupt), prompts once for a second password before failing. The
prompt is:

* **terminal-gated** — it fires whenever a controlling terminal is reachable for
  the prompt (`/dev/tty`), which `getpass` reads independently of stdin. So it
  works even when the ciphertext itself arrives on stdin
  (`pw-manager show … | decrypt -i /dev/stdin`), yet stays silent in a genuinely
  headless run (cron/CI, no tty anywhere) — those keep the silent generic error
  (`Security validation check failed`), so there is no behavioral signal to
  automated triage and no risk of a script hanging.
* **suppressible** with `--no-second-password-prompt` (and skipped under
  `--legacy-format`) — use this on a shared/observed/recorded terminal or any
  "prove this is just random data" situation where you want the tool to stay
  silent even interactively.
* **neutrally worded** — it fires on any non-keyless-peelable input, so it never
  asserts "this is one of our files". The peek is a single cheap HKDF (no inner
  KDF, no double-decrypt).

The generic error is intentional: a keyed file with a missing/wrong second
password is indistinguishable (to the tool and to an attacker) from a wrong,
corrupt, or non-ours file — the tool genuinely cannot tell, which *is* the
deniability property.

## Notes and current limitations

* Supported on the symmetric, keystore-wrapped, and asymmetric (PQC) paths, for
  both buffered and streaming files.
* Hidden decryption from **piped stdin** works for `decrypt`/`info`: the stream
  is buffered to a temp file, de-armored if needed, then hidden-detected, and the
  keyed second-password prompt is offered on `/dev/tty`. Other non-seekable inputs
  (`/dev/*` other than stdin, `/proc/*`) still skip the peek/prompt (they cannot
  be re-read), so a keyed hidden file there needs an explicit `--second-password*`.
* Tools that parse the raw file format directly (e.g. `info`-style inspection,
  the desktop GUI/mobile apps) are being updated to route hidden files through
  the same peel step; until then, prefer the CLI `decrypt` path for hidden
  files.
* Keyless mode is the *default* only when `--hidden-header` is supplied without
  a second password; the global default output format remains legacy for now.
