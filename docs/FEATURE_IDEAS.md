# Feature Ideas — Candidate Capabilities for Future Versions

Status: brainstorming / pre-design. None of these are committed.
Branch: `feature/v1.5.x-development`
Last updated: 2026-06-22

This document captures five candidate features that fill genuine gaps in the
tool. They were selected after reviewing the existing command surface (PQC
hybrids, cascade, HSM/PIV/FIDO2/YubiKey/OnlyKey, Shamir `split-secret` /
`combine-secrets`, keystore, streaming chunked I/O, stdin/stdout, `rekey`,
plugins, USB) — so each item below is something the tool does **not** already
do.

Two further ideas were discussed and **deliberately parked**:

- **Deniable / decoy encryption** — sound in principle (independent encrypted
  slots, not a weakened cipher), but it depends on an opaque/headerless format,
  and that re-introduces the secret-transfer problem below. Not worth the
  downsides for the dominant password-based use case.
- **Headerless / encrypted-header format** — nice for indistinguishability and
  tamper-evidence, but for symmetric/password files it converts one
  self-contained artifact into a two-part secret-sharing problem (the KDF config
  or a header-secret must reach the recipient out-of-band). Parked for symmetric
  files. *Note:* it is downside-free for **asymmetric/recipient** files, where
  the recipient's public key is already the transport — revisit there if ever
  needed.

---

## 1. Detached hybrid signing (`sign` / `verify-signature`)

**Gap.** The primitives exist (`pqc_adapter.sign/verify`, ML-DSA, MAYO, CROSS)
but there is no user-facing command to sign an **arbitrary file** and verify it.
Symmetric AEAD gives confidentiality + integrity but **not authenticity** —
anyone who knows the password can forge a valid file. This is the biggest real
cryptographic capability gap.

**Proposal.**
- New actions `sign` and `verify-signature` producing a **detached** signature.
- Hybrid by default: classical + PQC (e.g. `Ed25519 + ML-DSA-65`) so a break in
  either scheme alone does not forge.
- Sign over a domain-separated hash of the file (and optionally the encrypted
  file's metadata) to bind signature to context.
- Key material drawn from the existing identity / keystore system.

**Considerations.**
- Detached vs. attached (embedded) signatures — start with detached.
- Signature file format + armor (see #2).
- Verification must report *which* component(s) verified, not just pass/fail.

**Effort:** medium. Primitives already present; work is CLI surface, format,
identity wiring, tests.

---

## 2. ASCII armor / paste-safe output (`--armor`)

**Gap.** Output is binary only. GPG and age both offer base64/PEM-style armor so
ciphertext survives email, chat, YAML, and copy-paste.

**Proposal.**
- `--armor` flag on `encrypt` (and `sign`) wrapping the existing binary output
  in a base64 block with `BEGIN/END` delimiters and a short header line.
- `decrypt` auto-detects armored vs. binary input.
- Optional CRC/length check line for paste-truncation detection.

**Considerations.**
- Keep the armor envelope minimal; it is a transport wrapper, not metadata.
- Round-trip must be byte-exact (armor → de-armor → identical ciphertext).

**Effort:** low (~half a day). Pure wrapper over existing format.

---

## 4. Time-lock encryption (`--unlock-after <date>`)

**Gap.** No way to make a file decryptable only after a future time.

**Proposal.**
- Use a public **drand / tlock** beacon so no trusted server holds keys — the
  file becomes decryptable once the beacon for the target round is published.
- New flag `--unlock-after <RFC3339 / duration>` on `encrypt`; the file key is
  additionally wrapped to the time-lock so decryption before the round is
  cryptographically impossible, not merely policy-enforced.
- Pairs naturally with the existing pepper/deadman-switch infrastructure
  (dead-man's-switch, embargoed disclosure, escrow).

**Considerations.**
- Beacon availability/longevity; document the trust assumption on the drand
  network and pin the chain hash.
- Clock-independence: security comes from the beacon, not the local clock.
- Offline decryptability after the round (cache the beacon value).

**Effort:** medium-high. New dependency + format slot + clear trust docs.

---

## 5. Interop: decrypt foreign `age` / OpenPGP files

**Gap.** No interoperability with the two dominant file-encryption ecosystems,
which raises migration friction.

**Proposal.**
- **Read-only first:** ability to *decrypt* existing `age` and `gpg -c`
  (symmetric) / public-key OpenPGP files, given the appropriate key/password.
- Producing foreign formats is explicitly out of scope for v1 (large surface,
  weaker guarantees) — import/migration is the value.

**Considerations.**
- Scope tightly: support the common modes (age X25519 + scrypt recipients;
  OpenPGP symmetric + a common public-key path), document what is unsupported.
- Treat foreign parsers as untrusted input — fuzz and bound them.
- Likely a thin adapter over `pyca/cryptography` + an age library; avoid pulling
  in heavy GnuPG runtime dependencies.

**Effort:** medium-high, scope-dependent. Bounded if read-only + common modes.

---

## 6. Encrypt-to-self / default recipient

**Gap.** When encrypting *for a recipient*, the sender cannot later decrypt their
own outbound file — a common and painful data-loss footgun.

**Proposal.**
- When encrypting to recipient(s), also wrap the file key to the sender's **own**
  identity public key as an additional recipient.
- Slots straight into the existing multi-recipient KEM wrapping (wrap the
  symmetric file key to each recipient pubkey + sender pubkey).

**Considerations.**
- Opt-in vs. default-on (recommend default-on with an opt-out flag).
- Which identity is "self" when several exist — needs a configured default
  identity.

**Effort:** low. Reuses existing recipient-wrapping path.

---

## Suggested sequencing

1. **#6 Encrypt-to-self** — smallest, immediate value, reuses existing path.
2. **#2 ASCII armor** — cheap, high day-to-day utility; also useful for #1.
3. **#1 Detached signing** — the real cryptographic gap.
4. **#5 Interop** / **#4 Time-lock** — larger, scope-dependent; schedule after
   the above.

All work to follow the project's TDD workflow: failing tests first, one feature
per commit (or per completed feature), full suite at feature boundaries.
