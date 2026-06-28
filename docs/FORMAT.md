# openssl_encrypt — On-Disk Format Specification

> **Status:** DRAFT / scaffold — not yet normative.
> **Spec version:** 0.1 (skeleton)
> **Covers tool versions:** 1.4.x and 1.5.x (format_version ≤ 13)
> **Last updated:** YYYY-MM-DD
> **Editor:** Tobias <…>
>
> This document is the **authoritative description of the bytes written to
> disk** by openssl_encrypt. Its goals:
> 1. Let an independent implementer write a **decryptor** without reading the
>    source.
> 2. Make the format **auditable** (a frozen target a reviewer can reason about).
> 3. Anchor the project's compatibility promise: *every released version MUST
>    decrypt every format_version it ever produced* (see §13).
>
> Anything marked **`TODO`** or **`⚠️ VERIFY`** is a placeholder requiring an
> authoritative value from the implementation; do not treat it as fact yet.

---

## 1. Conformance & scope

The key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY**
are to be interpreted as in [RFC 2119]/[RFC 8174].

This specification describes:

- the **container layouts** (§4): standard and hidden ("whitened")
- the **metadata object** and its field semantics (§5)
- **AEAD associated-data binding** rules (§6)
- **key derivation** including chained-salt derivation (§7)
- **symmetric data encryption**: single-cipher and cascade (§8)
- **envelope (DEK/KEK)** wrapping and **recovery slots** (§9)
- **asymmetric / PQC recipient** encryption (§10)
- **detached signatures** (§11)
- **ASCII armor** transport encoding (§12)
- **streaming / chunked** payload format (§8.4)
- the **algorithm identifier registries** (§14)
- the normative **format_version history** (§15)

Out of scope: the CLI surface, key-management UX, plugin internals, and the
**foreign-format read paths** (age / OpenPGP). Those formats are owned by their
respective specifications; openssl_encrypt only *consumes* them (read-only) and
they are **not** described here.

---

## 2. Notation & conventions

- **Byte order:** all multi-byte integer length fields are **`TODO` (big-endian / little-endian — VERIFY)**.
- **Encoding of binary fields inside metadata:** standard Base64,
  [RFC 4648] §4 (`+`/`/` alphabet, `=` padding). *Note:* the implementation uses
  URL-safe Base64 internally for some derived **key material**; that never
  appears on disk in the metadata and is not part of this spec.
- **`b64(x)`** denotes the Base64 encoding of byte string `x`.
- **`||`** denotes concatenation.
- **`HKDF`** is HKDF-[RFC 5869]; the hash is SHA-256 unless stated otherwise.
- **Hashes** named below (`sha256`, `sha3_256`, `blake3`, …) use the standard
  algorithm identifiers from §14.4.
- JSON is encoded as UTF-8. Field **insertion order is significant** for some
  versions (XOR composition, see §7.3) and MUST be preserved on round-trip.

---

## 3. Container at a glance

openssl_encrypt writes one of two physical containers. The **format byte**
(first byte) and a sniff of the leading bytes select the parser:

| Container          | Leading bytes                              | Plaintext metadata? | §   |
|--------------------|--------------------------------------------|---------------------|-----|
| Standard           | Base64 alphabet up to a `:` (0x3A)         | Yes (Base64 JSON)   | §4.1 |
| Hidden / whitened  | High-entropy salt+nonce (no `:` structure) | No (header is encrypted) | §4.2 |

> **⚠️ VERIFY — format detection.** Describe the exact discriminator the decoder
> uses to tell a standard file from a hidden file (e.g. "attempt Base64-until-`:`
> parse; on failure, fall back to the whitened parser", or a magic/length test).
> A decryptor needs this to be deterministic and unambiguous.

---

## 4. Container layouts

### 4.1 Standard container

```
┌──────────────────────────────┬───────┬───────────────────────────────┐
│ Base64( metadata JSON )       │  ':'  │ payload (bulk ciphertext)     │
│ (variable length)             │ 0x3A  │ (variable length)             │
└──────────────────────────────┴───────┴───────────────────────────────┘
```

- The metadata region is everything up to the **first** `:` (0x3A) byte.
- A reader MUST locate the separator without buffering the whole payload
  (the reference reader scans in 8 KiB blocks up to a **2 MiB** metadata cap).
- A file with no `:` separator is **invalid**.
- The payload framing (nonce/tag placement, chunking) is determined by the
  metadata; see §8.

> **⚠️ VERIFY — payload framing.** Specify exactly how the symmetric nonce(s) and
> authentication tag(s) are laid out in `payload` for each mode:
> single-cipher one-shot, cascade, and streaming. Is the nonce prefixed?
> Is the tag appended by the AEAD library or framed by us? Document per mode.

### 4.2 Hidden ("whitened") container — profile version 1

No plaintext magic bytes or JSON; the entire header is encrypted and
length-whitened so the file is indistinguishable from random of the same size.
Domain-separated by purpose:

- keyless:  `oe-hidden-header/keyless/v1`
- keyed:    `oe-hidden-header/keyed/v1`   (gated by a second password)

Physical layout:

```
┌──────────┬───────────┬──────────────┬───────────────┬──────────┬────────┐
│ salt     │ nonce     │ whitened_len │ header_region │ auth tag │ body   │
│ SALT_LEN │ NONCE_LEN │ LEN_FIELD    │ header_len    │ AUTH_LEN │  …     │
└──────────┴───────────┴──────────────┴───────────────┴──────────┴────────┘
                                       └─ encrypted standard header (§5)
```

- `HEADER_OFFSET = SALT_LEN + NONCE_LEN + LEN_FIELD = 44 bytes` (fixed for
  profile v1).
- The outer key is derived via `HKDF(..., info="outer-key")` from the password
  (keyed) or from a fixed keyless secret; see §7.4.
- `whitened_len` encodes the true `header_len` after de-whitening; bounds:
  `header_len ≤ 64 MiB` (`_MAX_HEADER_LEN`).
- `header_region` decrypts to a **standard metadata object** (§5); from there
  decryption proceeds as for the standard container.

> **⚠️ VERIFY — exact field lengths.** Fill in `SALT_LEN`, `NONCE_LEN`,
> `LEN_FIELD` (such that they sum to 44), and `AUTH_LEN`. State the outer AEAD
> (e.g. XChaCha20-Poly1305 / AES-256-GCM) and the length-whitening transform.

---

## 5. The metadata object

A JSON object. Schema below applies to **format_version ≥ 8**; see §15 for the
history and §5.4 for legacy shapes.

### 5.1 Top-level fields

| Field               | Type    | Presence            | Meaning                                              |
|---------------------|---------|---------------------|------------------------------------------------------|
| `format_version`    | int     | REQUIRED            | On-disk format version (§15). Drives all parsing.    |
| `mode`              | string  | REQUIRED            | `"symmetric"` or `"asymmetric"`.                     |
| `derivation_config` | object  | REQUIRED (symmetric)| KDF/salt parameters (§5.2).                          |
| `hashes`            | object  | REQUIRED            | `original_hash`, optional `encrypted_hash` (§5.3).   |
| `encryption`        | object  | REQUIRED            | Cipher parameters; shape depends on cascade (§8).    |
| `aead_binding`      | bool    | OPTIONAL            | `true` ⇒ metadata is bound as AEAD AAD (§6).         |

### 5.2 `derivation_config`

```jsonc
"derivation_config": {
  "salt": "<b64>",                       // primary KDF salt
  "hash_config": { "sha3_256": { "rounds": 10000 }, … },
  "kdf_config":  { "argon2": { … }, "balloon": { … }, "scrypt": { … },
                   "hkdf": { … }, "randomx": { … } }
}
```

- `hash_config` keys are iterative hash stages (§14.4); `rounds: 0` ⇒ disabled.
- `kdf_config` keys are memory-hard / KDF stages (§14.3). `randomx` is **opt-in**
  (disabled by default) and SHOULD NOT be relied on as a security parameter.
- **Order matters** for XOR-composition versions (§7.3).

> **TODO — per-KDF parameter tables.** Document the exact parameter object for
> each KDF (Argon2: time/memory/parallelism/variant; Balloon: space/time/hash;
> scrypt: N/r/p; RandomX: rounds/height). Include accepted ranges and defaults.

### 5.3 `hashes`

| Field            | Type   | Presence | Meaning                                            |
|------------------|--------|----------|----------------------------------------------------|
| `original_hash`  | string | REQUIRED | Hash of the **plaintext** (algorithm: **`TODO`**). |
| `encrypted_hash` | string | OPTIONAL | Hash of the **ciphertext** for tamper pre-check.   |

> **⚠️ VERIFY** which hash function produces these, what they cover exactly, and
> whether they are security-relevant or convenience-only (AEAD already provides
> integrity — clarify the role so implementers don't over-rely on them).

### 5.4 Legacy metadata shapes (format_version ≤ 7)

> **TODO.** Versions 0–7 used different, flatter structures and have in-code
> converters (`convert_metadata_v3_to_v4`, `v4↔v5`, …). A decryptor that targets
> only current files MAY ignore these, but the **reference** decryptor MUST
> support them (compatibility promise, §13). Document each legacy shape or
> explicitly scope them to "decrypt-only via the reference implementation".

---

## 6. AEAD associated-data (AAD) binding

When `aead_binding` is `true`, a **stable subset** of the metadata is supplied
as the AEAD associated data for the bulk encryption, so header tampering is
detected on decrypt.

- The AAD is a canonical serialization of the metadata **excluding** fields that
  are themselves keying/recovery material, namely (envelope mode):
  `encryption.wrapped_dek`, `encryption.dek_slots`, `encryption.dek_slots_mac`.
  Those are protected by their **own** DEK-keyed MAC instead (§9).

> **⚠️ VERIFY — canonicalization.** This is the single most audit-sensitive part
> of the spec. Specify **exactly**:
> 1. which keys are included vs. excluded, per mode and per version;
> 2. the canonical byte serialization (key ordering, whitespace, encoding) so
>    encrypt and decrypt produce byte-identical AAD;
> 3. what changed across versions (the README notes metadata-binding was
>    incomplete before 1.3.0 — pin the exact version that fixed it).

---

## 7. Key derivation

### 7.1 Chained KDF pipeline

```
password ── stage₁(salt₀) ─→ out₁ ── stage₂(salt₁=f(out₁)) ─→ out₂ ─→ … ─→ KEK
```

Stages are the enabled entries of `hash_config` then `kdf_config`, applied in a
defined order. The final output is the **key-encryption key (KEK)** used either
directly as the data key or to wrap a DEK (§9).

> **TODO — exact pipeline order.** State the canonical stage ordering (hashes
> before KDFs? config order? a fixed precedence?) and how outputs are normalized
> to the next stage's input length. This must be reproducible from metadata
> alone.

### 7.2 Chained-salt derivation (format_version ≥ 9) — **security-critical**

Each round's salt is derived from the previous round's output, rather than from
a predictable counter. This is the fix for **ADVISORY 2026-01** (predictable
salt derivation in the multi-round KDF).

> **⚠️ VERIFY — salt chaining function.** Specify `saltᵢ = f(outᵢ₋₁, …)` exactly
> (the function, any domain separation, output length). Files at
> `format_version ≤ 8` use the **legacy** derivation and MUST be decrypted with
> the legacy rule — document both.

### 7.3 XOR composition (format_version ≥ 10)

> **TODO.** v10 introduced XOR-composition of stage outputs. Document the
> composition (`key = out_a ⊕ out_b ⊕ …`), why dict/insertion order must be
> preserved, and how this interacts with §7.1 ordering.

### 7.4 Hidden-header outer key

> **TODO.** Document the outer-key derivation for the whitened container (§4.2):
> KDF, the `info="outer-key"` domain string, keyed vs. keyless secret source.

### 7.5 Hardware pepper (HSM / PIV / FIDO2)

An optional **pepper** is mixed into derivation from a hardware token:
HMAC-SHA1 challenge–response (YubiKey/OnlyKey), or a deterministic signature
(Ed25519 / RSA PKCS#1 v1.5) normalized into a pepper (PIV/PKCS#11 — Token2 R3.3,
YubiKey Bio MPE).

- The metadata records **which** plugin/slot was used so decryption can re-derive
  (`hsm_plugin_name`, `hsm_slot_used`, `pepper_plugin_name`, `pepper_name`).
- The secret itself is **never** stored; re-provisioning the token changes the
  output.

> **⚠️ VERIFY** the exact mixing point (is the pepper an extra KDF input? applied
> to which stage?) and the field names/locations as actually written.

---

## 8. Symmetric data encryption

### 8.1 Single-cipher mode

```jsonc
"encryption": {
  "cascade": false,
  "algorithm": "<cipher-id>",            // §14.1
  "encryption_data": "aes-gcm",          // bulk AEAD; §14.1
  "pq_security_bits": 128,
  "xchacha_nonce_format": 2              // present iff XChaCha (see §8.3)
}
```

### 8.2 Cascade mode (multi-layer)

```jsonc
"encryption": {
  "cascade": true,
  "cipher_chain": ["aes-256-gcm", "xchacha20-poly1305", …],  // applied in order
  "hkdf_hash": "sha256",
  "cascade_salt": "<b64>",
  "layer_info": [ … ],                   // per-layer overhead/nonce metadata
  "total_overhead": <int>,
  "pq_security_bits": 256
}
```

> **TODO.** Specify `layer_info` element schema, per-layer key derivation
> (HKDF(`hkdf_hash`, `cascade_salt`) → per-layer keys), nesting order
> (encrypt order vs. decrypt order), and per-layer nonce handling.

### 8.3 XChaCha nonce format

- `xchacha_nonce_format: 2` ⇒ **true 192-bit random nonce** (1.5+).
- Absent ⇒ legacy nonce handling; also absent on PQC-hybrid files, whose data
  layer uses 12-byte nonces under per-file keys.

> **⚠️ VERIFY** the legacy (format 1 / absent) nonce construction so old files
> remain decryptable, and confirm the 192-bit derivation/placement.

### 8.4 Streaming / chunked payload (format_version 12)

Constant-memory encryption of large inputs: the payload is a sequence of
AEAD chunks with per-chunk nonces derived via HKDF-SHA256.

> **TODO.** Specify: chunk size, the per-chunk nonce derivation (counter? HKDF
> info?), how the final/short chunk and total length are authenticated against
> truncation/reordering, and the on-disk chunk framing.

---

## 9. Envelope (DEK/KEK) wrapping & recovery slots

Optional two-tier keying so a credential change (`rekey`) rewraps only a small
key instead of re-encrypting the payload.

- A random **DEK** encrypts the bulk (§8).
- The DEK is wrapped by the **KEK** (the §7 output):
  - **Non-cascade:** AES-256-GCM, wrap key = `HKDF-SHA256(KEK,
    info="openssl_encrypt.envelope.dek-wrap.v1")` (domain-separated).
  - **Cascade bulk:** the DEK is wrapped under the **same** cascade chain (fixed
    32-byte salt `oesc.envelope.cascade-wrap.salt1`) so the envelope is never the
    weaker link.
- Stored fields (under `encryption`): `wrapped_dek`, plus recovery slots
  `dek_slots` and their integrity tag `dek_slots_mac` (a **DEK-keyed** MAC,
  verified after unwrap). These three are **excluded from the AEAD AAD** (§6).

**Recovery slots** let multiple independent credentials each unwrap the DEK:

| Slot type        | 1.4.x | 1.5.x | Notes                                  |
|------------------|:-----:|:-----:|----------------------------------------|
| recovery code    |  ✓    |  ✓    |                                        |
| passphrase       |  ✓    |  ✓    |                                        |
| PQC recipient    |  ✓    |  ✓    | escrow to a public key                 |
| Shamir (k-of-n)  |  —    |  ✓    | 1.5.x only                             |

> **TODO.** Specify each slot's binary layout, the slot-set MAC input, and the
> wrap of the DEK per slot type. Pin the `format_version`(s) that carry
> envelope/recovery so wrap/unwrap stay interoperable across 1.4.x ↔ 1.5.x.

---

## 10. Asymmetric / PQC recipient encryption

`mode: "asymmetric"`. The bulk symmetric key is encapsulated to one or more
recipient public keys via a KEM; classical+PQC **hybrid** is the default intent.

Relevant `encryption` fields (Base64): `pqc_public_key`, `pqc_private_key`
(when key is bundled/escrowed), `pqc_key_salt`, `pqc_sig_hkdf_salt`.

- **Multi-recipient:** the file key is wrapped to each recipient public key.
- **Encrypt-to-self (1.5+ default):** the sender's own identity public key is
  added as an additional recipient so outbound files stay decryptable by the
  sender.

> **TODO.** Specify: KEM identifiers (§14.2) and the hybrid combiner (how the
> classical + PQC shared secrets are combined into the KEK — e.g. concatenation
> then HKDF, with domain separation), the per-recipient wrap structure, and how
> recipients are enumerated on disk.

---

## 11. Detached signatures

`sign` / `verify-signature` produce a **detached** signature over a
domain-separated hash of the target (optionally binding the encrypted file's
metadata). Hybrid by default (classical + PQC, e.g. `Ed25519 + ML-DSA-65`); a
break in either component alone MUST NOT forge.

> **TODO.** Specify the signature container (fields, ordering), the
> domain-separation string, exactly what bytes are hashed/signed, and how
> verification reports **which** component(s) verified (not just pass/fail).
> Signature identifiers are in §14.2; PEM label is `SIGNATURE` (§12).

---

## 12. ASCII armor (transport encoding)

A paste-safe wrapper over the binary container:

```
-----BEGIN OPENSSL-ENCRYPT MESSAGE-----
<base64 of the binary container>
=XXXX            ← OpenPGP-style CRC-24 checksum line
-----END OPENSSL-ENCRYPT MESSAGE-----
```

- Custom PEM labels: `MESSAGE` (ciphertext) and `SIGNATURE` (detached signatures).
- `decrypt` auto-detects armored vs. binary input.
- Round-trip MUST be byte-exact: armor → de-armor → identical container bytes.

> **⚠️ VERIFY** the exact header/label strings, the CRC-24 parameters
> (polynomial/init, matching OpenPGP [RFC 4880] §6.1), and any header lines
> beyond BEGIN/END.

---

## 13. Compatibility & deprecation policy

- A released version **MUST** decrypt every `format_version` it (or any prior
  release) ever wrote. Decryption support is **append-only**.
- **Encryption** defaults track the newest version; older versions MAY be
  retired for *writing*.
- **1.5.0 removed deprecated algorithms entirely** (encrypt *and* decrypt). Files
  using them, or hidden/steganographic data, or the TESTDATA PQC simulation
  format, **must be migrated with 1.4.x before upgrading**. Such files are
  explicitly **out of the 1.5.x decryptor's scope** — this is the one sanctioned
  exception to the append-only rule and MUST be called out in release notes.

> **TODO.** Maintain the canonical list of "write-retired" and "read-dropped"
> algorithms/versions per release here.

---

## 14. Algorithm identifier registry

Identifiers as they appear on disk. Aliases are accepted on input; the
**canonical** id (first column) is what SHOULD be written.

### 14.1 Symmetric ciphers / bulk AEAD

| Canonical id           | Aliases                                   | Notes        |
|------------------------|-------------------------------------------|--------------|
| `aes-256-gcm`          | `aes-gcm`, `aes256-gcm`, `aesgcm`         | AEAD         |
| `aes-256-gcm-siv`      | `aes-gcm-siv`, `aesgcmsiv`                | nonce-misuse |
| `aes-256-siv`          | `aes-siv`, `aessiv`                       | nonce-misuse |
| `chacha20-poly1305`    | `chacha20`, `chacha20poly1305`            | AEAD         |
| `xchacha20-poly1305`   | `xchacha20`, `xchacha20poly1305`          | 192-bit nonce (§8.3) |
| `threefish-512`        | `tf512`, `threefish512`                   | ⚠️ VERIFY AEAD construction |
| `threefish-1024`       | `tf1024`, `threefish1024`                 | ⚠️ VERIFY AEAD construction |

> **⚠️ VERIFY** the Threefish mode (how confidentiality+integrity are achieved;
> it is not an AEAD on its own) and pin the exact list shipped in 1.5.0's
> "reduced algorithm set".

### 14.2 KEMs (recipient encapsulation) and signatures

| KEMs            | Signatures                                              |
|-----------------|---------------------------------------------------------|
| `ML-KEM-512`    | `ML-DSA-44` / `ML-DSA-65` / `ML-DSA-87`                 |
| `ML-KEM-768`    | `MAYO-1` / `MAYO-3` / `MAYO-5`                           |
| `ML-KEM-1024`   | `CROSS-128` / `CROSS-192` / `CROSS-256` (`cross-rsdp`)  |
| `HQC-128`       | `SLH-DSA-SHA2-128F` / `-192F` / `-256F`                  |
| `HQC-192`       | `Falcon-512` / `Falcon-1024`                             |
| `HQC-256`       | classical: `Ed25519`, `RSA` (hybrid component / pepper) |

> **TODO** confirm which are *shipped* in 1.5.0 vs. legacy-only, and the
> backing library identifiers (liboqs names).

### 14.3 KDFs

`argon2` (Argon2id), `balloon`, `scrypt`, `hkdf`, `randomx` (opt-in, default off).

### 14.4 Hash functions

`sha256`, `sha384`, `sha512`, `sha3_224`, `sha3_256`, `sha3_384`, `sha3_512`,
`blake2b`, `blake2s`, `blake3`, `shake128`, `shake256`.

---

## 15. Format-version history (normative)

> The crux of the spec. Each row pins what a decryptor must know. Fill in the
> empty/`TODO` cells from VERSION.md + the metadata creators.

| Version | Introduced in | Summary                                                        | Decrypt notes |
|:-------:|:--------------|:---------------------------------------------------------------|:--------------|
| 0–3     | early          | **TODO** flat legacy structures                                | reference impl only |
| 4 / 5   | **TODO**       | metadata restructure (converters v3↔v4↔v5)                     | **TODO** |
| 6 / 7   | **TODO**       | **TODO**                                                       | **TODO** |
| 8       | **TODO**       | cascade encryption support; current `encryption` shape         | §8 |
| 9       | 1.4.x          | **chained-salt derivation** (ADVISORY 2026-01); current default| §7.2 — legacy salt for ≤8 |
| 10      | 1.4.x          | **XOR composition** of stage outputs                           | §7.3 — order-sensitive |
| 11      | **TODO**       | **TODO** (⚠️ identify)                                          | **TODO** |
| 12      | 1.5.x          | **streaming chunked** AEAD; reduced algorithm set              | §8.4 |
| 13      | 1.5.x          | **TODO** (envelope / nonce-format related — ⚠️ identify)       | §9 / §8.3 |

---

## 16. Test vectors (KAT corpus)

To make the spec verifiable, ship a frozen corpus alongside it:

- For **each** `format_version`, at least one `{plaintext, password/keys,
  parameters} → ciphertext` golden file, with the parameters pinned.
- KATs for primitives where exact wording matters: XChaCha 192-bit, the AEAD
  constructions, the hybrid KEM combiner, and the cascade chain.
- A CI job asserting the **current** build decrypts the **entire historical
  corpus** (enforces §13).

> **TODO.** Point to the corpus location (e.g. `tests/format_vectors/`) and the
> generator/verifier. Some pieces already exist (XChaCha primitive KATs, age
> interop vectors, cross-backend determinism, recovery-slot golden fixtures) —
> consolidate them under one documented index.

---

## 17. Security considerations

This section is **non-normative**; the threat model lives in
[SECURITY.md](../SECURITY.md). Highlights an implementer must respect:

- Treat the metadata as **attacker-controlled** until the AEAD tag (and, in
  envelope mode, the `dek_slots_mac`) verifies. Never act on header fields
  pre-authentication beyond what is needed to derive keys.
- The bulk AEAD provides integrity; `hashes.*` are **not** a substitute and
  SHOULD NOT be the sole integrity check.
- Foreign-format parsers (age/OpenPGP) consume untrusted third-party files and
  are a distinct attack surface (fuzz/bound them); they are out of this spec.
- Plaintext **length is not hidden** by the standard container (size leaks).
  Optional padding is a future consideration.

---

## 18. Open questions / TODO index

A consolidated checklist of everything to resolve before this leaves DRAFT:

- [ ] §2 integer endianness of length fields
- [ ] §3 / §4.1 exact standard-vs-hidden detection + payload nonce/tag framing
- [ ] §4.2 hidden-header field lengths (`SALT_LEN`/`NONCE_LEN`/`LEN_FIELD`/`AUTH_LEN`) + outer AEAD + whitening
- [ ] §5.2 per-KDF parameter schemas, ranges, defaults
- [ ] §5.3 which hash backs `original_hash`/`encrypted_hash` and their role
- [ ] §5.4 legacy metadata shapes (v0–7) or explicit scoping
- [ ] §6 **AAD canonicalization** (the audit-critical item) + per-version diffs
- [ ] §7.1 canonical KDF pipeline order + normalization
- [ ] §7.2 chained-salt function (+ legacy rule for ≤8)
- [ ] §7.3 XOR-composition definition
- [ ] §7.4 hidden-header outer-key derivation
- [ ] §7.5 hardware-pepper mixing point + field names
- [ ] §8.2 cascade `layer_info` schema + per-layer keying/nonces
- [ ] §8.3 legacy XChaCha nonce construction
- [ ] §8.4 streaming chunk size/nonce/framing/anti-truncation
- [ ] §9 recovery-slot binary layouts + slot-set MAC + pinned versions
- [ ] §10 hybrid KEM combiner + per-recipient wrap + recipient enumeration
- [ ] §11 signature container + domain separation + signed bytes
- [ ] §12 armor labels + CRC-24 parameters
- [ ] §13 write-retired / read-dropped lists per release
- [ ] §14 shipped-vs-legacy algorithm sets + liboqs names + Threefish mode
- [ ] §15 fill the version table (esp. v11, v13)
- [ ] §16 corpus location + consolidated KAT index

---

## References

- [RFC 2119] / [RFC 8174] — requirement keywords
- [RFC 4648] — Base64
- [RFC 5869] — HKDF
- [RFC 4880] — OpenPGP (CRC-24 / armor lineage)
- FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA)
- Internal: [SECURITY.md](../SECURITY.md), [VERSION.md](VERSION.md),
  [HIDDEN_HEADER.md](HIDDEN_HEADER.md), [RECOVERY_SLOTS.md](RECOVERY_SLOTS.md)
