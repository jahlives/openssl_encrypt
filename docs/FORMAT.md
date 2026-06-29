# openssl_encrypt — On-Disk Format Specification

> **Status:** DRAFT — populated from the implementation and citation-backed.
> **Spec version:** 0.3 (code-derived)
> **Covers tool versions:** 1.4.x and 1.5.x (highest format_version: 13)
> **Last updated:** 2026-06-29
> **Editor:** Tobi <jahlives@gmx.ch>
>
> This document is the **authoritative description of the bytes written to
> disk** by openssl_encrypt. Its goals:
> 1. Let an independent implementer write a **decryptor** without reading the
>    source.
> 2. Make the format **auditable** (a frozen target a reviewer can reason about).
> 3. Anchor the project's compatibility promise: *every released version MUST
>    decrypt every format_version it ever produced* (see §13).
>
> Values below were extracted from the `feature/v1.5.x-development` tree and are
> annotated with `(src: file:line)` so any claim can be re-checked. Items that
> could **not** be confirmed from code are marked **`⚠️ UNVERIFIED`** and must be
> resolved before this leaves DRAFT.

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

- **Byte order:** there is **no single endianness** — it depends on the
  subsystem, and an implementer MUST respect each:
  - **Hidden-header** length field: **big-endian** uint32
    (`int.to_bytes(4, "big")`, src: hidden_header.py:408,438).
  - **Streaming** on-disk framing (payload version, per-chunk index and length,
    trailer chunk count): **little-endian** uint32 (`struct.pack("<I", …)`,
    src: streaming.py:574,609-610,624).
  - **Streaming** HKDF/AAD *inputs* (chunk index inside nonce/salt/AAD
    derivation): **big-endian** uint32 (`struct.pack(">I", …)`,
    src: streaming.py:146,208). These never appear as on-disk length prefixes.
  - The single-cipher and cascade bulk bodies use **no length prefix** — the
    nonce is a fixed-width raw byte prefix (§8.1).
- **Encoding of binary fields inside metadata:** standard Base64,
  [RFC 4648] §4 (`+`/`/` alphabet, `=` padding). *Note:* the implementation uses
  URL-safe Base64 internally for some derived **key material**; that never
  appears on disk in the metadata and is not part of this spec.
- **`b64(x)`** denotes the Base64 encoding of byte string `x`.
- **`||`** denotes concatenation.
- **`HKDF`** is HKDF-[RFC 5869]; the hash is SHA-256 unless stated otherwise.
- **Hashes** named below (`sha256`, `sha3_256`, `blake3`, …) use the standard
  algorithm identifiers from §14.4.
- JSON is encoded as UTF-8. Field **insertion order is significant** for the
  non-envelope AEAD AAD (§6) and for sequential XOR composition (§7.3) and MUST
  be preserved on round-trip.

---

## 3. Container at a glance

openssl_encrypt writes one of two physical containers. There is **no magic byte**
for the hidden container (by design — it must be indistinguishable from random),
so detection works by recognising the *standard* shape and treating everything
else as hidden (src: hidden_header.py:575-649, crypt_core.py:8685-8742):

| Container          | Discriminator                                                  | Plaintext metadata? | §   |
|--------------------|----------------------------------------------------------------|---------------------|-----|
| Standard           | A Base64-alphabet prefix (`len % 4 == 0`) up to the first `:` (0x3A) that decodes and begins with `{` | Yes (Base64 JSON)   | §4.1 |
| Hidden / whitened  | Anything ≥ 60 bytes that does **not** match the above ("does not look legacy") | No (header is encrypted) | §4.2 |

**Detection algorithm (normative, src: hidden_header.py:592-649):**

1. If `len(file) < HEADER_OFFSET + AUTH_LEN` (i.e. **< 60 bytes**) → treat as
   standard/legacy (too short to be a hidden blob).
2. `looks_like_legacy(file)`:
   - `colon = file.find(b":")`; if `colon <= 0` → **not legacy** (so a file with
     no `:` separator is classified as **hidden**, not rejected outright here).
   - the candidate prefix (bytes before the first `:`) MUST satisfy
     `len % 4 == 0` and match `^[A-Za-z0-9+/]+={0,2}$`, MUST Base64-decode with
     `validate=True`, and the decoded bytes MUST start with `b"{"`.
   - if all hold → **standard**; else → **hidden**.
3. The CLI may force the parser (`hidden_header=True/False`); `None` = auto-detect
   (src: crypt_core.py:8705-8742).

When scanning a stream, the hidden-detector reads up to
`_HIDDEN_DETECT_CAP = 4 MiB` in 64 KiB blocks (src: crypt_core.py:8685).

---

## 4. Container layouts

### 4.1 Standard container

```
┌──────────────────────────────┬───────┬───────────────────────────────┐
│ Base64( metadata JSON )       │  ':'  │ payload (bulk ciphertext)     │
│ (variable length)             │ 0x3A  │ (variable length)             │
└──────────────────────────────┴───────┴───────────────────────────────┘
```

- The metadata region is everything up to the **first** `:` (0x3A) byte
  (src: crypt_core.py:7178-7180 write; 4616-4620 / 7304 read).
- A reader MUST locate the separator without buffering the whole payload. The
  reference reader scans incrementally in **8 KiB** blocks
  (`_BLOCK_SIZE = 8192`) up to a **2 MiB** metadata cap
  (`_MAX_METADATA_SIZE = 2*1024*1024`); exceeding the cap with no `:` →
  `ValueError("…no metadata separator found")` (src: crypt_core.py:7290-7320).
- A file with no `:` separator is invalid for the standard parser
  (`ValueError("…missing colon separator")`, src: crypt_core.py:4616-4618) — but
  see §3: such a file is normally routed to the hidden parser first.
- **Payload framing** is determined by the metadata; see §8. For single-cipher
  and cascade the payload after `:` is **Base64-encoded**
  (`base64.b64encode`, src: crypt_core.py:7179); for **streaming** the payload is
  **raw binary** starting with the `OESC` magic (§8.4, src: streaming.py:569-574).

### 4.2 Hidden ("whitened") container — profile version 1

No plaintext magic bytes or JSON; the entire header is encrypted and
length-whitened so the file is indistinguishable from random of the same size.
Implemented in `hidden_header.py`. Domain-separated by purpose
(src: hidden_header.py:64-67):

- keyless:  `b"oe-hidden-header/keyless/v1"`
- keyed:    `b"oe-hidden-header/keyed/v1"`   (gated by a second password)

Physical layout (src: hidden_header.py:290-305):

```
┌──────────┬───────────┬──────────────┬───────────────┬──────────┬────────┐
│ salt     │ nonce     │ whitened_len │ header_region │ auth     │ body   │
│ 16 B     │ 24 B      │ 4 B          │ header_len    │ 16 B     │  …     │
└──────────┴───────────┴──────────────┴───────────────┴──────────┴────────┘
                                       └─ encrypted standard header (§5)
```

- **Field lengths (fixed for profile v1):** `SALT_LEN = 16`,
  `NONCE_LEN = 24` (XChaCha nonce), `LEN_FIELD_LEN = 4`, `AUTH_LEN = 16`, so
  `HEADER_OFFSET = 16 + 24 + 4 = 44` bytes (src: hidden_header.py:301-305).
  Minimum valid blob = `HEADER_OFFSET + AUTH_LEN = 60` bytes.
- **Outer AEAD:** XChaCha20-Poly1305 in **keyed** mode (`AUTH` = 16-byte
  Poly1305 tag; AAD = `salt || nonce || whitened_len`, src: hidden_header.py:413,461).
  In **keyless** mode the header is XORed with a raw XChaCha20 keystream and
  `AUTH` is 16 **random decoy** bytes (no real tag), preserving indistinguishability
  (src: hidden_header.py:417-420,462-463).
- **Length whitening:** `whitened_len = uint32_be(header_len) XOR
  XChaCha20_keystream(len_key, nonce)[:4]` (src: hidden_header.py:408-410). On read,
  `header_len ≤ _MAX_HEADER_LEN = 64 MiB`; over-range or inconsistent length →
  authentication/validation error (src: hidden_header.py:310,444-454).
- `header_region` decrypts to a **standard metadata object** (§5); from there
  decryption proceeds as for the standard container (the decryptor re-wraps it to
  the legacy `b64(meta):payload` form internally, src: crypt_core.py:4604-4613).
- **Keyed vs keyless gating:** presence of a non-empty *second password* selects
  keyed; `None`/empty selects keyless (src: hidden_header.py:403,434).

Outer-key derivation is in §7.4.

---

## 5. The metadata object

A JSON object. The schema below applies to **format_version ≥ 8**; see §15 for the
history and §5.4 for legacy shapes. Authoritative builder: `create_metadata_v8`
(src: crypt_core.py:4136-4242).

### 5.1 Top-level fields

| Field               | Type    | Presence            | Meaning                                              |
|---------------------|---------|---------------------|------------------------------------------------------|
| `format_version`    | int     | REQUIRED            | On-disk format version (§15). Drives all parsing.    |
| `mode`              | string  | REQUIRED            | `"symmetric"` (src: crypt_core.py:4234) or `"asymmetric"` (§10, format_version 7 path). |
| `derivation_config` | object  | REQUIRED (symmetric)| KDF/salt parameters (§5.2).                          |
| `hashes`            | object  | REQUIRED            | `original_hash`, optional `encrypted_hash` (§5.3).   |
| `encryption`        | object  | REQUIRED            | Cipher parameters; shape depends on cascade (§8).    |
| `aead_binding`      | bool    | OPTIONAL            | `true` ⇒ metadata is bound as AEAD AAD (§6). Set only when AAD mode is on (src: crypt_core.py:4241-4242). |
| `encrypted_at`      | string  | OPTIONAL            | UTC timestamp `%Y-%m-%dT%H:%M:%SZ` (src: crypt_core.py:4356). |
| `archive`           | object  | OPTIONAL            | Present when a directory was encrypted (src: crypt_core.py:6800-6805). |
| `signature`         | object  | OPTIONAL            | Asymmetric-mode metadata signature (§10/§11).        |

Envelope fields (`wrapped_dek`, `dek_slots`, `dek_slots_mac`) live **inside**
`encryption`, not at top level (§9; src: crypt_core.py:6807-6816).

### 5.2 `derivation_config`

```jsonc
"derivation_config": {
  "salt": "<b64>",                       // primary KDF salt
  "hash_config": { "sha3_512": { "rounds": 10000 }, … },
  "kdf_config":  { "argon2": { … }, "balloon": { … }, "scrypt": { … },
                   "hkdf": { … }, "randomx": { … } }
}
```

- `hash_config` keys are iterative hash stages (§14.4); `rounds: 0` ⇒ disabled
  (the entry is still written, but the stage is skipped, src: crypt_core.py:1210,2199).
  Accepted hash keys: `sha512, sha384, sha256, sha224, sha3_512, sha3_384,
  sha3_256, sha3_224, blake2b, blake2s, blake3, shake256, shake128`
  (src: crypt_core.py:4248-4262).
- `kdf_config` keys are memory-hard / KDF stages (§14.3): `scrypt, argon2,
  balloon, hkdf, randomx` (src: crypt_core.py:4266-4269). `randomx` is **opt-in**
  in spirit but **is enabled in the STANDARD template** (src: crypt_cli.py:627);
  it is a CPU-bound PoW, not a vetted password KDF — SHOULD be treated as
  defense-in-depth, not the primary cost parameter.
- **Insertion order matters** — see §6 (the non-envelope AAD is the literal
  `json.dumps(metadata)` without `sort_keys`) and §7.3 (XOR composition).

**Per-KDF parameter objects** (keys as written; defaults as read by the sequential
`generate_key`, src: crypt_core.py:2857-3353):

| KDF      | Keys (on disk)                                              | Defaults (sequential read)                          |
|----------|------------------------------------------------------------|-----------------------------------------------------|
| argon2   | `enabled, time_cost, memory_cost, parallelism, hash_len, type, rounds` | time_cost 3, memory_cost 65536 (KiB), parallelism 4, type 2 (=Argon2id), rounds 1; `hash_len` forced to key length |
| balloon  | `enabled, time_cost, space_cost, parallelism, hash_len, rounds`        | time_cost 3, space_cost 65536, parallelism 4, rounds 1; output 32 B |
| scrypt   | `enabled, n, r, p, rounds`                                  | n/r/p REQUIRED (no defaults — KeyError if missing), rounds 1; output 32 B |
| hkdf     | `enabled, algorithm, rounds`                                | algorithm `sha256` (sha224/384/512 accepted), info `b"openssl_encrypt_hkdf"`, rounds 1 |
| randomx  | `enabled, rounds, mode, height, hash_len`                  | rounds 1, mode `light`, height 1 |

> **Note:** the **independent-XOR** path (§7.3) reads slightly different defaults
> (argon2 time_cost 2 / memory_cost 102400 / parallelism 8; hkdf info
> `b"independent-xor-hkdf"`) (src: crypt_core.py:1858-2049). The template presets
> QUICK/STANDARD/PARANOID set their own values (src: crypt_cli.py:585,607,640).
> **Accepted ranges (verified).** No centralized numeric range-clamping is done in
> application code: parameters are passed straight to the backends, so out-of-range
> values surface as **library exceptions on decrypt** — argon2-cffi requires
> `time_cost ≥ 1`, `memory_cost ≥ 8 KiB`, `parallelism ≥ 1`; scrypt requires `n` a
> power of two `≥ 1`, `r ≥ 1`, `p ≥ 1`. The only in-code clamps are in the Balloon
> backend: `space_cost ≤ 1 000 000` and `time_cost ≤ 100 000`
> (src: balloon.py:64-66,120-124). An implementer reproduces the stored parameters
> verbatim; there is no additional normative accepted-range table to honour beyond
> these backend limits.

### 5.3 `hashes`

| Field            | Type   | Presence | Meaning                                            |
|------------------|--------|----------|----------------------------------------------------|
| `original_hash`  | string | REQUIRED | **SHA-256 hex** of the **plaintext** (src: crypt_core.py:921-942,6106). |
| `encrypted_hash` | string | OPTIONAL | **SHA-256 hex** of the **ciphertext**, for a tamper pre-check. |

- Both are SHA-256 hex digests, compared in constant time on decrypt
  (src: crypt_core.py:10497-10505, 9300-9308).
- `encrypted_hash` is written **only on the non-AEAD path** and is **omitted for
  all AEAD ciphers** (`include_encrypted_hash=False`, src: crypt_core.py:6791,6909-6914).
  For AEAD files the tag provides ciphertext/metadata integrity; `original_hash`
  is a post-decryption plaintext check (defense-in-depth, **not** the primary
  integrity mechanism). For legacy/non-AEAD ciphers (Fernet), `encrypted_hash`
  **is** the security-relevant ciphertext-tamper check.

### 5.4 Legacy metadata shapes (format_version 3–7)

The on-disk floor is **format_version 3** (`MIN_FORMAT_VERSION = 3`,
src: verify.py:46); there is **no v0/v1/v2** on disk (in-code `…get("format_version", 1)`
defaults are memory sentinels, not real formats). In-code converters bridge the
shapes (all in crypt_core.py):

- **v3 — flat.** Top-level `salt`, `hash_config` (flat `{algo: int_rounds}`),
  `original_hash`, `encrypted_hash`, `algorithm`, flat `scrypt`/`argon2`/`balloon`,
  flat `pqc_*`. (`convert_metadata_v3_to_v4`, src: crypt_core.py:3612.)
- **v4 — nested.** Introduces `derivation_config{salt,hash_config:{algo:{rounds}},
  kdf_config}`, `hashes{…}`, `encryption{algorithm,…}` — the structure v5–v12
  retain. (`convert_metadata_v4_to_v3`, src: crypt_core.py:3741.)
- **v5 — adds `encryption.encryption_data`** (configurable bulk algorithm for PQC).
  (`convert_metadata_v4_to_v5` / `v5_to_v4`, src: crypt_core.py:3719,3698.)
- **v6 — adds formal HSM validation** fields (schema title).
- **v7 — adds PQC-signature support for asymmetric mode**, and is the first
  version under the secure chained-salt rule (§7.2).

A decryptor targeting only current files MAY ignore v3–v5, but the **reference**
decryptor MUST support them (§13).

---

## 6. AEAD associated-data (AAD) binding

When `aead_binding` is `true`, metadata is supplied as the AEAD associated data
for the bulk encryption, so header tampering is detected on decrypt. There are
**two distinct AAD constructions** — pick by whether the file is an envelope file
(presence of `encryption.wrapped_dek`):

### 6.1 Non-envelope AEAD (the common case)

The AAD is the **literal `metadata_b64` bytes** — i.e.
`base64( json.dumps(metadata) )` using **default `json` separators and NO
`sort_keys`** (src: crypt_core.py:6817-6818, 6879-6887). On decrypt the SAME
bytes are taken directly from the file header (not re-serialized), so the AAD is
byte-identical regardless of Python dict quirks — **which is exactly why metadata
insertion order is load-bearing** (§5.2). Decrypt selects it at
crypt_core.py:9988-9996.

### 6.2 Envelope AEAD (canonical, sorted)

For envelope files the AAD is `envelope_aad(metadata)` — a **canonical**
serialization (src: envelope.py:80-116):

```python
json.dumps(reduced, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
```

`reduced` is a deep copy of the metadata with these keys removed
(src: envelope.py:45,51,106-112):

- the **entire top-level `derivation_config`** subtree, **and**
- `encryption.wrapped_dek`, `encryption.dek_slots`, `encryption.dek_slots_mac`.

These are excluded because they change on rekey / recovery-slot edits; the slot
set has its own DEK-keyed MAC (§9). Everything else (`format_version`, `mode`,
`hashes`, `aead_binding`, `encryption.algorithm`/cascade fields, `archive`) stays
authenticated.

> **Correction to earlier drafts:** the exclusion set includes the **whole
> `derivation_config`**, not only the three envelope keys. An implementer MUST
> exclude `derivation_config` from the envelope AAD.

### 6.3 Version history

Before **1.3.0**, AEAD ciphers passed `None` as AAD despite the docs claiming
binding — metadata tampering was only caught post-KDF, not by the AEAD tag. 1.3.0
fixed this (src: README.md:507-519; CHANGELOG dates 1.3.0 to 2025-12-15). The
non-envelope full-metadata binding is byte-for-byte unchanged since 1.3.0; the
envelope canonical AAD is a later addition on the envelope feature line.

---

## 7. Key derivation

### 7.1 Chained KDF pipeline (sequential path, v1–v10)

Driver: `generate_key` (src: crypt_core.py:2512). The stage order is a **fixed
precedence**, not config order:

1. **Iterative hashes first**, via `multi_hash_password`
   (src: crypt_core.py:1035,2726). Within this stage, hash algorithms run in
   **dict-insertion order** (src: crypt_core.py:1202-1203).
2. **Then the memory-hard / KDF stages in this hard-coded sequence:**
   `argon2 → balloon → scrypt → hkdf → randomx`
   (src: crypt_core.py:2834,3013,3137,3232,3321).

The sequential chain passes each stage's raw output forward as the next stage's
password (`password = SecureBytes(result)`); there is no inter-stage length
normalization on the pure-sequential path. The final output length is set by the
cipher: 32 B (AES-256-GCM/ChaCha20/XChaCha20/AES-GCM-SIV/Fernet/cascade/PQC-hybrid),
64 B (AES-SIV, Threefish-512), 128 B (Threefish-1024) (src: crypt_core.py:2603-2643).

For XOR composition (§7.3), each collected intermediate is normalized to the key
length with **`normalize_to_key_length_secure`** = HKDF-SHA256, `salt=None`,
`info=b"v10_xor_normalize"` (src: crypt_core.py:1635,1668-1674).

### 7.2 Chained-salt derivation — **security-critical**

Each round's salt is derived from the previous round's **output**, not from a
predictable counter. This is the fix for **ADVISORY 2026-01**.

**Code-authoritative rule** (verified across argon2/balloon/scrypt/hkdf,
src: crypt_core.py:2904-2920, 3035-3051, 3153-3169, 3268-3279):

```
round 0:                 round_salt = base_salt
format_version >= 7:     round_salt = (previous round output)[:16]      # SECURE
format_version  < 7:     round_salt = SHA256(base_salt || str(i))[:16]  # LEGACY (predictable)
```

Hash-stage keyed chaining (blake2b/blake3/shake256) follows the same `>= 7` gate
with `hashed[:32]` (src: crypt_core.py:1364-1376,1421-1435,1511-1523). RandomX uses
its own always-chained construction (first salt `SHA256(salt || password[:16] ||
b"randomx_salt")[:16]`, then `password[:32]`, src: crypt_core.py:3331-3364).

**v8 status (resolved).** The shipped code gates the secure rule at
`format_version >= 7` with **no `!= 8` exception**, so **v7, v8, v9, v10+ all use
the secure rule** — a reference decryptor MUST do the same. This was a
*deliberate* decision: the gate evolved `>= 9` → `>= 7 and != 8` → `>= 7`
(commit `22059bab`, "v8 ≡ v10"), making v8 derive identically to v10. v8 used
predictable salt only in **pre-release builds** (alpha.1 … beta.9); the fix
shipped in beta.10 and **every stable release (v1.4.0 … v1.4.5) reads/writes v8
as secure**. Crucially, **no release ever wrote v8 as a default** — the encrypt
default was always v9 (secure), and v8 was not CLI-selectable during the
predictable window — so no predictable-salt v8 files are expected to exist.
Consequence: a hypothetical legacy predictable-salt v8 file (if one were ever
produced programmatically on a pre-beta.10 build) would **not** decrypt under
current code; this is accepted as out of scope. Files at `format_version ≤ 6` use
the legacy rule. *(Note: `docs/metadata-formats.md` and SECURITY.md ADVISORY
2026-01 historically described v8 as "decrypts via legacy / vulnerable"; those
were corrected to match this code-authoritative behavior.)*

### 7.3 XOR composition (v8 / v10 / v11 / v13)

Combine primitive: `xor_bytes_secure` — byte-wise XOR of equal-length
`SecureBytes` (src: crypt_core.py:1582-1626).

- **Sequential XOR** (`use_xor_composition = format_version >= 10 or
  format_version == 8`): the sequential chain runs end-to-end, but each stage
  *also* contributes a normalized snapshot to an accumulator, and the key is the
  XOR of all snapshots.
  - **⚠️ v8/v10 CANCELLATION BUG (cost bypass).** These versions also append the
    chain's *final value* to the accumulator — but that equals the **last stage's**
    own snapshot, so the two XOR to zero and the **last stage cancels out of the
    key**. The surviving terms are the **initial** snapshot
    `SHA256(plaintext-pw ‖ salt_0)` — computed *before* the chain runs, so it uses
    the original password and salt, not the derived/chained values — XOR'd with any
    earlier non-final stage snapshots. With a single memory-hard KDF (Argon2-only)
    Argon2 is last, so the key reduces to exactly that cheap initial hash,
    **independent of the configured Argon2 cost** (a cost bypass). Affects
    `format_version ∈ {8, 10}` (`--xor`), not v9/v11/v13. See ADVISORY 2026-02 in
    [SECURITY.md](../SECURITY.md). Existing v8/v10 files **keep** this derivation
    (decrypt-compat, append-only) — re-encrypt to fix.
  - **Fix at `format_version >= 13`** (`xor_mode: "sequential"`): the redundant
    final-result append is skipped, so every stage contributes and the last
    stage's cost is paid (src: the `format_version < 13` gate around the
    `sequential_result` append in crypt_core.py). The per-stage chained inputs
    already differentiate the components, so no per-component salt is added here
    (that is the independent-mode fix).
- **Independent XOR** (`format_version >= 11`, src: crypt_core.py:5820,9564):
  every component gets the **same** input `x = SHA256(password || salt)`
  (src: crypt_core.py:2175,2184) and `K = H1(x) ⊕ H2(x) ⊕ … ⊕ Hn(x)`
  (src: crypt_core.py:2396), followed by a cipher-specific final transform
  (SHA-256 / SHA-512 / HKDF / base64, src: crypt_core.py:2412-2482). This is a
  robust XOR-combiner: secure if ≥1 component is unbroken (output/PRF sense).
- **Independent XOR + per-component salts** (`format_version >= 13`): identical to
  v11, except each component (each enabled hash/KDF stage) gets a **distinct,
  domain-separated salt** instead of the shared `salt_0`
  (src: `_indep_xor_component_salt`, crypt_core.py). Per component `name`:
  `component_salt = HKDF-SHA256(IKM=salt_0, salt=none,
  info=b"openssl_encrypt.indep-xor.v13.salt:" + name, length=len(salt_0))`, where
  `name` ∈ {`sha256`,`sha512`,`sha3_256`,`sha3_512`,`blake2b`,`blake3`,`shake256`,
  `argon2`,`scrypt`,`balloon`,`hkdf`,`randomx`}. The shared input
  `SHA256(pw‖salt_0)` and the initial-hash component are **unchanged** (they are
  singular and cannot duplicate). This retires the cancellation footgun below
  while keeping the robust-combiner proof. v13 metadata shape == v11; the
  derivation is parallel-incompatible (the parallel path delegates to sequential
  for v13). **This derivation is pinned for cross-line byte-identity** — do not
  alter the `info` string or output length.

Hashes are iterated in dict-insertion order; XOR itself is commutative, so order
does not change the v11/v13 result. At **v11/v12** the components share `salt_0`,
so **duplicate identical stages would cancel to zero** (cancellation caveat,
src: crypt_core.py:2085-2091) — this is retired at **v13** by the distinct
per-component salts. Order matters for the sequential chain. Independent-XOR
multi-round chaining uses `result[:32]` (src: crypt_core.py:1887, parallel_kdf.py).

**Mode routing (v13 holds both modes).** From v13, the on-disk `xor_mode` field —
not the version — selects the derivation: a v13 file is **independent** iff
`xor_mode == "independent"`, otherwise **sequential**. Decrypt routes by this
(`xor_mode == "independent" or format_version in (11, 12)`); v11/v12 are always
independent (caught by the version), v8/v10/v13-sequential are sequential. Encrypt
stamps `xor_mode` explicitly for every v13 file. Older code that equated
`format_version >= 11` with "independent" was corrected to this `xor_mode`-driven
routing.

### 7.4 Hidden-header outer key

`derive_outer_key(salt, second_password, length, profile)`
(src: hidden_header.py:246-284); `_subkeys` requests 64 bytes and splits into a
32-byte `stream_key` (AEAD/whitening) + 32-byte `len_key` (length whitening)
(src: hidden_header.py:340-360).

- **Keyless** (no secret): `HKDF(SHA512, length, salt=DOMAIN_KEYLESS,
  info=b"outer-key").derive(file_salt)` (src: hidden_header.py:165-180). The
  `info="outer-key"` string applies **only** to keyless.
- **Keyed** (second password): a heavy chain
  `material = SHA3-512(DOMAIN_KEYED || salt || password)`, then 100 000 rounds of
  `SHA3-512(material || salt)`, then 5 chained Argon2id passes (time_cost 3,
  128 MiB/pass, parallelism 4, 64-byte output), then scrypt (n=2¹⁵, r=8, p=1,
  64-byte), then `HKDF(SHA512, length, salt=salt,
  info=DOMAIN_KEYED || b"|final")` (src: hidden_header.py:183-239, profile 107-116).

### 7.5 Hardware pepper (HSM / PIV / FIDO2)

The optional pepper is **mixed in at stage 0**, concatenated into the password
material before any hashing (`password || salt || hsm_pepper` in
`multi_hash_password`; `SecureBytes(password || hsm_pepper)` before the initial
hash in the independent-XOR path) — it is **not** a separate KDF stage and not a
per-round input (src: crypt_core.py:1185,2758,2167). When both an HSM pepper and a
remote pepper exist they are concatenated `hsm_pepper || remote_pepper`
(src: crypt_core.py:5810).

**Metadata fields actually written** (under `encryption`, src: crypt_core.py:3922-3931)
— note these differ from the in-code parameter names:

| On-disk key            | Meaning                       |
|------------------------|-------------------------------|
| `hsm_plugin`           | HSM plugin name               |
| `hsm_config.slot`      | HSM slot used                 |
| `pepper_plugin`        | pepper plugin name            |
| `pepper_name`          | pepper name                   |

PIV/PKCS#11 pepper derivation (src: piv_backend.py:110-161): HKDF-SHA256 with
fixed salt `b"openssl_encrypt-piv-v1"`, challenge `info=b"piv-challenge"`
(64 B), pepper `info=b"piv-pepper"` (32 B) over the deterministic signature
(Ed25519 / RSA-PKCS1v1.5 only; ECDSA rejected, determinism enforced by
double-sign-and-compare). **Pepper byte lengths by device (verified):** FIDO2
(hmac-secret / CredRandom) = **32 B**
(src: plugins/hsm/fido2_pepper/__init__.py:520-524); YubiKey and OnlyKey
(HMAC-SHA1 challenge-response) = **20 B**
(src: plugins/hsm/yubikey_challenge_response/__init__.py:182-183,
onlykey_challenge_response/__init__.py:275); PIV/PKCS#11 = **32 B** (HKDF-SHA256
normalised, configurable, src: piv_backend.py:123). All are mixed in at stage 0
(see above), never as a separate KDF stage.

---

## 8. Symmetric data encryption

### 8.1 Single-cipher mode

```jsonc
"encryption": {
  "cascade": false,
  "algorithm": "<cipher-id>",            // §14.1
  "encryption_data": "<bulk-aead-id>",   // §14.1
  "pq_security_bits": 128,
  "xchacha_nonce_format": 2              // present iff XChaCha (see §8.3)
}
```
(src: crypt_core.py:4216-4229.)

**On-disk framing:** `nonce || ciphertext || tag`, then the whole blob is
Base64-encoded into the standard container. The nonce is a raw fixed-width prefix;
the 16-byte AEAD tag is appended to the ciphertext by the library
(src: crypt_core.py:6385-6536,7179). Per-cipher nonce/tag sizes:

| Algorithm            | Nonce | Tag | Notes                                            |
|----------------------|:-----:|:---:|--------------------------------------------------|
| aes-256-gcm          | 12    | 16  |                                                  |
| aes-256-gcm-siv      | 12    | 16  | nonce-misuse resistant                           |
| aes-256-siv          | 16*   | 16  | *16-byte nonce stored but **not** used (deterministic SIV); key 64 B |
| chacha20-poly1305    | 12    | 16  |                                                  |
| xchacha20-poly1305   | 24    | 16  | 24-byte nonce on new files (§8.3); key 32 B      |
| threefish-512        | 32    | 16  | Threefish-512-CTR + Poly1305 (§14.1); key 64 B   |
| threefish-1024       | 64    | 16  | Threefish-1024-CTR + Poly1305; key 128 B         |

(src: crypt_core.py:6140-6168; registry cipher_registry.py.)

### 8.2 Cascade mode (multi-layer)

```jsonc
"encryption": {
  "cascade": true,
  "cipher_chain": ["aes-256-gcm", "xchacha20-poly1305", …],  // applied in order
  "hkdf_hash": "sha256",
  "cascade_salt": "<b64>",               // 32 random bytes (secrets.token_bytes(32))
  "layer_info": [ {"cipher": "<id>", "key_size": <int>, "tag_size": <int>}, … ],
  "total_overhead": <int>,
  "pq_security_bits": 256
}
```
(src: crypt_core.py:4204-4215, 6722,6731-6738.)

- **`layer_info`** element schema is exactly `{cipher, key_size, tag_size}`
  (src: crypt_core.py:6731-6738, cascade.py:483-489).
- **Per-layer key/nonce derivation** (`CascadeKeyDerivation.derive_layer_keys`,
  src: cascade.py:175-238): for each layer with cipher name `c`,
  - `key   = HKDF(hkdf_hash, len=key_size,   salt=layer_salt, info=b"cascade:key:"   || c || prev_prefix).derive(master_key)`
  - `nonce = HKDF(hkdf_hash, len=nonce_size, salt=layer_salt, info=b"cascade:nonce:" || c || prev_prefix).derive(master_key)`
  - `prev_prefix = key[:16]` carried to the next layer (first layer: empty).
- **Per-layer salt (format_version ≥ 12):** `layer_salt = HKDF(hkdf_hash, 32,
  salt=None, info=b"cascade:salt:" || str(i)).derive(master_salt)`; legacy (< 12)
  all layers share `cascade_salt` (src: cascade.py:156-173,196-207).
- **AAD per layer:** v12+ applies AAD on **every** layer; legacy only on layer 0
  (src: cascade.py:329-335,373-382).
- **Order:** encrypt plaintext → layer 0 → 1 → … → ciphertext; decrypt reverses
  (src: cascade.py:331-385). Each layer prepends its (HKDF-derived) nonce to its
  own output; decrypt extracts it from the layer ciphertext (`nonce=None`).

### 8.3 XChaCha nonce format

- `xchacha_nonce_format: 2` ⇒ **true 192-bit (24-byte) random nonce**, real
  XChaCha20-Poly1305 (HChaCha20 subkey per draft-irtf-cfrg-xchacha-03)
  (src: xchacha.py:36-132). New files always write `2`
  (src: crypt_core.py:4229, 5935,6718).
- **Absent / `1` (legacy):** the metadata getter defaults to `1`
  (src: crypt_core.py:8056 etc.). Two legacy behaviors:
  - **single-cipher legacy:** pre-1.5 files stored a **12-byte** nonce and used
    direct ChaCha20-Poly1305 (src: crypt_core.py:351-358,397-404).
  - **registry/cascade legacy (format 1):** a 24-byte nonce is funnelled to 12 via
    `HKDF(SHA256, 12, salt=nonce[:16], info=nonce[16:]).derive(key)`, then plain
    ChaCha20-Poly1305 (src: cipher_registry.py:648-673).
- **PQC-hybrid data layer** uses 12-byte AES-GCM nonces under per-file HKDF keys
  and omits `xchacha_nonce_format` (src: crypt_core.py:4226-4227,6334-6341).

### 8.4 Streaming / chunked payload (format_version 12)

Constant-memory encryption. Streaming files are written with metadata
`format_version = 12` (src: crypt_core.py:5940-5948) and a **raw binary** payload
after the `:` (or after a whitened header in hidden mode).

**On-disk layout** (src: streaming.py:7-9,429-433,573-631):

```
OESC | payload_version(u32le=1) | [ chunk ]* | chunk_count(u32le) | HMAC-SHA256(32 B)
chunk := chunk_index(u32le) | ciphertext_len(u32le) | ciphertext(=ct||tag16)
```

- Magic `STREAMING_MAGIC = b"OESC"`; `PAYLOAD_VERSION = 1`
  (src: streaming.py:45-46).
- `DEFAULT_CHUNK_SIZE = 1 MiB`; streaming kicks in above
  `DEFAULT_STREAMING_THRESHOLD = 10 MiB` (src: streaming.py:47-48).
- **Per-chunk nonce is derived, not stored:** an 8-byte random `nonce_prefix` is
  generated per file (src: streaming.py:468); per chunk,
  `nonce = HKDF(SHA256, nonce_size, salt=nonce_prefix,
  info=b"oesc-chunk-nonce:" || u32be(index)).derive(nonce_prefix || u32be(index))`
  (src: streaming.py:121-153). `nonce_size` per §8.1 (24 for XChaCha v2).
- **Anti-truncation / reordering** is enforced three ways:
  1. per-chunk AAD `aad_prefix || b":" || u32be(index) || b":" || u32be(count)`
     (`aad_prefix` = `metadata_b64` or the envelope `bulk_aad`)
     (src: streaming.py:191-209);
  2. the stored `chunk_index` is checked against a running counter on decrypt
     (src: streaming.py:855-861);
  3. the trailer `chunk_count` and a 32-byte **HMAC-SHA256** over the
     concatenation of every chunk's 16-byte tag (key =
     `HKDF(SHA256, 32, salt=None, info=b"openssl_encrypt-streaming-hmac-key")
     .derive(key)`; legacy key `SHA256(key || b"oesc-trailer-hmac")`)
     (src: streaming.py:483-493,623-633,905-942).
- `ciphertext_len` is capped at `chunk_size + 1024` on read
  (`_MAX_CHUNK_OVERHEAD`, src: streaming.py:722,864-868).
- **Cascade-over-streaming** derives a fresh 32-byte per-chunk cascade salt
  (`info=b"oesc-cascade-chunk-salt:" || u32be(index)`, scheme 2 = default for new
  writes); the **decryptor defaults to the legacy single-salt scheme 1** for files
  written before the fix and warns (src: streaming.py:50-59,156-188,445,668-685).

---

## 9. Envelope (DEK/KEK) wrapping & recovery slots

Optional two-tier keying so a credential change (`rekey`) rewraps only a small
key instead of re-encrypting the payload. Implemented in `envelope.py` /
`recovery_slots.py`.

- A random **32-byte DEK** (`DEK_SIZE = 32`, `secrets.token_bytes`) encrypts the
  bulk (§8) (src: envelope.py:31,70-77).
- The DEK is wrapped by the **KEK** (the §7 output):
  - **Non-cascade:** AES-256-GCM, wrap key =
    `HKDF-SHA256(KEK, salt=None, info=b"openssl_encrypt.envelope.dek-wrap.v1")`;
    output `nonce(12) || ct || tag(16)` = 60 bytes
    (src: envelope.py:57,119-162).
  - **Cascade bulk:** the same wrap key feeds `CascadeEncryption.encrypt` under a
    fixed 32-byte salt `b"oesc.envelope.cascade-wrap.salt1"`, pinned at
    `_CASCADE_WRAP_FORMAT_VERSION = 12` (src: envelope.py:66-67,203-252).
- Stored under `encryption`: `wrapped_dek` (b64), `dek_slots` (raw JSON list),
  `dek_slots_mac` (b64). These three are **excluded from the AEAD AAD** (§6;
  src: crypt_core.py:6009-6018).
- **`dek_slots_mac`** is an HMAC-SHA256 over `canonical_slots(dek_slots)` keyed by
  `HKDF-SHA256(DEK, salt=None, info=b"openssl_encrypt.envelope.slot-set-mac.v1")`,
  verified **after** unwrap, fail-closed (src: recovery_slots.py:42,75-96;
  crypt_core.py:9705-9713). `canonical_slots` = `json.dumps(slots, sort_keys=True,
  separators=(",",":"), ensure_ascii=True)` (src: recovery_slots.py:58-72).

**Recovery slots** let multiple independent credentials each unwrap the DEK. Each
slot is `{id, type, wrap (b64 of the standard AES-256-GCM DEK wrap), params{…}}`;
only the KEK derivation differs by type (per-slot 16-byte salt;
src: recovery_slots.py:39-49):

| Slot type      | 1.4.x | 1.5.x | KEK derivation                                                                 |
|----------------|:-----:|:-----:|--------------------------------------------------------------------------------|
| recovery_code  |  ✓    |  ✓    | `HKDF-SHA256(code, salt, info=b"…recovery-code-kek.v1")`; 256-bit base32 code   |
| passphrase     |  ✓    |  ✓    | Argon2id (time_cost 3, memory 64 MiB, parallelism 4); params stored in slot     |
| pqc            |  ✓    |  ✓    | ML-KEM encapsulate → `HKDF-SHA256(ss, salt, info=b"…pqc-recipient-kek.v1")`     |
| shamir (k-of-n)|  —    |  ✓    | reconstruct secret → `HKDF-SHA256(secret, salt, info=b"…shamir-secret-kek.v1")` |

(src: recovery_slots.py:124-538; info strings prefixed `openssl_encrypt.envelope.`.)
Shamir shares are written out-of-band as `recovery_share_<i>.json`; the slot stores
only `{threshold, num_shares}` (src: recovery_slots.py:287-295,710-726).

> **Version gating (verified).** No `format_version` constant gates the *presence*
> of envelope/recovery fields — they are purely additive under `encryption`, and a
> reader detects them by presence rather than by version
> (src: crypt_core.py:5949-5953,6061-6070). The cascade DEK-wrap internally pins
> v12 for its wrap-key derivation only (src: envelope.py:67). The
> "shamir = 1.5.x only" split is a product/release statement, **not** a code-level
> version gate in `recovery_slots.py` (all four slot types are handled uniformly).

---

## 10. Asymmetric / PQC recipient encryption

`mode: "asymmetric"` (format_version 7 path, `encrypt_file_asymmetric`,
src: crypt_core.py:4822-5094).

> **There is NO classical+PQC hybrid KEM combiner in the recipient path.**
> Recipient encapsulation is **PQC-only, ML-KEM** (`PasswordWrapper` accepts only
> ML-KEM-512/768/1024, default ML-KEM-768; src: asymmetric_core.py:65-88). The
> word "hybrid" elsewhere (e.g. `ml-kem-768-hybrid`) means **PQC-KEM + classical
> *symmetric* AEAD** (data under AES/ChaCha, key wrapped by the KEM), **not**
> classical + PQC KEM. The only X25519 in the tree is **age-format interop**
> (`--age-identity`), not a native KEM. So **recipient confidentiality rests
> solely on ML-KEM** — a legitimate choice (NIST permits standalone ML-KEM) but
> **not** the classical+PQC "belt-and-suspenders" hybrid (à la X25519+ML-KEM in
> TLS) that hedges against a future ML-KEM break.

- **Wrap:** a random bulk password encrypts the data (AES-256-GCM, 12-byte nonce,
  `derived_key[:32]`); that password is wrapped per recipient. The per-recipient
  AES-256-GCM **wrap key = `HKDF-SHA256(salt=None,
  info=b"openssl_encrypt.password_wrap.v2").derive(shared_secret)`** (no AAD;
  output `nonce(12) || ct || tag(16)`) (src: asymmetric_core.py:205-216).
  > **Format note.** The `…password_wrap.v2` HKDF derivation replaced an earlier
  > **bare SHA-256** of the shared secret (`…password_wrap.v1`). Decrypt tries
  > HKDF/v2 first and **falls back to the legacy v1 bare-SHA256** so existing
  > recipient files still open (src: asymmetric_core.py:287-309). Both lines
  > (1.4.x and 1.5.x) now write v2 and read v2+v1, so recipient files are
  > cross-line interoperable. (The bare-SHA256 v1 derivation was itself
  > cryptographically sound — an ML-KEM shared secret is already a uniform 32-byte
  > key per FIPS 203 — but HKDF aligns this spot with the rest of the codebase.)
- **Recipients on disk:** `metadata["asymmetric"]["recipients"]` is a JSON **list**;
  each entry = `{key_id, kem_algorithm, encapsulated_key (b64), encrypted_password
  (b64)}`. Sender block = `metadata["asymmetric"]["sender"] = {key_id,
  sig_algorithm: "ML-DSA-65"}` (src: crypt_core.py:4979-4994).
- **Encrypt-to-self (1.5+ default):** the sender's own identity public key is added
  as an additional recipient (deduped by fingerprint), default on
  (src: identity.py:1000-1028).
- **Metadata signature:** the whole metadata (minus any `signature` key) is
  canonicalized by `MetadataCanonicalizer` (`sort_keys=True,
  separators=(",",":"), ensure_ascii=False`) and signed with ML-DSA-65; stored as
  `metadata["signature"] = {algorithm: "ML-DSA-65", value: b64}`
  (src: asymmetric_core.py:336-404, crypt_core.py:5027-5037).
- **`pqc_*` single-keypair fields** (separate bulk mode, under `encryption`):
  `pqc_public_key`, `pqc_private_key` (only if self-decrypt requested),
  `pqc_key_salt`, `pqc_sig_hkdf_salt` (32-byte random, v12+)
  (src: crypt_core.py:3896-3917).

---

## 11. Detached signatures

`sign` / `verify-signature` produce a **detached** sidecar
(src: file_signature.py).

- **Sidecar fields** (`build_signature`, src: file_signature.py:148-158):
  `openssl_encrypt_signature` (=1), `algorithm`, `hash_algorithm` (`"SHA-512"`),
  `file_hash` (lowercase hex SHA-512 of the target file), `signer_fingerprint`,
  `signed_at` (RFC3339 UTC), `signatures` (list of
  `{component: <algo.lower()>, value: <b64 raw sig>}`). Serialized with
  `json.dumps(sig, sort_keys=True, indent=2)` → **on-disk key order is
  alphabetical** (src: file_signature.py:168).
- **Signed bytes:** `b"openssl-encrypt/detached-file-signature/v1" || b"\x00" ||
  canonical`, where `canonical = json.dumps(core, sort_keys=True,
  separators=(",",":"))` and `core = {algorithm, file_hash, hash_algorithm,
  signed_at, signer_fingerprint, version}` (src: file_signature.py:92-110). The
  target file is bound **via its SHA-512 `file_hash`**, and the `signatures` list
  itself is excluded from the signed payload.
- **Algorithms:** v1 emits a **single** component, **ML-DSA-65** by default
  (`DEFAULT_SIG_ALGORITHM`, src: file_signature.py:48). The `signatures` list is
  structured so a classical (e.g. Ed25519) component can be added later without a
  format break. **Not yet implemented (verified):** no Ed25519 component is signed
  or verified anywhere — only ML-DSA-65 is written; the multi-component
  `signatures` array merely reserves room for a future hybrid
  (src: file_signature.py:16-18,144-157,262-275). The asymmetric-mode *metadata*
  signature is likewise ML-DSA-65-only (src: crypt_core.py:5066).
- **Verification reports per-component** results
  (`components = [{component, valid}, …]`); overall valid = file-hash match AND
  all components valid (src: file_signature.py:231-293). PEM label = `SIGNATURE`
  (src: file_signature.py:42; §12). Signer key is resolved from the local identity
  store by fingerprint, fail-closed if unknown.

The detached-file domain tag is distinct from the asymmetric-metadata signature
(§10), so signatures cannot be replayed across contexts.

---

## 12. ASCII armor (transport encoding)

A paste-safe wrapper over the binary container (src: armor.py):

```
-----BEGIN OPENSSL-ENCRYPT MESSAGE-----
<base64 of the binary container, wrapped at 64 cols>
=XXXX            ← OpenPGP-style CRC-24 checksum line
-----END OPENSSL-ENCRYPT MESSAGE-----
```

- Marker prefixes `-----BEGIN OPENSSL-ENCRYPT ` / `-----END OPENSSL-ENCRYPT `,
  suffix `-----`; labels `MESSAGE` (ciphertext) and `SIGNATURE` (detached
  signatures) (src: armor.py:34-40,95-100). Lines wrap at `LINE_WIDTH = 64`.
- **CRC-24** matches OpenPGP [RFC 4880] §6.1: `init = 0xB704CE`,
  `poly = 0x1864CFB`, 24-bit, MSB-first; emitted as `=` + b64 of the 3 CRC bytes
  (src: armor.py:45-77).
- The **encoder emits no header lines**; the decoder tolerates optional
  `Key: value` header lines terminated by a blank line (src: armor.py:95-115,201-206).
- Auto-detection sniffs the first **256 bytes** for the BEGIN prefix
  (`is_armored_file`, src: armor.py:226-245); `dearmor` fails closed on missing
  markers, label mismatch, bad base64, or CRC mismatch.
- **Where it is applied:** `decrypt`/`info`/`verify`/`rekey` transparently
  de-armor armored input before parsing (content-sniffed, no flag); `encrypt
  --armor` wraps output. The standalone `armor` / `dearmor` subcommands apply or
  reverse this transform on an existing file without encrypting/decrypting
  (pure, keyless, reversible: `dearmor(armor(x)) == x`, src: armor.py:run_armor_cli).
- **Interaction with the hidden container (§4.2):** armor wraps the *whole*
  binary container, including a hidden/whitened blob. The
  `-----BEGIN OPENSSL-ENCRYPT …-----` markers are a public, plaintext
  fingerprint, so **armoring a hidden file negates its indistinguishability**
  (anti-fingerprinting) guarantee — though the metadata/data confidentiality of a
  *keyed* hidden file is unaffected. Use armor on hidden files only when transport
  encoding is worth more than "looks random."

---

## 13. Compatibility & deprecation policy

- A released version **MUST** decrypt every `format_version` it (or any prior
  release) ever wrote. Decryption support is **append-only**. Supported on-disk
  range: `MIN_FORMAT_VERSION = 3` … `MAX_FORMAT_VERSION = 13` (src: verify.py:46-47).
- **Encryption** defaults track the newest version; older versions MAY be retired
  for *writing*.
- **1.5.0 removed the following entirely (encrypt *and* decrypt)**
  (src: VERSION.md:26-45; `DEPRECATED_ALGORITHMS` now empty,
  algorithm_warnings.py:120-124):
  - **Algorithms:** AES-OCB3, Camellia, Whirlpool (hash), PBKDF2 (KDF), the legacy
    **Kyber** algorithm names, and the **TESTDATA PQC simulation** format.
  - **Subsystems:** steganography (numpy dropped), the D-Bus service/client, the
    in-package security/KAT testing framework, and advisory config tooling.
  Files using any removed algorithm — or hidden/steganographic data — are
  **explicitly out of the 1.5.x decryptor's scope** and **must be migrated with
  1.4.x before upgrading** (decrypt + re-encrypt with a supported algorithm such
  as AES-GCM or an ML-KEM-768 hybrid). This is the one sanctioned exception to the
  append-only rule and is called out in the release notes.
- Earlier deprecations: AES-OCB3 blocked for new encryption in v1.0.1/1.0.2;
  PBKDF2 + Whirlpool deprecated in v1.2.0 (src: VERSION.md).

---

## 14. Algorithm identifier registry

Identifiers as they appear on disk. Aliases are accepted on input; the
**canonical** id (first column) is what SHOULD be written
(src: cipher_registry.py, kem_registry.py, signature_registry.py).

### 14.1 Symmetric ciphers / bulk AEAD

| Canonical id           | Aliases                                   | key/nonce/tag | Notes        |
|------------------------|-------------------------------------------|:-------------:|--------------|
| `aes-256-gcm`          | `aes-gcm`, `aes256-gcm`, `aesgcm`         | 32/12/16      | AEAD         |
| `aes-256-gcm-siv`      | `aes-gcm-siv`, `aesgcmsiv`                | 32/12/16      | nonce-misuse |
| `aes-256-siv`          | `aes-siv`, `aessiv`                       | 64/0/16       | deterministic (nonce stored unused) |
| `chacha20-poly1305`    | `chacha20`, `chacha20poly1305`            | 32/12/16      | AEAD         |
| `xchacha20-poly1305`   | `xchacha20`, `xchacha20poly1305`          | 32/24/16      | 192-bit nonce (§8.3) |
| `threefish-512`        | `tf512`, `threefish512`                   | 64/32/16      | Threefish-512-CTR + Poly1305 (native ext) |
| `threefish-1024`       | `tf1024`, `threefish1024`                 | 128/64/16     | Threefish-1024-CTR + Poly1305 (native ext) |

**Threefish AEAD** = Threefish-*n*-CTR for confidentiality with Poly1305 for
integrity (an encrypt-then-MAC-style AEAD), implemented in the optional
`threefish_native` C extension; decrypt raises on `"Authentication failed"`
(src: cipher_registry.py:787-1096). **Removed in 1.5.0** (decrypt-only via 1.4.x):
AES-OCB3, Camellia, Fernet's role as a default; the registry docstring mentioning
OCB3/Camellia is stale — neither is registered.

### 14.2 KEMs and signatures (shipped in 1.5.0)

Canonical → liboqs identifier (src: kem_registry.py:540-549,
signature_registry.py:991-1016):

| KEMs (→ liboqs)              | Signatures (→ liboqs)                                              |
|-----------------------------|-------------------------------------------------------------------|
| `ml-kem-512` → ML-KEM-512   | `ml-dsa-44/65/87` → ML-DSA-44/65/87                               |
| `ml-kem-768` → ML-KEM-768   | `slh-dsa-sha2-128f/192f/256f` → SPHINCS+-SHA2-128f/192f/256f-simple|
| `ml-kem-1024` → ML-KEM-1024 | `fn-dsa-512/1024` → Falcon-512/1024                               |
| `hqc-128` → HQC-128         | `mayo-1/3/5` → MAYO-1/3/5                                          |
| `hqc-192` → HQC-192         | `cross-128/192/256` → cross-rsdp-{128,192,256}-balanced           |
| `hqc-256` → HQC-256         | classical Ed25519 / RSA used only as pepper/identity components    |

Legacy-only (in the `PQAlgorithm` enum but **not registered** → not shipped):
Kyber-512/768/1024, MAYO-2. Dilithium/Falcon/SPHINCS+ names are accepted as
aliases that normalize to the ML-DSA/FN-DSA/SLH-DSA canonical ids
(src: pqc.py:106-139).

### 14.3 KDFs

`argon2` (Argon2id), `balloon`, `scrypt`, `hkdf`, `randomx` (CPU-bound PoW,
enabled in STANDARD; treat as defense-in-depth — §5.2). PBKDF2 removed in 1.5.0.

### 14.4 Hash functions

`sha256, sha384, sha512, sha3_224, sha3_256, sha3_384, sha3_512, blake2b, blake2s,
blake3, shake128, shake256` (src: crypt_core.py:4248-4262). Whirlpool removed in 1.5.0.

---

## 15. Format-version history (normative)

`MIN_FORMAT_VERSION = 3`, `MAX_FORMAT_VERSION = 13` (src: verify.py:46-47). There
is **no v0/v1/v2 on disk**. Per-version JSON schemas live in
`openssl_encrypt/schemas/metadata_v{3..12}_schema.json`.

| Version | Introduced in     | Summary                                                              | Decrypt notes |
|:-------:|:------------------|:--------------------------------------------------------------------|:--------------|
| 0–2     | — (not on disk)   | code sentinels only; never written                                  | n/a |
| 3       | early (≤ 0.7.0)   | **flat** metadata structure                                         | reference impl only |
| 4       | 0.7.2             | **nested** `derivation_config`/`hashes`/`encryption` (converters v3↔v4) | §5.4 |
| 5       | 0.8.1             | adds `encryption.encryption_data` (converters v4↔v5)                | §5.4 |
| 6       | pre-1.4.0 (unpinned) | adds formal **HSM validation** fields (`create_metadata_v6`)       | §7.5 |
| 7       | 1.3.4             | adds **PQC signatures** (asymmetric mode); first under secure chained-salt (§7.2) | §7.2, §10 |
| 8       | 1.4.0-alpha       | adds **cascade** encryption; also uses **sequential XOR** (`==8`); decrypts as secure (≡ v10) | §7.3, §7.2 |
| 9       | 1.4.0b8           | **secure chained-salt derivation** as the default (ADVISORY 2026-01) | §7.2 |
| 10      | 1.4.x             | **sequential XOR** composition of stage outputs                     | §7.3 — order-sensitive |
| 11      | 1.4.0b10          | **Independent XOR** key derivation (robust XOR-combiner)            | §7.3 |
| 12      | 1.4.x             | **streaming chunked** AEAD (per-chunk HKDF nonces, trailer HMAC); `OESC` magic; current default | §8.4 |
| 13      | 1.4.x / 1.5.x     | **Corrected XOR derivation**; `xor_mode` selects the variant: **independent** (per-component domain-separated salts; default for `--independent-xor` / STANDARD / PARANOID / rekey) or **sequential** (last-stage cancellation fixed; `--xor`). Decrypt routes by `xor_mode`. metadata shape == v11; same number/meaning on both lines; v8/v10/v11 stay decrypt-only | §7.3 |

**One residual unknown:** the exact introducing tool-version of **v6** is not
pinned by any CHANGELOG line or git commit — the format exists in code
(`create_metadata_v6`, adding the HSM-validation fields) and predates the 1.4.0
alphas, but the precise version is undocumented. Everything else in this table is
code-/changelog-confirmed; `MIN_FORMAT_VERSION = 3`, `MAX_FORMAT_VERSION = 13`
(src: verify.py:46-47). The v8 salt question is settled in §7.2 (v8 ≡ v10, secure).

---

## 16. Test vectors (KAT corpus)

Golden corpus root: `openssl_encrypt/unittests/testfiles/`:

- `v5/`, `v7/`, `v12/` — golden encrypted files per format version (v12 holds the
  large cipher × hash × KDF matrix, `test_v12_<cipher>_<hash>=<rounds>_<kdf>=<rounds>.txt`).
- `xchacha_legacy/`, `xchacha_v2/` — XChaCha nonce-format-1 vs -2 cross-version vectors.
- `envelope_xchacha_v14/` — envelope + XChaCha 1.4.x cross-version fixtures.
- `recovery_slots/` — recovery-slot golden fixtures (`recovery_code.enc`,
  `passphrase.enc`, `shamir.enc`, `shamir_share_{1,2,3}.json`; fixed password `1234`).
- `openpgp/`, `openpgp_pubkey/` — OpenPGP interop fixtures.

Primitive KATs are hardcoded in tests (no standalone generators): XChaCha
(`test_xchacha_primitives.py`, draft-irtf-cfrg-xchacha-03 §2.2.1 + Appendix A.3),
age interop (`test_interop_age.py`, `test_interop_age_cli.py`), OpenPGP interop
(`test_interop_openpgp.py`), recovery-slot golden (`test_recovery_slots_golden.py`).
The former in-package KAT harness (`modules/testing/kat_tests.py`) was removed from
the 1.5.0 shipped surface (§13).

---

## 17. Security considerations

This section is **non-normative**; the threat model lives in
[SECURITY.md](../SECURITY.md). Highlights an implementer must respect:

- Treat the metadata as **attacker-controlled** until the AEAD tag (and, in
  envelope mode, the `dek_slots_mac`) verifies. Never act on header fields
  pre-authentication beyond what is needed to derive keys.
- The bulk AEAD provides integrity; `hashes.*` are **not** a substitute and
  SHOULD NOT be the sole integrity check (§5.3).
- Foreign-format parsers (age/OpenPGP) consume untrusted third-party files and
  are a distinct attack surface (fuzz/bound them); they are out of this spec.
- Plaintext **length is not hidden** by the standard container (size leaks).
  Optional padding is a future consideration.

---

## 18. Open questions / TODO index

Spec 0.3 verified every previously-flagged item against the code (see the cited
sections). The only residual unknown is the exact tool-version that introduced
format_version 6 (§15). Remaining before this leaves DRAFT: the full citation
review (last item below).

- [x] §2 integer endianness (mixed: hidden=BE, streaming framing=LE, streaming KDF inputs=BE)
- [x] §3/§4.1 standard-vs-hidden detection + payload nonce/tag framing
- [x] §4.2 hidden-header field lengths + outer AEAD (XChaCha20-Poly1305) + whitening
- [x] §5.2 per-KDF parameter schemas/defaults — ranges are backend-enforced only (Balloon caps verified; no app-level clamps)
- [x] §5.3 hashes are SHA-256; role clarified
- [x] §5.4 legacy metadata shapes (v3–v7) characterized
- [x] §6 **AAD canonicalization** — two paths; envelope also excludes `derivation_config`
- [x] §7.1 KDF pipeline order + normalization (`v10_xor_normalize`)
- [x] §7.2 chained-salt function — v8 reconciled (secure rule gated at `>= 7`; v8 ≡ v10)
- [x] §7.3 XOR composition (v8/v10 sequential, v11 independent)
- [x] §7.4 hidden-header outer-key derivation (keyless vs keyed chains)
- [x] §7.5 hardware-pepper mixing point + field names — pepper lengths verified (FIDO2 32 B; YubiKey/OnlyKey 20 B; PIV 32 B)
- [x] §8.2 cascade `layer_info` schema + per-layer keying/nonces
- [x] §8.3 legacy XChaCha nonce construction
- [x] §8.4 streaming chunk size/nonce/framing/anti-truncation
- [x] §9 recovery-slot schemas + slot-set MAC — gating verified (additive; no format_version gate; shamir split = product policy)
- [x] §10 recipient encryption is **ML-KEM-768-only** (no classical+PQC combiner) — verified (decrypt reads 512/768/1024)
- [x] §11 signature container + domain separation + signed bytes — single ML-DSA-65 confirmed; Ed25519 hybrid not implemented (array reserves room)
- [x] §12 armor labels + CRC-24 parameters
- [x] §13 write-retired / read-dropped lists (1.5.0)
- [x] §14 shipped-vs-legacy algorithm sets + liboqs names + Threefish mode
- [x] §15 version table (v3–v13) — complete; v6's introducing tool-version is the one residual unknown (see §15 note)
- [x] §16 corpus location + KAT index
- [ ] Independent code review of every `(src: …)` citation before declaring NORMATIVE
  (spec 0.3 verified the §5.2/§7.2/§7.5/§9/§10/§11/§15 citations against the 1.5.x tree)

---

## References

- [RFC 2119] / [RFC 8174] — requirement keywords
- [RFC 4648] — Base64
- [RFC 5869] — HKDF
- [RFC 4880] — OpenPGP (CRC-24 / armor lineage)
- draft-irtf-cfrg-xchacha-03 — XChaCha20-Poly1305
- FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA)
- Internal: [SECURITY.md](../SECURITY.md),
  [VERSION.md](../openssl_encrypt/docs/VERSION.md),
  [HIDDEN_HEADER.md](HIDDEN_HEADER.md), [RECOVERY_SLOTS.md](RECOVERY_SLOTS.md)
