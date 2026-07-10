# Plan — pointed error for 1.4.x PBKDF2-chain files (1.5.x)

**Status: PLANNED 2026-07-10. Not yet implemented.**

## Problem

1.5.0 removed the deprecated PBKDF2 stage from the sequential key-derivation
chain (documented breaking change: "decrypt such files with v1.4.x first").
A 1.4.x **sequential** file whose chain used `pbkdf2_iterations > 0` cannot
be derived on 1.5.x — but the failure surfaces as a generic AEAD
authentication error ("Security verification check failed"), indistinguishable
from a wrong password. Users have no way to know the real cause or the
migration path. Verified empirically during the v14 rollout (fixture corpus:
`v9_plain.enc` and `v13_sequential.enc` fail exactly this way, while
pbkdf2-free 1.4.x sequential files decrypt fine).

## Verified mechanics (1.5.x, commit b2e277b3 — line numbers drift)

- Decrypt builds the derivation config from metadata and **silently drops**
  the `pbkdf2` entry: the kdf merge loop copies only
  `["scrypt", "argon2", "balloon", "hkdf", "randomx"]`
  (`crypt_core.py:~9503-9509`; other hash_config build sites at ~4066
  asymmetric, ~8357 rekey, ~9600 legacy/streaming variants).
- The wrong key then fails AEAD authentication — fail-closed, never wrong
  plaintext (confirmed by the port crypto-review), but with a generic error.
- **Independent-XOR files are NOT affected**: 1.4.x's metadata builder writes
  `derivation_config.kdf_config.pbkdf2 = {"rounds": N}` whenever
  `pbkdf2_iterations > 0` even for independent files, but the independent
  path never consumed PBKDF2 — those files decrypt correctly on 1.5.x (the
  fixture corpus's v11/v13-independent/v14 fixtures carry the entry and
  pass). Detection must therefore be **scoped to sequential-routed files**.
- Sequential routing predicate on decrypt (`crypt_core.py:~9987+`):
  `xor_mode = metadata.get("xor_mode", "sequential")` and the file routes
  sequential when NOT
  (`xor_mode == "independent" or format_version in (11, 12) or >= 14`).
- Metadata shapes: v4+ `derivation_config.kdf_config.pbkdf2.rounds`
  (sometimes `iterations`); v3 flat `pbkdf2_iterations`. 1.5.x already has
  messaging precedent: `_append_pbkdf2_removed_comment`
  (`crypt_core.py:~8180`) emits the migration hint in `info` output.

## Design

One helper in `crypt_core.py`:

```python
def _check_removed_pbkdf2_chain(metadata: dict) -> None:
    """Raise a pointed DecryptionError for 1.4.x sequential files whose
    chain used the PBKDF2 stage removed in 1.5.0 (breaking change).

    Only sequential-routed files are affected: the independent-XOR path
    never consumed PBKDF2, so files carrying the metadata entry but routing
    independent decrypt fine and MUST NOT be refused.
    """
```

- Routing check first (same predicate as the decrypt dispatch): return
  early for independent-routed files.
- Extract rounds: v4+ `kdf_config.pbkdf2` (`rounds` or `iterations`),
  v3 flat `pbkdf2_iterations`; treat `> 0` as affected.
- Raise `DecryptionError` with a message naming the cause and the fix:

  > This file's key derivation includes N rounds of the PBKDF2 chain
  > stage, which was removed in v1.5.0 (see the 1.5.0 breaking-changes
  > note). openssl-encrypt 1.5.x cannot derive its key. Decrypt the file
  > with openssl-encrypt 1.4.x and re-encrypt it (the 1.4.8+ default
  > format does not use the PBKDF2 chain).

- Call sites: the main decrypt dispatch (before key generation, so the
  user never burns KDF time on a doomed derivation), the rekey decrypt
  half, and `_derive_envelope_kek`'s sequential route (a 1.4.x sequential
  envelope file has the same wrong-KEK failure). The asymmetric path
  (~4066) to be checked during implementation — likely covered via the
  main dispatch.
- No behavior change for any readable file: the check only fires where
  today's outcome is a guaranteed generic AEAD failure.

## TDD

1. Failing tests first (extend `test_format_fixture_corpus.py` or a new
   `test_pbkdf2_chain_error.py`):
   - `v9_plain.enc` and `v13_sequential.enc` now fail with
     `DecryptionError` whose message contains "PBKDF2" and "1.4" (replaces
     the generic `assertRaises(Exception)` pin).
   - Negative: all independent/streaming/PQC corpus fixtures (which carry
     the `pbkdf2` metadata entry) still decrypt — no false positives.
   - Negative: a pbkdf2-free v13-sequential file written by 1.5.x still
     round-trips.
   - Wrong password on a *readable* file still reports the normal
     authentication error (the new message must not mask wrong-password).
2. Implement the helper + call sites.
3. Changelog (`### Changed` or `### Fixed`, CHANGELOG.md; notable enough
   for the release files: brief "clear migration error for removed-PBKDF2
   files" line).
4. crypto-reviewer gate (error-oracle check: the message reveals only
   metadata-derived facts — the pbkdf2 rounds are already public in the
   cleartext metadata, so no new information leak; confirm no
   wrong-password oracle is introduced by raising BEFORE key derivation
   based on public metadata only).
5. Full suite; commit.

## Non-goals

- No PBKDF2 re-implementation or read-compat shim (the 1.5.0 removal is
  deliberate).
- No change on 1.4.x (it reads these files natively; nothing to do).
