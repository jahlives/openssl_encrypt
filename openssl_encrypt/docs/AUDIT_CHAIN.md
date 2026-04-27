# Tamper-Evident Audit Chain

Status: **opt-in (experimental)**, available since `feature/v1.5.x-development`.

## Why

The existing `security_logger` writes structured JSON-line events to disk.
Without a chain, an attacker with write access to the log can silently rewrite,
delete, or reorder past events — there is no integrity evidence.

The audit chain wraps every event in a forward-secure HMAC chain so that any
silent modification, deletion, reordering, or front-truncation becomes
detectable by an offline verifier. With an optional persisted state file, the
verifier can additionally detect *tail* truncation between the last flush and
the last record.

This is a prerequisite for the planned local-FIPS-140-2 / local-audit-log
work in [`FUTURE_FEATURES.md`](FUTURE_FEATURES.md).

## What is added to each record

In chained mode every JSON-line audit record carries three additional fields:

| Field       | Type      | Meaning                                              |
| ----------- | --------- | ---------------------------------------------------- |
| `seq`       | integer   | Sequence number, starts at 0, monotonically `+1`.    |
| `prev_hash` | string    | `blake2b-256:<hex>` of the prior record's canonical encoding (including its MAC). |
| `mac`       | string    | `hmac-sha256:<hex>` over the canonical encoding of the record minus `mac`. |

Existing fields (`timestamp`, `event_type`, `severity`, `pid`, `user`,
`details`) are unchanged. Adding the chain is **purely additive** — log
consumers that ignore unknown fields keep working.

## Cryptographic design

* **Genesis prev_hash**: `blake2b-256("ssle-audit-genesis-v1")`. Pinned in
  the test suite; bumping the suffix is a chain-format migration.
* **Forward-secure key evolution** (Schneier–Kelsey style):

      K_0      = HKDF-SHA256(seed, info=b"ssle-audit-mac-v1",   L=32)
      K_{n+1}  = HKDF-SHA256(K_n,  info=b"ssle-audit-evolve-v1", L=32)

  Record *n* is MACed with `K_n`. After writing record *n* the in-memory
  `K_n` is wiped via `secure_memzero` and only `K_{n+1}` is persisted. An
  attacker who reads the live key cannot forge any past record.
* **Record MAC**: HMAC-SHA256 over the canonical encoding of the record
  minus the `mac` field, keyed with `K_seq`.
* **Chain hash**: BLAKE2b-256 over the canonical encoding of the *full*
  prior record (including its MAC). Committing to the MAC means an attacker
  cannot swap MACs without breaking the next record's `prev_hash`.
* **Canonical encoding**: `json.dumps(..., sort_keys=True, ensure_ascii=False,
  separators=(",", ":")).encode("utf-8")`. Stable across Python versions;
  unit-tested against reference vectors.

## Threat model

| Defended                                                    | Not defended                                                       |
| ----------------------------------------------------------- | ------------------------------------------------------------------ |
| Retroactive modification of past records (chain + MAC break)| Compromise of the seed *before* it has evolved (root-of-trust)    |
| Silent deletion / reordering (seq + chain)                  | Real-world timestamp authenticity (no TSA — offline policy)        |
| Front-truncation (seq doesn't start at 0)                   | Total destruction of both log and state file                       |
| Tail-truncation between flushes (state-file mismatch)       |                                                                    |
| Forgery without the live MAC key                            |                                                                    |

The seed lives in `~/.openssl_encrypt/audit-seed.bin` (mode 0600). Future
work will move this into the PQC-protected keystore or an HSM-derived
secret; the env var `OPENSSL_ENCRYPT_AUDIT_SEED_FILE` overrides the path.

## Enabling the chain

Chain mode is **opt-in** for v1.5.x. Enable via either:

* environment variable:

      export OPENSSL_ENCRYPT_AUDIT_CHAIN=1

* constructor argument:

      from openssl_encrypt.modules.security_logger import SecurityAuditLogger
      logger = SecurityAuditLogger(chain_enabled=True)

On first activation against an existing unchained `security-audit.log`,
the old log is renamed to `security-audit.log.legacy` and a fresh chain
starts at `seq=0`. Old records cannot be retroactively chained (no MAC
to bind them).

## Files written

| Path                              | Mode   | Purpose                                          |
| --------------------------------- | ------ | ------------------------------------------------ |
| `~/.openssl_encrypt/security-audit.log`        | 0600   | JSONL audit records (chained when enabled).     |
| `~/.openssl_encrypt/audit-seed.bin`            | 0600   | 32-byte seed; root of forward-secure key chain. |
| `~/.openssl_encrypt/audit-state.json`          | 0600   | `{current_seq, current_key_b64, last_record_hash, ...}` — persisted atomically (tempfile + `os.replace` + dir fsync). |
| `~/.openssl_encrypt/security-audit.log.legacy` | inherits | Archived pre-chain log (created on first activation if a legacy log exists). |

## CLI

A standalone CLI is available immediately:

    python -m openssl_encrypt.modules.audit_cli verify [--log PATH] [--seed PATH]
                                                       [--state PATH] [--json]
    python -m openssl_encrypt.modules.audit_cli status [--log-dir PATH] [--json]

`verify` exit codes:

| Code | Meaning                                       |
| ---- | --------------------------------------------- |
| 0    | Chain intact.                                 |
| 1    | I/O error (log unreadable).                   |
| 2    | Chain broken (tamper, gap, MAC mismatch).     |
| 3    | Required key material missing (seed/state).   |

A future commit will fold `audit verify` and `audit status` into the main
`openssl_encrypt` argparse tree.

## `clear_logs()` in chained mode

In chained mode `clear_logs()` raises `PermissionError` unless invoked with
`break_glass=True`. The break-glass clear:

1. Removes the live log and any rotated logs.
2. Wipes the seed file and the state file.
3. Re-initializes the chain so the next event starts a fresh chain at
   `seq=0` with a freshly generated seed.

Use sparingly. Forensic continuity ends at the break-glass point.

## What's deferred

* **Periodic Merkle anchors signed with ML-DSA-65** — provides non-repudiation
  per window of records. Tracked as a v1.5.1 follow-up. The hash chain alone
  already detects every tampering threat in the table above; anchors add
  cryptographic non-repudiation against future seed compromise.
* **Keystore-backed seed** — replace the `audit-seed.bin` file with a PQC-
  protected entry in the existing keystore (`audit/chain-seed/v1`).
* **HSM-derived seed** — derive the seed from a FIDO2 hmac-secret credential
  so that the seed never lives at rest as cleartext.
* **Integration with `openssl_encrypt audit ...`** — move the standalone CLI
  into the main subparser tree.

## See also

* `openssl_encrypt/modules/audit_chain.py` — chain primitives.
* `openssl_encrypt/modules/audit_verifier.py` — offline verifier.
* `openssl_encrypt/modules/audit_cli.py` — standalone CLI.
* `openssl_encrypt/modules/security_logger.py` — integration point.
* `openssl_encrypt/unittests/test_audit_chain.py`, `test_audit_verifier.py`,
  `test_security_logger_chained.py`, `test_audit_cli.py` — TDD test suite.
