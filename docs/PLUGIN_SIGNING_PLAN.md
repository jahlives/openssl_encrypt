# Signature-Gated Plugin Loading — Design Plan (#66 / CLI-3)

Target: **1.5.x first** (branch off `feature/v1.5.x-development`), then 1.4.x
backport. Resolves GitLab #66, the last actionable finding above LOW from
`sec-review::1.4.7`.

**Status: feature-complete on `feature/plugin-signing` (pending review + backport).**
Implemented and tested (`test_plugin_signing.py`, `test_plugin_cli.py`):
verifier + trust-anchor store, loader policy gate, operator helpers, the
`plugin sign|trust-key|list-keys` CLI command, and policy resolution via
`OPENSSL_ENCRYPT_PLUGIN_SIGNATURE_POLICY` in `create_default_plugin_manager`.
Operator docs added to `plugins/PLUGIN_DEVELOPMENT.md`. Default policy is OFF
(zero behavior change). Decisions D1–D3 taken "as proposed" (warn→enforce,
project key enabled by default, `.asc` sidecars).

Remaining: (a) enable the project-key anchor by default (D2) — currently only
enrolled/operator keys are anchors; (b) flip the default policy to WARN when
the maintainer approves the D1 timeline; (c) 1.4.x backport after soak.

## 1. Problem Statement

Plugin top-level code runs via `spec.loader.exec_module()` **in the main
process** (`plugin_system/plugin_manager.py`, `load_plugin`). Import-time code
executes with the full privileges of the process holding passwords, derived
keys, and plaintext. The execution-time sandbox (capabilities, import guard,
`_plugin_worker` subprocess, resource limits) engages only *after* top-level
code has already run.

Current gates before exec, in order:

1. **Insecure-location refusal (H8)** — group/world-writable file or ancestor
   directory → refused.
2. **Built-in containment** — plugins under the shipped package root
   (realpath-resolved) are trusted; covered by the source-integrity manifest.
3. **AST denylist** (`plugin_ast_analyzer.py`) — dangerous imports/calls/
   dunder-attribute escapes, strict mode by default.
4. **TOCTOU re-hash** — source hashed at validation, re-checked immediately
   before exec (restored on 1.5.x in commit 24b4ae7a).

Residual risk: an AST denylist over Python is a losing game (attribute
laundering, string assembly, indirection through allowed modules). The trust
decision must stop depending on "does this code look evil?" and become "did
someone trusted vouch for these exact bytes?".

## 2. Threat Model — what signing does and does not defend

| Attacker capability | Today (AST only) | Signed plugins (on-disk key) | Signed plugins (hardware-backed key) |
|---|---|---|---|
| **A. Can place/modify files as the user, cannot execute code** (malicious archive extraction, sync/share folders, "install this plugin" social engineering) | Blocked only if AST catches it | **Blocked** — cannot produce a signature | **Blocked** |
| **B. User voluntarily installs a malicious third-party plugin** | Blocked only if AST catches it | Forced explicit trust ceremony (sign/enroll); AST remains last automated line | Same, plus physical confirmation |
| **C. Arbitrary code execution as the user** | Defeated | **Defeated** (can use the on-disk key — but can also patch this package, so out of scope for any same-user software defense) | **Not defeated for signing**: key never on disk, touch/PIN required. (Attacker still owns the process at runtime — boundary honesty, see §7) |

Design consequence (maintainer-confirmed): **trust anchors must be
pluggable** — the mechanism is the same detached-signature check regardless of
where the key lives; the strength tier is the operator's choice.

## 3. Trust Anchors

Verification reuses `openssl_encrypt/integrity/gpg_runner.py:verify_detached()`
(throwaway GNUPGHOME, explicit key, expected-fingerprint check — no dependence
on the operator's keyring).

Anchor tiers, all optional and combinable:

1. **Project key** (`D269D6A5…`, the source-integrity production key):
   verifies officially distributed plugins. Shipped built-ins continue to be
   covered by containment + manifest and need no per-file signature.
2. **Enrolled author keys**: for third-party plugins, the *author* signs; the
   operator enrolls the author's public key once
   (`plugin trust-key <keyfile>` with mandatory fingerprint confirmation —
   TOFU-style, mirroring the identity store's pinning semantics).
3. **Operator's own key**: for self-written plugins.
   `plugin sign <file> [--key <id>]` wraps
   `gpg --detach-sign --armor`. Docs recommend a hardware-backed key
   (YubiKey/OnlyKey — already first-class citizens in this project) or at
   least a passphrase-protected key with gpg-agent.

Key store: `~/.openssl_encrypt/trusted_plugin_keys/*.asc`, created 0700 and
subject to the same insecure-location checks as plugin directories (H8 logic
reused). A key file that is group/world-writable is refused as an anchor.

## 4. Verification Flow (changes to `_validate_plugin_file` / `load_plugin`)

```
locate plugin file
├── insecure-location check (H8)            [unchanged]
├── built-in containment                    [unchanged — manifest covers these]
├── NEW: signature gate (policy-dependent, §5)
│     read plugin bytes B
│     read detached signature <plugin>.py.asc (same directory)
│     for each enabled trust anchor key K:
│         verify_detached(B, sig, public_key=K, expected_fingerprint=fp(K))
│     any good signature → proceed; none → refuse (or warn, per policy)
├── AST analysis                            [unchanged — defense in depth]
├── record SHA-256 of B                     [TOCTOU, existing]
└── exec_module only after re-hash matches  [TOCTOU, existing]
```

Ordering rationale: the signature is verified over **the same bytes** that are
hashed for the TOCTOU check, so "signed bytes = scanned bytes = executed
bytes" holds end-to-end. Packages (`__init__.py` discovery) sign every `.py`
file in the package directory — one detached sig per source file (simple,
uniform, no new manifest format; revisit only if package plugins proliferate).

## 5. Policy & Migration

New `PluginManager` policy knob `plugin_signature_policy`:

| Value | Behavior | Default in |
|---|---|---|
| `off` | current behavior (AST only) | — |
| `warn` | unsigned/unverifiable plugins load with a loud warning + security-log event | first release with the feature |
| `enforce` | unsigned/unverifiable plugins are refused | the following minor release |

CLI: `--plugin-signature-policy {off,warn,enforce}` plus config-file setting;
`enforce` is also implied by `--paranoid` if/when such a profile exists.
Per-plugin escape hatch stays the existing `allow_unsafe_plugin()` whitelist —
explicitly logged, never silent.

## 6. Component Breakdown

| # | Work item | Where |
|---|---|---|
| 1 | `plugin_signature.py`: anchor-store loading, key-file permission checks, `verify_plugin_signature(bytes, sig_path) -> Verdict` | `modules/plugin_system/` |
| 2 | Loader integration + policy knob + security-log events | `plugin_manager.py` |
| 3 | `plugin sign` / `plugin trust-key` / `plugin list-keys` CLI subcommands | `crypt_cli_subparser.py`, `crypt_cli.py` |
| 4 | Docs: this plan → operator guide section in `PLUGIN_DEVELOPMENT.md` + honest threat-model table (§2) | docs |
| 5 | Tests: signed/unsigned/tampered/wrong-key/revoked-anchor/downgrade (sig removed after enrollment), policy matrix, key-store permission attacks, cross-plugin smoke (HSM/FIDO2/stego/telemetry/keyserver) | `unittests/test_plugin_signing.py` |
| 6 | 1.4.x backport after 1.5.x soak | both branches |

Estimated size: comparable to the source-integrity feature (same primitives,
new wiring); the test matrix is the bulk.

## 7. Explicit Non-Goals / Honesty Notes (for the operator docs)

- Signing does **not** sandbox a signed plugin: a trusted-but-buggy plugin
  still runs with import-time full privileges. Signing changes *who can get
  code loaded*, not *what loaded code can do*.
- Against an attacker with code execution as the operator, no same-user
  mechanism in this package holds — including this one (with an on-disk key).
  A hardware-backed key protects the *signing capability*, not the running
  process.
- The AST scanner is retained as defense-in-depth, not as a trust decision.

## 8. Open Decision Points (maintainer input wanted)

- **D1**: default policy timeline (§5) — `warn` for one minor release, then
  `enforce`? Or keep `warn` as the permanent default and let hardened
  deployments opt into `enforce`?
- **D2**: should the project key anchor ship enabled (verifies future
  officially-distributed non-built-in plugins) or empty-by-default?
- **D3**: `.asc` sidecar naming vs. a per-directory `SIGNATURES` bundle —
  sidecars proposed (simpler, per-file TOCTOU parity).
