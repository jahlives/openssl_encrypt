# Pre-staged design — plugin trust-boundary fix (follow-up H2 [PLUGIN-1] + M1 [PLUGIN-2])

**Status: LARGELY IMPLEMENTED.** M1 (read-once) and H2 (signed per-package manifest §3
Approach B + CLI package-mode signing §5) are done, crypto-reviewer-approved, and
tested — see `docs/SECURITY_REVIEW_FOLLOWUP_2026-07-07.md` for commit refs. **Remaining
follow-on: the runtime import hook (§3.1)** — re-verify sibling modules at import time to
close the validation→import TOCTOU sibling-swap window (currently bounded by the H8
owner-only-writable check). Re-signing shipped built-in packages (§5) is unnecessary while
built-in packages use the trust shortcut. Line refs verified against
`feature/v1.5.x-development` (2026-07-07); re-verify before further work.

## The findings
- **H2 [PLUGIN-1]** — package plugins: only `__init__.py` is signature/AST/hash-verified;
  sibling modules it imports (`from .helper import ...`) execute unverified. All shipped
  token/keyserver/telemetry/pepper/stego plugins are packages.
- **M1 [PLUGIN-2]** — the signature is verified over a *different read* than the
  AST-scanned/executed bytes (verify-A / execute-B).

## Verified current flow (the M1 defect is FOUR reads, three byte sources)
`discover_plugins` (`plugin_manager.py:136-167`; packages register only `subdir/__init__.py`
at `156-161`) → `load_plugin` (`169-339`) → `_validate_plugin_file` (`970-1115`) →
`_check_signature_policy` (`880-968`) → AST + hash-pin → back in `load_plugin`: TOCTOU
re-hash (`235-247`) → `exec_module` (`250`).

Four independent reads of the same file:
1. **Signature bytes** — `_check_signature_policy:910-911` `open(path,"rb")` → `verify_plugin_signature` (`916`). *What the anchor vouches for.*
2. **AST bytes** — `_validate_plugin_file:1034-1035` text-mode `open(...,encoding="utf-8")` (universal-newline translation) → `.encode("utf-8")` hash pinned (`1040-1042`). *What the denylist scanned.*
3. **TOCTOU re-hash** — `load_plugin:242-243` another text read+encode, compared only to #2.
4. **Execution** — `exec_module:250`: `SourceFileLoader` does its own raw read and may load a cached **`.pyc`**. *What actually runs.*

Nothing binds 1≡2≡4. Exploitable discrepancies: CRLF/BOM/encoding-cookie (raw signed bytes
≠ newline-translated AST/hash bytes), and `.pyc` shadowing (#4 runs bytecode never covered
by #1-#3). Signature format is one detached PGP `.asc` per single file — no manifest/tree
concept (hence H2). Note: shipped plugins live under `builtin_plugin_root`, whose shortcut
(`1012-1017`) skips signature+AST — so H2/M1 bite hardest for **third-party package plugins**
and the ENFORCE story; the mechanism must be fixed regardless of the built-in shortcut.

## M1 fix — read once; verify/scan/pin/execute the SAME buffer
Add `_read_and_gate(file_path) -> (bytes, digest)` owning the single read:
1. `raw = open(realpath, "rb").read()` (binary, once; realpath so symlink target is what we read/hash/exec). Size cap moves here.
2. Signature gate: refactor `_check_signature_policy(realpath, raw)` to **take the bytes** (delete its own `open`) → `verify_plugin_signature(raw, ...)`.
3. AST scan **from raw**: `ast.parse(raw, filename=path)` (CPython handles encoding cookie/BOM, matching `compile`), or decode via `importlib.util.decode_source(raw)` — never text-mode `open` / `raw.decode("utf-8")`. Adjust `analyze_plugin_code` (`plugin_ast_analyzer.py:412`) to accept bytes/tree.
4. Hash pin `sha256(raw)` (raw bytes, not a re-encoded text read), keyed by realpath.

Execute from the verified buffer: in `load_plugin`, replace `242-247`+`250` with a TOCTOU
re-read (`raw_now = open(realpath,"rb").read()`, compare `sha256` to pin, refuse on mismatch),
`code = compile(raw_now, realpath, "exec")`, then **`exec(code, module.__dict__)`** instead of
`spec.loader.exec_module` — guarantees signed≡scanned≡executed and kills the `.pyc` shadow.
Keep `__package__`/`__path__` set so relative sibling imports resolve into the H2 hook.

## H2 fix — cover every file a package can execute (recommended: signed manifest)
**Approach B (recommended): one signed manifest per package.** Add `PLUGIN.manifest` in the
package dir listing `{relative_path: sha256}` for **every** file allowed to load — all `*.py`
recursively (including `_`-prefixed and nested subpackages) + optional resource files — and a
single `PLUGIN.manifest.asc` over its canonical serialization.

Verification: resolve package root → verify manifest via the §M1 read-once gate (one GPG call,
one hardware-key touch) → enumerate the tree; every present `.py` must have a manifest entry
with a byte-exact `sha256` match; refuse any extra/unlisted `.py`, any missing listed file, or
any mismatch; run the AST denylist over each verified buffer. Install a `sys.meta_path` finder
scoped to the package that refuses importing any module whose realpath is not in the verified
set (contains runtime `importlib.import_module` of dropped files → `plugin_blocked`
`unverified_dynamic_import`). Realpath-confine every entry to the package root (reject symlink
escapes, reusing the built-in symlink check pattern at `1013-1015`).

*Approach A (per-file `.asc` for every sibling)* was rejected: N signatures/touches per
package, misses non-`.py` resources, coverage emergent not declared.

Retain the single-file `.asc` path unchanged for standalone `*.py` plugins (backward-compat).
A package verifies iff its manifest verifies and the tree matches exactly; a lone file verifies
iff its `<file>.py.asc` verifies.

**Honesty caveat (state in docs):** the manifest guarantees "only vouched-for bytes are
imported," NOT "vouched-for bytes are benign" — `exec`/`eval`/`ctypes` inside verified bytes
remain the AST-denylist's and runtime-sandbox's job.

## Policy interaction (unchanged 3-state, extended to packages)
- **OFF**: no signature/manifest check; AST + read-once still apply (scanned≡executed even unsigned).
- **WARN (default)**: missing/invalid manifest or sibling mismatch → loud warning + `security_logger` event; never refuses.
- **ENFORCE**: non-built-in package requires a verified manifest with an exact tree match; any
  missing/extra/mismatched/underscore/dynamic-unverified file → refuse. Non-built-in single file
  requires its `.asc` (unchanged). This is where "signed `__init__.py` + tampered sibling" fails.
- **Built-in** (`builtin_plugin_root` shortcut `1012-1017`): keep the writable-location gate;
  recommend shipping signed manifests for built-ins and degrading the shortcut to
  "verify-manifest-if-present"; at minimum built-ins must also exec from the verified buffer
  (no `.pyc`). Trust-anchor fail-closed (`905-907`) + writable-location refusal now also apply to
  the manifest and every sibling.

## Migration
1. `plugin sign --package <dir>`: walk the tree, write canonical `PLUGIN.manifest`, sign →
   `PLUGIN.manifest.asc` with the project source-integrity key. Run for every shipped package
   (hsm/fido2_pepper, yubikey/onlykey/piv_card, pepper, keyserver, telemetry, integrity,
   steganography). Commit manifests + `.asc`; add to `MANIFEST.in`/packaging.
2. CLI (`plugin_signing_cli.py:39-84`, `plugin_cli.py:27-46`): `sign_plugin` gains package mode;
   add a read-only `plugin verify <path>` diagnostic (per-file status).
3. Legacy `<file>.py.asc` keeps working for single files; packages that had only
   `__init__.py.asc` must re-sign in package mode (document in signing plan / dev docs).
4. Docs: `docs/SOURCE_INTEGRITY.md` / signing plan — manifest format, canonicalization
   (sorted POSIX relative paths, LF, fixed grammar), "manifest signs the tree" model.

## Canonicalization (must be reproducible)
Sorted POSIX relative paths, normalized separators, LF, fixed JSON/`key=hex` grammar, so
signing and verifying serialize byte-identically. Round-trip: sign→verify passes;
whitespace-mangled manifest → verification fails (proves exact-byte coverage).

## Risks
Breaking legit packages (WARN default; ship built-in manifests before ENFORCE; `plugin verify`
diagnostic); performance (bounded by 1 MB/file cap + lazy hashing + one GPG call/manifest);
`.pyc` shadow (eliminated by exec-from-buffer — test it); symlink escape (realpath-confine);
canonicalization drift (round-trip test); dynamic imports (import hook contains imports, not
`exec` — documented); TOCTOU (re-hash now covers the executed buffer — test the window).

## TDD sequence (adversarial-first)
1. verify-A/execute-B impossible: CRLF+BOM file signed raw; executed behavior matches signed
   bytes; post-sign byte flip → refuse; assert pinned hash == sha256(raw signed bytes).
2. CRLF/BOM equivalence: `\r\n` file signs+loads under ENFORCE with no hash mismatch.
3. `.pyc` shadow: malicious `.pyc` beside a verified source → source runs, not the `.pyc`.
4. Signed `__init__.py` + tampered sibling: ENFORCE refuses, WARN warns, OFF loads.
5. Extra unlisted sibling → ENFORCE refuses.
6. Underscore sibling (`_helper.py`) imported by `__init__` → in manifest + hash-checked;
   tampering refused under ENFORCE despite discovery skipping `_` files.
7. Dynamic import of a runtime-dropped unverified module → import hook raises + `plugin_blocked`.
8. Symlink escape → refused.
9. Canonical round-trip: sign→verify passes; mangled manifest fails.
10. Backward-compat: legacy single-file `foo.py`+`foo.py.asc` still verifies (no manifest).
11. Shipped built-in packages load under ENFORCE with bundled manifests; a byte-flip in any
    shipped sibling is refused.
12. CLI: `plugin sign` package mode writes manifest+`.asc`; `plugin verify` reports per-file status.

## Critical files
- `plugin_system/plugin_manager.py` (discovery 136-167, load_plugin 169-339, TOCTOU 235-247,
  _check_signature_policy 880-968, _validate_plugin_file 970-1115, built-in shortcut 1012-1017)
- `plugin_system/plugin_signature.py` (verify_plugin_signature 233-290, signature_path_for
  198-200, TrustAnchorStore 89-159, SIGNATURE_SUFFIX 81)
- `plugin_system/plugin_signing_cli.py` (sign_plugin 39-84), `plugin_cli.py` (cmd_sign 27-46)
- `plugin_system/plugin_ast_analyzer.py` (analyze_plugin_code 412), `plugin_system/__init__.py:252-254`
- tests: `unittests/test_plugin_signing.py`, `unittests/test_plugin_cli.py`
