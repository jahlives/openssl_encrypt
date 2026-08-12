# Plan: uniform JSON output (`--json`) across the CLI

Status: draft
Created: 2026-08-12

## Goal

Give (almost) every command machine-readable JSON output behind a `--json`
flag, in one envelope shape, so the desktop GUI and scripts consume structured
results instead of parsing human text ("total JSON", user decision 2026-08-12).
The capabilities manifest's curated `json_endpoints`/`json_fields` track each
addition, so the GUI's capability gating sees the JSON surface per CLI version.
Excluded by design: `config-wizard`, `install-dependencies` (interactive),
`test` (dev tool).

## Rules (apply to every step)

- One envelope for all NEW endpoints: `{"status": "ok"|"error", "data": {...}}`
  on success, `{"status": "error", "error": {"message": ...}}` on failure,
  emitted ONCE on stdout; progress/prompts/touch lines stay on stderr; exit
  codes unchanged. Existing endpoints keep their current shapes (no breakage).
- Flag standard is `--json`; commands that already use `--output-format json`
  (analyze-security, smart-recommendations, analyze-config on 1.4.x) keep it
  and additionally accept `--json` as an alias.
- Secrets are stdout-only (gitlab#193/#194 rule): a secret may appear in the
  stdout JSON document and nowhere else; nothing new is ever logged.
- JSON output stays raw/unsanitized (gitlab#183 rule): display safety is the
  consumer's decode-boundary job.
- Every endpoint lands with tests (TDD) and is registered in capabilities.py
  `_JSON_ENDPOINTS` + `_JSON_FIELDS` in the same commit.
- Each phase lands on 1.4.x first, then is ported to 1.5.x (whose command set
  is smaller; port only what exists there).

## Steps

- [x] P1: Shared envelope helper `emit_json(data)` / `emit_json_error(...)`
  used by all new endpoints (single stdout emission, envelope shape above).
  target: openssl_encrypt/modules/json_output.py
- [x] P2: Phase 1a (DONE 2026-08-12, 1.4.x 2ac6663a / 1.5.x 758cf917; security-info deferred to P3's batch) — version-and-catalog reporters gain `--json`:
  `version`, `show-version-file`, `list-algorithms`,
  `list-available-algorithms` (bare document frozen, registered as-is),
  `check-argon2`, `check-pqc`.
  target: openssl_encrypt/modules/crypt_cli.py (+ per-command handlers)
- [ ] P3: Phase 1b — file/config reporters gain `--json`: `info`,
  `analyze-config` (alias to existing --output-format), `template` (listing),
  `list-plugins`, `plugin-info`.
  target: openssl_encrypt/modules/crypt_cli.py
- [ ] P4: Phase 1c — verifiers gain `--json`: `verify-integrity`,
  `verify-signature`, `verify-usb`.
  target: openssl_encrypt/modules/crypt_cli.py
- [ ] P5: Phase 2 — operation result reports gain `--json`: `encrypt`,
  `decrypt`, `rekey`, `sign`, `armor`, `dearmor`, `shred`, `create-usb`,
  `derive-password`, `generate-password` (secret in stdout JSON only).
  target: openssl_encrypt/modules/crypt_cli.py
- [ ] P6: Phase 3 — grouped-command subcommands gain `--json` where output
  exists: `hsm`, `keyserver`, `plugin` (beyond the existing pepper/integrity
  JSON), remaining `identity` subcommands.
  target: openssl_encrypt/modules/crypt_cli.py, plugin CLI modules
- [ ] P7: Port each completed phase to feature/v1.5.x-development (P2-P6
  applied to the 1.5.x command set).
  target: 1.5.x line
- [ ] P8: Documentation: JSON usage section in the user guide; changelog files
  per phase (both lines).
  target: openssl_encrypt/docs/, CHANGELOG.md etc.

## Open questions

- `json_fields` granularity: pin full field lists per endpoint (better GUI
  gating, more curation) or only for endpoints the GUI actually consumes?
  Current approach: pin fields for every new endpoint as implemented.
- Phase 2 `decrypt --json` with stdout plaintext (no output file): the report
  and the plaintext both target stdout — decision: with `--json` and no `-o`,
  refuse (JSON mode requires an output path) rather than mixing streams.
