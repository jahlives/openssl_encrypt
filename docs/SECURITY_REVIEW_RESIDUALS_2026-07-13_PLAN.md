# Plan: Security review residuals 2026-07-13 (LOW-1, INFO-1, INFO-2)
Status: in progress (only P16 open)
Created: 2026-07-13

## Goal
Fix the three residual findings from the 2026-07-13 security review of
feature/v1.5.x-development: the `derive-password` CLI path leaves the HSM
pepper and derived-key copies unwiped in memory (LOW-1), the legacy
no-hash-iteration path builds an unwipeable password+salt+pepper concatenation
(INFO-1), and the independent-XOR Balloon fallback default (`space_cost=16`)
contradicts the memory-hard encrypt-time default of 65536 (INFO-2, also
present in parallel_kdf.py). All three are memory-hygiene / defense-in-depth
hardening; none is a user-facing vulnerability.

## Steps
- [x] P1: Three separate confidential GitLab issues created (one per finding)
      per issue-tracking skill; each fix commit references its issue.
  target: gitlab world/openssl_encrypt
- [x] P2: Baseline full test run recorded before any change (tdd-workflow).
  target: openssl_encrypt/unittests/
- [x] P3: Regression test exists asserting the derive-password handler
      zeroizes the HSM pepper buffer (fails against current code).
  target: openssl_encrypt/unittests/
- [x] P4: derive-password holds `hsm_pepper` in a `bytearray` and
      `secure_memzero`s it in a `finally` (mirror crypt_core.py:6380-6389).
  target: openssl_encrypt/modules/crypt_cli.py:4842
- [x] P5: derive-password wipes the wipeable derived-key copies (`derived`
      output buffer held as bytearray, wiped after output). The immutable
      `bytes` returned by generate_key (crypt_core.py:3929-3931, M10 design,
      common to all callers) is accepted as out of scope — decided 2026-07-13.
  target: openssl_encrypt/modules/crypt_cli.py:4881-4898
- [x] P6: Changelog files updated for LOW-1 and fix committed (one commit,
      references its P1 issue). No SECURITY.md advisory (pure hardening).
  target: CHANGELOG.md, version.py.template, metainfo.xml, changelog.html
- [x] P7: Regression test exists asserting the no-hash-iterations legacy path
      does not leave an unwiped password+salt+pepper concatenation, and that
      derived keys are byte-identical before/after the fix (golden values).
  target: openssl_encrypt/unittests/
- [x] P8: The `password + salt + hsm_pepper` seed at crypt_core.py:3058 is
      built in a wipeable `bytearray` and zeroized after key derivation,
      without changing derived key bytes.
  target: openssl_encrypt/modules/crypt_core.py:3057-3060
- [x] P9: Changelog files updated for INFO-1 and fix committed (one commit,
      references its P1 issue).
  target: CHANGELOG.md, version.py.template, metainfo.xml, changelog.html
- [x] P10: INFO-2 behavior decided (2026-07-13, user): version-gated
      fail-closed — format_version >= 14 with balloon enabled and
      `space_cost` absent refuses decryption; v11-13 keep the 16 fallback
      (load-bearing for pre-M3 v1.4.0-v1.4.3 files). Record rationale in the
      INFO-2 issue when created (P1).
  target: (decision)
- [x] P11: Tests exist covering (a) v14+ balloon config with `space_cost`
      absent is refused, (b) v11-13 config without `space_cost` still derives
      with 16 (existing test_balloon_defaults_m3.py legacy-compat test keeps
      passing).
  target: openssl_encrypt/unittests/
- [x] P12: `compute_kdf_independent` implements the version-gated fail-closed
      behavior from P10 (needs format_version available at that point —
      verify plumbing).
  target: openssl_encrypt/modules/crypt_core.py:2095
- [x] P13: Changelog files updated for INFO-2 and fix committed (one commit,
      references its P1 issue).
  target: CHANGELOG.md, version.py.template, metainfo.xml, changelog.html
- [x] P14: Full test suite green at the feature boundary
      (pytest -n auto --dist=worksteal openssl_encrypt/unittests/).
  target: openssl_encrypt/unittests/
- [x] P15: security-reviewer re-run confirms all three findings resolved with
      no new findings introduced.
  target: (review, no code)
- [ ] P16: feature/v1.4.x-development checked and fixes ported with the same
      test/commit discipline. Sites verified present on 1.4.x (2026-07-13):
      crypt_cli.py:6053, crypt_core.py:3564, crypt_core.py:2547,
      parallel_kdf.py:303.
  target: 1.4.x branch counterparts
- [x] P17: parallel_kdf needs no gate of its own — resolved by evidence
      (2026-07-13): generate_key_independent_xor_parallel delegates all
      format_version >= 13 dispatch to the sequential (gated) path
      (parallel_kdf.py:539-554), so the worker fallback is unreachable for
      v14+. Invariant pinned by
      test_balloon_v14_fail_closed.py::test_parallel_v14_delegates_to_sequential
      plus an explanatory comment at the fallback site.
  target: openssl_encrypt/modules/parallel_kdf.py:287

## Open questions
None — all resolved 2026-07-13:
- Balloon fallback (was: can legitimate files omit space_cost?): YES for
  v11 files from v1.4.0-v1.4.3 (pre-M3 a2935be1/deb4bc09, in v1.4.4);
  guarded by test_balloon_defaults_m3.py. v14 postdates M3 (spec 2026-07-07,
  stable 2026-07-10), so v14+ can fail closed safely. Decision: P10.
- Issue granularity: three separate confidential issues (user decision).
- generate_key return type: immutable `bytes` by design (crypt_core.py:3929,
  M10 — secure_memzero refuses immutable input). LOW-1 scoped to pepper +
  wipeable copies only; no return-type refactor (user decision).
- 1.4.x sites: confirmed present, see P16.
