# liboqs 0.12.0 → 0.16.0 Upgrade Plan

Status: **Planned** — waiting for liboqs 0.16.0 release.

Last reviewed: 2026-03-30

## Summary of liboqs Changes (0.13.0 → 0.16.0)

- **SPHINCS+ removed** in 0.16.0, replaced by SLH-DSA (NIST FIPS 205)
- **Dilithium removed** in 0.15.0, replaced by ML-DSA (already handled in our code)
- **HQC disabled by default** since 0.13.0 due to security flaws (secret-dependent branching, design flaw). May be re-enabled in 0.16.0 if fixes land.
- **SNOVA added** in 0.15.0 (NIST Additional Signatures Round 2). Still under attack analysis — wait before integrating.
- **ML-KEM updated** to mlkem-native v1.0.0 in 0.15.0

## Phase 1: Critical — SPHINCS+ → SLH-DSA Migration

The only code that will **break** is in `signature_registry.py` — 6 `oqs.Signature()` calls using legacy algorithm strings:

| File | Lines | Current | New (TBD) |
|---|---|---|---|
| `modules/registry/signature_registry.py` | 346, 359 | `SPHINCS+-SHA2-128f-simple` | `SLH-DSA-SHA2-128f` |
| `modules/registry/signature_registry.py` | 404, 417 | `SPHINCS+-SHA2-192f-simple` | `SLH-DSA-SHA2-192f` |
| `modules/registry/signature_registry.py` | 462, 475 | `SPHINCS+-SHA2-256f-simple` | `SLH-DSA-SHA2-256f` |

> **Note:** Exact liboqs 0.16.0 algorithm strings must be verified from their release notes before making changes.

**Backward compatibility:** Keep the mapping table in `pqc.py:158-159` so files signed with old SPHINCS+ names can still be verified. Also keep the deprecated enum values in `pqc.py:131-137`.

## Phase 2: Version Pin Updates (9 files)

| File | What to change |
|---|---|
| `setup.py:13-14` | `REQUIRED_LIBOQS_VERSION` / `_PYTHON_VERSION` |
| `openssl_encrypt/__init__.py:19-20` | Same constants |
| `openssl_encrypt/versions.py:5-6` | `LIBOQS_VERSION` / `LIBOQS_PYTHON_VERSION` |
| `scripts/build_local_deps.sh:7-8` | Default version vars |
| `scripts/build_local_deps.ps1:14,30-31` | PowerShell version vars |
| `docker/Dockerfile:27-28,44-45` | Git clone branch tags |
| `.gitlab-ci-docker.yml:11` | `LIBOQS_VERSION` variable |
| `docker/build-base-image.sh:12` | Version variable |
| `flatpak/com.opensslencrypt.OpenSSLEncrypt.json:73,143` | Archive URL, SHA256 hash, pip install tag |

## Phase 3: HQC Verification

HQC code is already fully implemented in:
- `modules/registry/kem_registry.py` (classes HQC128, HQC192, HQC256)
- `modules/pqc_adapter.py` (algorithm type mapping, security levels)
- `modules/pqc_liboqs.py` (enum definitions)

**If 0.16.0 re-enables HQC:**
- Verify algorithm strings (`HQC-128`, `HQC-192`, `HQC-256`) still match
- Run existing HQC tests in `unittests/registry/test_kem_registry.py`
- Update `README.md` to remove "HQC disabled" warnings

**If still disabled:** No changes needed.

## Phase 4: Optional — Add SNOVA Support

No SNOVA code exists yet. Would require:
- New enum entries in `pqc.py` and `pqc_liboqs.py`
- 3 new classes in `signature_registry.py`
- Adapter mappings in `pqc_adapter.py`
- Tests in `unittests/registry/test_signature_registry.py`

**Recommendation:** Wait until SNOVA survives NIST Round 2 evaluation before adding. SNOVA has been weakened by three attacks found during Round 1.

## Phase 5: Dilithium Cleanup (Optional)

Dilithium was removed in liboqs 0.15.0. Our code already maps Dilithium → ML-DSA (`pqc.py:153-155`). The deprecated enums and mappings must stay for backward compatibility with files signed using older versions. Check `pqc_signing.py` for any remaining direct `oqs.Signature("Dilithium*")` calls that would break.

## Phase 6: Documentation Updates

Files with version references that need updating:
- `docs/INSTALLATION.md` (~15 references to 0.12.0)
- `docs/cross-platform.md` (~7 references)
- `README.md`
- `CHANGELOG.md`
- `RELEASE_NOTES.md`
- `docker/Docker-README.md`

## Phase 7: Test & Validate

- [ ] Run full test suite against liboqs 0.16.0
- [ ] Validate SLH-DSA sign/verify round-trip with new algorithm strings
- [ ] Test backward compat: verify files signed with 0.12.0 SPHINCS+ can still be verified
- [ ] Test HQC if re-enabled
- [ ] Flatpak build test
- [ ] Docker build test
- [ ] Cross-platform build scripts test (Linux, Windows PowerShell)

## References

- [liboqs releases](https://github.com/open-quantum-safe/liboqs/releases)
- [liboqs 0.15.0 release notes](https://github.com/open-quantum-safe/liboqs/releases/tag/0.15.0)
- [HQC update issue #1319](https://github.com/open-quantum-safe/liboqs/issues/1319)
- [HQC design flaw advisory](https://github.com/open-quantum-safe/liboqs/security/advisories/GHSA-3rxw-4v8q-9gq5)
- [NIST PQC Additional Digital Signatures](https://csrc.nist.gov/projects/pqc-dig-sig)
