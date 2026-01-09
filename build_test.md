# GitLab CI Build and Test Investigation Summary

## Problem Statement
GitLab CI pipeline started failing yesterday with HQC algorithm compatibility issues and segmentation faults. Previously worked fine with Docker-based approach for months.

## Investigation Timeline

### Original Working Setup (2+ months)
- **Image**: `python-liboqs:3.13-alpine` (Alpine-based, 2 months old)
- **Status**: ✅ Worked perfectly, could decrypt HQC test files created on Fedora (glibc)
- **Key insight**: Alpine (musl) could successfully decrypt glibc-created files

### Yesterday's Problem
- Docker image started having **whirlpool dependency issues**
- Root cause: 2-month-old image with stale/incompatible dependency versions
- Image became incompatible with updated `requirements.txt`

### Today's Attempted Solutions

#### Approach 1: Switch to CI-based building
- **Image**: `python:3.11-slim` (Debian-based)
- **Method**: Build liboqs 0.12.0 from scratch in CI
- **Results**:
  - HQC round-trip tests failed with "Can not decapsulate secret"
  - HQC-256 tests segfaulted: `Fatal Python error: Segmentation fault` in `oqs.py:337 __repr__`
  - 22+ test failures consistently

#### Approach 2: Split CI jobs for efficiency
- **Architecture**: Separate `build-liboqs` and `test` jobs
- **Benefit**: Avoid "rebuild hell" - cache liboqs build for faster iterations
- **Status**: Successfully implemented but tests still failing

## Key Findings

### Environment Compatibility
- ✅ **Alpine (musl) CAN decrypt Fedora (glibc) created files** - proven by months of working pipeline
- ❌ **glibc vs musl theory disproven** - the compatibility issue is elsewhere
- 🤔 **Same liboqs version (0.12.0)** behaves differently in different build environments

### Segmentation Fault Analysis
- **Location**: `/root/.local/lib/python3.11/site-packages/oqs/oqs.py:337 in __repr__`
- **Context**: During HQC-256 chacha test execution
- **Symptoms**: Memory corruption, not authentication/decryption error
- **Implication**: Suggests build environment or library linking issues

### Docker vs CI Differences
Both use **same base environments**:
- Docker: `python:3.11-slim` (Debian) + liboqs 0.12.0 ✅ (was working)
- CI: `python:3.11-slim` (Debian) + liboqs 0.12.0 ❌ (segfaults)

**Real difference**: Controlled Docker build vs dynamic CI environment

## Current Test Status
- **Active**: Testing original Alpine image (`python-liboqs:3.13-alpine`) to determine:
  1. Does old Alpine image still work?
  2. Are the whirlpool issues resolved?
  3. Is the problem with our new build process?

## Next Steps
1. **Analyze Alpine test results** - Will determine if issue is:
   - Stale dependencies in Docker image
   - Our Debian-based build process
   - Something else entirely

2. **If Alpine works**: Problem is with our Debian build - investigate liboqs compilation flags, library versions, or build sequence

3. **If Alpine fails with whirlpool**: Rebuild Docker image with current dependencies

4. **If Alpine fails with HQC segfaults**: Deeper investigation needed - possible liboqs upstream changes or memory management issues

## Architecture Implemented
- ✅ **Split CI jobs**: `build-liboqs` → `test` dependency chain
- ✅ **Efficient caching**: Avoid rebuilding liboqs on every test failure
- ✅ **A/B testing capability**: Easy to switch between Alpine and Debian approaches

## Files Modified
- `.gitlab-ci.yml`: Complete CI pipeline restructure
- `docker/Dockerfile`: Updated to Debian base (but not rebuilt/pushed)

---
*Generated during investigation session on 2025-09-05*
