# CI Testing Notes

## Cryptography Library Version Requirements

The test files in this project were created using cryptography library version 42.x. Due to breaking changes in newer versions of the cryptography library (particularly version 44.x and above), these test files may not be compatible with newer versions.

### Fixed Dependency Version

To ensure consistent and reliable testing across all environments, we have:

1. **Pinned the cryptography library version**:
   - Set version requirements to `cryptography>=42.0.0,<43.0.0` in:
     - requirements.txt
     - setup.py
   - Added explicit version pinning in CI configuration with `--force-reinstall`

2. **CI Pipeline Modifications**:
   - The GitLab CI pipeline has been configured to verify and use the correct version
   - Prints the cryptography version before running tests for verification

### Test Files

All test files in the repository were created with cryptography version 42.x. This approach ensures that all encryption algorithms are thoroughly tested in both development and CI environments.

### Compatibility Notes

Compatibility issues with cryptography versions:
- Version 44.0.0+ introduces breaking changes in AEAD implementations
- Changes affect how authentication tags are handled
- Test files encrypted with older versions may fail integrity checks with newer library versions

### Future Improvements

For future work:
- Consider generating test files during the CI process itself
- Create a version compatibility layer for handling files across different cryptography versions
- Add tests to verify compatibility between versions