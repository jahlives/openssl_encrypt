# Version 1.0.0-rc1 - Improvments focusing on code quality, security, and developer experience
The **1.0.0-rc1** has recently undergone significant improvements focusing on code quality, security, and developer experience. We've implemented a **comprehensive multi-layered static code analysis system** with
  7 new GitLab CI jobs covering security scanning (Bandit, Semgrep), code quality analysis (Pylint, MyPy), and complexity metrics, plus 18+ pre-commit hooks for immediate feedback during development. A **legacy algorithm
   warning system** has been added to guide users away from deprecated cryptographic algorithms as we approach the 1.0.0 release. **Code formatting and consistency** improvements have been applied across the entire
  codebase using automated tools like Black and isort. The CI pipeline has been enhanced with **Docker improvements** and better job isolation to ensure reliable builds and testing. Finally, we've cleaned up the
  repository by **removing unnecessary development artifacts** like test files, backup configurations, and personal documentation files to maintain a clean production-ready codebase.



  Post-quantum cryptography support is now seamless - the application automatically adds necessary key storage flags when PQC algorithms are selected, enabling complete encrypt-to-decrypt workflows for ML-KEM and HQC
  hybrid algorithms without user intervention. The CLI gained environment variable password support (CRYPT_PASSWORD) with secure multi-pass clearing to prevent password exposure in process lists.

  Subprocess handling was improved with better buffering and error capture, ensuring password validation errors and other failures are properly displayed to users. A comprehensive test suite with 11 specialized tests was
   added to verify environment variable password handling, secure clearing functionality, and edge cases. These improvements transform the user experience from technical command-line complexity to professional-grade GUI
  usability while maintaining the strong security foundation and expanding post-quantum cryptography readiness.
# Secure File Encryption Tool
A powerful tool for securely encrypting, decrypting, and shredding files with military-grade cryptography and multi-layer password hashing.
## History
The project is historically named `openssl-encrypt` because it once was a python script wrapper around openssl. But that did not work anymore with recent python versions.
Therefore I decided to do a complete rewrite in pure python also using modern cipher and hashes. So the projectname is a "homage" to the root of all :-)

**Whirlpool support**: The `whirlpool` hash algorithm is now supported on all Python versions, including Python 3.11, 3.12, and 3.13. The package will automatically detect your Python version and install the appropriate Whirlpool implementation. If you encounter any issues with Whirlpool, please see the [Whirlpool Installation Guide](https://gitlab.rm-rf.ch/world/openssl_encrypt/-/tree/main/openssl_encrypt/docs/whirlpool_installation.md) for manual setup instructions.
## Issues
you can create issues by [sending mail](mailto:issue+world-openssl-encrypt-2-issue-+gitlab@rm-rf.ch) to the linked address

## Features
- **Strong Encryption**: Uses Fernet symmetric encryption (AES-128-CBC) as default with secure key derivation. Also supports `AES-GCM`, `AES-SIV`, `CAMLELIA`, `POLY1305-CHACHA20`, `AES-GCM-SIV`, `AES-OCB3` ans `XCHACHA20_POLY1305` as ecnryption algorithm
- **Multi-hash Password Protection**: Optional layered hashing with SHA-256, SHA-512, SHA3-256, SHA3-512, Whirlpool, BLAKE2b and SHAKE-256 they all can be chained with different rounds to create key-stretching
- **Multi-KDF Password Protection**: Optional layered KFD with PBKDF2, Scrypt, Argon2 and Ballon they all can be chained with different rounds to create key-stretching and very strong brute-force prevention
- **Postquantum Resistance**: Using a hybrid approach to implement postquantum resistance. Still using symetrical encryption but with a key derived with `Kyber KEM` for postquantum resistance
- **Keystore for PQC keys**: a local keystore can be used to maintain and manage the PQC keys used for encrypting your files
- **Password Management**: Password confirmation to prevent typos, random password generation, and standalone password generator
- **File Integrity Verification**: Built-in hash verification to detect corrupted or tampered files
- **Secure File Shredding**: Military-grade secure deletion with multi-pass overwriting
- **Directory Support**: Recursive processing of directories
- **Memory-Secure Processing**: Protection against memory-based attacks and data leakage
- **Glob Pattern Support**: Batch operations using wildcard patterns
- **Safe Overwriting**: Secure in-place file replacement with atomic operations
- **Progress Visualization**: Real-time progress bars for lengthy operations
- **Graphical User Interface**: User-friendly GUI for all operations (beta)
- **Built-in and custom Templates**: built in templates like `--quick` `--standard` and `--paranoid` can be used. You can also define your own customized templates in `./templates`
## Files Included
- [crypt.py](https://gitlab.rm-rf.ch/world/openssl_encrypt/-/tree/main/openssl_encrypt/crypt.py) - Main command-line utility
- [crypt_gui.py](https://gitlab.rm-rf.ch/world/openssl_encrypt/-/tree/main/openssl_encrypt/crypt_gui.py) - Graphical user interface
- [modules/crypt_cli.py](https://gitlab.rm-rf.ch/world/openssl_encrypt/-/tree/main/openssl_encrypt/modules/crypt_cli.py) - Command-line interface
- [modules/crypt_core.py](https://gitlab.rm-rf.ch/world/openssl_encrypt/-/tree/main/openssl_encrypt/modules/crypt_core.py) - Provides the core functionality
- [modules/crypt_utils.py](https://gitlab.rm-rf.ch/world/openssl_encrypt/-/tree/main/openssl_encrypt/modules/crypt_utils.py) - Provides utility functions
- [modules/crypt_errors.py](https://gitlab.rm-rf.ch/world/openssl_encrypt/-/tree/main/openssl_encrypt/modules/crypt_errors.py) - Custom exception classes
- [modules/crypt_settings.py](https://gitlab.rm-rf.ch/world/openssl_encrypt/-/tree/main/openssl_encrypt/modules/crypt_settings.py) - Configuration settings
- [modules/balloon.py](https://gitlab.rm-rf.ch/world/openssl_encrypt/-/tree/main/openssl_encrypt/modules/balloon.py) - Password hashing implementation
- [modules/secure_memory.py](https://gitlab.rm-rf.ch/world/openssl_encrypt/-/tree/main/openssl_encrypt/modules/secure_memory.py) - Provides functions for secure memory handling
- [modules/password_policy.py](https://gitlab.rm-rf.ch/world/openssl_encrypt/-/tree/main/openssl_encrypt/modules/password_policy.py) - Password validation
- [modules/pqc.py](https://gitlab.rm-rf.ch/world/openssl_encrypt/-/tree/main/openssl_encrypt/modules/pqc.py) - Post-quantum cryptography implementation
- [modules/keystore_cli.py](https://gitlab.rm-rf.ch/world/openssl_encrypt/-/tree/main/openssl_encrypt/modules/keystore_cli.py) - Keystore CLI functionality
- [modules/keystore_utils.py](https://gitlab.rm-rf.ch/world/openssl_encrypt/-/tree/main/openssl_encrypt/modules/keystore_utils.py) - Keystore utility functions
- [modules/keystore_wrapper.py](https://gitlab.rm-rf.ch/world/openssl_encrypt/-/tree/main/openssl_encrypt/modules/keystore_wrapper.py) - Keystore wrapper module
- [keystore_cli_main.py](https://gitlab.rm-rf.ch/world/openssl_encrypt/-/tree/main/openssl_encrypt/keystore_cli_main.py) - Keystore CLI entry point
- [docs/install.md](https://gitlab.rm-rf.ch/world/openssl_encrypt/-/tree/main/openssl_encrypt/docs/install.md) - Installation notes
- [docs/usage.md](https://gitlab.rm-rf.ch/world/openssl_encrypt/-/tree/main/openssl_encrypt/docs/usage.md) - Usage notes
- [docs/examples.md](https://gitlab.rm-rf.ch/world/openssl_encrypt/-/tree/main/openssl_encrypt/docs/examples.md) - Some examples
- [docs/pqc.md](https://gitlab.rm-rf.ch/world/openssl_encrypt/-/tree/main/openssl_encrypt/docs/pqc.md) - Post-quantum notes
- [docs/password-handling.md](https://gitlab.rm-rf.ch/world/openssl_encrypt/-/tree/main/openssl_encrypt/docs/password-handling.md) - Notes about password handling
- [docs/security-notes.md](https://gitlab.rm-rf.ch/world/openssl_encrypt/-/tree/main/openssl_encrypt/docs/security-notes.md) - Notes about security
- [docs/buffer_overflow_prevention.md](https://gitlab.rm-rf.ch/world/openssl_encrypt/-/tree/main/openssl_encrypt/docs/buffer_overflow_prevention.md) - Security implementation
- [docs/security_improvements.md](https://gitlab.rm-rf.ch/world/openssl_encrypt/-/tree/main/openssl_encrypt/docs/security_improvements.md) - Security enhancement details
- [docs/whirlpool_installation.md](https://gitlab.rm-rf.ch/world/openssl_encrypt/-/tree/main/openssl_encrypt/docs/whirlpool_installation.md) - Whirlpool installation guide
- [docs/keystore_cli_guide.md](https://gitlab.rm-rf.ch/world/openssl_encrypt/-/tree/main/openssl_encrypt/docs/keystore_cli_guide.md) - Keystore CLI documentation
- [docs/DUAL_ENCRYPTION_TESTS.md](https://gitlab.rm-rf.ch/world/openssl_encrypt/-/tree/main/openssl_encrypt/docs/DUAL_ENCRYPTION_TESTS.md) - Dual encryption test details
- [docs/PQC_DUAL_ENCRYPTION.md](https://gitlab.rm-rf.ch/world/openssl_encrypt/-/tree/main/openssl_encrypt/docs/PQC_DUAL_ENCRYPTION.md) - PQC dual encryption documentation
- [unittests/unittests.py](https://gitlab.rm-rf.ch/world/openssl_encrypt/-/tree/main/openssl_encrypt/unittests/unittests.py) - Unit tests for the utility
- [unittests/test_gui.py](https://gitlab.rm-rf.ch/world/openssl_encrypt/-/tree/main/openssl_encrypt/unittests/test_gui.py) - Simple test for `tkinter`
- [unittests/testfiles](https://gitlab.rm-rf.ch/world/openssl_encrypt/-/tree/main/openssl_encrypt/unittests/testfiles) - Testfiles for `unittests` encryption
- [tests/](https://gitlab.rm-rf.ch/world/openssl_encrypt/-/tree/main/tests) - Contains all test modules for dual encryption and keystore functionality
- [requirements.txt](https://gitlab.rm-rf.ch/world/openssl_encrypt/-/tree/main/openssl_encrypt/requirements.txt) - Required Python packages
- [README.md](https://gitlab.rm-rf.ch/world/openssl_encrypt/-/tree/main/openssl_encrypt/README.md) - This documentation file

all testfile files are encrypted with password `1234` for your testing
## License

[MIT License](LICENSE)
