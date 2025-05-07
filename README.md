# Breaking Changes: release 0.7.0 is a BREAKING release, before updating to this release DECRYPT your already encrypted data with the EXACT version used for encrypting. Then update and encrypt again
[![Breaking Changes](https://img.shields.io/badge/WARNING-BREAKING%20CHANGES-red)](https://gitlab.rm-rf.ch/world/openssl_encrypt) The breaking change 0.7.0 was introduced because the final implementation of keystore required some bigger changes to the encryption/decryption logic which finally lead to the breaking changes in behaviour
# Version 0.7.1: Feature Complete Status
  With the release of version **0.7.1** openssl_encrypt is now really **considered feature complete**. No new features will be added to the codebase, which should **significantly reduce the likelihood of breaking changes**. Moving forward, our development efforts will focus
  exclusively on bug fixes, security updates, deployment enhancements, and documentation improvements. The latest added feature was necessary as handling PQC keys is cumbersome. Therefore a keystore to have the PQC keys saved to is important as an alternative to store they keys (encrypted) in metadata
# Secure File Encryption Tool
A powerful tool for securely encrypting, decrypting, and shredding files with military-grade cryptography and multi-layer password hashing.
## History
The project is historically named `openssl-encrypt` because it once was a python script wrapper around openssl. But that did not work anymore with recent python versions.
Therefore I decided to do a complete rewrite in pure python also using modern cipher and hashes. So the projectname is a "homage" to the root of all :-)

**Important note**: although `whirlpool` is supported by this tool, I do not recommend using this hashing algorithm. That is because building `whirlpool` via pip fails on recent Python versions (>= Python 3.12). If you want to use it you should have a look at [pyenv](https://github.com/pyenv/pyenv) which allows multiple Python versions to exist in peaceful co-existence. `whirlpool` will remain in the code also in future versions of this application \
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
- [docs/keystore_cli_guide.md](https://gitlab.rm-rf.ch/world/openssl_encrypt/-/tree/main/openssl_encrypt/docs/keystore_cli_guide.md) - Keystore CLI documentation
- [docs/DUAL_ENCRYPTION_TESTS.md](https://gitlab.rm-rf.ch/world/openssl_encrypt/-/tree/main/openssl_encrypt/docs/DUAL_ENCRYPTION_TESTS.md) - Dual encryption test details
- [docs/PQC_DUAL_ENCRYPTION.md](https://gitlab.rm-rf.ch/world/openssl_encrypt/-/tree/main/openssl_encrypt/docs/PQC_DUAL_ENCRYPTION.md) - PQC dual encryption documentation
- [unittests/unittests.py](https://gitlab.rm-rf.ch/world/openssl_encrypt/-/tree/main/openssl_encrypt/unittests/unittests.py) - Unit tests for the utility
- [unittests/test_gui.py](https://gitlab.rm-rf.ch/world/openssl_encrypt/-/tree/main/openssl_encrypt/unittests/test_gui.py) - Simple test for `tkinter`
- [unittests/testfiles](https://gitlab.rm-rf.ch/world/openssl_encrypt/-/tree/main/openssl_encrypt/unittests/testfiles) - Testfiles for `unittests` encryption
- [tests/](https://gitlab.rm-rf.ch/world/openssl_encrypt/-/tree/main/tests) - Contains all test modules for dual encryption and keystore functionality
- [requirements.txt](https://gitlab.rm-rf.ch/world/openssl_encrypt/-/tree/main/openssl_encrypt/requirements.txt) - Required Python packages
- [README.md](https://gitlab.rm-rf.ch/world/openssl_encrypt/-/tree/main/openssl_encrypt/README.md) - This documentation file

all testfile files are ecrypted with password `1234` for your testing
## License

[MIT License](LICENSE)

