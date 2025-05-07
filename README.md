# Breaking Changes: release 0.7.0 is a BREAKING release, before updating to this release DECRYPT your already encrypted data with the EXACT version used for encrypting. Then update and encrypt again
[![Breaking Changes](https://img.shields.io/badge/WARNING-BREAKING%20CHANGES-red)](https://gitlab.rm-rf.ch/world/openssl_encrypt) The breaking change 0.7.0 was introduced because the final implementation of keystore required some bigger changes to the encryption/decryption logic which finally lead to the breaking changes in behaviour
# Version 0.7.0: Feature Complete Status
  With the release of version **0.7.0rc1**, openssl_encrypt is now really **considered feature complete**. No new features will be added to the codebase, which should **significantly reduce the likelihood of breaking changes**. Moving forward, our development efforts will focus
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
- [modules/crypt.cli.py](https://gitlab.rm-rf.ch/world/openssl_encrypt/-/tree/main/openssl_encrypt/modules/crypt.cli.py) - command-line interface
- [modules/crypt_core.py](https://gitlab.rm-rf.ch/world/openssl_encrypt/-/tree/main/openssl_encrypt/modules/crypt_core.py) - provides the core functionality
- [modules/crypt_utils.py](https://gitlab.rm-rf.ch/world/openssl_encrypt/-/tree/main/openssl_encrypt/modules/crypt_utils.py) - provides utility functions
- [modules/secure_memory.py](https://gitlab.rm-rf.ch/world/openssl_encrypt/-/tree/main/openssl_encrypt/modules/secure_memory.py) - provides functions for secure memory handling
- [requirements.txt](https://gitlab.rm-rf.ch/world/openssl_encrypt/-/tree/main/openssl_encrypt/requirements.txt) - Required Python packages
- [README.md](https://gitlab.rm-rf.ch/world/openssl_encrypt/-/tree/main/openssl_encrypt/README.md) - This documentation file
- [docs/install.md](https://gitlab.rm-rf.ch/world/openssl_encrypt/-/tree/main/openssl_encrypt/docs/install.md) - installation notes
- [docs/usage.md](https://gitlab.rm-rf.ch/world/openssl_encrypt/-/tree/main/openssl_encrypt/docs/usage.md) - usage notes
- [docs/examples.md](https://gitlab.rm-rf.ch/world/openssl_encrypt/-/tree/main/openssl_encrypt/docs/examples.md) - some examples
- [docs/pqc.md](https://gitlab.rm-rf.ch/world/openssl_encrypt/-/tree/main/openssl_encrypt/docs/pqc.md) - postquantum notes
- [docs/password-handling.md](https://gitlab.rm-rf.ch/world/openssl_encrypt/-/tree/main/openssl_encrypt/docs/password-handling.md) - notes about password handling
- [docs/security-notes.md](https://gitlab.rm-rf.ch/world/openssl_encrypt/-/tree/main/openssl_encrypt/docs/security-notes.md) - notes about security
- [unittests/unittests.py](https://gitlab.rm-rf.ch/world/openssl_encrypt/-/tree/main/openssl_encrypt/unittests/unittests.py) - Unit tests for the utility
- [unittests/test_gui.py](https://gitlab.rm-rf.ch/world/openssl_encrypt/-/tree/main/openssl_encrypt/unittests/test_gui.py) - simple test for `tkinter`
- [unittests/testfiles](https://gitlab.rm-rf.ch/world/openssl_encrypt/-/tree/main/openssl_encrypt/unittests/testfiles) - testfiles for `unittests` encryption

all testfile files are ecrypted with password `1234` for your testing
## License

[MIT License](LICENSE)

