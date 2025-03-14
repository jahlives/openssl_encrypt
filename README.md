# Secure File Encryption Tool

A powerful tool for securely encrypting, decrypting, and shredding files with military-grade cryptography and multi-layer password hashing.

## History

The project is historically named `openssl-encrypt` because it once was a python script wrapper around openssl. But that did not work anymore with recent python versions.
Therefore I decided to do a complete rewrite in pure python also using modern cipher and hashes. So the projectname is a "homage" to the root of all :-)

## Features

- **Strong Encryption**: Uses Fernet symmetric encryption (AES-128-CBC) with secure key derivation \
  Because of this "restriction" in Fernet
  ```
  Fernet is designed so that it doesn’t expose unauthenticated bytes. 
  Because of this, the entire message contents must be able to fit in the available memory. 
  This makes Fernet unsuitable for encrypting very large files.
  ```
  therefore "AES-GCM" and "ChaCha20" are now available in the final [final candidate](https://gitlab.rm-rf.ch/world/openssl_encrypt/-/tree/v1.0)
- **Multi-hash Password Protection**: Optional layered hashing with SHA-256, SHA-512, SHA3-256, SHA3-512, Whirlpool, Scrypt and Argon2
- **Password Management**: Password confirmation to prevent typos, random password generation, and standalone password generator
- **File Integrity Verification**: Built-in hash verification to detect corrupted or tampered files
- **Secure File Shredding**: Military-grade secure deletion with multi-pass overwriting
- **Directory Support**: Recursive processing of directories
- **Memory-Secure Processing**: Protection against memory-based attacks and data leakage
- **Argon2 Support**: Memory-hard key derivation function that won the Password Hashing Competition
- **Glob Pattern Support**: Batch operations using wildcard patterns
- **Safe Overwriting**: Secure in-place file replacement with atomic operations
- **Progress Visualization**: Real-time progress bars for lengthy operations
- **Graphical User Interface**: User-friendly GUI for all operations

## Files Included

- [crypt.py](crypt.py) - Main command-line utility
- [crypt_gui.py](crypt_gui.py) - Graphical user interface
- [modules/crypt.cli.py](modules/crypt.cli.py) - command-line interface
- [modules/crypt_core.py](modules/crypt_core.py) - provides the core functionality
- [modules/crypt_utils.py](modules/crypt_utils.py) - provides utility functions
- [modules/secure_memory.py](modules/secure_memory.py) - provides functions for secure memory handling
- [requirements.txt](requirements.txt) - Required Python packages
- [README.md](README.md) - This documentation file
- [docs/install.md](docs/install.md) - installation notes
- [docs/usage.md](docs/usage.md) - usage notes
- [docs/examples.md](docs/examples.md) - some examples
- [docs/password-handling.md](docs/password-handling.md) - notes about password handling
- [docs/security-notes.md](docs/security-notes.md) - notes about security
- [tests/unittests.py](tests/unittests.py) - Unit tests for the utility
- [tests/test_gui.py](tests/test_gui.py) - simple test for `tkinter`

## License

[MIT License](LICENSE)

