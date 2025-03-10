# Secure File Encryption Tool

A powerful tool for securely encrypting, decrypting, and shredding files with military-grade cryptography and multi-layer password hashing.

## Features

- **Strong Encryption**: Uses Fernet symmetric encryption (AES-128-CBC) with secure key derivation
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

- `crypt.py` - Main command-line utility
- `crypt_gui.py` - Graphical user interface
- `modules/crypt.cli.py` - command-line interface
- `modules/crypt_core.py` - provides the core functionality
- `modules/crypt_utils.py` - provides utility functions
- `modules/secure_memory.py` - provides functions for secure memory handling
- `requirements.txt` - Required Python packages
- `README.md` - This documentation file
- `docs/install.md` - installation notes
- `docs/usage.md` - usage notes
- `docs/examples.md` - some examples
- `docs/password-handling.md` - notes about password handling
- `docs/security-notes.md` - notes about security
- `tests/unittests.py` - Unit tests for the utility
- `tests/test_gui.py` - simple test for `tkinter`

## License

[MIT License](LICENSE)

