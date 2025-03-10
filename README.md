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

## Installation

### Requirements

- Python 3.6 or higher
- Dependencies: cryptography (required), pywhirlpool (optional), tkinter (for GUI)

### Setup

1. Clone or download this repository
2. Install required packages:

```bash
pip install -r requirements.txt
```

For Argon2 support:

```bash
pip install argon2-cffi
```

## Usage

The tool can be used either through the command line interface or the graphical user interface.

### GUI Interface

To start the graphical user interface:

```bash
python crypt_launcher.py
```

or directly:

```bash
python crypt_gui.py
```

The GUI provides a user-friendly interface with four main tabs:

1. **Encrypt**: Encrypt files with various options
   - Select input and output files
   - Enter and confirm password
   - Choose to shred original or overwrite in place
   - Select hash algorithm

2. **Decrypt**: Decrypt previously encrypted files
   - Select encrypted file and output location
   - Enter password
   - Options to display to screen, shred encrypted file, or overwrite

3. **Shred**: Securely delete files beyond recovery
   - Select files using path or glob patterns
   - Preview matched files before deletion
   - Configure overwrite passes and recursive options
   - Confirmation dialog to prevent accidental deletion

4. **Advanced**: Configure detailed security options
   - Set PBKDF2 iterations
   - Configure iterations for each hash algorithm
   - Adjust Scrypt parameters (cost factor, block size, parallelization)

### Command-Line Interface

```
python crypt.py ACTION [OPTIONS]
```

#### Actions:

- `encrypt`: Encrypt a file with a password
- `decrypt`: Decrypt a file with a password
- `shred`: Securely delete a file by overwriting its contents
- `generate-password`: Generate a secure random password

#### Common Options:

| Option | Description |
|--------|-------------|
| `-i`, `--input` | Input file or directory (required for encrypt/decrypt/shred, supports glob patterns for shred action) |
| `-o`, `--output` | Output file (optional for decrypt) |
| `-p`, `--password` | Password (will prompt if not provided) |
| `--random` | Generate a random password of specified length for encryption |
| `-q`, `--quiet` | Suppress all output except decrypted content and exit code |
| `--overwrite` | Overwrite the input file with the output |
| `-s`, `--shred` | Securely delete the original file after encryption/decryption |
| `--shred-passes` | Number of passes for secure deletion (default: 3) |
| `-r`, `--recursive` | Process directories recursively when shredding |
| `--disable-secure-memory` | Disable secure memory handling (not recommended) |
| `--argon2-time` | Argon2 time cost parameter (default: 0, not used) |

#### Password Generation Options:

| Option | Description |
|--------|-------------|
| `--length` | Length of generated password (default: 16) |
| `--use-digits` | Include digits in generated password |
| `--use-lowercase` | Include lowercase letters in generated password |
| `--use-uppercase` | Include uppercase letters in generated password |
| `--use-special` | Include special characters in generated password |

#### Hash Configuration Options:

| Option | Description |
|--------|-------------|
| `--sha256` | Number of SHA-256 iterations (default: 1,000,000 if flag provided without value) |
| `--sha512` | Number of SHA-512 iterations (default: 1,000,000 if flag provided without value) |
| `--sha3-256` | Number of SHA3-256 iterations (default: 1,000,000 if flag provided without value) |
| `--sha3-512` | Number of SHA3-512 iterations (default: 1,000,000 if flag provided without value) |
| `--whirlpool` | Number of Whirlpool iterations (default: 0, not used) |
| `--scrypt-cost` | Scrypt cost factor N as power of 2 (default: 0, not used) |
| `--scrypt-r` | Scrypt block size parameter r (default: 8) |
| `--scrypt-p` | Scrypt parallelization parameter p (default: 1) |
| `--pbkdf2` | Number of PBKDF2 iterations (default: 100,000) |
| `--argon2-time` | Argon2 time cost parameter (default: 0, not used) |
| `--argon2-memory` | Argon2 memory cost in KB (default: 102400 = 100MB) |
| `--argon2-parallelism` | Argon2 parallelism parameter (default: 8) | 
| `--argon2-type` | Argon2 variant to use: argon2i, argon2d, or argon2id (default: argon2id) |

## Command-Line Examples

### Basic Encryption/Decryption

```bash
# Encrypt a file (creates file.txt.encrypted)
python crypt.py encrypt -i file.txt

# Decrypt a file
python crypt.py decrypt -i file.txt.encrypted -o file.txt

# Decrypt and display contents to screen (for text files)
python crypt.py decrypt -i config.encrypted
```

### Password Features

```bash
# Generate a secure random password
python crypt.py generate-password

# Generate a custom password (20 chars, only lowercase and digits)
python crypt.py generate-password --length 20 --use-lowercase --use-digits

# Encrypt with a randomly generated password
python crypt.py encrypt -i secret.txt --random 16

# The tool will display the generated password for 10 seconds, giving you time to save it
```

### Enhanced Security Options

```bash
# Encrypt with multiple hashing algorithms
python crypt.py encrypt -i important.docx --sha512 --sha3-512 --pbkdf2 200000

# Use Scrypt for memory-hard password protection (cost factor 2^15)
python crypt.py encrypt -i secrets.txt --scrypt-cost 15

# Combine multiple hash functions for layered security
python crypt.py encrypt -i critical.pdf --sha512 --sha3-256 --scrypt-cost 14

# Use Argon2 for state-of-the-art password hashing
python crypt.py encrypt -i topsecret.zip --argon2-time 3

# Configure Argon2 for maximum security
python crypt.py encrypt -i classified.db --argon2-time 10 --argon2-memory 1048576 --argon2-parallelism 8

# Use Argon2i for side-channel attack resistance
python crypt.py encrypt -i sensitive_data.txt --argon2-time 4 --argon2-type argon2i

# Combine Argon2 with other hash functions for defense-in-depth
python crypt.py encrypt -i ultra_secret.dat --argon2-time 3 --sha3-512 --pbkdf2 200000
```

### Managing Files

```bash
# Encrypt and overwrite the original file (in-place encryption)
python crypt.py encrypt -i confidential.txt --overwrite

# Decrypt and overwrite the encrypted file
python crypt.py decrypt -i important.encrypted --overwrite

# Encrypt and securely shred the original file
python crypt.py encrypt -i secret.doc -s

# Decrypt and securely shred the encrypted file
python crypt.py decrypt -i backup.encrypted -o backup.tar -s
```

### Secure File Shredding

```bash
# Basic secure shredding
python crypt.py shred -i obsolete.txt

# Increased security with more overwrite passes
python crypt.py shred -i sensitive.doc --shred-passes 7

# Shred a directory recursively
python crypt.py shred -i old_project/ -r

# Shred multiple files using glob pattern
python crypt.py shred -i "temp*.log"

# Shred all files matching a pattern
python crypt.py shred -i "backup_*.old"
```

## Security Notes

- Use strong, unique passwords! The security of your encrypted files depends primarily on password strength
- For maximum security, use multiple hash algorithms and higher iteration counts
- When encrypting files, the tool requires password confirmation to prevent typos that could lead to data loss
- The `--random` option generates a strong password and displays it for a limited time (10 seconds)
- Securely shredded files cannot be recovered, even with forensic tools
- The `--overwrite` option uses secure techniques to replace the original file
- Note that due to SSD, RAID, and file system complications, secure shredding may not completely remove all traces on some storage systems

### Memory Security

This tool implements several memory security features to protect sensitive data:

- **Secure Buffers**: Password and key material is stored in special memory buffers that are protected against swapping to disk
- **Memory Wiping**: Sensitive information is immediately wiped from memory when no longer needed
- **Side-Channel Protection**: Argon2i variant provides additional protection against cache-timing and other side-channel attacks
- **Defense Against Cold Boot Attacks**: Minimizes the time sensitive data remains in memory

By default, secure memory handling is enabled. It can be disabled with `--disable-secure-memory`, but this is not recommended unless you encounter compatibility issues.

### Argon2 Key Derivation

Argon2 is a state-of-the-art password hashing algorithm designed to be:

- **Memory-Hard**: Requires significant amounts of memory to compute, making hardware-based attacks difficult
- **Time-Tunable**: Configurable time cost to scale with available resources
- **Parallelism-Aware**: Can leverage multiple CPU cores for better performance

Three variants are supported:
- **argon2d**: Provides the highest resistance against GPU cracking attempts (uses data-dependent memory access)
- **argon2i**: Provides resistance against side-channel attacks (uses data-independent memory access)
- **argon2id**: A hybrid approach offering good protection against both GPU and side-channel attacks (default)

## How It Works

### Encryption Process

1. Generate a cryptographic key from your password using:
   - Optional multi-layer password hashing (SHA-256/512, SHA3-256/512, Whirlpool, Scrypt)
   - Final PBKDF2 key derivation
   - Optional Argon2 memory-hard key derivation
2. Encrypt the file using Fernet (AES-128-CBC with HMAC)
3. Store encryption parameters and file integrity hash in the file header

### Secure Shredding Process

1. Overwrite the file's contents multiple times with:
   - Random data
   - All 1's (0xFF)
   - All 0's (0x00)
2. Truncate the file to zero bytes
3. Delete the file from the filesystem

### Password Generation Process

1. Creates a cryptographically secure random password using the system's secure random number generator
2. Ensures inclusion of selected character types (lowercase, uppercase, digits, special characters)
3. Shuffles the password to avoid predictable patterns
4. Displays the password with a countdown timer
5. Securely clears the password from the screen after timeout or user interruption

### Memory-Secure Processing

1. All sensitive data (passwords, encryption keys) is isolated in protected memory areas
2. When sensitive operations complete, memory is securely wiped with zeros
3. Temporary buffers are allocated and freed as needed to minimize exposure
4. The tool implements defense-in-depth with multiple memory protection techniques

## Files Included

- `crypt.py` - Main command-line utility
- `crypt_gui.py` - Graphical user interface
- `crypt_launcher.py` - Simple launcher for the GUI
- `requirements.txt` - Required Python packages
- `README.md` - This documentation file
- `test_crypt.py` - Unit tests for the utility

## License

[MIT License](LICENSE)

