# Secure File Encryption Tool

A powerful tool for securely encrypting, decrypting, and shredding files with military-grade cryptography and multi-layer password hashing.

## Features

- **Strong Encryption**: Uses Fernet symmetric encryption (AES-128-CBC) with secure key derivation
- **Multi-hash Password Protection**: Optional layered hashing with SHA-256, SHA-512, SHA3-256, SHA3-512, Whirlpool, and Scrypt
- **File Integrity Verification**: Built-in hash verification to detect corrupted or tampered files
- **Secure File Shredding**: Military-grade secure deletion with multi-pass overwriting
- **Directory Support**: Recursive processing of directories
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

#### Common Options:

| Option | Description |
|--------|-------------|
| `-i`, `--input` | Input file or directory (required, supports glob patterns for shred action) |
| `-o`, `--output` | Output file (optional for decrypt) |
| `-p`, `--password` | Password (will prompt if not provided) |
| `-q`, `--quiet` | Suppress all output except decrypted content and exit code |
| `--overwrite` | Overwrite the input file with the output |
| `-s`, `--shred` | Securely delete the original file after encryption/decryption |
| `--shred-passes` | Number of passes for secure deletion (default: 3) |
| `-r`, `--recursive` | Process directories recursively when shredding |

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

### Enhanced Security Options

```bash
# Encrypt with multiple hashing algorithms
python crypt.py encrypt -i important.docx --sha512 --sha3-512 --pbkdf2 200000

# Use Scrypt for memory-hard password protection (cost factor 2^15)
python crypt.py encrypt -i secrets.txt --scrypt-cost 15

# Combine multiple hash functions for layered security
python crypt.py encrypt -i critical.pdf --sha512 --sha3-256 --scrypt-cost 14
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

- Use strong, unique passwords! The security of your encrypted files depends primarily on password strength.
- For maximum security, use multiple hash algorithms and higher iteration counts.
- Securely shredded files cannot be recovered, even with forensic tools.
- The `--overwrite` option uses secure techniques to replace the original file.
- Note that due to SSD, RAID, and file system complications, secure shredding may not completely remove all traces on some storage systems.

## How It Works

### Encryption Process

1. Generate a cryptographic key from your password using:
   - Optional multi-layer password hashing (SHA-256/512, SHA3-256/512, Whirlpool, Scrypt)
   - Final PBKDF2 key derivation
2. Encrypt the file using Fernet (AES-128-CBC with HMAC)
3. Store encryption parameters and file integrity hash in the file header

### Secure Shredding Process

1. Overwrite the file's contents multiple times with:
   - Random data
   - All 1's (0xFF)
   - All 0's (0x00)
2. Truncate the file to zero bytes
3. Delete the file from the filesystem

## Files Included

- `crypt.py` - Main command-line utility
- `crypt_gui.py` - Graphical user interface
- `crypt_launcher.py` - Simple launcher for the GUI
- `requirements.txt` - Required Python packages
- `README.md` - This documentation file
- `test_crypt.py` - Unit tests for the utility

## License

[MIT License](LICENSE)
