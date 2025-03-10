## Usage

The tool can be used either through the command line interface or the graphical user interface.

### GUI Interface

To start the graphical user interface:

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