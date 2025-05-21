## Usage

The tool can be used either through the command line interface or the graphical user interface.

### GUI Interface

To start the graphical user interface:

```bash
python -m openssl_encrypt.crypt_gui
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

```bash
python -m openssl_encrypt.crypt ACTION [OPTIONS]
```

#### Actions:

- `encrypt`: Encrypt a file with a password
- `decrypt`: Decrypt a file with a password
- `shred`: Securely delete a file by overwriting its contents
- `generate-password`: Generate a secure random password
- `security-info`: Show security recommendations
- `check-argon2`: Check Argon2 support

#### General Options:

| Option | Description |
|--------|-------------|
| `-i`, `--input` | Input file or directory (supports glob patterns for shred) |
| `-o`, `--output` | Output file (optional for decrypt) |
| `-p`, `--password` | Password (will prompt if not provided) |
| `--random LENGTH` | Generate random password of specified length for encryption |
| `-q`, `--quiet` | Suppress all output except decrypted content and exit code |
| `-f`, `--overwrite` | Overwrite the input file with the output |
| `-s`, `--shred` | Securely delete the original file after encryption/decryption |
| `--shred-passes` | Number of passes for secure deletion (default: 3) |
| `-r`, `--recursive` | Process directories recursively when shredding |
| `--progress` | Show progress bar |
| `--verbose` | Show hash/KDF details |
| `--algorithm` | Encryption algorithm: fernet (default), aes-gcm, or chacha20-poly1305 |

#### Template Options:

| Option | Description |
|--------|-------------|
| `-t`, `--template` | Specify a template name (built-in or from ./template directory) |
| `--quick` | Use quick but secure configuration |
| `--standard` | Use standard security configuration (default) |
| `--paranoid` | Use maximum security configuration |

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
| `--sha256-rounds` | Number of SHA-256 iterations (default: 1,000,000 if enabled) |
| `--sha512-rounds` | Number of SHA-512 iterations (default: 1,000,000 if enabled) |
| `--sha3-256-rounds` | Number of SHA3-256 iterations (default: 1,000,000 if enabled) |
| `--sha3-512-rounds` | Number of SHA3-512 iterations (default: 1,000,000 if enabled) |
| `--whirlpool-rounds` | Number of Whirlpool iterations (default: 0) |
| `--pbkdf2-iterations` | Number of PBKDF2 iterations (default: 100000) |

#### Scrypt Options:

| Option | Description |
|--------|-------------|
| `--enable-scrypt` | Enable Scrypt password hashing |
| `--scrypt-rounds` | Scrypt iteration rounds (default: 1) |
| `--scrypt-n` | CPU/memory cost factor (default: 128, use power of 2) |
| `--scrypt-r` | Block size parameter (default: 8) |
| `--scrypt-p` | Parallelization parameter (default: 1) |

#### Argon2 Options:

| Option | Description |
|--------|-------------|
| `--enable-argon2` | Enable Argon2 password hashing |
| `--argon2-rounds` | Time cost (default: 1) |
| `--argon2-time` | Time cost parameter (default: 3) |
| `--argon2-memory` | Memory usage in KB (default: 65536 - 64MB) |
| `--argon2-parallelism` | Parallelism factor (default: 4) |
| `--argon2-hash-len` | Hash length in bytes (default: 32) |
| `--argon2-type` | Argon2 variant: id (recommended), i, or d |
| `--argon2-preset` | Predefined parameters: low, medium, high, or paranoid |

#### Balloon Hashing Options:

| Option | Description |
|--------|-------------|
| `--enable-balloon` | Enable Balloon Hashing KDF |
| `--balloon-time-cost` | Time cost parameter (default: 3) |
| `--balloon-space-cost` | Memory usage in bytes (default: 65536) |
| `--balloon-parallelism` | Thread count (default: 4) |
| `--balloon-rounds` | Number of rounds (default: 2) |
| `--balloon-hash-len` | Hash output length in bytes (default: 32) |

#### Read Input from stdin
It can be helpful to get the decrypted content from stdin (ex when encrypted content is from wallet). Here a sample of reading data from `kdewallet`
```
kwallet-query -f "Secret Service" -r KeePassCrypt -v kdewallet | python -m openssl_encrypt.crypt decrypt --input /dev/stdin -q
```

### Test Module

The package includes a test module to verify encryption/decryption functionality and hash algorithms. The test module can be run as a Python module:

```bash
python -m openssl_encrypt.crypt_test [OPTIONS]
```

#### Test Options:

| Option | Description |
|--------|-------------|
| `--algorithm`, `-a` | Specific encryption algorithm to test (e.g., fernet, aes-gcm, chacha20-poly1305) |
| `--iterations`, `-i` | Number of test iterations to run (default: 1) |
| `--all` | Test all supported encryption algorithms |
| `--hash-functions` | Test hash functions |
| `--entropy` | Test password entropy evaluation |

#### Examples:

Test a specific encryption algorithm:
```bash
python -m openssl_encrypt.crypt_test --algorithm fernet
```

Test all encryption algorithms with multiple iterations:
```bash
python -m openssl_encrypt.crypt_test --all --iterations 3
```

Test only the hash functions:
```bash
python -m openssl_encrypt.crypt_test --hash-functions
```

Run a comprehensive test suite:
```bash
python -m openssl_encrypt.crypt_test --all --hash-functions --entropy
```