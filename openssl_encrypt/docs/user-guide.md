# User Guide - OpenSSL Encrypt

## Table of Contents

1. [Installation](#installation)
2. [Getting Started](#getting-started)
3. [Command-Line Interface](#command-line-interface)
4. [Graphical User Interface](#graphical-user-interface)
5. [Examples](#examples)
6. [Password Management](#password-management)
7. [Security Templates](#security-templates)
8. [Advanced Features](#advanced-features)
9. [Troubleshooting](#troubleshooting)

## Installation

### System Requirements

- **Python**: 3.9 or higher (3.11+ recommended for full feature support)
- **Operating System**: Windows, macOS, Linux
- **Memory**: Minimum 512MB RAM (2GB+ recommended for paranoid security settings)
- **Storage**: 100MB for installation plus encrypted file storage space

### Installation Methods

#### From PyPI (Recommended)

The easiest way to install is via pip from PyPI:

```bash
pip install openssl_encrypt
```

#### From GitLab Package Registry

The package is also available from the custom GitLab package registry:

```bash
# Configure pip to use the custom package registry
pip config set global.extra-index-url https://gitlab.rm-rf.ch/api/v4/projects/world%2Fopenssl_encrypt/packages/pypi/simple

# Install the package
pip install openssl_encrypt
```

#### From Source

1. Clone or download the repository:
```bash
git clone https://gitlab.rm-rf.ch/world/openssl_encrypt.git
cd openssl_encrypt
```

2. Install required packages:
```bash
pip install -r requirements-prod.txt
```

3. Install the package:
```bash
pip install -e .
```

### Core Dependencies

The installation automatically includes these critical dependencies:

- **cryptography**: Core cryptographic operations
- **argon2-cffi**: Memory-hard password hashing
- **PyYAML**: Configuration file support

### Optional Dependencies

#### GUI Support
The graphical interface requires tkinter:

```bash
# On Debian/Ubuntu
sudo apt-get install python3-tk

# On Fedora/CentOS
sudo dnf install python3-tkinter

# On macOS (with Homebrew)
brew install python-tk
```

#### Post-Quantum Cryptography
For extended post-quantum algorithm support:

```bash
pip install liboqs-python
```

#### Whirlpool Hash Algorithm

The package automatically installs the appropriate Whirlpool module for your Python version:

- **Python 3.11+**: `whirlpool-py311>=1.0.0`
- **Python 3.10 and below**: `Whirlpool`

If you encounter installation issues, see the [Whirlpool Troubleshooting](#whirlpool-troubleshooting) section.

### Development Installation

For development and testing:

```bash
# Install with development dependencies
pip install -e ".[dev]"

# Or manually install development tools
pip install pytest pylint black mypy bandit
```

### Verifying Installation

Test your installation:

```bash
# Check version
python -m openssl_encrypt.cli --version

# Run basic functionality test
python -m openssl_encrypt.crypt security-info

# Run unit tests (recommended)
python -m pytest openssl_encrypt/unittests/
```

### Offline Installation

For air-gapped systems:

1. Download the wheel file from PyPI or GitLab
2. Transfer to the target system
3. Install using:

```bash
pip install openssl_encrypt-*.whl
```

## Getting Started

### First Steps

1. **Verify Installation**:
```bash
python -m openssl_encrypt.crypt --help
```

2. **Create a Test File**:
```bash
echo "Hello, World!" > test.txt
```

3. **Encrypt the File**:
```bash
python -m openssl_encrypt.crypt encrypt -i test.txt
# You'll be prompted for a password
```

4. **Decrypt the File**:
```bash
python -m openssl_encrypt.crypt decrypt -i test.txt.enc -o decrypted.txt
```

5. **Verify the Content**:
```bash
cat decrypted.txt
```

### Choosing Your Interface

**Command-Line Interface (CLI)**:
- Best for automation, scripting, and advanced users
- Full feature access with extensive configuration options
- Ideal for server environments and batch operations

**Graphical User Interface (GUI)**:
- User-friendly for beginners
- Visual feedback and intuitive controls
- Great for occasional use and one-off operations

## Command-Line Interface

### Basic Syntax

```bash
python -m openssl_encrypt.crypt ACTION [OPTIONS]
```

### Available Actions

| Action | Description |
|--------|-------------|
| `encrypt` | Encrypt a file with a password |
| `decrypt` | Decrypt a file with a password |
| `shred` | Securely delete a file by overwriting its contents |
| `generate-password` | Generate a secure random password |
| `security-info` | Show security recommendations |
| `check-argon2` | Check Argon2 support |

### Core Options

| Option | Description |
|--------|-------------|
| `-i`, `--input` | Input file or directory |
| `-o`, `--output` | Output file (optional for decrypt to stdout) |
| `-p`, `--password` | Password (prompts if not provided) |
| `-q`, `--quiet` | Suppress all output except errors |
| `-f`, `--overwrite` | Overwrite input file with output |
| `-s`, `--shred` | Securely delete original file after operation |
| `--progress` | Show progress bar for large files |
| `--verbose` | Show detailed operation information |

### Algorithm Selection

| Option | Algorithm | Description |
|--------|-----------|-------------|
| `--algorithm fernet` | Fernet | AES-128-CBC with HMAC (default) |
| `--algorithm aes-gcm` | AES-GCM | AES-256 with authentication |
| `--algorithm aes-gcm-siv` | AES-GCM-SIV | Nonce-misuse resistant |
| `--algorithm chacha20-poly1305` | ChaCha20-Poly1305 | Stream cipher alternative |
| `--algorithm xchacha20-poly1305` | XChaCha20-Poly1305 | Extended nonce space |

### Post-Quantum Options

| Option | Algorithm | Security Level |
|--------|-----------|---------------|
| `--algorithm ml-kem-512-hybrid` | ML-KEM-512 + AES | Level 1 (AES-128 equivalent) |
| `--algorithm ml-kem-768-hybrid` | ML-KEM-768 + AES | Level 3 (AES-192 equivalent) |
| `--algorithm ml-kem-1024-hybrid` | ML-KEM-1024 + AES | Level 5 (AES-256 equivalent) |
| `--algorithm hqc-128-hybrid` | HQC-128 + AES | Level 1 (code-based) |
| `--algorithm hqc-192-hybrid` | HQC-192 + AES | Level 3 (code-based) |
| `--algorithm hqc-256-hybrid` | HQC-256 + AES | Level 5 (code-based) |

## Graphical User Interface

### Launching the GUI

```bash
# Method 1: Direct GUI module
python -m openssl_encrypt.crypt_gui

# Method 2: Via main CLI with --gui flag
python -m openssl_encrypt.cli --gui
```

### GUI Features

#### 1. Encrypt Tab
- **File Selection**: Browse for input and output files
- **Password Entry**: Secure password input with confirmation
- **Algorithm Selection**: Choose from available encryption algorithms
- **Security Options**: Configure hash rounds and KDF parameters
- **Progress Display**: Real-time progress for large files

#### 2. Decrypt Tab
- **File Selection**: Select encrypted file and output location
- **Password Entry**: Enter decryption password
- **Display Options**: View decrypted content or save to file
- **Security Options**: Shred encrypted file after decryption

#### 3. Shred Tab
- **File Selection**: Choose files or use glob patterns
- **Preview**: Preview files to be deleted before confirmation
- **Shred Configuration**: Configure overwrite passes and recursion
- **Safety Features**: Confirmation dialogs to prevent accidents

#### 4. Advanced Tab
- **Security Templates**: Quick access to predefined security levels
- **Custom Configuration**: Fine-tune all security parameters
- **Algorithm Configuration**: Advanced algorithm-specific settings
- **Memory Settings**: Configure memory usage for key derivation

## Examples

### Basic Operations

#### File Encryption
```bash
# Simple encryption with prompt for password
python -m openssl_encrypt.crypt encrypt -i document.pdf

# Encrypt with specific output file
python -m openssl_encrypt.crypt encrypt -i document.pdf -o document.pdf.encrypted

# Encrypt and show progress
python -m openssl_encrypt.crypt encrypt -i largefile.zip --progress

# Encrypt with specific algorithm
python -m openssl_encrypt.crypt encrypt -i data.txt --algorithm aes-gcm
```

#### File Decryption
```bash
# Decrypt with automatic output filename
python -m openssl_encrypt.crypt decrypt -i document.pdf.enc

# Decrypt to specific output file
python -m openssl_encrypt.crypt decrypt -i document.pdf.enc -o restored_document.pdf

# Decrypt and display content (text files)
python -m openssl_encrypt.crypt decrypt -i config.txt.enc

# Decrypt and shred encrypted file
python -m openssl_encrypt.crypt decrypt -i secret.txt.enc --shred
```

#### Secure File Deletion
```bash
# Securely delete a single file
python -m openssl_encrypt.crypt shred -i sensitive.txt

# Securely delete with multiple passes
python -m openssl_encrypt.crypt shred -i confidential.doc --shred-passes 7

# Recursively shred directory contents
python -m openssl_encrypt.crypt shred -i /tmp/secret_folder/ --recursive

# Shred files matching pattern
python -m openssl_encrypt.crypt shred -i "*.tmp" --recursive
```

### Advanced Examples

#### Post-Quantum Encryption
```bash
# Encrypt with ML-KEM-768 (recommended for most use cases)
python -m openssl_encrypt.crypt encrypt -i important.txt --algorithm ml-kem-768-hybrid

# Maximum security with ML-KEM-1024
python -m openssl_encrypt.crypt encrypt -i top_secret.pdf --algorithm ml-kem-1024-hybrid

# Alternative quantum-resistant algorithm (HQC)
python -m openssl_encrypt.crypt encrypt -i data.txt --algorithm hqc-256-hybrid
```

#### Custom Security Configuration
```bash
# High-memory Argon2 configuration
python -m openssl_encrypt.crypt encrypt -i file.txt \
    --enable-argon2 --argon2-memory 2097152 --argon2-time 4

# Multiple hash layers
python -m openssl_encrypt.crypt encrypt -i file.txt \
    --sha256-rounds 2000000 --sha512-rounds 1500000 --blake2b-rounds 1000000

# Custom Scrypt parameters
python -m openssl_encrypt.crypt encrypt -i file.txt \
    --enable-scrypt --scrypt-n 1024 --scrypt-r 32 --scrypt-p 4
```

#### Keystore Operations
```bash
# Create a new keystore
python -m openssl_encrypt.keystore_cli_main create --keystore-path my_keys.pqc

# List keys in keystore
python -m openssl_encrypt.keystore_cli_main list-keys --keystore-path my_keys.pqc

# Encrypt using keystore key
python -m openssl_encrypt.crypt encrypt -i file.txt \
    --keystore my_keys.pqc --use-keystore-key --algorithm ml-kem-768-hybrid
```

## Password Management

### Password Security Guidelines

1. **Length**: Use passwords with at least 16 characters
2. **Complexity**: Mix uppercase, lowercase, numbers, and symbols
3. **Uniqueness**: Use different passwords for different files
4. **Storage**: Use a password manager for secure storage

### Password Generation

```bash
# Generate a 20-character password with all character types
python -m openssl_encrypt.crypt generate-password --length 20 \
    --use-lowercase --use-uppercase --use-digits --use-special

# Generate a simple alphanumeric password
python -m openssl_encrypt.crypt generate-password --length 16 \
    --use-lowercase --use-uppercase --use-digits

# Generate and use a random password for encryption
python -m openssl_encrypt.crypt encrypt -i file.txt --random 24
# The tool displays the generated password for 10 seconds
```

### Environment Variable Support

```bash
# Set password via environment variable (secure for scripts)
export CRYPT_PASSWORD="your-secure-password"
python -m openssl_encrypt.crypt encrypt -i file.txt

# Use password file
echo "your-secure-password" > password.txt
chmod 600 password.txt
python -m openssl_encrypt.crypt encrypt -i file.txt --password-file password.txt
```

## Security Templates

Pre-configured security profiles for different use cases:

### Quick Template
- **Use Case**: Fast encryption for temporary files
- **Security Level**: Good
- **Performance**: High
- **Configuration**:
  - Argon2id: 512MB memory, 2 iterations
  - Single-layer key derivation
  - PBKDF2: 50,000 iterations

```bash
python -m openssl_encrypt.crypt encrypt -i file.txt --quick
```

### Standard Template (Default)
- **Use Case**: Balanced security and performance
- **Security Level**: High
- **Performance**: Medium
- **Configuration**:
  - Argon2id: 1GB memory, 3 iterations
  - PBKDF2: 100,000 iterations
  - BLAKE2b file hashing

```bash
python -m openssl_encrypt.crypt encrypt -i file.txt --standard
# or simply:
python -m openssl_encrypt.crypt encrypt -i file.txt
```

### Paranoid Template
- **Use Case**: Maximum security for highly sensitive data
- **Security Level**: Maximum
- **Performance**: Low
- **Configuration**:
  - Argon2id: 2GB memory, 4 iterations
  - Multiple KDF layers (Argon2 + PBKDF2 + Scrypt)
  - All available hash functions
  - Extended key derivation chains

```bash
python -m openssl_encrypt.crypt encrypt -i top_secret.txt --paranoid
```

### Custom Templates

Create custom templates in the `./templates` directory:

```bash
# Create a custom template file
cat > ./templates/my_template.json << EOF
{
    "argon2": {
        "enabled": true,
        "rounds": 5,
        "memory_cost": 1048576,
        "time_cost": 3
    },
    "pbkdf2": {
        "enabled": true,
        "iterations": 200000
    },
    "sha256": 1000000,
    "blake2b": 500000
}
EOF

# Use your custom template
python -m openssl_encrypt.crypt encrypt -i file.txt --template my_template
```

## Advanced Features

### Dual Encryption

Combine password-based encryption with keystore keys for enhanced security:

```bash
# Create keystore and encrypt with dual protection
python -m openssl_encrypt.crypt encrypt -i critical.txt \
    --algorithm ml-kem-768-hybrid \
    --keystore secure.pqc --use-keystore-key \
    --password "additional-password"
```

### Batch Operations

```bash
# Encrypt multiple files
for file in *.txt; do
    python -m openssl_encrypt.crypt encrypt -i "$file" --standard
done

# Decrypt multiple files
for file in *.enc; do
    python -m openssl_encrypt.crypt decrypt -i "$file"
done
```

### Secure Workflows

```bash
# Secure encryption workflow
python -m openssl_encrypt.crypt encrypt -i sensitive.txt \
    --algorithm ml-kem-768-hybrid \
    --paranoid \
    --shred \
    --progress

# This will:
# 1. Use post-quantum encryption
# 2. Apply maximum security settings
# 3. Securely delete the original file
# 4. Show progress during operation
```

## Troubleshooting

### Common Issues

#### Installation Problems

**Problem**: `pip install` fails with SSL errors
**Solution**:
```bash
pip install --trusted-host pypi.org --trusted-host pypi.python.org openssl_encrypt
```

**Problem**: Permission denied during installation
**Solution**:
```bash
# Use user installation
pip install --user openssl_encrypt

# Or use virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# venv\Scripts\activate   # Windows
pip install openssl_encrypt
```

#### Whirlpool Troubleshooting

**Problem**: `ImportError: No module named 'whirlpool'`
**Solution**:
```bash
# For Python 3.11+
pip install whirlpool-py311

# For older Python versions
pip install Whirlpool

# Manual setup if needed
python -m openssl_encrypt.modules.setup_whirlpool
```

**Problem**: Whirlpool module installed but not recognized
**Solution**:
```bash
# Check Python environment
python -c "import sys; print(sys.executable)"
python -c "import whirlpool; print('OK')"

# Reinstall in correct environment
pip uninstall whirlpool whirlpool-py311
pip install whirlpool-py311  # For Python 3.11+
```

#### Runtime Issues

**Problem**: `MemoryError` during encryption
**Solution**:
```bash
# Use quick template for lower memory usage
python -m openssl_encrypt.crypt encrypt -i file.txt --quick

# Or reduce Argon2 memory
python -m openssl_encrypt.crypt encrypt -i file.txt \
    --enable-argon2 --argon2-memory 524288  # 512MB instead of 1GB
```

**Problem**: GUI doesn't start
**Solution**:
```bash
# Install tkinter
sudo apt-get install python3-tk  # Ubuntu/Debian
sudo dnf install python3-tkinter  # Fedora

# Test tkinter
python -c "import tkinter; print('Tkinter OK')"
```

**Problem**: Decryption fails with "Authentication failed"
**Solution**:
1. Verify the password is correct
2. Check the file hasn't been corrupted
3. Ensure you're using the correct algorithm
4. Try verbose mode for more information:
```bash
python -m openssl_encrypt.crypt decrypt -i file.enc --verbose
```

#### Performance Issues

**Problem**: Encryption is very slow
**Solution**:
```bash
# Use faster algorithm
python -m openssl_encrypt.crypt encrypt -i file.txt --algorithm chacha20-poly1305

# Use quick template
python -m openssl_encrypt.crypt encrypt -i file.txt --quick

# Reduce hash iterations
python -m openssl_encrypt.crypt encrypt -i file.txt \
    --pbkdf2-iterations 50000
```

#### Post-Quantum Issues

**Problem**: Post-quantum algorithms not available
**Solution**:
```bash
# Install liboqs-python for extended PQ support
pip install liboqs-python

# Check available algorithms
python -c "from openssl_encrypt.modules.pqc import get_supported_algorithms; print(get_supported_algorithms())"
```

### Getting Help

1. **Check version and basic info**:
```bash
python -m openssl_encrypt.crypt --version
python -m openssl_encrypt.crypt security-info
```

2. **Run with verbose output**:
```bash
python -m openssl_encrypt.crypt encrypt -i file.txt --verbose
```

3. **Check logs and error messages carefully**

4. **Report issues**: Use the project's issue tracking system

### Best Practices

1. **Always test decryption** before deleting original files
2. **Use the `--progress` flag** for large files
3. **Keep backups** of encrypted files
4. **Use strong, unique passwords** for each file
5. **Consider post-quantum encryption** for long-term data protection
6. **Regularly update** the software for security patches

---

This user guide provides comprehensive information for using OpenSSL Encrypt effectively and securely. For advanced security topics, refer to the [Security Documentation](security.md).

**Last updated**: June 16, 2025
