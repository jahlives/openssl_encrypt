# Keystore Guide - OpenSSL Encrypt

## Table of Contents

1. [Overview](#overview)
2. [Getting Started](#getting-started)
3. [Keystore CLI Reference](#keystore-cli-reference)
4. [Integration with Main CLI](#integration-with-main-cli)
5. [Security Levels](#security-levels)
6. [Key Management](#key-management)
7. [Dual Encryption](#dual-encryption)
8. [Advanced Usage](#advanced-usage)
9. [Best Practices](#best-practices)
10. [Troubleshooting](#troubleshooting)

## Overview

The Post-Quantum Cryptography (PQC) keystore functionality provides a secure, centralized way to manage cryptographic keys for file encryption and decryption operations. It enables:

### Features
- **Centralized Key Management**: Store multiple post-quantum key pairs in a single encrypted container
- **Key Identification**: Reference keys by human-readable IDs instead of managing files
- **Automated Key Generation**: Automatically create appropriate keys for different algorithms
- **Enhanced Security**: Dual encryption using both passwords and keystore keys
- **Key Sharing**: Share encrypted files without exposing private keys

### Supported Algorithms
- **ML-KEM (Module Lattice KEM)**: NIST FIPS 203 standardized algorithms
  - ML-KEM-512 (Security Level 1)
  - ML-KEM-768 (Security Level 3)
  - ML-KEM-1024 (Security Level 5)
- **HQC (Hamming Quasi-Cyclic)**: Code-based post-quantum algorithms
  - HQC-128, HQC-192, HQC-256
- **Legacy Kyber**: Original CRYSTALS-Kyber implementation (deprecated naming)

## Getting Started

### Prerequisites
- OpenSSL Encrypt package installed
- Basic familiarity with command-line interfaces
- Understanding of public-key cryptography concepts

### Creating Your First Keystore

#### Method 1: Standalone Keystore Creation
```bash
# Create a keystore with standard security settings
python -m openssl_encrypt.keystore_cli_main create --keystore-path my_keystore.pqc
# You'll be prompted for a keystore password
```

#### Method 2: Create During Encryption
```bash
# Create keystore automatically during first encryption
python -m openssl_encrypt.crypt encrypt -i file.txt \
    --algorithm ml-kem-768-hybrid \
    --keystore my_keystore.pqc \
    --use-keystore-key \
    --create-keystore
```

### Basic Workflow Example

1. **Create a keystore**:
```bash
python -m openssl_encrypt.keystore_cli_main create \
    --keystore-path secure.pqc \
    --security-level high
```

2. **Generate a key**:
```bash
python -m openssl_encrypt.keystore_cli_main generate-key \
    --keystore-path secure.pqc \
    --algorithm ml-kem-768 \
    --key-id "project-alpha"
```

3. **Encrypt a file**:
```bash
python -m openssl_encrypt.crypt encrypt -i document.pdf \
    --keystore secure.pqc \
    --key-id "project-alpha" \
    --algorithm ml-kem-768-hybrid
```

4. **Decrypt the file**:
```bash
python -m openssl_encrypt.crypt decrypt -i document.pdf.enc \
    --keystore secure.pqc \
    --key-id "project-alpha"
```

## Keystore CLI Reference

### Command Structure
```bash
python -m openssl_encrypt.keystore_cli_main COMMAND [OPTIONS]
```

### Available Commands

#### create
Create a new keystore with specified security settings.

**Syntax:**
```bash
python -m openssl_encrypt.keystore_cli_main create [OPTIONS]
```

**Options:**
- `--keystore-path PATH`: Path for the new keystore file (required)
- `--keystore-password PASSWORD`: Keystore password (will prompt if not provided)
- `--security-level LEVEL`: Security level (standard, high, paranoid)

**Examples:**
```bash
# Standard security keystore
python -m openssl_encrypt.keystore_cli_main create \
    --keystore-path company.pqc

# High security keystore with explicit password
python -m openssl_encrypt.keystore_cli_main create \
    --keystore-path secure.pqc \
    --security-level high \
    --keystore-password "my-secure-password"

# Maximum security keystore
python -m openssl_encrypt.keystore_cli_main create \
    --keystore-path paranoid.pqc \
    --security-level paranoid
```

#### list-keys
Display all keys stored in the keystore.

**Syntax:**
```bash
python -m openssl_encrypt.keystore_cli_main list-keys [OPTIONS]
```

**Options:**
- `--keystore-path PATH`: Path to the keystore file (required)
- `--keystore-password PASSWORD`: Keystore password (will prompt if not provided)

**Examples:**
```bash
# List all keys with password prompt
python -m openssl_encrypt.keystore_cli_main list-keys \
    --keystore-path my_keystore.pqc

# List keys with explicit password
python -m openssl_encrypt.keystore_cli_main list-keys \
    --keystore-path my_keystore.pqc \
    --keystore-password "password"
```

#### generate-key
Generate a new key pair in the keystore.

**Syntax:**
```bash
python -m openssl_encrypt.keystore_cli_main generate-key [OPTIONS]
```

**Options:**
- `--keystore-path PATH`: Path to the keystore file (required)
- `--keystore-password PASSWORD`: Keystore password (will prompt if not provided)
- `--algorithm ALGORITHM`: PQ algorithm (ml-kem-512, ml-kem-768, ml-kem-1024, hqc-128, hqc-192, hqc-256)
- `--key-id ID`: Human-readable identifier for the key

**Examples:**
```bash
# Generate ML-KEM-768 key
python -m openssl_encrypt.keystore_cli_main generate-key \
    --keystore-path secure.pqc \
    --algorithm ml-kem-768 \
    --key-id "project-beta"

# Generate maximum security key
python -m openssl_encrypt.keystore_cli_main generate-key \
    --keystore-path secure.pqc \
    --algorithm ml-kem-1024 \
    --key-id "top-secret"
```

#### delete-key
Remove a key from the keystore.

**Syntax:**
```bash
python -m openssl_encrypt.keystore_cli_main delete-key [OPTIONS]
```

**Options:**
- `--keystore-path PATH`: Path to the keystore file (required)
- `--keystore-password PASSWORD`: Keystore password (will prompt if not provided)
- `--key-id ID`: Identifier of the key to delete

**Examples:**
```bash
# Delete a specific key
python -m openssl_encrypt.keystore_cli_main delete-key \
    --keystore-path secure.pqc \
    --key-id "old-project"
```

#### info
Display detailed information about the keystore.

**Syntax:**
```bash
python -m openssl_encrypt.keystore_cli_main info [OPTIONS]
```

**Options:**
- `--keystore-path PATH`: Path to the keystore file (required)
- `--keystore-password PASSWORD`: Keystore password (will prompt if not provided)

**Examples:**
```bash
# Show keystore information
python -m openssl_encrypt.keystore_cli_main info \
    --keystore-path secure.pqc
```

## Integration with Main CLI

The keystore integrates seamlessly with the main encryption/decryption CLI through additional command-line arguments.

### Keystore Arguments for Main CLI

| Argument | Description |
|----------|-------------|
| `--keystore PATH` | Path to the PQC keystore file |
| `--keystore-password PASSWORD` | Password for the keystore |
| `--keystore-password-file FILE` | File containing the keystore password |
| `--key-id ID` | Specific key ID to use from the keystore |
| `--use-keystore-key` | Use a key from the keystore for encryption/decryption |
| `--create-keystore` | Create keystore if it doesn't exist |
| `--keystore-security LEVEL` | Security level for new keystores |

### Integration Examples

#### Encryption with Keystore

**Using existing key:**
```bash
python -m openssl_encrypt.crypt encrypt -i document.txt \
    --algorithm ml-kem-768-hybrid \
    --keystore secure.pqc \
    --key-id "project-alpha" \
    --use-keystore-key
```

**Auto-generating key:**
```bash
python -m openssl_encrypt.crypt encrypt -i secret.txt \
    --algorithm ml-kem-1024-hybrid \
    --keystore secure.pqc \
    --use-keystore-key \
    --create-keystore
# This will create the keystore and generate an appropriate key
```

#### Decryption with Keystore

```bash
python -m openssl_encrypt.crypt decrypt -i document.txt.enc \
    --keystore secure.pqc \
    --key-id "project-alpha"
```

#### Password File Usage

```bash
# Store keystore password in a file
echo "my-keystore-password" > keystore.pass
chmod 600 keystore.pass

# Use password file for automation
python -m openssl_encrypt.crypt encrypt -i file.txt \
    --keystore secure.pqc \
    --keystore-password-file keystore.pass \
    --use-keystore-key
```

## Security Levels

The keystore supports three security levels with different performance and security trade-offs:

### Standard Security Level
- **Use Case**: General purpose encryption
- **Performance**: Good
- **Memory Usage**: Moderate
- **Configuration**:
  - Argon2id: 512MB memory, 2 iterations
  - AES-256-GCM for keystore encryption
  - PBKDF2: 100,000 iterations

```bash
python -m openssl_encrypt.keystore_cli_main create \
    --keystore-path standard.pqc \
    --security-level standard
```

### High Security Level
- **Use Case**: Sensitive data protection
- **Performance**: Moderate
- **Memory Usage**: High
- **Configuration**:
  - Argon2id: 1GB memory, 3 iterations
  - AES-256-GCM for keystore encryption
  - PBKDF2: 200,000 iterations
  - Additional entropy gathering

```bash
python -m openssl_encrypt.keystore_cli_main create \
    --keystore-path high.pqc \
    --security-level high
```

### Paranoid Security Level
- **Use Case**: Maximum security for critical data
- **Performance**: Slow
- **Memory Usage**: Very High
- **Configuration**:
  - Argon2id: 2GB memory, 4 iterations
  - AES-256-GCM for keystore encryption
  - PBKDF2: 500,000 iterations
  - Multiple layers of key derivation
  - Extended secure memory usage

```bash
python -m openssl_encrypt.keystore_cli_main create \
    --keystore-path paranoid.pqc \
    --security-level paranoid
```

## Key Management

### Key Lifecycle

#### 1. Key Generation
Generate keys with appropriate algorithms for your security needs:

```bash
# For general use (balanced security/performance)
python -m openssl_encrypt.keystore_cli_main generate-key \
    --keystore-path keys.pqc \
    --algorithm ml-kem-768 \
    --key-id "general-use"

# For maximum security
python -m openssl_encrypt.keystore_cli_main generate-key \
    --keystore-path keys.pqc \
    --algorithm ml-kem-1024 \
    --key-id "top-secret"

# For code-based diversity
python -m openssl_encrypt.keystore_cli_main generate-key \
    --keystore-path keys.pqc \
    --algorithm hqc-256 \
    --key-id "code-based"
```

#### 2. Key Organization
Use descriptive key IDs to organize your keys:

```bash
# Project-based organization
generate-key --key-id "project-alpha-2024"
generate-key --key-id "project-beta-backup"
generate-key --key-id "personal-documents"

# Security-based organization
generate-key --key-id "confidential-ml1024"
generate-key --key-id "internal-ml768"
generate-key --key-id "public-ml512"
```

#### 3. Key Rotation
Regularly rotate keys for enhanced security:

```bash
# Generate new key version
python -m openssl_encrypt.keystore_cli_main generate-key \
    --keystore-path keys.pqc \
    --algorithm ml-kem-768 \
    --key-id "project-alpha-2025"

# Re-encrypt files with new key
python -m openssl_encrypt.crypt encrypt -i file.txt \
    --keystore keys.pqc \
    --key-id "project-alpha-2025" \
    --algorithm ml-kem-768-hybrid

# Delete old key after migration
python -m openssl_encrypt.keystore_cli_main delete-key \
    --keystore-path keys.pqc \
    --key-id "project-alpha-2024"
```

### Key Inspection

View detailed key information:

```bash
# List all keys with details
python -m openssl_encrypt.keystore_cli_main list-keys \
    --keystore-path keys.pqc

# Show keystore metadata
python -m openssl_encrypt.keystore_cli_main info \
    --keystore-path keys.pqc
```

## Dual Encryption

Combine password-based encryption with keystore keys for maximum security:

### Password + Keystore Protection

```bash
# Encrypt with both password and keystore key
python -m openssl_encrypt.crypt encrypt -i critical.txt \
    --algorithm ml-kem-1024-hybrid \
    --keystore secure.pqc \
    --key-id "critical-data" \
    --use-keystore-key \
    --password "additional-password"

# Decrypt requires both the keystore and password
python -m openssl_encrypt.crypt decrypt -i critical.txt.enc \
    --keystore secure.pqc \
    --key-id "critical-data" \
    --password "additional-password"
```

### Security Benefits

1. **Two-Factor Security**: Requires both keystore access and password knowledge
2. **Key Compromise Protection**: Even if keystore is compromised, password is still needed
3. **Password Compromise Protection**: Even if password is known, keystore access is required
4. **Organizational Security**: Different people can hold keystore and password

## Advanced Usage

### Automated Workflows

#### Script-Based Key Management
```bash
#!/bin/bash
# Key rotation script

KEYSTORE="production.pqc"
OLD_KEY="prod-2024"
NEW_KEY="prod-2025"

# Generate new key
python -m openssl_encrypt.keystore_cli_main generate-key \
    --keystore-path "$KEYSTORE" \
    --algorithm ml-kem-768 \
    --key-id "$NEW_KEY" \
    --keystore-password-file keystore.pass

# Re-encrypt files
for file in *.enc; do
    # Decrypt with old key
    python -m openssl_encrypt.crypt decrypt -i "$file" \
        --keystore "$KEYSTORE" \
        --key-id "$OLD_KEY" \
        --keystore-password-file keystore.pass \
        -o "${file%.enc}"

    # Re-encrypt with new key
    python -m openssl_encrypt.crypt encrypt -i "${file%.enc}" \
        --keystore "$KEYSTORE" \
        --key-id "$NEW_KEY" \
        --algorithm ml-kem-768-hybrid \
        --keystore-password-file keystore.pass

    # Clean up temporary file
    rm "${file%.enc}"
done

# Delete old key
python -m openssl_encrypt.keystore_cli_main delete-key \
    --keystore-path "$KEYSTORE" \
    --key-id "$OLD_KEY" \
    --keystore-password-file keystore.pass
```

#### Backup and Recovery
```bash
# Create encrypted backup of keystore
python -m openssl_encrypt.crypt encrypt -i production.pqc \
    --algorithm ml-kem-1024-hybrid \
    --paranoid \
    -o production-backup.pqc.enc

# Store backup securely (e.g., different location, cloud storage)
# Verify backup integrity
python -m openssl_encrypt.crypt decrypt -i production-backup.pqc.enc \
    -o production-restored.pqc

# Verify keystore contents
python -m openssl_encrypt.keystore_cli_main list-keys \
    --keystore-path production-restored.pqc
```

### Multiple Keystores

Organize keys across multiple keystores for different purposes:

```bash
# Personal keystore
python -m openssl_encrypt.keystore_cli_main create \
    --keystore-path personal.pqc \
    --security-level standard

# Work keystore
python -m openssl_encrypt.keystore_cli_main create \
    --keystore-path work.pqc \
    --security-level high

# High-security keystore
python -m openssl_encrypt.keystore_cli_main create \
    --keystore-path classified.pqc \
    --security-level paranoid

# Use appropriate keystore for each file type
python -m openssl_encrypt.crypt encrypt -i family_photos.zip \
    --keystore personal.pqc --use-keystore-key

python -m openssl_encrypt.crypt encrypt -i project_plan.pdf \
    --keystore work.pqc --use-keystore-key

python -m openssl_encrypt.crypt encrypt -i confidential.doc \
    --keystore classified.pqc --use-keystore-key
```

## Best Practices

### Security Best Practices

1. **Strong Keystore Passwords**:
   - Use unique, complex passwords for each keystore
   - Consider using passphrases (e.g., "correct-horse-battery-staple-2024")
   - Store passwords securely in a password manager

2. **Key Management**:
   - Use descriptive key IDs for easy identification
   - Implement regular key rotation schedules
   - Document key purposes and lifecycles
   - Delete unused keys promptly

3. **Backup Strategy**:
   - Maintain encrypted backups of keystores
   - Store backups in geographically separate locations
   - Test backup restoration procedures regularly
   - Document recovery procedures

4. **Access Control**:
   - Limit keystore access to authorized personnel only
   - Use file system permissions to protect keystore files
   - Consider hardware security modules for critical keystores
   - Implement audit logging for keystore access

### Operational Best Practices

1. **Environment Management**:
   - Use different keystores for different environments (dev, test, prod)
   - Never share production keystores across environments
   - Implement proper key lifecycle management

2. **Automation**:
   - Use password files for automated scripts
   - Implement proper error handling in automation
   - Log operations for audit trails
   - Use configuration management for consistency

3. **Performance Optimization**:
   - Choose appropriate security levels for your use case
   - Consider memory requirements for high-security settings
   - Monitor keystore operation performance
   - Use caching where appropriate

## Troubleshooting

### Common Issues and Solutions

#### Keystore Creation Issues

**Problem**: "Permission denied" when creating keystore
**Solution**:
```bash
# Ensure directory exists and is writable
mkdir -p /path/to/keystore/directory
chmod 755 /path/to/keystore/directory

# Use absolute paths
python -m openssl_encrypt.keystore_cli_main create \
    --keystore-path /absolute/path/to/keystore.pqc
```

**Problem**: "Insufficient memory" during keystore creation
**Solution**:
```bash
# Use standard security level instead of high/paranoid
python -m openssl_encrypt.keystore_cli_main create \
    --keystore-path keystore.pqc \
    --security-level standard

# Or increase system memory/swap space
```

#### Key Management Issues

**Problem**: "Key not found" when encrypting/decrypting
**Solution**:
```bash
# List available keys to verify key ID
python -m openssl_encrypt.keystore_cli_main list-keys \
    --keystore-path keystore.pqc

# Check exact key ID spelling (case-sensitive)
python -m openssl_encrypt.crypt encrypt -i file.txt \
    --keystore keystore.pqc \
    --key-id "exact-key-name"
```

**Problem**: "Invalid keystore password"
**Solution**:
```bash
# Verify password is correct
# Check for invisible characters if copying/pasting
# Try typing password manually instead of copy/paste

# If password is definitely correct, keystore may be corrupted
# Restore from backup if available
```

#### Algorithm Issues

**Problem**: "Algorithm not supported"
**Solution**:
```bash
# Check available algorithms
python -c "from openssl_encrypt.modules.pqc import get_supported_algorithms; print(get_supported_algorithms())"

# Install liboqs-python for extended algorithm support
pip install liboqs-python

# Use supported algorithm names:
# ml-kem-512, ml-kem-768, ml-kem-1024
# hqc-128, hqc-192, hqc-256
```

#### Performance Issues

**Problem**: Keystore operations are very slow
**Solution**:
```bash
# Use lower security level
python -m openssl_encrypt.keystore_cli_main create \
    --keystore-path fast.pqc \
    --security-level standard

# Increase system RAM
# Close other memory-intensive applications
# Use SSD storage for better I/O performance
```

#### File Corruption Issues

**Problem**: "Corrupted keystore" error
**Solution**:
```bash
# Restore from backup
cp keystore-backup.pqc keystore.pqc

# If no backup, check file integrity
file keystore.pqc
ls -la keystore.pqc

# Check disk space and file system errors
df -h
fsck /dev/your-device  # (unmounted filesystem only)
```

### Diagnostic Commands

```bash
# Check keystore integrity
python -m openssl_encrypt.keystore_cli_main info \
    --keystore-path keystore.pqc

# Test key generation
python -m openssl_encrypt.keystore_cli_main generate-key \
    --keystore-path test.pqc \
    --algorithm ml-kem-512 \
    --key-id "test-key"

# Test encryption/decryption roundtrip
echo "test data" > test.txt
python -m openssl_encrypt.crypt encrypt -i test.txt \
    --keystore test.pqc --key-id "test-key"
python -m openssl_encrypt.crypt decrypt -i test.txt.enc \
    --keystore test.pqc --key-id "test-key"
```

### Getting Help

1. **Check error messages carefully** - they often contain specific guidance
2. **Use verbose mode** for detailed operation information
3. **Verify system requirements** (Python version, available memory)
4. **Check file permissions** for keystore files and directories
5. **Test with simple cases** before complex operations
6. **Consult the main documentation** for general troubleshooting

---

This keystore guide provides comprehensive information for managing post-quantum cryptographic keys effectively and securely. For general usage information, refer to the [User Guide](user-guide.md).

**Last updated**: June 16, 2025
