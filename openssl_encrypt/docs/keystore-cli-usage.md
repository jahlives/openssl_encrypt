# Using PQCKeystore with Encryption CLI

This document explains how to use the Post-Quantum Cryptography (PQC) keystore functionality with the main encryption/decryption CLI.

## Prerequisites

- OpenSSL Encrypt package installed
- Basic familiarity with command-line interfaces
- Understanding of public-key cryptography concepts

## Overview

The keystore integration allows you to:

1. Store post-quantum key pairs securely in a central location
2. Reference keys by ID instead of managing individual key files
3. Automatically generate and use appropriate keys for different algorithms
4. Share encrypted files without exposing private keys

## Keystore Command Line Arguments

The following arguments have been added to the main encryption/decryption CLI:

| Argument | Description |
|----------|-------------|
| `--keystore` | Path to the PQC keystore file |
| `--keystore-password` | Password for the keystore (will prompt if not provided) |
| `--keystore-password-file` | File containing the keystore password |
| `--key-id` | Specific key ID to use from the keystore |
| `--use-keystore-key` | Use a key from the keystore for encryption/decryption |
| `--create-keystore` | Create keystore if it does not exist |
| `--keystore-security` | Security level for new keystores (standard, high, paranoid) |

## Workflow Examples

### Creating and Using a Keystore for Encryption

1. **Create a new keystore:**

```bash
python -m openssl_encrypt.crypt encrypt -i /path/to/file.txt --algorithm kyber768-hybrid \
    --keystore /path/to/keystore.pqc --use-keystore-key --create-keystore
```

This will:
- Create a new keystore if it doesn't exist
- Prompt for a keystore password
- Generate a new kyber768 key in the keystore
- Use that key to encrypt the file

2. **Encrypt using an existing keystore:**

```bash
python -m openssl_encrypt.crypt encrypt -i /path/to/file.txt -o /path/to/file.enc \
    --algorithm kyber768-hybrid --keystore /path/to/keystore.pqc --use-keystore-key
```

This will:
- Open the existing keystore (prompting for the password)
- Search for a matching kyber768 key or generate a new one
- Use that key to encrypt the file

3. **Encrypt using a specific key from the keystore:**

```bash
python -m openssl_encrypt.crypt encrypt -i /path/to/file.txt -o /path/to/file.enc \
    --algorithm kyber768-hybrid --keystore /path/to/keystore.pqc --key-id 12345678-abcd-1234-efgh-123456789abc
```

This will use the specific key ID from the keystore for encryption.

### Decryption Using the Keystore

1. **Automatic Key ID Detection:**

```bash
python -m openssl_encrypt.crypt decrypt -i /path/to/file.enc -o /path/to/file.txt \
    --keystore /path/to/keystore.pqc --use-keystore-key
```

The program will:
- Extract the key ID from the encrypted file's metadata
- Load the corresponding private key from the keystore
- Use it to decrypt the file

2. **Specifying a Key ID Explicitly:**

```bash
python -m openssl_encrypt.crypt decrypt -i /path/to/file.enc -o /path/to/file.txt \
    --keystore /path/to/keystore.pqc --key-id 12345678-abcd-1234-efgh-123456789abc
```

## Advanced Usage

### Embedding Private Keys for Self-Decryption

You can still use the `--pqc-store-key` option with keystore keys to embed the private key in the encrypted file:

```bash
python -m openssl_encrypt.crypt encrypt -i /path/to/file.txt \
    --algorithm kyber768-hybrid --keystore /path/to/keystore.pqc --use-keystore-key --pqc-store-key
```

This allows the file to be decrypted using just the password, without needing the keystore.

### Improved Keystore Integration

The system now includes special wrapper functions that ensure robust keystore integration:

1. **Enhanced Key ID Storage**: The system will reliably store the key ID in the file metadata, ensuring it can be retrieved during decryption.

2. **Robust Metadata Handling**: The system can now handle large PQC keys that might cause metadata JSON parsing issues.

3. **Automatic Fallback Methods**: If JSON parsing fails, the system will automatically try alternative methods to extract the key ID.

Using these wrapper functions happens automatically when you specify the keystore options, so no special flags are needed.

### Keystore Security Levels

When creating a new keystore, you can specify the security level:

```bash
python -m openssl_encrypt.crypt encrypt -i /path/to/file.txt \
    --algorithm kyber768-hybrid --keystore /path/to/keystore.pqc --use-keystore-key \
    --create-keystore --keystore-security paranoid
```

Available security levels:
- `standard`: Balanced security (default)
- `high`: Stronger security, more computational resources
- `paranoid`: Maximum security, significant computational resources

## Keystore Password Handling

1. **Interactive Password Entry:**
   By default, the system will prompt for the keystore password interactively.

2. **Password on Command Line:**
   ```bash
   python -m openssl_encrypt.crypt encrypt -i file.txt --keystore keystore.pqc \
       --keystore-password MySecretPassword --use-keystore-key
   ```
   Note: This is less secure as passwords can appear in shell history.

3. **Password in File:**
   ```bash
   python -m openssl_encrypt.crypt encrypt -i file.txt --keystore keystore.pqc \
       --keystore-password-file /path/to/password.txt --use-keystore-key
   ```

## Troubleshooting

### Key Not Found
If you receive a "Key not found" error when decrypting:
- Check that the keystore path is correct
- Verify that the key ID in the file metadata matches a key in your keystore
- Try using the `--verbose` flag to see detailed information about the key lookup process
- Use the `--key-id` option to specify the key ID explicitly if automatic extraction fails

### Authentication Failed
If decryption fails with an authentication error:
- Ensure you're using the correct keystore that contains the private key
- Check if the key was rotated or replaced since the file was encrypted
- Try using the original keyfile if available with the `--pqc-keyfile` option

### Key ID Extraction Issues
If you experience problems with key ID extraction from file metadata:

1. Our improved key ID extraction includes regex-based fallback for handling potentially malformed metadata
2. The system will now automatically try multiple methods to extract the key ID:
   - First attempt: Parse metadata as JSON and find the key ID
   - Second attempt: Use regex pattern matching to find UUID patterns in the metadata
   - Third attempt: Check for embedded private key markers

To debug key ID extraction issues:
```bash
python -m openssl_encrypt.crypt decrypt -i /path/to/file.enc -o /path/to/file.txt \
    --keystore /path/to/keystore.pqc --use-keystore-key --verbose
```

This will show detailed information about the key ID extraction process.

## Managing the Keystore

For detailed keystore management operations (listing keys, removing keys, etc.), refer to the `keystore_cli_guide.md` documentation.