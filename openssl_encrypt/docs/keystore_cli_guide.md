# Using PQC Keystore with the Command Line Interface

This guide demonstrates how to use the PQC keystore feature with the command line interface for encrypting and decrypting files.

## 1. Create a Keystore

First, create a PQC keystore to store your keys:

```bash
# Create a keystore with standard security settings
python -m openssl_encrypt.keystore_cli_main create --keystore-path my_keystore.pqc
# You'll be prompted for a password
```

For higher security:

```bash
# Create a keystore with high security settings
python -m openssl_encrypt.keystore_cli_main create --keystore-path my_keystore.pqc --security-level high
```

Example command:
```bash
python -m openssl_encrypt.keystore_cli_main create --keystore-path /tmp/my_keystore.pqc --security-level high --keystore-password mypassword
```

Make sure you use the exact module path shown above.

Note: To avoid import warnings, use the above commands. If you encounter the warning:
`<frozen runpy>:128: RuntimeWarning: '...' found in sys.modules...`, it's a harmless
import-related warning and doesn't affect functionality.

## 2. List Keys in the Keystore

To check the keys in your keystore:

```bash
# List all keys in the keystore
python -m openssl_encrypt.keystore_cli_main list-keys --keystore-path my_keystore.pqc
# You'll be prompted for the keystore password

# Or provide the password directly (less secure)
python -m openssl_encrypt.keystore_cli_main list-keys --keystore-path my_keystore.pqc --keystore-password "your-password"
```

**Parameter Consistency**:
All commands now use consistent parameter names:
- `--keystore-path` instead of `--keystore`
- `--keystore-password` instead of `--keystore-password`

Example:

```bash
# Create a keystore
python -m openssl_encrypt.keystore_cli_main create --keystore-path /tmp/my_keystore.pqc --security-level high

# List keys
python -m openssl_encrypt.keystore_cli_main list-keys --keystore-path /tmp/my_keystore.pqc
```

## 3. Encrypt a File Using PQC with Keystore

To encrypt a file and store the key ID in the metadata (no private key in file):

```bash
# Encrypt with a PQC algorithm and keystore
python -m openssl_encrypt.crypt encrypt \
  --input plaintext.txt \
  --output encrypted.enc \
  --algorithm kyber768-hybrid \
  --keystore my_keystore.pqc \
  --password "your-encryption-password"
```

The command will:
1. Generate a new Kyber768 keypair
2. Add it to the keystore (or use an existing one)
3. Store only the key ID in the file metadata
4. Encrypt the file with the public key and password

## 4. Decrypt a File Using the Keystore

To decrypt a file that has a key ID stored in its metadata:

```bash
# Decrypt using the key from the keystore
python -m openssl_encrypt.crypt decrypt \
  --input encrypted.enc \
  --output decrypted.txt \
  --keystore my_keystore.pqc \
  --password "your-encryption-password"
```

The command will:
1. Extract the key ID from the file metadata
2. Retrieve the corresponding private key from the keystore
3. Use the private key and password to decrypt the file

## 5. Self-Contained Encryption (Embedded Key)

If you want the file to be decryptable without needing access to the keystore, you can embed the private key in the file metadata:

```bash
# Encrypt with embedded private key
python -m openssl_encrypt.crypt encrypt \
  --input plaintext.txt \
  --output encrypted_self_contained.enc \
  --algorithm kyber768-hybrid \
  --password "your-encryption-password" \
  --pqc-store-key
```

This way, the file can be decrypted with just the password:

```bash
# Decrypt a file with embedded key
python -m openssl_encrypt.crypt decrypt \
  --input encrypted_self_contained.enc \
  --output decrypted.txt \
  --password "your-encryption-password"
```

## 6. Managing Keys

### Remove a Key
```bash
python -m openssl_encrypt.keystore_cli_main remove-key KEY_ID --keystore my_keystore.pqc
```

### Change Keystore Password
```bash
python -m openssl_encrypt.keystore_cli_main change-master-password --keystore my_keystore.pqc
```

### Set Default Key for an Algorithm
```bash
python -m openssl_encrypt.keystore_cli_main set-default KEY_ID --keystore my_keystore.pqc
```

## Security Considerations

1. **Keystore Security**: The keystore file contains your private keys (encrypted with your master password). Protect it accordingly.
   
2. **Password Strength**: Use strong passwords for both your keystore and file encryption.

3. **Key Storage Options**:
   - **Embedded key**: More convenient but less secure (anyone with the password can decrypt)
   - **Keystore only**: More secure but requires access to the keystore

4. **Backup**: Regularly back up your keystore file. If you lose it, you won't be able to decrypt files that reference keys in that keystore.