# Security Notes

## Core Security Features

### Password Security

- Use strong, unique passwords - the security of your encrypted files depends primarily on password strength
- Default minimum password length is 12 characters
- Password strength is evaluated in real-time using zxcvbn
- Passwords are never stored on disk unencrypted
- All password operations occur in secure memory buffers

### Encryption Features

- Uses AES-256-GCM by default for authenticated encryption
- Supports ChaCha20-Poly1305 as an alternative cipher
- Includes Authenticated Encryption with Associated Data (AEAD)
- Optional compression before encryption (disabled by default for security)

## Memory Security Implementation

### Secure Memory Management

- **Protected Memory Buffers**: All sensitive data (passwords, keys) stored in locked memory
- **Immediate Wiping**: Zero-fill memory immediately after use
- **Swap Prevention**: Memory pages locked to prevent swapping to disk
- **Side-Channel Mitigation**: Constant-time operations for sensitive comparisons
- **Cold Boot Attack Protection**: Minimizes sensitive data lifetime in memory

## Key Derivation Security

### Multi-Layer Key Derivation

1. **Primary KDF**: Argon2id (default), Argon2i, or Argon2d
2. **Secondary KDF Options**:
   - PBKDF2-HMAC-SHA512
   - Scrypt
   - Balloon Hashing
3. **Additional Hash Functions**:
   - SHA-256/512
   - SHA3-256/512
   - BLAKE2b/BLAKE3
   - Whirlpool

### Argon2 Configuration

Default parameters:
- Memory: 1GB
- Iterations: 3
- Parallelism: 4
- Hash length: 32 bytes

Customizable via:
```bash
python -m openssl_encrypt.crypt encrypt -i file.txt \
    --enable-argon2 \
    --argon2-memory 2097152 \
    --argon2-time 4 \
    --argon2-parallelism 8 \
    --argon2-type id
```

## File Security Features

### Secure File Operations

- Atomic write operations for file integrity
- Temporary files are encrypted
- Secure file deletion with multiple passes
- Directory permissions verification
- Backup creation before modifications (optional)

### Secure Shredding Implementation

Multi-pass overwrite sequence:
1. Random data (cryptographically secure)
2. Alternating patterns (0xFF, 0x00)
3. Final zero-fill pass
4. File truncation
5. Filesystem deletion

```bash
# Maximum security shredding
python -m openssl_encrypt.crypt shred -i sensitive.txt --shred-passes 35 --verify

# Directory recursive shredding
python -m openssl_encrypt.crypt shred -i secret_folder/ -r --shred-passes 7
```

## Random Number Generation

- Uses operating system's cryptographic RNG
- Implements additional entropy gathering
- Supports hardware RNG when available
- Fallback to software CSPRNG if needed

### Password Generation

```bash
# Generate strong random password
python -m openssl_encrypt.crypt generate-password --length 24 --all-chars

# Custom character set password
python -m openssl_encrypt.crypt generate-password --length 20 --no-special
```

## Template-Based Security Profiles

### Available Templates

1. **quick**: Balanced security for regular use
   - Argon2id (512MB RAM, 2 iterations)
   - Single-layer key derivation

2. **standard** (default): Strong security
   - Argon2id (1GB RAM, 3 iterations)
   - PBKDF2 secondary KDF
   - BLAKE3 file hashing

3. **paranoid**: Maximum security
   - Argon2id (2GB RAM, 4 iterations)
   - Multiple KDF layers
   - All available hash functions
   - Secure memory level: maximum

```bash
# Use paranoid template
python -m openssl_encrypt.crypt encrypt -i critical.dat --template paranoid
```

## Security Considerations

### Storage System Limitations

- SSD wear leveling may retain old data
- RAID systems may have multiple copies
- File system journaling may preserve fragments
- Cloud storage may create automatic backups

### Recommendations

1. **Password Management**:
   - Use generated passwords when possible
   - Store passwords securely (password manager)
   - Change passwords regularly
   - Never reuse passwords

2. **File Handling**:
   - Verify encryption success before deleting originals
   - Use `--verify` option for critical files
   - Keep secure backups of encrypted files
   - Test decryption process regularly

3. **System Security**:
   - Keep system and tool updated
   - Use full-disk encryption
   - Monitor system logs
   - Maintain secure backups

## Emergency Procedures

### Data Compromise Response

1. Immediately revoke compromised passwords
2. Re-encrypt affected files with new passwords
3. Verify secure deletion of old files
4. Document incident and review security measures

### Recovery Process

1. Maintain encrypted backups
2. Test recovery procedures regularly
3. Document all encryption parameters
4. Store recovery information securely

For additional security information or to report security issues, please use the project's security contact channels.