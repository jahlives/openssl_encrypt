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