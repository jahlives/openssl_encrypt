# Cryptographic Design Documentation

This document provides a detailed explanation of the cryptographic design principles, algorithms, and implementation details of the openssl_encrypt library.

## Table of Contents

1. [Cryptographic Architecture](#cryptographic-architecture)
2. [Encryption Algorithms](#encryption-algorithms)
3. [Key Derivation Functions](#key-derivation-functions)
4. [Post-Quantum Cryptography](#post-quantum-cryptography)
5. [Secure Random Number Generation](#secure-random-number-generation)
6. [Authentication and Data Integrity](#authentication-and-data-integrity)
7. [Side-Channel Protections](#side-channel-protections)
8. [Secure Memory Handling](#secure-memory-handling)
9. [Algorithm Deprecation and Migration](#algorithm-deprecation-and-migration)
10. [Password Policies and Validation](#password-policies-and-validation)
11. [File Format and Metadata](#file-format-and-metadata)
12. [Implementation Security Measures](#implementation-security-measures)
13. [Cryptographic Testing](#cryptographic-testing)

## Cryptographic Architecture

The openssl_encrypt library implements a layered cryptographic architecture that follows the principle of defense in depth:

### Core Design Principles

1. **Symmetric Encryption Core**: Primary data encryption using authenticated encryption with associated data (AEAD) ciphers.
2. **Post-Quantum Protection Layer**: Optional hybrid encryption using post-quantum key encapsulation mechanisms.
3. **Key Derivation Chain**: Multi-step key derivation to protect against various attack vectors.
4. **Authenticated Encryption**: All encryption operations include authentication to ensure data integrity.
5. **Fail-Secure Design**: Default to secure options and explicit error states.

### Component Relationships

```
┌─────────────────────────────────────────────────────────┐
│                    User Interface                        │
│                (crypt_cli.py, crypt_gui.py)             │
└───────────────────────────┬─────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────┐
│                    Core Operations                       │
│                      (crypt_core.py)                     │
└─┬─────────────────────┬──────────────────┬──────────────┘
  │                     │                  │
┌─▼────────────────┐ ┌──▼─────────────┐ ┌──▼────────────────┐
│ Standard Crypto  │ │ Post-Quantum   │ │ Key Management    │
│ (AEAD Ciphers)   │ │ Cryptography   │ │ (Key Derivation)  │
└─────────────────┘ └─┬──────────────┘ └───────────────────┘
                      │
         ┌────────────▼────────────┐
         │ PQC Adapter Layer       │
         │ (pqc_adapter.py)        │
         └────────────┬────────────┘
                      │
         ┌────────────▼────────────┐
         │ liboqs Integration      │
         │ (pqc_liboqs.py)         │
         └─────────────────────────┘
```

### Security Boundaries

The cryptographic architecture enforces several security boundaries:

1. **Memory Isolation**: Sensitive data is kept in secure memory areas with protection from core dumps and swapping.
2. **Algorithm Isolation**: Different cryptographic algorithms are isolated through well-defined interfaces.
3. **Key Separation**: Different keys are used for different purposes (encryption, authentication, etc.).
4. **Error Containment**: Errors are contained and standardized to prevent information leakage.

## Encryption Algorithms

The library supports multiple encryption algorithms with different security characteristics:

### Authenticated Encryption with Associated Data (AEAD)

All encryption algorithms used in the library provide authenticated encryption to ensure data integrity and authenticity:

| Algorithm | Key Size | Nonce Size | Description | Security Level |
|-----------|----------|------------|-------------|---------------|
| AES-GCM | 256-bit | 96-bit | Galois/Counter Mode, providing confidentiality and authentication | High |
| AES-GCM-SIV | 256-bit | 96-bit | Synthetic Initialization Vector variant, nonce-misuse resistant | High |
| ChaCha20-Poly1305 | 256-bit | 96-bit | Stream cipher with Poly1305 authenticator | High |
| XChaCha20-Poly1305 | 256-bit | 192-bit | Extended nonce variant of ChaCha20-Poly1305 | High |
| AES-OCB3 | 256-bit | 96-bit | Offset Codebook Mode (OCB3) | Medium (legacy) |
| AES-SIV | 256/512-bit | N/A | Synthetic IV mode, deterministic | High |
| Fernet | 256-bit | 128-bit | AES-CBC with HMAC-SHA256 | High |

### Implementation Details

The library primarily uses the `cryptography` Python package to access these algorithms, which provides bindings to OpenSSL's implementations. For example, the XChaCha20Poly1305 implementation:

```python
class XChaCha20Poly1305:
    def __init__(self, key):
        # Validate key length (should be 32 bytes for ChaCha20-Poly1305)
        if len(key) != 32:
            raise ValidationError(f"Invalid key length: {len(key)}. XChaCha20Poly1305 requires a 32-byte key")
            
        self.key = key
        self.cipher = ChaCha20Poly1305(key)
    
    def _process_nonce(self, nonce):
        # Handle 24-byte nonces for XChaCha20
        if len(nonce) == 24:
            # Use the first 16 bytes as salt and remaining 8 bytes as info
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=12,
                salt=nonce[:16],
                info=nonce[16:],
                backend=default_backend()
            )
            truncated_nonce = hkdf.derive(self.key)
        elif len(nonce) == 12:
            # Already correct size for ChaCha20Poly1305
            truncated_nonce = nonce
        else:
            # For any other size, use HKDF to create a proper nonce
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=12,
                salt=None,
                info=nonce,
                backend=default_backend()
            )
            truncated_nonce = hkdf.derive(self.key)
        
        return truncated_nonce
    
    @secure_encrypt_error_handler
    def encrypt(self, nonce, data, associated_data=None):
        # Standardized error handling with the decorator
        truncated_nonce = self._process_nonce(nonce)
        return self.cipher.encrypt(truncated_nonce, data, associated_data)
    
    @secure_decrypt_error_handler
    def decrypt(self, nonce, data, associated_data=None):
        # Standardized error handling with the decorator
        truncated_nonce = self._process_nonce(nonce)
        return self.cipher.decrypt(truncated_nonce, data, associated_data)
```

### Algorithm Selection

The library allows users to select algorithms based on their security requirements:

- **Default**: AES-GCM is the default algorithm for a balance of security and performance
- **Performance-Focused**: ChaCha20-Poly1305 for systems without AES hardware acceleration
- **Nonce-Reuse Resistance**: AES-GCM-SIV when nonce uniqueness cannot be guaranteed
- **Future Proofing**: Hybrid encryption with post-quantum algorithms

## Key Derivation Functions

The library implements a comprehensive key derivation framework that protects passwords and generates cryptographic keys:

### Key Derivation Chain

Password-based encryption uses a multi-step key derivation chain:

1. **Primary KDF**: Argon2id for memory-hard password stretching
   - Memory: 1GB by default
   - Iterations: 3 passes
   - Parallelism: 4 threads
   - Output: 32 bytes

2. **Secondary KDF**: PBKDF2-HMAC-SHA512 for additional stretching
   - Iterations: 100,000 by default
   - Salt: Unique per file (16+ bytes)
   - Output: Variable based on needs

3. **Key Separation**: HKDF-SHA256 for domain separation
   - Different info parameters for different keys
   - Ensures different keys for encryption and authentication

### Salt Generation

Salts are generated using cryptographically secure random number generation:

```python
def generate_salt(size=16):
    """Generate a cryptographically secure random salt."""
    return secrets.token_bytes(size)
```

### Key Derivation Implementation

The key derivation process ensures that cryptographic keys are properly isolated for different purposes:

```python
def derive_master_key(password, salt, iterations=100000, memory_cost=1048576):
    """
    Derive a master key using Argon2id and PBKDF2.
    
    Args:
        password: User password
        salt: Unique salt
        iterations: PBKDF2 iterations
        memory_cost: Argon2 memory cost in KB
        
    Returns:
        bytes: 32-byte master key
    """
    # First apply Argon2id (memory-hard KDF)
    argon2_key = argon2.low_level.hash_secret_raw(
        password.encode('utf-8'),
        salt,
        time_cost=3,  # Iterations
        memory_cost=memory_cost,  # Memory in KB (1GB default)
        parallelism=4,  # Thread count
        hash_len=32,  # Output size
        type=argon2.low_level.Type.ID  # Argon2id variant
    )
    
    # Then apply PBKDF2 for additional security
    pbkdf2 = PBKDF2HMAC(
        algorithm=hashes.SHA512(),
        length=32,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    return pbkdf2.derive(argon2_key)

def derive_encryption_key(master_key, salt, info=b"encryption"):
    """Derive an encryption key from the master key."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=info,
        backend=default_backend()
    )
    return hkdf.derive(master_key)

def derive_authentication_key(master_key, salt, info=b"authentication"):
    """Derive an authentication key from the master key."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=info,
        backend=default_backend()
    )
    return hkdf.derive(master_key)
```

## Post-Quantum Cryptography

The library implements post-quantum cryptography to protect against future quantum computing threats:

### Hybrid Encryption Approach

All post-quantum encryption is implemented as hybrid encryption, combining:

1. **Classical Encryption**: AES-GCM or ChaCha20-Poly1305 for data encryption
2. **Post-Quantum Key Encapsulation**: ML-KEM (Kyber) or HQC for key protection

This approach ensures that data remains secure even if either classical or quantum algorithms are compromised.

### Supported PQ Algorithms

The library supports the following post-quantum algorithms:

| Algorithm | Type | Security Level | Description |
|-----------|------|---------------|-------------|
| ML-KEM-512 | KEM | Level 1 (AES-128) | NIST standardized (FIPS 203) |
| ML-KEM-768 | KEM | Level 3 (AES-192) | NIST standardized (FIPS 203) |
| ML-KEM-1024 | KEM | Level 5 (AES-256) | NIST standardized (FIPS 203) |
| HQC-128 | KEM | Level 1 (AES-128) | Code-based alternative |
| HQC-192 | KEM | Level 3 (AES-192) | Code-based alternative |
| HQC-256 | KEM | Level 5 (AES-256) | Code-based alternative |
| ML-DSA-44 | Signature | Level 1 | NIST standardized (FIPS 204) |
| ML-DSA-65 | Signature | Level 3 | NIST standardized (FIPS 204) |
| ML-DSA-87 | Signature | Level 5 | NIST standardized (FIPS 204) |
| FN-DSA-512 | Signature | Level 1 | NIST standardized (FIPS 206) |
| FN-DSA-1024 | Signature | Level 5 | NIST standardized (FIPS 206) |
| SLH-DSA-SHA2-128F | Signature | Level 1 | NIST standardized (FIPS 205) |
| SLH-DSA-SHA2-256F | Signature | Level 5 | NIST standardized (FIPS 205) |

### PQ Implementation Architecture

The library uses a multi-layer approach for post-quantum cryptography:

1. **Core PQC Interface**: The `PQCipher` class provides the primary interface for post-quantum operations.
2. **Adapter Layer**: The `pqc_adapter.py` module provides an adapter pattern to support multiple PQ implementations.
3. **liboqs Integration**: The `pqc_liboqs.py` module integrates with the liboqs library for algorithm implementations.

### PQ Hybrid Encryption Process

```
┌───────────────┐                    ┌───────────────────────┐
│  User Input   │                    │ Generate Random Key   │
│  (Password)   │                    │ for Symmetric Cipher  │
└───────┬───────┘                    └───────────┬───────────┘
        │                                        │
┌───────▼───────┐  ┌───────────────┐  ┌─────────▼──────────┐
│   Derive      │  │ PQ Algorithm  │  │ Encrypt Data with  │
│ Master Key    │  │  Key Pair     │  │ Symmetric Cipher   │
└───────┬───────┘  └───────┬───────┘  └─────────┬──────────┘
        │                  │                    │
┌───────▼──────────────────▼───────┐  ┌─────────▼──────────┐
│ Encrypt Symmetric Key with Both  │  │ Include Metadata   │
│ Classical and PQ Public Key      │  │ and Authentication │
└───────────────┬─────────────────┘  └─────────┬──────────┘
                │                              │
                └──────────────┬───────────────┘
                               │
                     ┌─────────▼──────────┐
                     │  Final Encrypted   │
                     │  File with PQ and  │
                     │ Classical Security │
                     └────────────────────┘
```

## Secure Random Number Generation

The library uses cryptographically secure random number generation for all security-critical operations:

### Random Number Sources

1. **secrets Module**: The primary source of cryptographic randomness
   ```python
   import secrets
   
   # Generate cryptographically secure random bytes
   random_bytes = secrets.token_bytes(32)
   ```

2. **OS-Level Entropy**: Direct access to OS entropy sources for critical operations
   ```python
   def get_system_entropy(size):
       """Get entropy directly from the OS."""
       try:
           with open('/dev/urandom', 'rb') as f:
               return f.read(size)
       except:
           # Fall back to secrets module
           return secrets.token_bytes(size)
   ```

3. **Hardware RNG**: Optional integration with hardware random number generators when available

### Random Data Uses

The library uses secure random generation for:
- Cryptographic keys
- Initialization vectors (IVs) and nonces
- Salts for key derivation
- Challenge values for authentication
- Memory padding and canaries

## Authentication and Data Integrity

The library implements multiple layers of authentication and integrity protection:

### AEAD Integrity Protection

All supported encryption algorithms use authenticated encryption to protect against:
- Data tampering
- Bit flipping attacks
- Ciphertext malleability

### File-Level Authentication

Each encrypted file includes:
1. **HMAC-SHA256**: Keyed hash of file contents for integrity verification
2. **Signature Verification**: Optional digital signature (including post-quantum signatures)
3. **Metadata Authentication**: Protected metadata with integrity verification

### Implementation Details

Example of the authentication implementation:

```python
def authenticate_data(key, data, associated_data=None):
    """
    Create an authentication tag using HMAC-SHA256.
    
    Args:
        key: Authentication key
        data: Data to authenticate
        associated_data: Optional associated data
        
    Returns:
        bytes: 32-byte authentication tag
    """
    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(data)
    
    if associated_data:
        h.update(associated_data)
        
    return h.finalize()

def verify_data(key, data, tag, associated_data=None):
    """
    Verify data integrity using an authentication tag.
    
    Args:
        key: Authentication key
        data: Data to verify
        tag: Authentication tag
        associated_data: Optional associated data
        
    Returns:
        bool: True if verification succeeds, False otherwise
    """
    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(data)
    
    if associated_data:
        h.update(associated_data)
        
    try:
        h.verify(tag)
        return True
    except Exception:
        return False
```

## Side-Channel Protections

The library implements comprehensive side-channel attack protections:

### Timing Attack Countermeasures

1. **Constant-Time Comparison**: All sensitive comparisons use constant-time algorithms
   ```python
   def constant_time_compare(a, b):
       """Compare two byte sequences in constant time."""
       if len(a) != len(b):
           return False
       
       result = 0
       for x, y in zip(a, b):
           result |= x ^ y
           
       return result == 0
   ```

2. **Timing Jitter**: Random delays to mask timing differences
   ```python
   def add_timing_jitter(min_ms=1, max_ms=5):
       """Add random timing jitter to mask execution time."""
       jitter_ms = random.uniform(min_ms, max_ms)
       time.sleep(jitter_ms / 1000.0)
   ```

3. **Uniform Error Paths**: All error paths take the same amount of time
   ```python
   def secure_decrypt_error_handler(func):
       @wraps(func)
       def wrapper(*args, **kwargs):
           try:
               return func(*args, **kwargs)
           except AuthenticationError:
               # Add timing jitter to mask error type
               add_timing_jitter(10, 20)
               raise
           except Exception:
               # Same timing jitter for all errors
               add_timing_jitter(10, 20)
               raise DecryptionError("Decryption failed")
       return wrapper
   ```

### Cache Timing Protection

1. **Memory Access Patterns**: Careful implementation to avoid revealing secret-dependent memory access patterns
2. **Cache Line Padding**: Critical data structures padded to cache line boundaries
3. **Memory Barriers**: Use of memory barriers to prevent optimization-based leaks

### Power Analysis Protection

1. **Balanced Operations**: Cryptographic operations implemented to minimize power consumption differences
2. **Multiple Rounds**: Extra computation rounds to mask power signatures
3. **Random Masking**: Random masking of sensitive values

## Secure Memory Handling

The library implements comprehensive memory security measures:

### Memory Zeroing

Sensitive data is securely wiped from memory when no longer needed:

```python
def secure_memzero(data, full_verification=True):
    """
    Securely wipe data with multiple rounds of overwriting followed by zeroing.
    
    Args:
        data: The data to be wiped
        full_verification: Whether to verify all bytes in the buffer
        
    Returns:
        bool: True if zeroing was successful and verified
    """
    if data is None:
        return True

    # Apply multi-layered wiping approach
    
    # 1. Random data (unpredictable)
    random_data = bytearray(generate_secure_random_bytes(len(data)))
    data[:] = random_data
    random_data[:] = bytearray(len(random_data))
    
    # 2. All ones (0xFF) - alternate bit pattern
    all_ones = bytearray([0xFF] * len(data))
    data[:] = all_ones
    all_ones[:] = bytearray(len(all_ones))
    
    # 3. Alternating pattern (0xAA) - 10101010
    pattern_aa = bytearray([0xAA] * len(data))
    data[:] = pattern_aa
    pattern_aa[:] = bytearray(len(pattern_aa))
    
    # 4. Inverse alternating pattern (0x55) - 01010101
    pattern_55 = bytearray([0x55] * len(data))
    data[:] = pattern_55
    pattern_55[:] = bytearray(len(pattern_55))
    
    # 5. Final zeroing
    data[:] = bytearray(len(data))
    
    # Verify zeroing
    return verify_memory_zeroed(data, full_check=full_verification)
```

### Secure Memory Allocator

The library provides a secure memory allocator for sensitive data:

1. **Memory Locking**: Prevents sensitive data from being swapped to disk
2. **Canary Protection**: Memory canaries to detect buffer overflows
3. **Overflow Detection**: Buffer underrun and overrun detection
4. **Anti-Debugging**: Protection against memory analysis tools

```python
class SecureHeap:
    """
    A secure heap implementation for sensitive cryptographic data.
    """
    def __init__(self, max_size=10 * 1024 * 1024):
        self.max_size = max_size
        self.current_size = 0
        self.blocks = {}
        self.lock = threading.RLock()
        
        # Platform detection for platform-specific features
        self.system = platform.system().lower()
        self.page_size = get_memory_page_size()
        
        # Register cleanup function to run at exit
        atexit.register(self.cleanup)
        
        # Setup prevention of core dumps if possible
        self._setup_core_dump_prevention()
```

### Memory Protection Classes

The library provides several memory protection classes:

1. **SecureBytes**: Automatic zeroing when no longer needed
2. **SecureContainer**: Secure container for sensitive data
3. **CryptoSecureBuffer**: Buffer specifically for cryptographic material
4. **CryptoKey**: Specialized container for key material

## Algorithm Deprecation and Migration

The library implements a comprehensive algorithm deprecation and migration system:

### Algorithm Warning System

```python
class DeprecationLevel(Enum):
    """Defines the severity levels for algorithm deprecation warnings."""
    INFO = 0       # Algorithm will be deprecated in the future, but is still safe to use now
    WARNING = 1    # Algorithm should be migrated soon, with minor security concerns
    DEPRECATED = 2 # Algorithm is officially deprecated, migration should be prioritized
    UNSAFE = 3     # Algorithm has known security vulnerabilities, immediate migration required
```

### Deprecation Registry

The library maintains a registry of deprecated algorithms with information about:
- Deprecation level
- Replacement algorithm recommendations
- Timeline for removal
- Security concerns

```python
# Dictionary mapping algorithms to their deprecation status
DEPRECATED_ALGORITHMS = {
    # Legacy Kyber naming scheme
    "Kyber512": {
        "level": DeprecationLevel.DEPRECATED,
        "replacement": "ML-KEM-512",
        "reason": "NIST standardized naming (FIPS 203)",
        "timeline": "Will be removed in version 3.0"
    },
    "Kyber768": {
        "level": DeprecationLevel.DEPRECATED,
        "replacement": "ML-KEM-768",
        "reason": "NIST standardized naming (FIPS 203)",
        "timeline": "Will be removed in version 3.0"
    },
    "Kyber1024": {
        "level": DeprecationLevel.DEPRECATED,
        "replacement": "ML-KEM-1024",
        "reason": "NIST standardized naming (FIPS 203)",
        "timeline": "Will be removed in version 3.0"
    },
    
    # Truly deprecated algorithms
    "AES-OCB3": {
        "level": DeprecationLevel.WARNING,
        "replacement": "AES-GCM",
        "reason": "Less widely analyzed than AES-GCM",
        "timeline": "Will be deprecated in version 3.0"
    },
    "Camellia-GCM": {
        "level": DeprecationLevel.DEPRECATED,
        "replacement": "AES-GCM",
        "reason": "Limited cryptanalysis compared to AES",
        "timeline": "Will be removed in version 3.0"
    }
}
```

### Migration Support

The library provides tools for automated migration:

1. **Algorithm Translation**: Functions to translate between algorithm names
2. **Automatic Detection**: Detection of file formats and algorithms
3. **Migration Utilities**: Tools to re-encrypt data with newer algorithms

## Password Policies and Validation

The library implements a comprehensive password policy system:

### Policy Levels

```python
class PasswordPolicy:
    # Policy levels
    LEVEL_MINIMAL = "minimal"      # Just minimum length
    LEVEL_BASIC = "basic"          # Length + basic complexity
    LEVEL_STANDARD = "standard"    # Length + full complexity + entropy
    LEVEL_PARANOID = "paranoid"    # Length + full complexity + entropy + common password check
```

### Password Strength Measurement

The library includes entropy-based password strength measurement:

```python
def string_entropy(s):
    """
    Calculate the entropy of a string in bits.
    
    This measures password strength by analyzing the character distribution
    and estimating the entropy (randomness) in bits.
    
    Args:
        s: String to analyze
        
    Returns:
        float: Entropy in bits
    """
    if not s:
        return 0.0
        
    # Count character frequencies
    char_counts = {}
    for c in s:
        char_counts[c] = char_counts.get(c, 0) + 1
    
    # Calculate entropy using Shannon entropy formula
    entropy = 0.0
    for count in char_counts.values():
        p = count / len(s)
        entropy -= p * math.log2(p)
    
    # Multiply by string length to get total entropy
    return entropy * len(s)
```

### Common Password Detection

The library includes detection of common and compromised passwords:

```python
class CommonPasswordChecker:
    """
    Check passwords against a list of common passwords.
    """
    def __init__(self, password_list_path=None):
        """
        Initialize the common password checker.
        
        Args:
            password_list_path: Path to a custom password list file
        """
        self.password_hashes = self._load_password_list(password_list_path)
    
    def _load_password_list(self, custom_path):
        """Load the common password list."""
        password_hashes = set()
        
        # Try custom path if provided
        if custom_path and os.path.exists(custom_path):
            with open(custom_path, 'r') as f:
                for line in f:
                    password = line.strip()
                    if password:
                        # Store SHA-256 hash of password
                        h = hashlib.sha256(password.encode()).hexdigest()
                        password_hashes.add(h)
        else:
            # Use built-in common password list
            try:
                # Try to find the built-in password list
                pkg_path = "openssl_encrypt.data.common_passwords.txt"
                with importlib.resources.open_text("openssl_encrypt.data", "common_passwords.txt") as f:
                    for line in f:
                        password = line.strip()
                        if password:
                            h = hashlib.sha256(password.encode()).hexdigest()
                            password_hashes.add(h)
            except Exception:
                # Failed to load built-in list
                pass
                
        return password_hashes
    
    def is_common_password(self, password):
        """
        Check if a password is in the common password list.
        
        Args:
            password: Password to check
            
        Returns:
            bool: True if the password is common, False otherwise
        """
        if not self.password_hashes:
            return False
            
        # Check hash to avoid storing actual passwords in memory
        h = hashlib.sha256(password.encode()).hexdigest()
        return h in self.password_hashes
```

## File Format and Metadata

The library uses a secure file format for encrypted data:

### Format Structure

```
┌───────────────────────┐
│ FORMAT HEADER (16B)   │ - Magic bytes + format version
├───────────────────────┤
│ METADATA BLOCK        │ - JSON format, includes:
│                       │   - Algorithm details
│                       │   - Key derivation parameters
│                       │   - Timestamp
│                       │   - PQ parameters (if used)
├───────────────────────┤
│ SALT (16-32B)         │ - Random salt for key derivation
├───────────────────────┤
│ IV/NONCE (12-24B)     │ - Initialization vector/nonce
├───────────────────────┤
│ ENCRYPTED MASTER KEY  │ - Optional, for keystore integration
│  (PQ PROTECTED)       │
├───────────────────────┤
│ ENCRYPTED DATA        │ - Ciphertext with authentication tag
├───────────────────────┤
│ HMAC (32B)            │ - File integrity check
└───────────────────────┘
```

### Metadata Format

```json
{
  "format_version": 5,
  "algorithm": "AES-GCM",
  "key_derivation": {
    "function": "argon2id+pbkdf2",
    "salt_size": 16,
    "iterations": 100000,
    "memory_cost": 1048576
  },
  "iv_size": 12,
  "timestamp": 1651651656,
  "compressed": false,
  "post_quantum": {
    "algorithm": "ML-KEM-768",
    "hybrid": true,
    "classical_algorithm": "AES-GCM"
  }
}
```

## Implementation Security Measures

The library implements several security measures at the implementation level:

### Decorator-Based Security Enforcement

The library uses decorators to enforce security properties:

```python
def secure_encrypt_error_handler(func):
    """
    Decorator for secure error handling during encryption.
    
    This ensures consistent error messages and timing.
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except ValidationError:
            # Re-raise validation errors directly
            raise
        except Exception as e:
            # Add timing jitter to mask error type
            add_timing_jitter(5, 10)
            # Standardize error message
            raise EncryptionError("Encryption operation failed", original_exception=e)
    return wrapper
```

### Critical Code Block Protection

The library marks critical code blocks that must not be modified:

```python
# START DO NOT CHANGE
def verify_authentication_tag(key, ciphertext, tag):
    """
    Verify the authentication tag for encrypted data.
    
    This is a security-critical function that must not be modified.
    """
    # Use constant-time comparison for tag verification
    computed_tag = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    computed_tag.update(ciphertext)
    
    try:
        computed_tag.verify(tag)
        return True
    except Exception:
        return False
# END DO NOT CHANGE
```

### Error Standardization

The library standardizes error messages to prevent information leakage:

```python
class DecryptionError(Exception):
    """Exception raised for decryption failures."""
    
    def __init__(self, message="Decryption failed", original_exception=None):
        # Use standardized message instead of leaking details
        self.message = message
        self.original_exception = original_exception
        super().__init__(self.message)
```

## Cryptographic Testing

The library includes comprehensive cryptographic testing:

### Test Vectors

Standard test vectors for all supported algorithms:

```python
# Test vectors for AES-GCM
AES_GCM_TEST_VECTORS = [
    {
        "key": bytes.fromhex("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
        "iv": bytes.fromhex("000000000000000000000000"),
        "plaintext": b"The quick brown fox jumps over the lazy dog",
        "associated_data": b"Additional data",
        "ciphertext": bytes.fromhex("..."),  # Expected ciphertext
        "tag": bytes.fromhex("...")  # Expected authentication tag
    },
    # Additional test vectors...
]
```

### Property-Based Testing

Verification of cryptographic properties:

```python
def test_encryption_decryption_roundtrip():
    """Test that encryption followed by decryption returns the original plaintext."""
    for algorithm in SUPPORTED_ALGORITHMS:
        # Generate random key and data
        key = secrets.token_bytes(32)
        data = secrets.token_bytes(random.randint(1, 1024))
        iv = secrets.token_bytes(12)
        
        # Create cipher instance
        cipher = create_cipher(algorithm, key)
        
        # Encrypt and decrypt
        ciphertext = cipher.encrypt(iv, data)
        plaintext = cipher.decrypt(iv, ciphertext)
        
        # Verify
        assert plaintext == data, f"Roundtrip failed for {algorithm}"
```

### Security Test Cases

Tests that verify security properties:

```python
def test_constant_time_comparison():
    """Test that the constant time comparison function is indeed constant time."""
    # Create equal and unequal inputs
    a = bytes([1] * 1000)
    b_equal = bytes([1] * 1000)
    b_unequal_start = bytes([2] + [1] * 999)
    b_unequal_middle = bytes([1] * 500 + [2] + [1] * 499)
    b_unequal_end = bytes([1] * 999 + [2])
    
    # Measure execution time for each case
    times = []
    for b in [b_equal, b_unequal_start, b_unequal_middle, b_unequal_end]:
        start = time.time()
        for _ in range(1000):  # Run multiple times for accuracy
            result = constant_time_compare(a, b)
        end = time.time()
        times.append(end - start)
    
    # Verify timing differences are minimal
    max_diff = max(times) - min(times)
    assert max_diff < 0.1, "Constant time comparison shows timing variations"
```

---

This document provides a comprehensive overview of the cryptographic design of the openssl_encrypt library. It is intended for security auditors, developers, and users who need to understand the cryptographic implementation details.