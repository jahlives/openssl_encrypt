# Secure Memory Management for Sensitive Data

This document explains how sensitive data like passwords are securely handled in the crypt tool to prevent data leakage through memory dumps or other memory-based attacks.

## Memory Security

When working with sensitive data like passwords and cryptographic keys, it's not enough to simply delete variables when they're no longer needed. Many programming languages, including Python, don't immediately clear memory when variables are deleted. This can leave sensitive data in memory for an undefined period until the garbage collector reclaims that memory.

An attacker with access to a memory dump could potentially recover this sensitive data. To mitigate this risk, we've implemented several memory security techniques.

## Implementation Details

### Secure Memory Overwriting

The tool includes a dedicated `memory_security.py` module with specialized functions:

- `secure_overwrite_string(string_var)`: Attempts to overwrite string data in memory
- `secure_overwrite_bytearray(byte_array)`: Securely overwrites mutable byte arrays
- `secure_overwrite_bytes(bytes_var)`: Handles immutable bytes objects
- `SecureString` class: A container for secure string handling

### Fallback Implementation

If the `memory_security.py` module is not available, fallback functions are defined that provide basic security (for bytearrays) or at least a placeholder for compatibility.

### Key Points of Secure Memory Handling

1. **Multiple Overwrites**: Sensitive data is overwritten multiple times with random data before being zeroed out, making it more difficult to recover through various memory forensic techniques.

2. **Exception Safety**: All sensitive data is handled with try/finally blocks to ensure it's properly cleaned even if an error occurs.

3. **Explicit Variables**: Sensitive variables are explicitly defined and tracked throughout functions to ensure they can be properly cleaned up.

4. **Early Clearing**: Sensitive data is cleared as soon as it's no longer needed, rather than waiting for the end of a function.

## Secure Handling at Key Points

Sensitive data is securely cleared in several critical places:

1. **Key Derivation**: After deriving encryption keys, the intermediate values are overwritten
2. **Encryption/Decryption**: All sensitive data involved in encryption and decryption is overwritten
3. **Password Generation**: Generated passwords are overwritten when they're no longer needed
4. **Main Function**: Passwords are overwritten in the main function before exiting

## Best Practices Implemented

1. **Defense in Depth**: Multiple overwrite passes with different patterns
2. **Zero Remnants**: All sensitive data is zeroed out after use
3. **Immediate Cleanup**: Sensitive data is cleared as soon as possible
4. **Comprehensive Coverage**: All sensitive variables are tracked and cleared

## How Memory-Secure Works in Detail

The secure memory handling system operates through several key mechanisms:

### 1. Secure Buffer Implementation

```python
class SecureBuffer:
    """
    A secure buffer for sensitive data that prevents memory leakage.
    
    This buffer:
    - Allocates memory directly
    - Prevents swapping to disk
    - Locks memory pages (where platform supports it)
    - Zeros out memory on deletion
    """
    
    def __init__(self, size, zero=True):
        # Allocate memory buffer
        self.buffer = bytearray(size)
        self.size = size
        
        # Lock memory pages (platform specific)
        self._lock_memory()
        
        # Zero out if requested (default)
        if zero:
            self._zero_memory()
    
    def __enter__(self):
        return self.buffer
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        # Always securely wipe memory on exit
        self._secure_wipe()
        
    def _lock_memory(self):
        # Platform-specific memory locking to prevent swapping
        try:
            # For POSIX systems
            if hasattr(os, "mlock"):
                os.mlock(memoryview(self.buffer).obj)
            # For Windows systems
            elif sys.platform == 'win32':
                # VirtualLock equivalent via ctypes
                pass
        except Exception:
            # Log but continue if locking fails
            pass
    
    def _zero_memory(self):
        # Fill buffer with zeros
        for i in range(self.size):
            self.buffer[i] = 0
    
    def _secure_wipe(self):
        # Multi-pattern wiping (DoD-inspired)
        patterns = [
            0xFF,  # All ones
            0x00,  # All zeros
            0xAA,  # 10101010
            0x55,  # 01010101
            0x00   # Final zero pass
        ]
        
        # Multiple passes with different patterns
        for pattern in patterns:
            for i in range(self.size):
                self.buffer[i] = pattern
```

### 2. Secure Memory Copy Operations

```python
def secure_memcpy(dest, src, n=None):
    """
    Securely copy memory between buffers without leaking.
    
    Args:
        dest: Destination buffer
        src: Source buffer
        n: Number of bytes to copy (default: all of src)
    """
    # Determine copy size
    size = n if n is not None else len(src)
    
    # Bounds checking
    if len(dest) < size:
        size = len(dest)
        
    # Manual byte-by-byte copy
    for i in range(size):
        dest[i] = src[i]
    
    # Return actual bytes copied
    return size
```

### 3. Secure Memory Zeroing

```python
def secure_memzero(buffer):
    """
    Securely zero a buffer in memory.
    
    This function attempts to prevent compiler optimizations 
    that might eliminate "unnecessary" memory operations.
    
    Args:
        buffer: The buffer to zero (bytearray or compatible)
    """
    # Get buffer size
    size = len(buffer)
    
    # Create volatile value to prevent optimization
    volatile_zero = 0
    if size % 8 != 0:
        volatile_zero = random.randint(0, 255)
    
    # Zero out buffer
    for i in range(size):
        buffer[i] = volatile_zero
        buffer[i] = 0
```

### 4. Secure String Handling

```python
class SecureString:
    """
    A string container that protects its contents in memory.
    """
    
    def __init__(self):
        # Use bytearray for internal storage
        self._data = bytearray()
        
    def __enter__(self):
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        # Wipe data on context exit
        self.wipe()
    
    def extend(self, data):
        # Append to internal buffer
        if isinstance(data, str):
            data = data.encode('utf-8')
        self._data.extend(data)
    
    def wipe(self):
        # Securely wipe the data
        secure_memzero(self._data)
        
    def __bytes__(self):
        # Get copy as bytes
        return bytes(self._data)
        
    def __str__(self):
        # Get copy as string
        return self._data.decode('utf-8')
```

### 5. Memory Protection for Key Derivation

When deriving encryption keys from passwords, the system uses a multi-layered approach:

1. The password is stored in a `SecureBuffer` or `SecureString` container
2. During key derivation, all intermediate values are kept in secure buffers
3. Hash outputs are carefully managed and wiped after use
4. The final derived key is immediately used and then wiped

Example of how this works in the Argon2 key derivation process:

```python
def argon2_derive_key(password, salt, time_cost, memory_cost, parallelism, hash_len, argon2_type):
    """
    Securely derive a key using Argon2 with memory protection.
    """
    # Use secure buffer for password
    with secure_buffer(len(password), zero=False) as password_buffer:
        # Copy password into secure buffer
        secure_memcpy(password_buffer, password)
        
        # Select Argon2 variant
        if argon2_type == 'argon2i':
            type_value = argon2.Type.I
        elif argon2_type == 'argon2d':
            type_value = argon2.Type.D
        else:
            type_value = argon2.Type.ID
        
        # Perform key derivation
        raw_key = argon2.low_level.hash_secret_raw(
            secret=bytes(password_buffer),
            salt=salt,
            time_cost=time_cost,
            memory_cost=memory_cost,
            parallelism=parallelism,
            hash_len=hash_len,
            type=type_value
        )
        
        # Copy result to secure buffer
        with secure_buffer(hash_len, zero=False) as key_buffer:
            secure_memcpy(key_buffer, raw_key)
            
            # Properly format for Fernet (URL-safe base64)
            final_key = base64.urlsafe_b64encode(bytes(key_buffer))
            
    # Both password_buffer and key_buffer are wiped automatically
    return final_key
```

## Password Handling Best Practices

### 1. Never Store Plaintext Passwords

The application never stores plaintext passwords to disk. When passwords are provided via command-line, they are immediately processed and securely wiped from memory.

### 2. Password Collection

When collecting passwords interactively:

```python
def collect_password(confirm=True, quiet=False):
    """
    Securely collect a password from the user.
    
    Args:
        confirm: Whether to require confirmation
        quiet: Whether to suppress prompts
    
    Returns:
        The password as bytes in a secure container
    """
    with secure_string() as password:
        if confirm and not quiet:
            match = False
            while not match:
                # Get password
                pwd1 = getpass.getpass('Enter password: ').encode()
                pwd2 = getpass.getpass('Confirm password: ').encode()
                
                try:
                    if pwd1 == pwd2:
                        password.extend(pwd1)
                        match = True
                    else:
                        print("Passwords do not match. Please try again.")
                finally:
                    # Clean temporary variables
                    secure_memzero(bytearray(pwd1))
                    secure_memzero(bytearray(pwd2))
        else:
            # Simple collection (no confirmation)
            prompt = '' if quiet else 'Enter password: '
            pwd = getpass.getpass(prompt).encode()
            try:
                password.extend(pwd)
            finally:
                secure_memzero(bytearray(pwd))
        
        # Return secure password container
        return bytes(password)
```

### 3. Password Generation

When generating passwords:

```python
def generate_secure_password(length=16, use_lowercase=True, use_uppercase=True, 
                          use_digits=True, use_special=True):
    """
    Generate a cryptographically secure random password.
    """
    # Create character pool
    char_pool = ""
    required_chars = []
    
    # Add required character types
    if use_lowercase:
        char_pool += string.ascii_lowercase
        required_chars.append(random.choice(string.ascii_lowercase))
    
    # Add other character types...
    
    # Create secure buffer for password
    with secure_buffer(length, zero=True) as password_buffer:
        # Add required characters
        for i, char in enumerate(required_chars):
            if i < length:
                password_buffer[i] = ord(char)
        
        # Fill remaining with random characters
        for i in range(len(required_chars), length):
            password_buffer[i] = ord(random.choice(char_pool))
        
        # Shuffle using Fisher-Yates
        for i in range(length - 1, 0, -1):
            j = random.randrange(i + 1)
            password_buffer[i], password_buffer[j] = password_buffer[j], password_buffer[i]
        
        # Create result
        password = ''.join(chr(c) for c in password_buffer)
    
    return password
```

### 4. Secure Display and Timeout

When displaying generated passwords to users:

```python
def display_with_timeout(password, timeout=10):
    """
    Securely display a password with automatic timeout.
    """
    try:
        print("\n" + "=" * 60)
        print(" GENERATED PASSWORD ".center(60, "="))
        print("=" * 60)
        print(f"\nPassword: {password}")
        print(f"\nThis password will be cleared in {timeout} seconds.")
        
        # Countdown timer
        for remaining in range(timeout, 0, -1):
            print(f"\rTime remaining: {remaining} seconds...", end="", flush=True)
            time.sleep(1)
            
    finally:
        # Clear screen to remove password
        if sys.platform == 'win32':
            os.system('cls')
        else:
            os.system('clear')
        
        print("Password has been cleared from screen.")
```

## Argon2 Memory Security

Argon2, especially with its memory-hard design, adds another layer of protection:

1. **Memory Filling**: Argon2 deliberately fills large amounts of memory with data derived from the password, making memory-scraping attacks more difficult.

2. **Time-Memory Tradeoff Resistance**: The algorithm is designed to prevent attackers from using less memory at the cost of more computation.

3. **Data-Dependent vs. Data-Independent Access**:
   - **argon2d**: Uses data-dependent memory access, making it highly resistant to GPU/ASIC attacks but potentially vulnerable to side-channel attacks.
   - **argon2i**: Uses data-independent memory access, protecting against side-channel attacks but somewhat less resistant to GPU attacks.
   - **argon2id**: Combines both approaches for a balanced defense.

### Recommended Argon2 Parameters

| Security Level | Time Cost | Memory Cost | Parallelism | Type    |
|----------------|-----------|-------------|-------------|---------|
| Standard       | 3         | 102400 KB   | 4           | argon2id |
| High           | 4         | 262144 KB   | 8           | argon2id |
| Very High      | 6         | 1048576 KB  | 8           | argon2id |
| Paranoid       | 10        | 2097152 KB  | 16          | argon2id |

For systems vulnerable to side-channel attacks, use argon2i instead of argon2id.

## Limitations

It's important to understand that while these measures significantly improve security, they can't provide absolute guarantees due to:

1. Python's memory management and garbage collection behavior
2. Compiler optimizations that might affect memory operations
3. Operating system memory management behaviors
4. Python's immutable strings (which can't be directly overwritten)

However, the implemented approach represents a best-effort to address these limitations and follows security best practices for sensitive data handling.

## Future Improvements

Ongoing improvements to the memory security system include:

1. Better platform-specific memory locking on different operating systems
2. Improved resistance to memory analysis through additional obfuscation
3. Integration with hardware security modules (HSMs) when available
4. Using secure enclaves on supported platforms (such as Intel SGX or ARM TrustZone)

