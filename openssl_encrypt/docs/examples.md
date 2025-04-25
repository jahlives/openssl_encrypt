## Command-Line Examples

### Basic Encryption/Decryption

```bash
# Encrypt a file (creates file.txt.encrypted)
python crypt.py encrypt -i file.txt

# Decrypt a file
python crypt.py decrypt -i file.txt.encrypted -o file.txt

# Decrypt and display contents to screen (for text files)
python crypt.py decrypt -i config.encrypted

# Encrypt with specific algorithm
python crypt.py encrypt -i data.txt --algorithm aes-gcm

# Show progress during operation
python crypt.py encrypt -i largefile.dat --progress

# Show detailed hash information
python crypt.py encrypt -i file.txt --verbose
```

### Template Usage

```bash
# Use quick template for faster operation
python crypt.py encrypt -i file.txt --template quick

# Use standard security template (default)
python crypt.py encrypt -i file.txt --template standard

# Use paranoid template for maximum security
python crypt.py encrypt -i file.txt --template paranoid

# Use custom template from template directory
python crypt.py encrypt -i file.txt --template my_custom_template
```

### Password Features

```bash
# Generate a secure random password
python crypt.py generate-password

# Generate a custom password (20 chars, only lowercase and digits)
python crypt.py generate-password --length 20 --use-lowercase --use-digits

# Generate password with all character types
python crypt.py generate-password --length 24 --use-lowercase --use-uppercase --use-digits --use-special

# Encrypt with a randomly generated password
python crypt.py encrypt -i secret.txt --random 16

# The tool will display the generated password for 10 seconds, giving you time to save it
```

### Hash Configuration Examples

```bash
# Use SHA-256 with custom iterations
python crypt.py encrypt -i file.txt --sha256-rounds 2000000

# Use SHA-512 with default iterations
python crypt.py encrypt -i file.txt --sha512-rounds 1000000

# Use SHA3-256 with custom iterations
python crypt.py encrypt -i file.txt --sha3-256-rounds 1500000

# Use SHA3-512 with custom iterations
python crypt.py encrypt -i file.txt --sha3-512-rounds 800000

# Use Whirlpool with custom rounds
python crypt.py encrypt -i file.txt --whirlpool-rounds 500000

# Custom PBKDF2 iterations
python crypt.py encrypt -i file.txt --pbkdf2-iterations 150000
```

### Scrypt Configuration

```bash
# Enable Scrypt with default parameters
python crypt.py encrypt -i file.txt --enable-scrypt

# Custom Scrypt configuration
python crypt.py encrypt -i file.txt --enable-scrypt --scrypt-rounds 2 --scrypt-n 256 --scrypt-r 16 --scrypt-p 2

# High-memory Scrypt configuration
python crypt.py encrypt -i file.txt --enable-scrypt --scrypt-n 1024 --scrypt-r 32
```

### Argon2 Configuration

```bash
# Enable Argon2 with default parameters
python crypt.py encrypt -i file.txt --enable-argon2

# Custom Argon2 configuration
python crypt.py encrypt -i file.txt --enable-argon2 --argon2-rounds 2 --argon2-time 4

# High-memory Argon2 configuration
python crypt.py encrypt -i file.txt --enable-argon2 --argon2-memory 131072 --argon2-parallelism 8

# Use specific Argon2 variant
python crypt.py encrypt -i file.txt --enable-argon2 --argon2-type i

# Use Argon2 preset
python crypt.py encrypt -i file.txt --enable-argon2 --argon2-preset high
```

### Balloon Hashing Configuration

```bash
# Enable Balloon hashing with default parameters
python crypt.py encrypt -i file.txt --enable-balloon

# Custom Balloon configuration
python crypt.py encrypt -i file.txt --enable-balloon --balloon-time-cost 4 --balloon-space-cost 131072

# High-security Balloon configuration
python crypt.py encrypt -i file.txt --enable-balloon --balloon-rounds 4 --balloon-parallelism 8

# Custom hash length
python crypt.py encrypt -i file.txt --enable-balloon --balloon-hash-len 64
```

### Enhanced Security Options

```bash
# Encrypt with multiple hashing algorithms
python crypt.py encrypt -i important.docx --sha512-rounds 200000 --sha3-512-rounds 200000 --pbkdf2-iterations 200000

# Use Scrypt for memory-hard password protection (cost factor 2^15)
python crypt.py encrypt -i secrets.txt --enable-scrypt --scrypt-n 32768

# Combine multiple hash functions for layered security
python crypt.py encrypt -i critical.pdf --sha512-rounds 200000 --sha3-256-rounds 200000 --enable-scrypt

# Use Argon2 for state-of-the-art password hashing
python crypt.py encrypt -i topsecret.zip --enable-argon2 --argon2-time 3

# Configure Argon2 for maximum security
python crypt.py encrypt -i classified.db --enable-argon2 --argon2-time 10 --argon2-memory 1048576 --argon2-parallelism 8

# Use Argon2i for side-channel attack resistance
python crypt.py encrypt -i sensitive_data.txt --enable-argon2 --argon2-time 4 --argon2-type i

# Combine Argon2 with other hash functions for defense-in-depth
python crypt.py encrypt -i ultra_secret.dat --enable-argon2 --argon2-time 3 --sha3-512-rounds 200000 --pbkdf2-iterations 200000
```

### Managing Files

```bash
# Encrypt and overwrite the original file (in-place encryption)
python crypt.py encrypt -i confidential.txt --overwrite

# Decrypt and overwrite the encrypted file
python crypt.py decrypt -i important.encrypted --overwrite

# Encrypt and securely shred the original file
python crypt.py encrypt -i secret.doc -s

# Decrypt and securely shred the encrypted file
python crypt.py decrypt -i backup.encrypted -o backup.tar -s

# Quiet mode (minimal output)
python crypt.py encrypt -i file.txt -q
```

### Secure File Shredding

```bash
# Basic secure shredding
python crypt.py shred -i obsolete.txt

# Increased security with more overwrite passes
python crypt.py shred -i sensitive.doc --shred-passes 7

# Shred a directory recursively
python crypt.py shred -i old_project/ -r

# Shred multiple files using glob pattern
python crypt.py shred -i "temp*.log"

# Shred all files matching a pattern
python crypt.py shred -i "backup_*.old"
```

### Advanced Usage Combinations

```bash
# Maximum security configuration
python crypt.py encrypt -i critical.dat \
    --enable-argon2 --argon2-time 10 --argon2-memory 2097152 --argon2-parallelism 8 \
    --enable-scrypt --scrypt-n 32768 --scrypt-r 32 \
    --sha3-512-rounds 1000000 \
    --pbkdf2-iterations 500000 \
    --progress --verbose

# Quick but secure configuration
python crypt.py encrypt -i file.txt --template quick --progress

# Paranoid configuration with file shredding
python crypt.py encrypt -i secret.txt \
    --template paranoid \
    --shred --shred-passes 35 \
    --progress --verbose
```
