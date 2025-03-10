## Command-Line Examples

### Basic Encryption/Decryption

```bash
# Encrypt a file (creates file.txt.encrypted)
python crypt.py encrypt -i file.txt

# Decrypt a file
python crypt.py decrypt -i file.txt.encrypted -o file.txt

# Decrypt and display contents to screen (for text files)
python crypt.py decrypt -i config.encrypted
```

### Password Features

```bash
# Generate a secure random password
python crypt.py generate-password

# Generate a custom password (20 chars, only lowercase and digits)
python crypt.py generate-password --length 20 --use-lowercase --use-digits

# Encrypt with a randomly generated password
python crypt.py encrypt -i secret.txt --random 16

# The tool will display the generated password for 10 seconds, giving you time to save it
```

### Enhanced Security Options

```bash
# Encrypt with multiple hashing algorithms
python crypt.py encrypt -i important.docx --sha512 --sha3-512 --pbkdf2 200000

# Use Scrypt for memory-hard password protection (cost factor 2^15)
python crypt.py encrypt -i secrets.txt --scrypt-cost 15

# Combine multiple hash functions for layered security
python crypt.py encrypt -i critical.pdf --sha512 --sha3-256 --scrypt-cost 14

# Use Argon2 for state-of-the-art password hashing
python crypt.py encrypt -i topsecret.zip --argon2-time 3

# Configure Argon2 for maximum security
python crypt.py encrypt -i classified.db --argon2-time 10 --argon2-memory 1048576 --argon2-parallelism 8

# Use Argon2i for side-channel attack resistance
python crypt.py encrypt -i sensitive_data.txt --argon2-time 4 --argon2-type argon2i

# Combine Argon2 with other hash functions for defense-in-depth
python crypt.py encrypt -i ultra_secret.dat --argon2-time 3 --sha3-512 --pbkdf2 200000
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