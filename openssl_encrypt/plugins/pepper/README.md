# Pepper Plugin

Secure remote pepper storage with mTLS authentication and TOTP 2FA.

## Overview

The Pepper Plugin provides secure, opt-in storage of encrypted pepper values on a remote server. Peppers are cryptographic salts that are kept separate from encrypted data to add an additional layer of security.

**Key Features:**
- 🔐 **mTLS Authentication** - Client certificate-based authentication
- 🔒 **Client-side Encryption** - Peppers encrypted before upload
- 📱 **TOTP 2FA** - Time-based OTP for destructive operations
- ⏱️ **Dead Man's Switch** - Auto-wipe on missed check-ins
- 🚨 **Panic Wipe** - Emergency delete all peppers
- 🌐 **HTTPS-only** - Secure communication

## Security Model

### OPT-IN by Default
The pepper plugin is **disabled by default**. You must explicitly enable it in your configuration.

### mTLS Authentication
All requests require client certificate authentication:
- Client presents certificate to server
- Server validates certificate against trusted CA
- Only authorized clients can access their peppers

### Client-side Encryption
**CRITICAL:** Peppers must be encrypted client-side before storing:
```python
# ✗ WRONG - Don't store plaintext!
plugin.store_pepper("my-pepper", b"plaintext pepper")

# ✓ CORRECT - Encrypt first!
encrypted = encrypt_pepper(b"plaintext pepper", password)
plugin.store_pepper("my-pepper", encrypted)
```

### TOTP 2FA Protection
Destructive operations require TOTP verification:
- Delete profile
- Disable TOTP
- Generate backup codes
- Panic operations (wipe all/single pepper)

### Dead Man's Switch
Automatically wipes all peppers if you don't check in:
- Configure check-in interval (e.g., "7d", "30d")
- Add grace period for flexibility (e.g., "24h")
- Server automatically wipes peppers if deadline + grace passes
- Prevents pepper exposure if you lose access to your account

## Installation

The pepper plugin is included with OpenSSL Encrypt. No additional installation required.

## Configuration

### 1. Generate Client Certificates

Generate a client certificate for mTLS authentication:

```bash
# Generate private key
openssl genrsa -out client.key 4096

# Generate certificate signing request (CSR)
openssl req -new -key client.key -out client.csr \
  -subj "/CN=My Laptop/O=Personal/C=US"

# Self-sign certificate (or get it signed by your CA)
openssl x509 -req -in client.csr -signkey client.key \
  -out client.crt -days 3650

# Move to pepper directory
mkdir -p ~/.openssl_encrypt/pepper/certs
mv client.key client.crt ~/.openssl_encrypt/pepper/certs/
chmod 600 ~/.openssl_encrypt/pepper/certs/client.key
```

### 2. Configure Plugin

Create `~/.openssl_encrypt/plugins/pepper.json`:

```json
{
  "enabled": true,
  "server_url": "https://pepper.openssl-encrypt.org",
  "client_cert": "~/.openssl_encrypt/pepper/certs/client.crt",
  "client_key": "~/.openssl_encrypt/pepper/certs/client.key",
  "ca_cert": null,
  "connect_timeout_seconds": 10,
  "read_timeout_seconds": 30
}
```

**Configuration Options:**
- `enabled`: Enable/disable plugin (default: `false`)
- `server_url`: Pepper server URL (HTTPS only)
- `client_cert`: Path to client certificate
- `client_key`: Path to client private key
- `ca_cert`: Path to CA certificate (optional, uses system CA if null)
- `connect_timeout_seconds`: Connection timeout (default: 10)
- `read_timeout_seconds`: Read timeout (default: 30)

### 3. Verify Configuration

```python
from openssl_encrypt.plugins.pepper import PepperPlugin

plugin = PepperPlugin()  # Loads from config file
profile = plugin.get_profile()  # Auto-registers on first request
print(f"Connected as: {profile['cert_fingerprint']}")
```

## Usage Guide

### Initialize Plugin

```python
from openssl_encrypt.plugins.pepper import PepperPlugin, PepperConfig
from pathlib import Path

# Option 1: Load from config file
plugin = PepperPlugin()

# Option 2: Explicit configuration
config = PepperConfig(
    enabled=True,
    server_url="https://pepper.example.com",
    client_cert=Path("~/.openssl_encrypt/pepper/certs/client.crt"),
    client_key=Path("~/.openssl_encrypt/pepper/certs/client.key"),
)
plugin = PepperPlugin(config)
```

### Profile Management

```python
# Get profile (auto-registers on first request)
profile = plugin.get_profile()
print(profile)
# {
#   "cert_fingerprint": "abc123...",
#   "name": null,
#   "totp_enabled": false,
#   "created_at": "2026-01-01T00:00:00Z",
#   "pepper_count": 0
# }

# Update profile name
plugin.update_profile("My Laptop")

# Delete profile (requires TOTP if enabled)
plugin.delete_profile(totp_code="123456")
```

### TOTP Setup

```python
# 1. Initiate TOTP setup
setup = plugin.setup_totp()
print(f"Secret: {setup['secret']}")
print(f"QR URI: {setup['uri']}")

# Save QR code for scanning
with open("totp_qr.svg", "w") as f:
    f.write(setup['qr_svg'])

# 2. Scan QR code with authenticator app
# (Google Authenticator, Authy, 1Password, etc.)

# 3. Verify with code from app
result = plugin.verify_totp("123456")
backup_codes = result['backup_codes']

# 4. SAVE BACKUP CODES SECURELY!
# These are one-time use codes for account recovery
print("Backup codes:")
for code in backup_codes:
    print(f"  - {code}")

# Disable TOTP (requires current code)
plugin.disable_totp(totp_code="123456")

# Generate new backup codes (requires current code)
result = plugin.generate_backup_codes(totp_code="123456")
new_codes = result['backup_codes']
```

### Pepper Storage

```python
# Store encrypted pepper
pepper_plaintext = b"my secret pepper value"
pepper_encrypted = encrypt_with_password(pepper_plaintext, password)

plugin.store_pepper(
    name="database-pepper",
    pepper_encrypted=pepper_encrypted,
    description="Pepper for production database"
)

# List all peppers (metadata only)
peppers = plugin.list_peppers()
for pepper in peppers:
    print(f"{pepper['name']}: {pepper['description']}")

# Retrieve specific pepper
encrypted = plugin.get_pepper("database-pepper")
pepper_plaintext = decrypt_with_password(encrypted, password)

# Update pepper
new_encrypted = encrypt_with_password(b"new value", password)
plugin.update_pepper("database-pepper", new_encrypted)

# Delete pepper
plugin.delete_pepper("database-pepper")
```

### Dead Man's Switch

```python
# Configure dead man's switch
plugin.configure_deadman(
    interval="7d",      # Check in every 7 days
    grace_period="24h", # 24 hour grace period after deadline
    enabled=True
)

# Check status
status = plugin.get_deadman_status()
print(f"Next deadline: {status['next_deadline']}")
print(f"Time remaining: {status['time_remaining_seconds']} seconds")

# Check in (reset timer)
plugin.checkin()

# Disable dead man's switch
plugin.disable_deadman()
```

**Interval/Grace Period Format:**
- `d` - days (e.g., "7d", "30d")
- `h` - hours (e.g., "24h", "72h")
- `m` - minutes (e.g., "30m", "120m")
- `s` - seconds (e.g., "3600s")

### Panic Operations

**WARNING: These operations are DESTRUCTIVE and cannot be undone!**

```python
# Panic delete specific pepper (requires TOTP)
result = plugin.panic_single("database-pepper", totp_code="123456")
print(f"Wiped {result['peppers_wiped']} pepper(s)")

# Panic delete ALL peppers (requires TOTP)
result = plugin.panic_all(totp_code="123456")
print(f"Wiped {result['peppers_wiped']} pepper(s)")
```

## Error Handling

```python
from openssl_encrypt.plugins.pepper import (
    PepperError,
    NetworkError,
    AuthenticationError,
    TOTPRequiredError,
)

try:
    plugin.store_pepper("test", encrypted_data)
except TOTPRequiredError:
    print("TOTP code required for this operation")
    code = input("Enter TOTP code: ")
    plugin.store_pepper("test", encrypted_data)
except AuthenticationError as e:
    print(f"mTLS authentication failed: {e}")
    print("Check your client certificate and key")
except NetworkError as e:
    print(f"Network error: {e}")
except PepperError as e:
    print(f"Pepper operation failed: {e}")
```

## Best Practices

### 1. Always Encrypt Client-Side
```python
# Use a strong encryption method
from cryptography.fernet import Fernet

key = Fernet.generate_key()  # Derive from user password
fernet = Fernet(key)

pepper_plaintext = b"sensitive pepper value"
pepper_encrypted = fernet.encrypt(pepper_plaintext)

plugin.store_pepper("my-pepper", pepper_encrypted)

# Later, retrieve and decrypt
encrypted = plugin.get_pepper("my-pepper")
pepper_plaintext = fernet.decrypt(encrypted)
```

### 2. Secure Certificate Storage
- Store client key with restrictive permissions (0600)
- Never commit certificates to version control
- Rotate certificates periodically
- Use separate certificates per device

### 3. TOTP Backup Codes
- Save backup codes in a secure location (password manager, encrypted file)
- Never store backup codes in plaintext
- Generate new codes periodically
- Keep codes offline when possible

### 4. Dead Man's Switch Configuration
- Set check-in interval based on your access patterns
- Add adequate grace period (e.g., 24h for 7d interval)
- Test check-in process before enabling
- Document check-in procedure for recovery

### 5. Regular Maintenance
```python
# Regular check-in (automated)
def daily_checkin():
    try:
        plugin.checkin()
        logging.info("Pepper dead man's switch check-in successful")
    except PepperError as e:
        logging.error(f"Check-in failed: {e}")

# Periodic certificate rotation
def rotate_certificate():
    # Generate new certificate
    # Update config
    # Test connection
    pass
```

## Server Setup

To set up your own pepper server, see:
- `openssl_encrypt_server/` - Server implementation
- Server configuration: `.env` file
- Docker deployment: `docker-compose.yml`

## Troubleshooting

### "mTLS authentication failed"
- Verify client certificate and key paths
- Check certificate is not expired: `openssl x509 -in client.crt -noout -dates`
- Verify certificate permissions: `chmod 600 client.key`
- Check server CA configuration

### "TOTP code required"
- Setup TOTP first: `plugin.setup_totp()`
- Verify TOTP: `plugin.verify_totp("123456")`
- Use backup code if authenticator unavailable

### "Network timeout"
- Check server URL is correct
- Verify network connectivity
- Increase timeout values in config

### "Pepper not found"
- Verify pepper name is correct (case-sensitive)
- List peppers to see available names: `plugin.list_peppers()`

## API Reference

See docstrings in `pepper_plugin.py` for complete API documentation:
- Profile: `get_profile()`, `update_profile()`, `delete_profile()`
- TOTP: `setup_totp()`, `verify_totp()`, `disable_totp()`
- Peppers: `store_pepper()`, `get_pepper()`, `list_peppers()`, `update_pepper()`, `delete_pepper()`
- Deadman: `configure_deadman()`, `checkin()`, `disable_deadman()`, `get_deadman_status()`
- Panic: `panic_all()`, `panic_single()`

## Security Considerations

1. **Never store plaintext peppers** - Always encrypt before upload
2. **Protect client certificates** - Private keys are sensitive
3. **Backup TOTP codes** - Required for account recovery
4. **Monitor dead man's switch** - Don't let it expire accidentally
5. **Use panic wisely** - Panic operations cannot be undone
6. **HTTPS only** - Never use HTTP for pepper server
7. **Rotate credentials** - Periodically rotate certificates and TOTP

## License

Part of OpenSSL Encrypt project. See main project LICENSE file.

## Support

- Issues: https://github.com/openssl-encrypt/openssl-encrypt/issues
- Documentation: https://docs.openssl-encrypt.org
- Security: security@openssl-encrypt.org
