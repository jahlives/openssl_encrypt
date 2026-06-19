# Keyserver Plugin User Guide

Complete guide for using the OpenSSL Encrypt keyserver plugin to distribute and discover post-quantum cryptographic public keys.

## Table of Contents

- [Overview](#overview)
- [Quick Start](#quick-start)
- [Setup](#setup)
  - [Enable the Plugin](#enable-the-plugin)
  - [Configure Servers](#configure-servers)
  - [Register an Account](#register-an-account)
  - [Login with Client ID](#login-with-client-id)
- [CLI Commands](#cli-commands)
  - [Configuration](#configuration-commands)
  - [Authentication](#authentication-commands)
  - [Key Operations](#key-operations)
  - [Token Management](#token-management)
  - [Cache Management](#cache-management)
- [Registration Flows](#registration-flows)
  - [Anonymous Registration](#anonymous-registration)
  - [Email-Confirmed Registration](#email-confirmed-registration)
  - [Login with Existing Client ID](#login-with-existing-client-id)
- [Token Lifecycle](#token-lifecycle)
  - [How Tokens Work](#how-tokens-work)
  - [Automatic Refresh](#automatic-refresh)
  - [Token Expiry](#token-expiry)
- [Using Keys](#using-keys)
  - [Upload Your Key](#upload-your-key)
  - [Search for Keys](#search-for-keys)
  - [Import Keys](#import-keys)
  - [Encrypt to Keyserver Recipients](#encrypt-to-keyserver-recipients)
  - [Revoke a Key](#revoke-a-key)
- [Configuration Reference](#configuration-reference)
  - [Config File](#config-file)
  - [Config Fields](#config-fields)
  - [File Locations](#file-locations)
- [Certificate Pinning](#certificate-pinning)
- [Cache System](#cache-system)
- [Python API](#python-api)
- [Security Model](#security-model)
- [Troubleshooting](#troubleshooting)

---

## Overview

The keyserver plugin provides:

- **Key discovery**: Search for PQC public keys by fingerprint, name, or email
- **Key distribution**: Upload your public key so others can encrypt to you
- **Local caching**: SQLite-backed cache with TTL for fast repeated lookups
- **Automatic token refresh**: JWT tokens refresh transparently on expiry
- **Certificate pinning**: Optional TLS certificate fingerprint validation
- **HTTPS-only**: All communication enforced over TLS

The plugin is **opt-in by default** (disabled) and **never handles private keys**.

---

## Quick Start

```bash
# 1. Enable the plugin
openssl-encrypt keyserver enable

# 2. Register with email (recommended)
openssl-encrypt keyserver register --email alice@example.com
# Wait for confirmation email, click the link

# 3. Or login with existing client ID
openssl-encrypt keyserver login cd94f345a0067203e01212fb4fa9ff8b

# 4. Upload your public key
openssl-encrypt keyserver upload my-identity

# 5. Search for someone's key
openssl-encrypt keyserver search bob@example.com

# 6. Encrypt to a keyserver recipient
openssl-encrypt encrypt file.txt --for bob@example.com --use-keyserver
```

---

## Setup

### Enable the Plugin

The keyserver plugin is disabled by default. Enable it:

```bash
openssl-encrypt keyserver enable
```

Output:

```
 Keyserver plugin enabled
  Servers: https://keys.openssl-encrypt.org
  Use 'openssl-encrypt keyserver status' to verify configuration
```

### Configure Servers

By default, the plugin uses `https://keys.openssl-encrypt.org`. To use a different server, edit the config file directly:

```bash
# Config location
~/.openssl_encrypt/plugins/keyserver/config.json
```

Example config:

```json
{
  "enabled": true,
  "servers": ["https://keyserver.example.com"],
  "cache_ttl_seconds": 86400,
  "cache_max_entries": 1000,
  "connect_timeout_seconds": 10,
  "read_timeout_seconds": 30,
  "upload_enabled": true
}
```

Multiple servers can be configured for failover:

```json
{
  "servers": [
    "https://keyserver.example.com",
    "https://backup-keyserver.example.com"
  ]
}
```

All server URLs must use HTTPS. HTTP URLs will be rejected.

### Register an Account

Registration is required for uploading and revoking keys. Searching is public (no account needed).

**With email confirmation (recommended):**

```bash
openssl-encrypt keyserver register --email alice@example.com
```

```
Registering with email: alice@example.com
A confirmation email will be sent to this address.
Please click the link in the email to complete registration.

Waiting for email confirmation... (press Ctrl+C to cancel)

 Email confirmed! Registration complete.
============================================================
Client ID:   cd94f345a0067203e01212fb4fa9ff8b
Token Type:  Bearer
Token File:  /home/alice/.openssl_encrypt/keyserver/token
============================================================

API token has been securely saved.
```

**Anonymous registration:**

```bash
openssl-encrypt keyserver register
```

Returns immediately with tokens. No email required.

**With a specific server:**

```bash
openssl-encrypt keyserver register --email alice@example.com --server https://keyserver.example.com
```

### Login with Client ID

If you already have a client_id (e.g., from the registration welcome email), you can obtain JWT tokens without re-registering:

```bash
openssl-encrypt keyserver login cd94f345a0067203e01212fb4fa9ff8b
```

```
Logging in to keyserver...

 Login successful
============================================================
Client ID:     cd94f345a0067203e01212fb4fa9ff8b
Token Type:    Bearer
Token File:    /home/alice/.openssl_encrypt/keyserver/token
Refresh File:  /home/alice/.openssl_encrypt/keyserver/refresh_token
============================================================

API tokens have been securely saved.
```

With a specific server:

```bash
openssl-encrypt keyserver login cd94f345a0067203e01212fb4fa9ff8b --server https://keyserver.example.com
```

---

## CLI Commands

All commands follow the format: `openssl-encrypt keyserver <command> [arguments]`

### Configuration Commands

#### `keyserver enable`

Enable the keyserver plugin.

```bash
openssl-encrypt keyserver enable
```

#### `keyserver disable`

Disable the keyserver plugin.

```bash
openssl-encrypt keyserver disable
```

#### `keyserver status`

Display current configuration and cache statistics.

```bash
openssl-encrypt keyserver status
```

Output:

```
KEYSERVER STATUS
============================================================
Enabled: Yes
Servers: https://keyserver.example.com
Cache TTL: 86400 seconds (24 hours)
Cache Max Entries: 1000
Upload Enabled: Yes
API Token: Present

CACHE STATISTICS
------------------------------------------------------------
Total Entries: 5
Valid Entries: 4
Expired Entries: 1
Total Accesses: 23
Most Accessed: alice@example.com (12 times)
============================================================
```

### Authentication Commands

#### `keyserver register`

Register a new account with the keyserver.

```bash
# Anonymous registration (immediate)
openssl-encrypt keyserver register

# Email-confirmed registration (recommended)
openssl-encrypt keyserver register --email alice@example.com

# With specific server
openssl-encrypt keyserver register --server https://keyserver.example.com --email alice@example.com
```

| Argument | Required | Description |
|----------|----------|-------------|
| `--email` | No | Register with email confirmation |
| `--server` | No | Specific keyserver URL (default: first configured) |

#### `keyserver login`

Login with an existing client_id to obtain JWT tokens.

```bash
openssl-encrypt keyserver login <client_id>
openssl-encrypt keyserver login <client_id> --server https://keyserver.example.com
```

| Argument | Required | Description |
|----------|----------|-------------|
| `client_id` | Yes | Client ID from registration |
| `--server` | No | Specific keyserver URL |

### Key Operations

#### `keyserver search`

Search for a public key on the keyserver. **No authentication required.**

```bash
# Search by email
openssl-encrypt keyserver search alice@example.com

# Search by name
openssl-encrypt keyserver search "Alice Smith"

# Search by fingerprint (full or prefix)
openssl-encrypt keyserver search 3a:4b:5c:d1

# Output as JSON
openssl-encrypt keyserver search alice@example.com --json
```

| Argument | Required | Description |
|----------|----------|-------------|
| `identifier` | Yes | Fingerprint, name, or email to search |
| `--json` | No | Output in JSON format |

Search priority: exact fingerprint > fingerprint prefix > exact name > exact email.

#### `keyserver import`

Fetch a key from the keyserver and import it to your local identity store.

```bash
# Interactive (prompts for trust confirmation)
openssl-encrypt keyserver import alice@example.com

# Skip trust prompt (use with caution)
openssl-encrypt keyserver import alice@example.com --no-trust-prompt
```

| Argument | Required | Description |
|----------|----------|-------------|
| `identifier` | Yes | Fingerprint, name, or email |
| `--no-trust-prompt` | No | Skip interactive trust confirmation |

#### `keyserver upload`

Upload your public key to the keyserver. **Requires authentication.**

```bash
openssl-encrypt keyserver upload my-identity
```

You will be prompted for your passphrase. The key bundle (public keys only) is uploaded after signature verification.

| Argument | Required | Description |
|----------|----------|-------------|
| `identity_name` | Yes | Name of your local identity to upload |

#### `keyserver revoke`

Revoke a key on the keyserver. **Requires authentication and proof of ownership.**

```bash
openssl-encrypt keyserver revoke 3a:4b:5c:d1:e2:f6:...
```

| Argument | Required | Description |
|----------|----------|-------------|
| `fingerprint` | Yes | Fingerprint of key to revoke |

### Token Management

#### `keyserver set-token`

Manually set the API token.

```bash
openssl-encrypt keyserver set-token eyJhbGciOiJIUzI1NiI...
```

#### `keyserver show-token`

Display the current API token (masked for security).

```bash
openssl-encrypt keyserver show-token
```

Output:

```
API Token: eyJhbGci...FkSY (masked)
Token file: /home/alice/.openssl_encrypt/keyserver/token
```

#### `keyserver clear-token`

Delete the stored API token.

```bash
openssl-encrypt keyserver clear-token
```

### Cache Management

#### `keyserver cache-stats`

Display cache statistics.

```bash
openssl-encrypt keyserver cache-stats
```

#### `keyserver cache-clear`

Clear the local key cache.

```bash
# Interactive (asks for confirmation)
openssl-encrypt keyserver cache-clear

# Skip confirmation
openssl-encrypt keyserver cache-clear --force
```

---

## Registration Flows

### Anonymous Registration

Best for: Development, testing, or when email is not required.

```
1. openssl-encrypt keyserver register
2. Receive client_id + tokens immediately
3. Tokens saved automatically
4. Ready to upload/revoke keys
```

### Email-Confirmed Registration

Best for: Production use. Links your email to your account.

```
1. openssl-encrypt keyserver register --email you@example.com
2. Plugin sends registration request to server
3. Server sends confirmation email with link (valid 30 minutes)
4. Plugin polls for confirmation (every 5 seconds)
5. You click the link in your email
6. Plugin receives tokens automatically
7. You also receive a welcome email with your client_id
```

**What happens if you confirmed in a browser?**

If you registered via API/curl and confirmed the email link in a browser, you'll have the client_id (from the welcome email) but no JWT tokens. Use `keyserver login`:

```bash
openssl-encrypt keyserver login <client_id_from_email>
```

### Login with Existing Client ID

For when you already have a client_id but need fresh JWT tokens:

- After confirming registration via browser
- After tokens expired (7+ days inactive)
- On a new machine

```bash
openssl-encrypt keyserver login cd94f345a0067203e01212fb4fa9ff8b
```

---

## Token Lifecycle

### How Tokens Work

The keyserver uses two JWT tokens:

| Token | Lifetime | Stored At | Purpose |
|-------|----------|-----------|---------|
| Access token | 60 minutes | `~/.openssl_encrypt/keyserver/token` | API authentication |
| Refresh token | 7 days | `~/.openssl_encrypt/keyserver/refresh_token` | Obtain new token pair |

Both files are created with `0600` permissions (owner read/write only).

### Automatic Refresh

The plugin handles token refresh **transparently**. You never need to refresh manually.

When an authenticated request receives a `401 Unauthorized`:

1. Plugin detects the expired access token
2. Plugin sends the refresh token to `POST /api/v1/keys/refresh`
3. Server returns new access + refresh tokens
4. Plugin saves both tokens
5. Plugin retries the original request with the new access token
6. All of this happens automatically — the operation succeeds

### Token Expiry

| Scenario | What Happens | User Action |
|----------|-------------|-------------|
| Access token expired (<60 min) | Auto-refreshed transparently | None |
| Active within 7 days | Refresh token slides forward | None |
| Inactive 7+ days | Both tokens expired | `keyserver login <client_id>` |
| Lost client_id | Cannot recover | Re-register with email |

**Keep your client_id safe.** It's the only way to re-authenticate if both tokens expire.

---

## Using Keys

### Upload Your Key

Prerequisites:
- Keyserver plugin enabled
- Registered and authenticated (have tokens)
- A local identity with private keys

```bash
openssl-encrypt keyserver upload my-identity
```

The plugin:
1. Loads your identity from the local store (prompts for passphrase)
2. Extracts the public key bundle (public keys only)
3. Verifies the self-signature locally
4. Uploads to all configured servers
5. Server verifies the signature again before storing

### Search for Keys

No authentication required. Anyone can search:

```bash
# By email
openssl-encrypt keyserver search bob@example.com

# By name
openssl-encrypt keyserver search "Bob Jones"

# By fingerprint prefix
openssl-encrypt keyserver search 3a:4b:5c

# JSON output for scripting
openssl-encrypt keyserver search bob@example.com --json
```

### Import Keys

Fetch a key from the keyserver and add it to your local identity store:

```bash
openssl-encrypt keyserver import bob@example.com
```

```
 Key found on keyserver
------------------------------------------------------------
Name:        Bob Jones
Email:       bob@example.com
Fingerprint: 3a:4b:5c:d1:e2:f6:...
Algorithms:  ML-KEM-768 / ML-DSA-65

Do you trust this key? [y/N]: y
 Key imported to local store
```

After importing, all future encryptions to Bob use the local copy (no network needed).

### Encrypt to Keyserver Recipients

Use the `--use-keyserver` flag to enable keyserver lookup during encryption:

```bash
openssl-encrypt encrypt secret.txt --for bob@example.com --use-keyserver
```

Resolution order:
1. Check local identity store (fast, no network)
2. If not found, query keyserver (network, prompts for trust)
3. Encrypt with resolved public key

### Revoke a Key

Revoke a key you previously uploaded:

```bash
openssl-encrypt keyserver revoke 3a:4b:5c:d1:e2:f6:...
```

Requires:
- Valid authentication (JWT token)
- Proof of ownership (revocation signature created with your private key)

Revoked keys are no longer returned by search queries.

---

## Configuration Reference

### Config File

Location: `~/.openssl_encrypt/plugins/keyserver/config.json`

Example:

```json
{
  "enabled": true,
  "servers": ["https://keyserver.example.com"],
  "cache_ttl_seconds": 86400,
  "cache_max_entries": 1000,
  "connect_timeout_seconds": 10,
  "read_timeout_seconds": 30,
  "upload_enabled": true
}
```

### Config Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `false` | Enable plugin (opt-in) |
| `servers` | list[str] | `["https://keys.openssl-encrypt.org"]` | Keyserver URLs (HTTPS only) |
| `cache_ttl_seconds` | int | `86400` (24h) | Cache entry lifetime |
| `cache_max_entries` | int | `1000` | Maximum cached keys |
| `cache_path` | str | `~/.openssl_encrypt/keyserver/cache.db` | SQLite cache database path |
| `connect_timeout_seconds` | int | `10` | TCP connection timeout |
| `read_timeout_seconds` | int | `30` | HTTP read timeout |
| `upload_enabled` | bool | `true` | Allow key uploads |
| `api_token_file` | str | `~/.openssl_encrypt/keyserver/token` | Access token file path |
| `refresh_token_file` | str | `~/.openssl_encrypt/keyserver/refresh_token` | Refresh token file path |
| `enable_cert_pinning` | bool | `false` | Enable certificate pinning |
| `cert_fingerprints` | list[str] | `null` | Expected SHA-256 cert fingerprints |

**Note:** The `api_token` field is intentionally excluded from the saved config file for security. Tokens are stored in separate files with restrictive permissions.

### File Locations

| File | Path | Permissions | Content |
|------|------|-------------|---------|
| Config | `~/.openssl_encrypt/plugins/keyserver/config.json` | 0600 | JSON settings |
| Access token | `~/.openssl_encrypt/keyserver/token` | 0600 | JWT access token |
| Refresh token | `~/.openssl_encrypt/keyserver/refresh_token` | 0600 | JWT refresh token |
| Cache | `~/.openssl_encrypt/keyserver/cache.db` | 0600 | SQLite database |

---

## Certificate Pinning

For additional security, you can pin the keyserver's TLS certificate fingerprint:

```json
{
  "enable_cert_pinning": true,
  "cert_fingerprints": [
    "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2"
  ]
}
```

**How it works:**
1. Standard TLS verification runs first (hostname, certificate chain)
2. Server certificate's SHA-256 fingerprint is computed
3. Compared against the configured list
4. Connection fails if fingerprint doesn't match

**Getting a server's fingerprint:**

```bash
openssl s_client -connect keyserver.example.com:443 </dev/null 2>/dev/null \
  | openssl x509 -fingerprint -sha256 -noout \
  | sed 's/.*=//;s/://g' | tr 'A-F' 'a-f'
```

Multiple fingerprints can be configured for certificate rotation.

---

## Cache System

The plugin caches fetched keys in a local SQLite database for fast repeated lookups.

### How It Works

- **On fetch**: If key is in cache and not expired, return immediately (no network)
- **On miss**: Fetch from server, verify signature, store in cache
- **TTL**: Cached entries expire after `cache_ttl_seconds` (default: 24 hours)
- **Eviction**: When cache is full, the oldest 10% of entries (by last access) are evicted
- **Cleanup**: Expired entries are cleaned up automatically on new inserts

### Cache Commands

```bash
# View statistics
openssl-encrypt keyserver cache-stats

# Clear all entries
openssl-encrypt keyserver cache-clear --force
```

### Cache Statistics

```
CACHE STATISTICS
------------------------------------------------------------
Total Entries:  42
Valid Entries:  38
Expired Entries: 4
Max Entries:    1000
TTL:            86400 seconds (24 hours)
Total Accesses: 156
Most Accessed:  alice@example.com (47 times)
Cache Path:     /home/alice/.openssl_encrypt/keyserver/cache.db
```

---

## Python API

The plugin can be used programmatically:

### Basic Usage

```python
from openssl_encrypt.plugins.keyserver import KeyserverConfig, KeyserverPlugin

# Load config from default location
config = KeyserverConfig.from_file()
plugin = KeyserverPlugin(config)

# Or create config programmatically
config = KeyserverConfig(
    enabled=True,
    servers=["https://keyserver.example.com"],
)
plugin = KeyserverPlugin(config)
```

### Login

```python
result = plugin.login("cd94f345a0067203e01212fb4fa9ff8b")
print(f"Logged in: {result['client_id']}")
# Tokens saved automatically
```

### Register

```python
# Anonymous
result = plugin.register()

# With email (blocks until confirmed or timeout)
result = plugin.register_with_email("alice@example.com")
```

### Search and Fetch

```python
# Returns PublicKeyBundle or None
bundle = plugin.fetch_key("alice@example.com")
if bundle:
    print(f"Found: {bundle.name} ({bundle.fingerprint})")
```

### Upload

```python
from openssl_encrypt.modules.key_bundle import PublicKeyBundle

bundle = PublicKeyBundle.from_identity(my_identity)
success = plugin.upload_key(bundle)
```

### Token Management

```python
# Load tokens
access_token = config.load_api_token()
refresh_token = config.load_refresh_token()

# Save tokens
config.save_api_token("eyJ...")
config.save_refresh_token("eyJ...")

# Clear tokens
config.clear_api_token()
config.clear_refresh_token()
```

### Cache Management

```python
stats = plugin.get_cache_stats()
print(f"Cached keys: {stats['valid_entries']}")

cleared = plugin.clear_cache()
print(f"Cleared {cleared} entries")
```

---

## Security Model

### What the Plugin Handles

- Public key bundles (encryption + signing public keys)
- JWT tokens for authentication
- Cached public keys in SQLite

### What the Plugin Never Handles

- Private keys (never sent to or received from keyserver)
- Passphrases (only used locally to unlock identities)
- Plaintext data (only key material)

### Trust Model

1. **Key verification**: All fetched keys have their self-signature verified before caching or returning
2. **User trust**: When importing, the user is prompted to explicitly trust the key
3. **Local-first**: Local identity store is always checked before keyserver
4. **HTTPS-only**: All communication over TLS (with optional certificate pinning)
5. **Opt-in**: Plugin is disabled by default

### Token Security

- Tokens stored in files with `0600` permissions (owner only)
- API token excluded from config JSON file
- Refresh token stored separately
- Automatic refresh prevents token exposure in error messages
- Constant-time comparison on server side prevents timing attacks

---

## Troubleshooting

### "Keyserver plugin is disabled"

```bash
openssl-encrypt keyserver enable
```

### "JWT token not set"

Register or login first:

```bash
openssl-encrypt keyserver register --email you@example.com
# or
openssl-encrypt keyserver login <your_client_id>
```

### "Authentication failed. Token refresh unsuccessful."

Both tokens have expired (inactive for 7+ days). Login again:

```bash
openssl-encrypt keyserver login <your_client_id>
```

### "Invalid credentials" on login

Double-check your client_id. It's the 32-character hex string from your registration email. If lost, re-register with email.

### "Connection failed" or timeouts

- Check network connectivity
- Verify server URL: `openssl-encrypt keyserver status`
- Try `curl https://keyserver.example.com/health`
- Check if running behind a proxy that blocks outbound HTTPS

### "HTTPS URLs only" error

All keyserver URLs must use `https://`. Edit your config:

```bash
vi ~/.openssl_encrypt/plugins/keyserver/config.json
```

### Token file permission warnings

The plugin expects `0600` permissions on token files. Fix:

```bash
chmod 600 ~/.openssl_encrypt/keyserver/token
chmod 600 ~/.openssl_encrypt/keyserver/refresh_token
```

### Cache issues

Clear and rebuild the cache:

```bash
openssl-encrypt keyserver cache-clear --force
```

### "Key not found" when searching

- Key may not have been uploaded yet
- Key may have been revoked
- Try searching by different identifiers (fingerprint, name, email)
- Partial fingerprint search works (prefix match)
