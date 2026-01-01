# mTLS Setup Guide for Pepper and Integrity Modules

## Overview

The **Pepper** and **Integrity** modules use mTLS (mutual TLS) authentication with a **self-signed Certificate Authority (CA)**. This keeps these modules non-public and restricted to clients with certificates signed by your private CA.

**Security Model:**
- ✓ Only clients with certificates signed by YOUR self-signed CA can connect
- ✗ Public CA certificates (Let's Encrypt, DigiCert, etc.) are NOT accepted
- ✗ Self-signed client certificates (not signed by your CA) are NOT accepted

## Architecture

```
Your Self-Signed CA (private, never shared)
├── Server Certificate (for HTTPS, optional)
├── Client Certificate 1 (for user/device 1)
├── Client Certificate 2 (for user/device 2)
└── Client Certificate N (for user/device N)
```

**What each party holds:**

| Party | Has | Purpose |
|-------|-----|---------|
| **Server** | CA certificate (public) | Verify client certificates |
| **Server** | Server cert + key (optional) | For direct mTLS mode |
| **Client** | Client cert + key | Authenticate to server |
| **Client** | CA certificate (public) | Verify server (optional) |
| **CA (you)** | CA private key | Sign new client certificates |

## Step 1: Create Your Self-Signed CA

**IMPORTANT:** Do this ONCE and keep the CA private key secure!

```bash
cd openssl_encrypt_server/certs

# Generate CA private key (keep this VERY secure!)
openssl genrsa -aes256 -out ca.key 4096

# Create CA certificate (valid for 10 years)
openssl req -x509 -new -nodes -key ca.key -sha256 -days 3650 -out ca.crt \
  -subj "/C=US/ST=State/L=City/O=YourOrg/OU=Security/CN=OpenSSL-Encrypt-CA"

# Verify CA certificate
openssl x509 -in ca.crt -text -noout
```

**Output files:**
- `ca.key` - CA private key (KEEP SECRET, needed to sign client certs)
- `ca.crt` - CA certificate (public, server needs this to verify clients)

## Step 2: Generate Client Certificates

For each client/user/device, generate a unique certificate:

```bash
# Set client name
CLIENT_NAME="client1"

# Generate client private key
openssl genrsa -out ${CLIENT_NAME}.key 4096

# Create certificate signing request (CSR)
openssl req -new -key ${CLIENT_NAME}.key -out ${CLIENT_NAME}.csr \
  -subj "/C=US/ST=State/L=City/O=YourOrg/OU=Clients/CN=${CLIENT_NAME}"

# Sign with your CA (creates client certificate)
openssl x509 -req -in ${CLIENT_NAME}.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out ${CLIENT_NAME}.crt -days 825 -sha256

# Verify client certificate
openssl verify -CAfile ca.crt ${CLIENT_NAME}.crt

# Clean up CSR (no longer needed)
rm ${CLIENT_NAME}.csr
```

**Output files per client:**
- `${CLIENT_NAME}.key` - Client private key (give to client)
- `${CLIENT_NAME}.crt` - Client certificate (give to client)

**Distribute to client:**
```bash
# Create client bundle
tar czf ${CLIENT_NAME}-bundle.tar.gz ${CLIENT_NAME}.key ${CLIENT_NAME}.crt ca.crt

# Securely send to client (encrypted email, secure file transfer, etc.)
```

## Step 3: Server Configuration

### Option A: Proxy Mode (Recommended)

Nginx terminates mTLS and passes certificate info via headers.

**Nginx configuration** (`/etc/nginx/sites-available/openssl-encrypt`):

```nginx
server {
    listen 443 ssl;
    server_name pepper.example.com;

    # Server SSL certificate (can be Let's Encrypt)
    ssl_certificate /etc/letsencrypt/live/pepper.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/pepper.example.com/privkey.pem;

    # Client certificate verification (YOUR CA only!)
    ssl_client_certificate /etc/ssl/certs/openssl-encrypt-ca.crt;
    ssl_verify_client on;
    ssl_verify_depth 1;  # Only accept certs directly signed by CA

    # Pass certificate info to backend
    location /api/v1/pepper/ {
        proxy_pass http://localhost:8080;
        proxy_set_header X-Client-Cert-Fingerprint $ssl_client_fingerprint;
        proxy_set_header X-Client-Cert-DN $ssl_client_s_dn;
        proxy_set_header X-Client-Cert-Verify $ssl_client_verify;
    }

    location /api/v1/integrity/ {
        proxy_pass http://localhost:8080;
        proxy_set_header X-Client-Cert-Fingerprint $ssl_client_fingerprint;
        proxy_set_header X-Client-Cert-DN $ssl_client_s_dn;
        proxy_set_header X-Client-Cert-Verify $ssl_client_verify;
    }
}
```

**Environment variables** (`.env`):

```bash
# Pepper Module
PEPPER_ENABLED=true
PEPPER_AUTH_MODE=proxy

# Integrity Module
INTEGRITY_ENABLED=true
INTEGRITY_AUTH_MODE=proxy
```

### Option B: Direct mTLS Mode

Server terminates mTLS directly (no Nginx).

**Generate server certificate:**

```bash
# Server key
openssl genrsa -out server.key 4096

# Server CSR
openssl req -new -key server.key -out server.csr \
  -subj "/C=US/ST=State/L=City/O=YourOrg/OU=Server/CN=pepper.example.com"

# Sign with CA
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out server.crt -days 825 -sha256
```

**Environment variables** (`.env`):

```bash
# Pepper Module
PEPPER_ENABLED=true
PEPPER_AUTH_MODE=mtls
PEPPER_MTLS_PORT=8444
PEPPER_MTLS_CERT=/certs/server.crt
PEPPER_MTLS_KEY=/certs/server.key
PEPPER_MTLS_CLIENT_CA=/certs/ca.crt

# Integrity Module
INTEGRITY_ENABLED=true
INTEGRITY_AUTH_MODE=mtls
INTEGRITY_MTLS_PORT=8445
INTEGRITY_MTLS_CERT=/certs/server.crt
INTEGRITY_MTLS_KEY=/certs/server.key
INTEGRITY_MTLS_CLIENT_CA=/certs/ca.crt
```

**Docker volume mounts** (`docker-compose.yml`):

```yaml
services:
  api:
    volumes:
      - ./certs/server.crt:/certs/server.crt:ro
      - ./certs/server.key:/certs/server.key:ro
      - ./certs/ca.crt:/certs/ca.crt:ro
    ports:
      - "8444:8444"  # Pepper mTLS
      - "8445:8445"  # Integrity mTLS
```

## Step 4: Client Usage

### With curl

```bash
# Test pepper endpoint
curl --cert client1.crt --key client1.key --cacert ca.crt \
  https://pepper.example.com/api/v1/pepper/profile

# Test integrity endpoint
curl --cert client1.crt --key client1.key --cacert ca.crt \
  https://pepper.example.com/api/v1/integrity/profile
```

### With Python requests

```python
import requests

# Client certificate files
CLIENT_CERT = '/path/to/client1.crt'
CLIENT_KEY = '/path/to/client1.key'
CA_CERT = '/path/to/ca.crt'

# Make request
response = requests.get(
    'https://pepper.example.com/api/v1/pepper/profile',
    cert=(CLIENT_CERT, CLIENT_KEY),
    verify=CA_CERT
)

print(response.json())
```

### With openssl_encrypt CLI

```python
# In openssl_encrypt plugin config
pepper_config = PepperConfig(
    enabled=True,
    server_url="https://pepper.example.com",
    client_cert="/path/to/client1.crt",
    client_key="/path/to/client1.key",
    ca_cert="/path/to/ca.crt"
)
```

## Security Best Practices

### CA Management

1. **Protect the CA private key** (`ca.key`):
   - Store encrypted (use passphrase when generating)
   - Keep offline when not signing certificates
   - Use hardware security module (HSM) for production
   - Never commit to version control

2. **CA certificate distribution**:
   - CA cert (`ca.crt`) is public, can be freely distributed
   - Include in server config, client bundles, documentation

### Client Certificate Management

1. **Generation**:
   - Unique certificate per user/device/application
   - Short validity period (1-2 years recommended)
   - Meaningful CN/OU fields for identification

2. **Distribution**:
   - Secure delivery channel (encrypted email, secure file transfer)
   - Never send via plaintext email or unencrypted channels
   - Consider password-protected archives

3. **Revocation**:
   - Maintain Certificate Revocation List (CRL) or use OCSP
   - For immediate revocation: regenerate CA and reissue all valid clients
   - Log all certificate fingerprints in server database

4. **Monitoring**:
   - Server logs all connecting fingerprints
   - Review `in_clients` and `pp_clients` tables regularly
   - Alert on unknown or suspicious connections

### Certificate Rotation

```bash
# Before expiry, generate new client cert with same CN
CLIENT_NAME="client1"

# New key + cert
openssl genrsa -out ${CLIENT_NAME}-new.key 4096
openssl req -new -key ${CLIENT_NAME}-new.key -out ${CLIENT_NAME}-new.csr \
  -subj "/C=US/ST=State/L=City/O=YourOrg/OU=Clients/CN=${CLIENT_NAME}"
openssl x509 -req -in ${CLIENT_NAME}-new.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out ${CLIENT_NAME}-new.crt -days 825 -sha256

# Distribute new cert to client
# Client updates configuration
# Old cert automatically expires
```

## Troubleshooting

### Client connection refused

**Check:** Is the client certificate signed by your CA?

```bash
openssl verify -CAfile ca.crt client1.crt
```

Expected output: `client1.crt: OK`

### "Client certificate verification failed"

**Check:** Does server have the correct CA certificate?

```bash
# In Nginx
grep ssl_client_certificate /etc/nginx/sites-available/openssl-encrypt

# In Docker
docker-compose exec api ls -la /certs/ca.crt
```

### "Request not from trusted proxy" (proxy mode)

**Check:** Is the request coming from a trusted IP?

Default trusted IPs: `127.0.0.1`, `::1`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`

### View certificate fingerprint

```bash
# SHA-256 fingerprint (what server uses)
openssl x509 -in client1.crt -noout -fingerprint -sha256

# Format: SHA256 Fingerprint=AB:CD:EF:12:34:...
# Server normalizes to: abcdef1234... (lowercase, no colons)
```

## Certificate Lifecycle Example

```
Day 0:   Generate CA (valid 10 years)
Day 1:   Issue client certificates (valid 2 years)
Day 30:  Client 1 first connection → auto-registered
Day 60:  Client 2 first connection → auto-registered
Day 365: Review active clients, revoke unused
Day 700: Renew client certificates (before expiry)
Year 10: Regenerate CA, reissue all certificates
```

## FAQ

**Q: Can I use Let's Encrypt for client certificates?**
A: No. These modules only accept certificates signed by YOUR self-signed CA.

**Q: How many clients can I have?**
A: Unlimited. Each gets a unique certificate from your CA.

**Q: What if CA private key is compromised?**
A: Generate new CA, reconfigure server, reissue all client certificates.

**Q: Can I use the same certificate for both pepper and integrity?**
A: Yes! Same client cert works for both modules.

**Q: Proxy vs Direct mTLS - which to use?**
A: Proxy mode (recommended) - easier management, Nginx handles TLS optimization.

**Q: How do I revoke a client certificate?**
A: Remove from database (`DELETE FROM pp_clients WHERE cert_fingerprint='...'`) or implement CRL.
