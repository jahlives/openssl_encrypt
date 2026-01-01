# Certificate Management Scripts

Helper scripts for managing mTLS certificates for Pepper and Integrity modules.

## Quick Start

### 1. Create Your CA (One-Time Setup)

```bash
./setup_ca.sh
```

This creates:
- `certs/ca.key` - CA private key (keep secure!)
- `certs/ca.crt` - CA certificate (distribute to server and clients)

**Important:** The CA key is encrypted with a passphrase. Store this passphrase securely.

### 2. Create Client Certificates (Per User/Device)

```bash
./create_client_cert.sh alice
```

Or run interactively:

```bash
./create_client_cert.sh
```

This creates:
- `certs/alice.key` - Client private key
- `certs/alice.crt` - Client certificate
- `certs/alice-bundle.tar.gz` - All files needed by client (optional)

### 3. Distribute to Clients

Send the bundle to your client via secure channel:

```bash
# Client receives: alice-bundle.tar.gz
tar xzf alice-bundle.tar.gz

# Client now has:
# - alice.key (keep private!)
# - alice.crt (public)
# - ca.crt (public, for verifying server)
```

### 4. Client Usage

```bash
# Test connection
curl --cert alice.crt --key alice.key --cacert ca.crt \
  https://pepper.example.com/api/v1/pepper/profile

# Expected response:
# {
#   "cert_fingerprint": "abc123...",
#   "name": null,
#   "created_at": "2026-01-01T10:00:00Z",
#   ...
# }
```

## Certificate Lifecycle

```
Day 0:    Run setup_ca.sh (creates CA)
Day 1:    Create client certs (alice, bob, server1)
Day 30:   Client "alice" makes first request → auto-registered
Day 365:  Review active clients, revoke unused ones
Day 700:  Renew expiring certificates (valid for ~2 years)
Year 10:  CA expires → regenerate CA and all client certs
```

## Files Created

```
certs/
├── ca.key              # CA private key (NEVER SHARE)
├── ca.crt              # CA certificate (public, distribute freely)
├── ca.srl              # Serial number tracker (auto-generated)
├── alice.key           # Client private key
├── alice.crt           # Client certificate
├── alice-bundle.tar.gz # Client distribution bundle
├── bob.key
├── bob.crt
└── bob-bundle.tar.gz
```

## Security Checklist

- [ ] CA key is encrypted with strong passphrase
- [ ] CA key is backed up to secure location
- [ ] CA key permissions are 600 (read/write by owner only)
- [ ] CA key is NOT in version control (.gitignore)
- [ ] Client certificates have short validity (2 years max)
- [ ] Client bundles sent via encrypted channels only
- [ ] Passphrase stored in password manager
- [ ] Regular review of connected clients
- [ ] Unused client certs are revoked

## Advanced Usage

### Batch Create Clients

```bash
for client in alice bob charlie device1 device2; do
    ./create_client_cert.sh "$client"
done
```

### Check Certificate Expiry

```bash
openssl x509 -in certs/alice.crt -noout -enddate
```

### List All Issued Certificates

```bash
for cert in certs/*.crt; do
    echo "=== $(basename $cert) ==="
    openssl x509 -in "$cert" -noout -subject -enddate -fingerprint -sha256
    echo ""
done
```

### Revoke a Client

```bash
# Remove from database
docker-compose exec db psql -U openssl_server -d openssl_encrypt \
  -c "DELETE FROM pp_clients WHERE cert_fingerprint='abc123...';"

docker-compose exec db psql -U openssl_server -d openssl_encrypt \
  -c "DELETE FROM in_clients WHERE cert_fingerprint='abc123...';"

# Move certificate files to revoked directory
mkdir -p certs/revoked
mv certs/alice.* certs/revoked/
```

### Renew Certificate Before Expiry

```bash
# Generate new certificate with same name
mv certs/alice.key certs/alice.key.old
mv certs/alice.crt certs/alice.crt.old

./create_client_cert.sh alice

# Distribute new certificate to client
# Old certificate will expire automatically
```

## Troubleshooting

### "CA not found"

Make sure you've run `setup_ca.sh` first.

### "Client certificate already exists"

You already created a certificate with this name. Either:
1. Use a different name
2. Rename/remove existing files

```bash
mv certs/alice.key certs/alice.key.old
mv certs/alice.crt certs/alice.crt.old
./create_client_cert.sh alice
```

### "verification failed"

Check the certificate was signed by the correct CA:

```bash
openssl verify -CAfile certs/ca.crt certs/alice.crt
```

Should output: `alice.crt: OK`

### View Certificate Details

```bash
openssl x509 -in certs/alice.crt -noout -text
```

## See Also

- [mTLS Setup Guide](../docs/MTLS_SETUP.md) - Comprehensive setup documentation
- [Server Configuration](../docs/CONFIGURATION.md) - Environment variables and settings
- [Security Best Practices](../docs/SECURITY.md) - Hardening and operational security
