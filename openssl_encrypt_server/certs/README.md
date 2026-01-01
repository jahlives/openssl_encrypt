# Certificate Directory

This directory stores TLS certificates for mTLS authentication.

## For Pepper and Integrity Modules

These modules require **self-signed CA certificates** (not public CAs).

### Quick Setup

```bash
# 1. Create your CA (one-time)
cd ../scripts
./setup_ca.sh

# 2. Create client certificates (per user/device)
./create_client_cert.sh alice
./create_client_cert.sh bob
```

See [scripts/README.md](../scripts/README.md) for detailed instructions.

## Directory Contents

After running the setup scripts:

```
certs/
├── ca.key              # CA private key (NEVER COMMIT!)
├── ca.crt              # CA certificate (public)
├── alice.key           # Client private key (NEVER COMMIT!)
├── alice.crt           # Client certificate (public)
├── alice-bundle.tar.gz # Client distribution bundle
└── ...
```

## Security

- **Private keys** (`.key` files) are **automatically excluded** from git via `.gitignore`
- Only commit documentation files
- CA key should be backed up to secure offline storage
- Client keys should only be distributed via secure channels

## Server Configuration

### Proxy Mode (Recommended)

Configure Nginx to verify client certificates:

```nginx
ssl_client_certificate /etc/ssl/certs/openssl-encrypt-ca.crt;
ssl_verify_client on;
```

Copy `ca.crt` to server:

```bash
sudo cp ca.crt /etc/ssl/certs/openssl-encrypt-ca.crt
```

### Direct mTLS Mode

Mount certificates in Docker:

```yaml
# docker-compose.yml
services:
  api:
    volumes:
      - ./certs/ca.crt:/certs/ca.crt:ro
      - ./certs/server.key:/certs/server.key:ro
      - ./certs/server.crt:/certs/server.crt:ro
```

Configure environment:

```bash
PEPPER_AUTH_MODE=mtls
PEPPER_MTLS_CLIENT_CA=/certs/ca.crt
```

## Documentation

- [Full mTLS Setup Guide](../docs/MTLS_SETUP.md)
- [Certificate Management Scripts](../scripts/README.md)
