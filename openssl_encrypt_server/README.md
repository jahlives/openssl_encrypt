# OpenSSL Encrypt Server

Unified FastAPI server with modular architecture for encryption key management, telemetry, pepper storage, and integrity verification.

## Features

### Public Modules (JWT Authentication)
- **Keyserver Module**: Post-quantum public key distribution with ML-KEM and ML-DSA support
- **Telemetry Module**: Anonymous usage statistics collection

### Private Modules (mTLS Authentication)
- **Pepper Module**: Secure pepper storage with TOTP 2FA and deadman switch (opt-in)
- **Integrity Module**: Encrypted file metadata hash verification (opt-in)

### Infrastructure
- **Dual Authentication**: JWT tokens (keyserver/telemetry) + mTLS certificates (pepper/integrity)
- **Async Architecture**: AsyncIO + asyncpg for high concurrency
- **Docker Ready**: Complete Docker Compose setup with fixed IPs
- **Modular Design**: Enable/disable modules independently via configuration

## Quick Start

### 1. Configuration

Copy the example environment file:

```bash
cp .env.example .env
```

Edit `.env` and **change the secrets**:

```bash
# IMPORTANT: Change these to random 32+ character strings!
KEYSERVER_TOKEN_SECRET=your-keyserver-secret-min-32-chars
TELEMETRY_TOKEN_SECRET=your-telemetry-secret-min-32-chars

# Database password
POSTGRES_PASSWORD=your-secure-database-password
```

### 2. Start with Docker Compose

```bash
docker-compose up -d
```

The server will start on http://localhost:8080

### 3. Verify

Check health:
```bash
curl http://localhost:8080/health
```

Check modules:
```bash
curl http://localhost:8080/info
```

## API Endpoints

### Core Endpoints

- `GET /health` - Health check
- `GET /ready` - Readiness check (database connectivity)
- `GET /info` - Server information
- `GET /docs` - OpenAPI documentation (if DEBUG=true)

### Keyserver Module (`/api/v1/keys`)

#### Public Endpoints
- `GET /api/v1/keys/search?q=<query>` - Search for public key

#### Authenticated Endpoints (require Keyserver token)
- `POST /api/v1/keys/register` - Register and get token
- `POST /api/v1/keys` - Upload public key
- `POST /api/v1/keys/{fingerprint}/revoke` - Revoke key

### Telemetry Module (`/api/v1/telemetry`)

#### Public Endpoints
- `GET /api/v1/telemetry/stats` - Get aggregated statistics

#### Authenticated Endpoints (require Telemetry token)
- `POST /api/v1/telemetry/register` - Register and get token
- `POST /api/v1/telemetry/events` - Submit telemetry events

### Pepper Module (`/api/v1/pepper`) - **Requires mTLS**

**Status**: Opt-in (disabled by default)

**Authentication**: Client certificate signed by your self-signed CA

#### All Endpoints (require mTLS client certificate)
- `GET /profile` - Get client profile (auto-registers on first connection)
- `PUT /profile` - Update profile name
- `DELETE /profile` - Delete account [TOTP required]
- `POST /totp/setup` - Setup TOTP 2FA
- `POST /totp/verify` - Verify TOTP setup
- `DELETE /totp` - Disable TOTP [TOTP required]
- `POST /peppers` - Store pepper
- `GET /peppers` - List peppers
- `GET /peppers/{name}` - Get pepper
- `PUT /peppers/{name}` - Update pepper
- `DELETE /peppers/{name}` - Delete pepper
- `GET /deadman` - Get deadman switch status
- `PUT /deadman` - Configure deadman switch
- `POST /deadman/checkin` - Check in (reset timer)
- `POST /panic` - Wipe all peppers [TOTP required]

**Setup**: See [docs/MTLS_SETUP.md](docs/MTLS_SETUP.md) and [scripts/README.md](scripts/README.md)

### Integrity Module (`/api/v1/integrity`) - **Requires mTLS**

**Status**: Opt-in (disabled by default)

**Authentication**: Client certificate signed by your self-signed CA

#### All Endpoints (require mTLS client certificate)
- `GET /profile` - Get client profile (auto-registers on first connection)
- `PUT /profile` - Update profile name
- `POST /hashes` - Store metadata hash
- `GET /hashes` - List all hashes
- `GET /hashes/{file_id}` - Get specific hash
- `PUT /hashes/{file_id}` - Update hash
- `DELETE /hashes/{file_id}` - Delete specific hash
- `DELETE /hashes` - Delete all hashes
- `POST /verify` - Verify single hash (detects tampering)
- `POST /verify/batch` - Batch verify multiple hashes
- `GET /stats` - Get verification statistics

**Setup**: See [docs/MTLS_SETUP.md](docs/MTLS_SETUP.md) and [scripts/README.md](scripts/README.md)

## Authentication

### JWT Tokens (Keyserver & Telemetry)

Tokens are **module-specific** and cannot be used across modules:

1. **Keyserver token** has issuer: `openssl_encrypt_keyserver`
2. **Telemetry token** has issuer: `openssl_encrypt_telemetry`

This prevents a Keyserver token from being used for Telemetry endpoints and vice versa.

### mTLS Certificates (Pepper & Integrity)

**Security Model**: Self-signed CA only (public CAs are NOT accepted)

These modules are **non-public** and require client certificates signed by YOUR private Certificate Authority:

1. **One-time setup**: Create your self-signed CA
2. **Per client/device**: Generate client certificates signed by your CA
3. **Server verification**: Server only trusts certificates from your CA
4. **Auto-registration**: Clients auto-register on first connection

**Quick Start**:
```bash
# 1. Create CA (one-time)
cd scripts
./setup_ca.sh

# 2. Generate client certificate
./create_client_cert.sh alice

# 3. Distribute to client
tar czf alice-bundle.tar.gz certs/alice.{key,crt} certs/ca.crt

# 4. Client connects
curl --cert alice.crt --key alice.key --cacert ca.crt \
  https://server/api/v1/pepper/profile
```

**See detailed documentation**:
- [mTLS Setup Guide](docs/MTLS_SETUP.md) - Complete setup instructions
- [Certificate Management Scripts](scripts/README.md) - Helper scripts usage

## Example Usage

### Register and upload a key

```bash
# 1. Register with keyserver
RESPONSE=$(curl -X POST http://localhost:8080/api/v1/keys/register)
TOKEN=$(echo $RESPONSE | jq -r '.token')

# 2. Upload a key (requires key bundle JSON)
curl -X POST http://localhost:8080/api/v1/keys \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d @key_bundle.json

# 3. Search for the key (public, no auth)
curl "http://localhost:8080/api/v1/keys/search?q=alice"
```

### Submit telemetry

```bash
# 1. Register with telemetry
RESPONSE=$(curl -X POST http://localhost:8080/api/v1/telemetry/register)
TOKEN=$(echo $RESPONSE | jq -r '.token')

# 2. Submit events
curl -X POST http://localhost:8080/api/v1/telemetry/events \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d @events.json

# 3. View stats (public, no auth)
curl http://localhost:8080/api/v1/telemetry/stats
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `POSTGRES_USER` | Database user | `openssl_server` |
| `POSTGRES_PASSWORD` | Database password | `change_me_in_production` |
| `POSTGRES_DB` | Database name | `openssl_encrypt` |
| `POSTGRES_HOST` | Database host | `db` |
| `POSTGRES_PORT` | Database port | `5432` |
| `SERVER_HOST` | Server bind address | `0.0.0.0` |
| `SERVER_PORT` | Server port | `8080` |
| `DEBUG` | Debug mode | `false` |
| `LOG_LEVEL` | Log level | `INFO` |
| `KEYSERVER_TOKEN_SECRET` | Keyserver JWT secret (32+ chars) | - |
| `TELEMETRY_TOKEN_SECRET` | Telemetry JWT secret (32+ chars) | - |
| `KEYSERVER_ENABLED` | Enable keyserver module | `true` |
| `TELEMETRY_ENABLED` | Enable telemetry module | `true` |
| `CORS_ORIGINS` | CORS allowed origins | `*` |

## Docker Network

The Docker Compose setup uses fixed IPs on the `172.28.0.0/16` subnet:

- **Database**: `172.28.0.2`
- **API Server**: `172.28.0.3`

This allows for predictable networking and easier integration with external services.

## Development

### Local Development (without Docker)

1. Install PostgreSQL:
```bash
# macOS
brew install postgresql@16

# Ubuntu/Debian
sudo apt-get install postgresql-16
```

2. Create database:
```bash
createdb openssl_encrypt
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Set environment variables:
```bash
export POSTGRES_HOST=localhost
export KEYSERVER_TOKEN_SECRET="dev-keyserver-secret-min-32-chars"
export TELEMETRY_TOKEN_SECRET="dev-telemetry-secret-min-32-chars"
```

5. Run server:
```bash
python -m uvicorn server:app --reload
```

### Testing Token Isolation

```bash
# Register with keyserver
KS_TOKEN=$(curl -X POST http://localhost:8080/api/v1/keys/register | jq -r '.token')

# Try to use keyserver token for telemetry (should fail with 401)
curl -X POST http://localhost:8080/api/v1/telemetry/events \
  -H "Authorization: Bearer $KS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"events": []}'
# Response: {"detail": "Token not valid for this service"}
```

## Architecture

```
openssl_encrypt_server/
├── server.py                 # Main entry point
├── config.py                 # Configuration
├── core/
│   ├── auth/
│   │   └── token.py          # JWT TokenAuth class
│   ├── database.py           # Async SQLAlchemy
│   └── exceptions.py         # Exception handlers
└── modules/
    ├── keyserver/            # Keyserver module
    │   ├── models.py         # KSClient, KSKey (ks_ tables)
    │   ├── schemas.py        # Pydantic schemas
    │   ├── auth.py           # Keyserver auth instance
    │   ├── routes.py         # API routes
    │   ├── service.py        # Business logic
    │   └── verification.py   # PQC signature verification
    └── telemetry/            # Telemetry module
        ├── models.py         # TMClient, TMEvent (tm_ tables)
        ├── schemas.py        # Pydantic schemas
        ├── auth.py           # Telemetry auth instance
        ├── routes.py         # API routes
        └── service.py        # Business logic
```

## Database Tables

### Keyserver Tables (ks_ prefix)

- `ks_clients` - Registered keyserver clients
- `ks_keys` - Public keys with metadata
- `ks_access_log` - Access audit log

### Telemetry Tables (tm_ prefix)

- `tm_clients` - Registered telemetry clients
- `tm_events` - Telemetry events
- `tm_daily_stats` - Aggregated statistics

## Security

### Token Security

1. **Unique Secrets**: Each module MUST have a different token secret (validated at startup)
2. **Minimum Length**: Token secrets must be at least 32 characters
3. **Issuer Claims**: JWT tokens include issuer claims for module isolation
4. **Expiry**: Tokens expire after 365 days (configurable)

### Signature Verification

The keyserver uses **liboqs** (Open Quantum Safe) for post-quantum signature verification:

- Supports ML-DSA-44, ML-DSA-65, ML-DSA-87 (Dilithium)
- Verifies self-signatures on all uploaded keys
- Validates fingerprints against calculated hashes

## Proxy Deployment

The server is designed to run behind a reverse proxy (e.g., Nginx):

1. Server binds to internal port (default: 8080)
2. Proxy handles TLS termination
3. Proxy forwards to backend on `http://172.28.0.3:8080`

Example Nginx config (basic):

```nginx
upstream openssl_encrypt_api {
    server 172.28.0.3:8080;
}

server {
    listen 443 ssl http2;
    server_name api.example.com;

    ssl_certificate /etc/ssl/certs/api.crt;
    ssl_certificate_key /etc/ssl/private/api.key;

    location / {
        proxy_pass http://openssl_encrypt_api;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### mTLS Configuration for Pepper/Integrity Modules

For modules requiring client certificate authentication (pepper, integrity), configure Nginx to pass the raw certificate:

```nginx
upstream openssl_encrypt_api {
    server 172.28.0.3:8080;
}

server {
    listen 443 ssl http2;
    server_name pepper.example.com integrity.example.com;

    # Server certificate (Let's Encrypt or your own)
    ssl_certificate /etc/ssl/certs/server.crt;
    ssl_certificate_key /etc/ssl/private/server.key;

    # Client certificate verification (your self-signed CA)
    ssl_client_certificate /path/to/your/ca.crt;
    ssl_verify_client optional;  # Optional so keyserver/telemetry still work

    location / {
        proxy_pass http://openssl_encrypt_api;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Pass raw client certificate (URL-encoded PEM)
        # Backend will compute SHA-256 fingerprint from this
        proxy_set_header X-Client-Cert $ssl_client_escaped_cert;
    }
}
```

**Key points:**
- Use `$ssl_client_escaped_cert` to pass the URL-encoded PEM certificate
- Backend server computes SHA-256 fingerprint from the certificate
- This works with Nginx's default SHA-1 fingerprint variable
- `ssl_verify_client optional` allows non-mTLS endpoints to work on same domain

## Future Modules

This server is designed to support additional modules:

- **Pepper Module** (mTLS auth) - Secure pepper storage with dead man's switch
- **Integrity Module** (JWT auth) - Metadata hash verification

See `SERVER_CONSOLIDATION_SPEC_v3.md` for the full roadmap.

## License

Same as parent project (Hippocratic License 3.0)

## Support

For issues or questions, please refer to the main project repository.
