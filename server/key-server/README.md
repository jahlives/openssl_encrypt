# OpenSSL Encrypt Keyserver

A post-quantum keyserver for distributing public keys using ML-KEM and ML-DSA algorithms.

## Features

- **Post-quantum cryptography**: Only ML-KEM and ML-DSA algorithms supported
- **Self-signed bundles**: All keys cryptographically verified before storage
- **Bearer token authentication**: Secure uploads and revocations
- **Public search**: Anyone can search and download public keys
- **PostgreSQL storage**: Reliable, scalable database
- **Docker deployment**: Easy deployment with Docker Compose
- **REST API**: Simple HTTP API with JSON

## Security

### Authentication

- **Upload**: Requires Bearer token (`Authorization: Bearer <token>`)
- **Search**: Public (no authentication)
- **Revoke**: Requires Bearer token + revocation signature

### Verification

All uploaded keys are verified:
1. Self-signature verification using liboqs
2. Fingerprint calculation and verification
3. Algorithm whitelist enforcement

### Supported Algorithms

**Key Encapsulation (ML-KEM)**:
- ML-KEM-512
- ML-KEM-768
- ML-KEM-1024

**Digital Signatures (ML-DSA)**:
- ML-DSA-44
- ML-DSA-65
- ML-DSA-87

## Quick Start

### Using Docker Compose (Recommended)

```bash
# 1. Set environment variables (optional)
export DB_PASSWORD=your_secure_password
export API_TOKEN_SALT=your_secret_salt
export API_PORT=8080

# 2. Start services
docker-compose up -d

# 3. Check health
curl http://localhost:8080/health

# 4. View logs
docker-compose logs -f api
```

### Manual Setup

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Install liboqs (see below)

# 3. Set environment variables
export DATABASE_URL=postgresql://user:pass@localhost/keyserver
export API_TOKEN_SALT=your_secret_salt

# 4. Run server
python -m app.main

# Or with uvicorn
uvicorn app.main:app --host 0.0.0.0 --port 8080
```

## API Endpoints

### Root

```http
GET /
```

Returns service information and available endpoints.

### Health Check

```http
GET /health
```

Returns server health status.

### Upload Key

```http
POST /api/v1/keys
Authorization: Bearer <token>
Content-Type: application/json

{
  "name": "alice",
  "email": "alice@example.com",
  "fingerprint": "3a:4b:5c:...",
  "created_at": "2025-12-30T12:00:00Z",
  "encryption_public_key": "<base64>",
  "signing_public_key": "<base64>",
  "encryption_algorithm": "ML-KEM-768",
  "signing_algorithm": "ML-DSA-65",
  "self_signature": "<base64>"
}
```

**Response**: `200 OK`
```json
{
  "success": true,
  "fingerprint": "3a:4b:5c:...",
  "message": "Key uploaded successfully"
}
```

**Errors**:
- `400`: Invalid bundle or verification failed
- `401`: Authentication required
- `409`: Key already exists

### Search Key

```http
GET /api/v1/keys/search?q=<query>
```

Search by:
- Fingerprint (exact or prefix)
- Name (exact)
- Email (exact)

**Response**: `200 OK`
```json
{
  "key": {
    "name": "alice",
    "email": "alice@example.com",
    "fingerprint": "3a:4b:5c:...",
    ...
  },
  "message": "Key found"
}
```

**Errors**:
- `404`: Key not found

### Revoke Key

```http
POST /api/v1/keys/{fingerprint}/revoke
Authorization: Bearer <token>
Content-Type: application/json

{
  "signature": "<hex-encoded-revocation-signature>"
}
```

**Response**: `200 OK`
```json
{
  "success": true,
  "fingerprint": "3a:4b:5c:...",
  "message": "Key revoked successfully"
}
```

**Errors**:
- `400`: Invalid revocation signature
- `401`: Authentication required
- `404`: Key not found

## Installing liboqs

### Ubuntu/Debian

```bash
# Install dependencies
sudo apt-get update
sudo apt-get install -y build-essential cmake git ninja-build libssl-dev

# Build and install liboqs
git clone --depth 1 --branch 0.10.0 https://github.com/open-quantum-safe/liboqs.git
cd liboqs
mkdir build && cd build
cmake -GNinja -DCMAKE_INSTALL_PREFIX=/usr/local -DBUILD_SHARED_LIBS=ON ..
ninja
sudo ninja install
sudo ldconfig

# Install Python bindings
pip install liboqs-python
```

### macOS

```bash
# Install dependencies
brew install cmake ninja openssl

# Build and install liboqs
git clone --depth 1 --branch 0.10.0 https://github.com/open-quantum-safe/liboqs.git
cd liboqs
mkdir build && cd build
cmake -GNinja -DCMAKE_INSTALL_PREFIX=/usr/local -DBUILD_SHARED_LIBS=ON ..
ninja
sudo ninja install

# Install Python bindings
pip install liboqs-python
```

## Configuration

### Environment Variables

- `DATABASE_URL`: PostgreSQL connection string
- `API_TOKEN_SALT`: Salt for API token hashing
- `DEBUG`: Enable debug mode (`true`/`false`)
- `DB_PASSWORD`: Database password (docker-compose)
- `API_PORT`: API port (docker-compose, default: 8080)

### Database

The server uses PostgreSQL for storage. Schema is automatically created on startup.

**Tables**:
- `public_keys`: Stores public key bundles

**Indices**:
- Fingerprint (unique, prefix search)
- Name + Email (search)
- Revoked + Created (filtering)

## Client Usage

### Enable Keyserver (Client)

```bash
openssl-encrypt keyserver enable
```

### Set API Token (Client)

```bash
openssl-encrypt keyserver set-token <your-token>
```

### Upload Key (Client)

```bash
openssl-encrypt keyserver upload alice
```

### Search Key (Client)

```bash
openssl-encrypt keyserver search alice@example.com
```

### Encrypt with Keyserver (Client)

```bash
openssl-encrypt encrypt \
  --for-identity alice@example.com \
  --sign-with mykey \
  --use-keyserver \
  input.txt -o output.enc
```

## Development

### Running Tests

```bash
# Install test dependencies
pip install pytest pytest-asyncio httpx

# Run tests
pytest
```

### Database Migrations

```bash
# Generate migration
alembic revision --autogenerate -m "description"

# Apply migration
alembic upgrade head

# Rollback
alembic downgrade -1
```

## Production Deployment

### Security Checklist

- [ ] Change default database password
- [ ] Set secure API_TOKEN_SALT
- [ ] Configure CORS appropriately
- [ ] Use HTTPS with reverse proxy (nginx/traefik)
- [ ] Set up database backups
- [ ] Enable rate limiting
- [ ] Monitor logs and health checks
- [ ] Use strong API tokens
- [ ] Restrict database access

### Recommended Setup

```
Internet → HTTPS (443) → Nginx/Traefik → Keyserver API (8080) → PostgreSQL (5432)
```

### Nginx Example

```nginx
server {
    listen 443 ssl http2;
    server_name keys.example.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        proxy_pass http://localhost:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

## Monitoring

### Health Check

```bash
curl http://localhost:8080/health
```

### Database Status

```bash
docker-compose exec db psql -U keyserver -c "SELECT COUNT(*) FROM public_keys;"
```

### Logs

```bash
# Docker logs
docker-compose logs -f api

# Application logs
tail -f /var/log/keyserver/app.log
```

## Troubleshooting

### liboqs not found

```bash
# Check if liboqs is installed
ldconfig -p | grep liboqs

# If not found, reinstall liboqs
sudo ldconfig
```

### Database connection failed

```bash
# Check PostgreSQL is running
docker-compose ps db

# Check connection
docker-compose exec db psql -U keyserver -c "SELECT 1;"
```

### Import errors

```bash
# Ensure all dependencies are installed
pip install -r requirements.txt

# Check Python path
python -c "import app; print(app.__file__)"
```

## License

Part of the OpenSSL Encrypt project.

## Support

For issues and questions:
- GitHub Issues: https://github.com/username/openssl_encrypt/issues
- Documentation: See main project README
