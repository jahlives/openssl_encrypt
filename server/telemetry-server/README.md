# OpenSSL Encrypt Telemetry Server

Anonymous telemetry server for collecting cryptographic algorithm usage statistics from OpenSSL Encrypt clients.

## Privacy Guarantees

- ✅ Only collects algorithm names and parameters
- ❌ NO passwords, keys, salts, filenames
- ❌ NO IP addresses or hardware identifiers
- ✅ Client ID is random (not hardware-based)
- ✅ 90-day raw data retention (then aggregated and deleted)
- ✅ Public statistics endpoint (transparency)

## Features

- **Client Registration**: Anonymous client registration with API keys
- **Batch Upload**: Efficient batch telemetry upload (up to 1000 events)
- **Rate Limiting**: 10,000 events per day per API key
- **Public Statistics**: Public endpoint for aggregated statistics
- **TLS Required**: HTTPS only (certificate validation enforced)
- **PostgreSQL**: Robust database with proper indexing

## Quick Start

### Using Docker Compose (Recommended)

```bash
# 1. Set environment variables
export SECRET_KEY="your-secret-key-here"

# 2. Start services
docker-compose up -d

# 3. Check health
curl http://localhost:8000/health

# 4. View API documentation
# Open http://localhost:8000/docs in your browser
```

### Manual Setup

```bash
# 1. Create virtual environment
python3 -m venv venv
source venv/bin/activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Set environment variables
export DATABASE_URL="postgresql://user:password@localhost:5432/telemetry"
export SECRET_KEY="your-secret-key-here"

# 4. Run server
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

## API Endpoints

### POST /api/v1/register
Register new client and receive API key.

**Request:**
```json
{
  "client_id": "random-32-char-hex",
  "platform": "linux",
  "client_version": "1.4.0"
}
```

**Response:**
```json
{
  "api_key": "sk_...",
  "expires": "2026-12-30T00:00:00Z"
}
```

### POST /api/v1/telemetry
Upload batch of telemetry events (requires Bearer token).

**Request:**
```json
{
  "events": [
    {
      "timestamp": "2025-12-30T12:00:00Z",
      "operation": "encrypt",
      "mode": "symmetric",
      "format_version": 8,
      "hash_algorithms": ["sha512", "blake2b"],
      "kdf_algorithms": ["argon2"],
      "encryption_algorithm": "aes-256-gcm",
      "success": true
    }
  ]
}
```

**Response:**
```json
{
  "received": 1,
  "processed": 1
}
```

### GET /api/v1/stats
Get public statistics (no authentication required).

**Response:**
```json
{
  "total_operations": 10000,
  "total_clients": 500,
  "modes": [{"algorithm": "symmetric", "count": 9000, "percentage": 90.0}],
  "encryption_algorithms": [...],
  "hash_algorithms": [...],
  "kdf_algorithms": [...],
  "success_rate": 0.985
}
```

### POST /api/v1/key/refresh
Refresh API key (requires valid Bearer token).

**Response:**
```json
{
  "api_key": "sk_new...",
  "expires": "2026-12-30T00:00:00Z"
}
```

## Configuration

Environment variables:

- `DATABASE_URL`: PostgreSQL connection string
- `SECRET_KEY`: Secret key for hashing (MUST change in production)
- `API_KEY_EXPIRY_DAYS`: Days until API key expires (default: 365)
- `MAX_EVENTS_PER_REQUEST`: Maximum events per batch (default: 1000)
- `RATE_LIMIT_EVENTS_PER_DAY`: Rate limit per API key (default: 10000)
- `RAW_DATA_RETENTION_DAYS`: Days to keep raw data (default: 90)

## Database Schema

### api_keys
- Client authentication and rate limiting
- Stores hashed API keys (SHA-256)
- Tracks usage statistics

### telemetry_raw
- Individual telemetry events
- 90-day retention
- Indexed for efficient queries

### telemetry_aggregated
- Daily aggregated statistics
- Permanent storage
- Public statistics source

## Security

- ✅ TLS 1.2+ enforced (HTTPS only)
- ✅ API key authentication (Bearer tokens)
- ✅ Rate limiting per client
- ✅ Input validation (Pydantic schemas)
- ✅ SQL injection prevention (SQLAlchemy ORM)
- ✅ No IP address logging
- ✅ Hashed API keys (SHA-256)

## Production Deployment

### Requirements
- PostgreSQL 15+
- Python 3.11+
- TLS certificate (Let's Encrypt recommended)
- Reverse proxy (nginx/Caddy)

### Recommended Setup
1. Use Docker Compose for deployment
2. Configure TLS termination at reverse proxy
3. Set strong SECRET_KEY
4. Enable database backups
5. Monitor disk usage (raw data retention)
6. Configure log rotation

### Nginx Example
```nginx
server {
    listen 443 ssl http2;
    server_name telemetry.yourdomain.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        proxy_pass http://localhost:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

## Monitoring

Health check endpoint: `GET /health`

Returns:
```json
{
  "status": "healthy",
  "version": "1.0.0"
}
```

## Development

```bash
# Run tests (when implemented)
pytest tests/

# Run with auto-reload
uvicorn app.main:app --reload

# View API docs
# http://localhost:8000/docs
```

## License

Same as OpenSSL Encrypt main project.
