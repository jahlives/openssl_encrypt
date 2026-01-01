# Server Consolidation Spec v3

*For Claude Code Implementation*

---

## Goal

Merge Keyserver and Telemetry Server into a unified server with feature flags. Add new Pepper module for secure pepper storage with dead man's switch functionality.

## Current State

- **Keyserver:** FastAPI, PostgreSQL - stores and serves public keys for openssl_encrypt
- **Telemetry Server:** FastAPI, PostgreSQL - anonymous usage telemetry (opt-in)
- Both servers use **API-Token authentication** (token issued via `/register` endpoint)
- Nginx reverse proxy in front

## Authentication Overview

| Module | Auth Method | Token Scope | Flow |
|--------|-------------|-------------|------|
| Keyserver | API-Token | Keyserver only | `POST /api/v1/keys/register` → Token → `Authorization: Bearer <token>` |
| Telemetry | API-Token | Telemetry only | `POST /api/v1/telemetry/register` → Token → `Authorization: Bearer <token>` |
| Pepper | mTLS | Certificate-based | Client certificate (via Nginx OR direct) |
| Integrity | API-Token | Integrity only | `POST /api/v1/integrity/register` → Token → `Authorization: Bearer <token>` |

**IMPORTANT: Token Independence**
- Keyserver, Telemetry, and Integrity tokens are **completely independent**
- Different secrets, different client tables, different token validation
- A Keyserver token **cannot** be used for Telemetry/Integrity and vice versa
- Cross-module token usage is cryptographically impossible (different signing keys)

**Pepper supports two deployment modes:**
1. **Proxy Mode:** Nginx terminates mTLS, passes fingerprint via header
2. **mTLS Mode:** Server handles mTLS directly on separate port

---

## Target Architecture

### Project Structure

```
openssl_encrypt_server/
├── server.py                 # Uvicorn entrypoint (main API port)
├── pepper_server.py          # Optional: Separate mTLS entrypoint for Pepper
├── config.py                 # Pydantic Settings with YAML loading
├── config.yml                # Main configuration file
├── core/
│   ├── __init__.py
│   ├── auth/
│   │   ├── __init__.py
│   │   ├── token.py          # Base TokenAuth class
│   │   ├── mtls.py           # mTLS auth for Pepper (direct mode)
│   │   └── proxy.py          # Proxy header auth for Pepper (proxy mode)
│   ├── database.py           # SQLAlchemy async engine + session
│   ├── middleware.py         # Logging, rate limiting, request ID
│   └── exceptions.py         # Custom exception handlers
├── modules/
│   ├── __init__.py           # Dynamic module loader
│   ├── keyserver/
│   │   ├── __init__.py
│   │   ├── routes.py         # FastAPI router
│   │   ├── models.py         # SQLAlchemy models (ks_ prefix)
│   │   ├── schemas.py        # Pydantic request/response schemas
│   │   ├── service.py        # Business logic
│   │   └── auth.py           # Keyserver-specific TokenAuth instance
│   ├── telemetry/
│   │   ├── __init__.py
│   │   ├── routes.py
│   │   ├── models.py         # (tm_ prefix)
│   │   ├── schemas.py
│   │   ├── service.py
│   │   └── auth.py           # Telemetry-specific TokenAuth instance
│   └── pepper/
│       ├── __init__.py
│       ├── routes.py
│       ├── models.py         # (pp_ prefix)
│       ├── schemas.py
│       ├── service.py
│       ├── auth.py           # Pepper-specific auth (proxy/mtls switch)
│       ├── deadman.py        # Dead man's switch background task
│       └── panic.py          # Panic/wipe functionality
│   └── integrity/
│       ├── __init__.py
│       ├── routes.py
│       ├── models.py         # (in_ prefix)
│       ├── schemas.py
│       ├── service.py
│       └── auth.py           # Integrity-specific TokenAuth instance
├── alembic/
│   ├── alembic.ini
│   ├── env.py
│   └── versions/             # Migration scripts
├── tests/
│   ├── conftest.py
│   ├── test_keyserver.py
│   ├── test_telemetry.py
│   ├── test_pepper.py
│   └── test_token_isolation.py  # Tests for token independence
├── Dockerfile
├── docker-compose.yml
├── docker-compose.mtls.yml   # Alternative: Pepper with direct mTLS
└── requirements.txt
```

---

## Configuration

### config.yml Schema

```yaml
server:
  host: 127.0.0.1             # localhost if behind Nginx
  port: 8080                  # Main API port (no TLS - Nginx handles it)
  workers: 4

database:
  url: postgresql+asyncpg://user:pass@localhost:5432/openssl_encrypt
  pool_size: 20
  max_overflow: 10

logging:
  level: INFO
  format: json                # json or text

rate_limiting:
  enabled: true
  requests_per_minute: 60

modules:
  keyserver:
    enabled: true
    max_key_size_kb: 100
    require_self_signature: true
    token:
      # MUST be different from telemetry.token.secret!
      secret: ${KEYSERVER_TOKEN_SECRET}
      algorithm: HS256
      expiry_days: 365
      issuer: "openssl_encrypt_keyserver"
    
  telemetry:
    enabled: true
    retention_days: 365
    token:
      # MUST be different from keyserver.token.secret!
      secret: ${TELEMETRY_TOKEN_SECRET}
      algorithm: HS256
      expiry_days: 365
      issuer: "openssl_encrypt_telemetry"
    
  pepper:
    enabled: true
    
    # Authentication mode: "proxy" or "mtls"
    auth:
      mode: proxy             # Default: Nginx terminates mTLS
      
      # === Proxy Mode Settings ===
      proxy:
        fingerprint_header: X-Client-Cert-Fingerprint
        dn_header: X-Client-Cert-DN           # Optional
        verify_header: X-Client-Cert-Verify   # Optional
        trusted_proxies:
          - 127.0.0.1
          - ::1
          - 10.0.0.0/8
          - 172.16.0.0/12
          - 192.168.0.0/16
      
      # === mTLS Mode Settings (alternative) ===
      # mode: mtls
      # mtls:
      #   host: 0.0.0.0
      #   port: 8444
      #   tls:
      #     cert: /certs/pepper-server.crt
      #     key: /certs/pepper-server.key
      #     client_ca: /certs/client-ca.crt
      #     verify_client: required
      #     check_crl: false
    
    deadman:
      enabled: true
      check_interval: 1h
      default_interval: 7d
      grace_period: 24h
    
    totp:
      enabled: true
      issuer: "openssl_encrypt"
      backup_codes_count: 10
    
    max_peppers_per_client: 100
    
  integrity:
    enabled: true
    token:
      # MUST be different from keyserver/telemetry secrets!
      secret: ${INTEGRITY_TOKEN_SECRET}
      algorithm: HS256
      expiry_days: 365
      issuer: "openssl_encrypt_integrity"
    # Hash algorithm for metadata hashes
    hash_algorithm: sha256
    # Maximum hashes per client (0 = unlimited)
    max_hashes_per_client: 0
```

### Environment Variables

```bash
# Required secrets - MUST ALL BE DIFFERENT!
KEYSERVER_TOKEN_SECRET=keyserver-secret-min-32-chars-long-abc123
TELEMETRY_TOKEN_SECRET=telemetry-secret-min-32-chars-long-xyz789
INTEGRITY_TOKEN_SECRET=integrity-secret-min-32-chars-long-def456
DB_PASSWORD=database-password

# Optional overrides
CONFIG_PATH=/app/config.yml
LOG_LEVEL=DEBUG
```

### Startup Validation

The server MUST validate at startup that token secrets are different:

```python
# In server.py or config.py
def validate_config(settings: Settings):
    """Validate configuration at startup"""
    ks_secret = settings.modules.keyserver.token.secret
    tm_secret = settings.modules.telemetry.token.secret
    in_secret = settings.modules.integrity.token.secret
    
    secrets = [
        ("Keyserver", ks_secret),
        ("Telemetry", tm_secret),
        ("Integrity", in_secret)
    ]
    
    # Check all secrets are unique
    seen = {}
    for name, secret in secrets:
        if secret in seen:
            raise ValueError(
                f"SECURITY ERROR: {name} and {seen[secret]} token secrets MUST be different! "
                "Using the same secret would allow cross-module token usage."
            )
        seen[secret] = name
    
    # Check minimum length
    for name, secret in secrets:
        if len(secret) < 32:
            raise ValueError(f"{name} token secret must be at least 32 characters")
```

---

## Authentication Implementation

### Base Token Auth Class (core/auth/token.py)

```python
from datetime import datetime, timedelta, timezone
from typing import Optional
import jwt
from fastapi import HTTPException, Security, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
import secrets
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update

security = HTTPBearer(auto_error=False)

class TokenPayload(BaseModel):
    """JWT Token payload structure"""
    sub: str              # Client ID
    iss: str              # Issuer (module identifier)
    exp: datetime         # Expiration
    iat: datetime         # Issued at
    jti: str              # Unique token ID

class TokenConfig(BaseModel):
    """Token configuration"""
    secret: str
    algorithm: str = "HS256"
    expiry_days: int = 365
    issuer: str

class TokenAuth:
    """
    Token authentication handler.
    
    Each module (Keyserver, Telemetry) gets its own instance with:
    - Unique secret key
    - Unique issuer string
    - Separate client table
    
    This ensures complete token isolation between modules.
    """
    
    def __init__(self, config: TokenConfig, client_model, db_session_factory):
        self.secret = config.secret
        self.algorithm = config.algorithm
        self.expiry_days = config.expiry_days
        self.issuer = config.issuer
        self.client_model = client_model
        self.db_session_factory = db_session_factory
    
    def generate_client_id(self) -> str:
        """Generate unique client ID"""
        return secrets.token_hex(16)
    
    def create_token(self, client_id: str) -> tuple[str, datetime]:
        """
        Create JWT token for client.
        Returns (token, expiry_datetime)
        """
        now = datetime.now(timezone.utc)
        expiry = now + timedelta(days=self.expiry_days)
        
        payload = TokenPayload(
            sub=client_id,
            iss=self.issuer,
            exp=expiry,
            iat=now,
            jti=secrets.token_hex(8)
        )
        
        token = jwt.encode(
            payload.model_dump(mode='json'),
            self.secret,
            algorithm=self.algorithm
        )
        
        return token, expiry
    
    def verify_token(self, token: str) -> TokenPayload:
        """
        Verify and decode JWT token.
        
        Raises HTTPException if:
        - Token is expired
        - Token signature is invalid (wrong secret = wrong module)
        - Token issuer doesn't match this module
        """
        try:
            data = jwt.decode(
                token,
                self.secret,
                algorithms=[self.algorithm],
                issuer=self.issuer  # Validates issuer claim
            )
            return TokenPayload(**data)
        
        except jwt.ExpiredSignatureError:
            raise HTTPException(
                status_code=401,
                detail="Token expired",
                headers={"WWW-Authenticate": "Bearer"}
            )
        except jwt.InvalidIssuerError:
            # This happens if someone tries to use a token from another module
            raise HTTPException(
                status_code=401,
                detail="Token not valid for this service",
                headers={"WWW-Authenticate": "Bearer"}
            )
        except jwt.InvalidTokenError as e:
            raise HTTPException(
                status_code=401,
                detail=f"Invalid token: {e}",
                headers={"WWW-Authenticate": "Bearer"}
            )
    
    async def register_client(self, metadata: dict = None) -> dict:
        """
        Register a new client and issue token.
        Creates entry in module-specific client table.
        """
        client_id = self.generate_client_id()
        token, expiry = self.create_token(client_id)
        
        async with self.db_session_factory() as session:
            client = self.client_model(
                client_id=client_id,
                metadata=metadata
            )
            session.add(client)
            await session.commit()
        
        return {
            "client_id": client_id,
            "token": token,
            "expires_at": expiry.isoformat(),
            "token_type": "Bearer"
        }
    
    async def get_client(self, client_id: str):
        """Get client from database"""
        async with self.db_session_factory() as session:
            stmt = select(self.client_model).where(
                self.client_model.client_id == client_id
            )
            result = await session.execute(stmt)
            return result.scalar_one_or_none()
    
    async def update_last_seen(self, client_id: str):
        """Update client's last_seen timestamp"""
        async with self.db_session_factory() as session:
            stmt = update(self.client_model).where(
                self.client_model.client_id == client_id
            ).values(last_seen_at=datetime.now(timezone.utc))
            await session.execute(stmt)
            await session.commit()
    
    def create_dependency(self):
        """
        Create FastAPI dependency for this auth instance.
        
        Usage:
            keyserver_auth = TokenAuth(keyserver_config, KSClient, db)
            require_keyserver_auth = keyserver_auth.create_dependency()
            
            @router.get("/keys")
            async def list_keys(client_id: str = Depends(require_keyserver_auth)):
                ...
        """
        async def verify_token_dependency(
            request: Request,
            credentials: HTTPAuthorizationCredentials = Security(security)
        ) -> str:
            if not credentials:
                raise HTTPException(
                    status_code=401,
                    detail="Authorization header required",
                    headers={"WWW-Authenticate": "Bearer"}
                )
            
            payload = self.verify_token(credentials.credentials)
            
            # Update last seen (fire and forget)
            try:
                await self.update_last_seen(payload.sub)
            except Exception:
                pass  # Don't fail request if update fails
            
            return payload.sub  # Return client_id
        
        return verify_token_dependency
```

### Keyserver Auth (modules/keyserver/auth.py)

```python
from core.auth.token import TokenAuth, TokenConfig
from .models import KSClient
from core.database import get_db_session_factory

# Module-specific auth instance - initialized at module load
_keyserver_auth: TokenAuth | None = None

def init_keyserver_auth(config):
    """Initialize Keyserver authentication"""
    global _keyserver_auth
    
    token_config = TokenConfig(
        secret=config.token.secret,
        algorithm=config.token.algorithm,
        expiry_days=config.token.expiry_days,
        issuer=config.token.issuer  # "openssl_encrypt_keyserver"
    )
    
    _keyserver_auth = TokenAuth(
        config=token_config,
        client_model=KSClient,
        db_session_factory=get_db_session_factory()
    )
    
    return _keyserver_auth

def get_keyserver_auth() -> TokenAuth:
    """Get Keyserver auth instance"""
    if not _keyserver_auth:
        raise RuntimeError("Keyserver auth not initialized")
    return _keyserver_auth

# Dependency for routes
async def require_keyserver_auth(
    client_id: str = None  # Will be injected by dependency
) -> str:
    """Dependency that validates Keyserver token and returns client_id"""
    auth = get_keyserver_auth()
    return await auth.create_dependency()
```

### Telemetry Auth (modules/telemetry/auth.py)

```python
from core.auth.token import TokenAuth, TokenConfig
from .models import TMClient
from core.database import get_db_session_factory

# Module-specific auth instance - initialized at module load
_telemetry_auth: TokenAuth | None = None

def init_telemetry_auth(config):
    """Initialize Telemetry authentication"""
    global _telemetry_auth
    
    token_config = TokenConfig(
        secret=config.token.secret,
        algorithm=config.token.algorithm,
        expiry_days=config.token.expiry_days,
        issuer=config.token.issuer  # "openssl_encrypt_telemetry"
    )
    
    _telemetry_auth = TokenAuth(
        config=token_config,
        client_model=TMClient,
        db_session_factory=get_db_session_factory()
    )
    
    return _telemetry_auth

def get_telemetry_auth() -> TokenAuth:
    """Get Telemetry auth instance"""
    if not _telemetry_auth:
        raise RuntimeError("Telemetry auth not initialized")
    return _telemetry_auth

# Dependency for routes  
async def require_telemetry_auth(
    client_id: str = None
) -> str:
    """Dependency that validates Telemetry token and returns client_id"""
    auth = get_telemetry_auth()
    return await auth.create_dependency()
```

### Pepper Auth - Proxy Mode (core/auth/proxy.py)

```python
from ipaddress import ip_address, ip_network
from fastapi import Request, HTTPException
from typing import Optional

class ProxyAuth:
    """
    Authentication via reverse proxy headers.
    
    Nginx terminates mTLS and passes certificate info via headers.
    This class validates the request comes from a trusted proxy
    and extracts the client certificate fingerprint.
    """
    
    def __init__(
        self,
        fingerprint_header: str,
        trusted_proxies: list[str],
        dn_header: Optional[str] = None,
        verify_header: Optional[str] = None
    ):
        self.fingerprint_header = fingerprint_header
        self.dn_header = dn_header
        self.verify_header = verify_header
        self.trusted_networks = [ip_network(p, strict=False) for p in trusted_proxies]
    
    def _is_trusted_proxy(self, client_ip: str) -> bool:
        """Check if request comes from trusted proxy"""
        try:
            addr = ip_address(client_ip)
            return any(addr in network for network in self.trusted_networks)
        except ValueError:
            return False
    
    async def get_client_fingerprint(self, request: Request) -> str:
        """Extract client certificate fingerprint from proxy headers"""
        # Verify request source
        client_ip = request.client.host if request.client else None
        if not client_ip or not self._is_trusted_proxy(client_ip):
            raise HTTPException(
                status_code=403,
                detail=f"Request must come from trusted proxy (got {client_ip})"
            )
        
        # Check Nginx verification status if configured
        if self.verify_header:
            verify_status = request.headers.get(self.verify_header)
            if verify_status and verify_status != "SUCCESS":
                raise HTTPException(
                    status_code=401,
                    detail=f"Client certificate verification failed: {verify_status}"
                )
        
        # Get fingerprint
        fingerprint = request.headers.get(self.fingerprint_header)
        if not fingerprint:
            raise HTTPException(
                status_code=401,
                detail="Client certificate required (missing fingerprint header)"
            )
        
        # Normalize fingerprint (lowercase, no colons)
        fingerprint = fingerprint.lower().replace(":", "")
        
        return fingerprint
    
    async def get_client_dn(self, request: Request) -> Optional[str]:
        """Get client certificate DN if available"""
        if self.dn_header:
            return request.headers.get(self.dn_header)
        return None
```

### Pepper Auth - mTLS Mode (core/auth/mtls.py)

```python
from fastapi import Request, HTTPException
from cryptography import x509
from cryptography.hazmat.primitives import hashes

class MTLSAuth:
    """
    Direct mTLS authentication.
    
    Server handles TLS directly and extracts client certificate
    from the SSL context.
    """
    
    async def get_client_fingerprint(self, request: Request) -> str:
        """Extract client certificate fingerprint from TLS connection"""
        # Get SSL object from connection
        transport = request.scope.get("transport")
        if not transport:
            raise HTTPException(401, "No TLS connection")
        
        ssl_object = transport.get_extra_info("ssl_object")
        if not ssl_object:
            raise HTTPException(401, "No SSL context")
        
        # Get client certificate
        cert_der = ssl_object.getpeercert(binary_form=True)
        if not cert_der:
            raise HTTPException(401, "Client certificate required")
        
        # Parse and compute fingerprint
        cert = x509.load_der_x509_certificate(cert_der)
        fingerprint = cert.fingerprint(hashes.SHA256()).hex()
        
        return fingerprint
    
    async def get_client_dn(self, request: Request) -> str:
        """Get client certificate subject DN"""
        transport = request.scope.get("transport")
        ssl_object = transport.get_extra_info("ssl_object")
        cert_der = ssl_object.getpeercert(binary_form=True)
        cert = x509.load_der_x509_certificate(cert_der)
        return cert.subject.rfc4514_string()
```

### Pepper Auth Wrapper (modules/pepper/auth.py)

```python
from fastapi import Request, Depends
from core.auth.proxy import ProxyAuth
from core.auth.mtls import MTLSAuth
from config import PepperAuthConfig

class PepperAuthHandler:
    """
    Unified auth handler for Pepper module.
    
    Delegates to either ProxyAuth or MTLSAuth based on configuration.
    This allows users to choose their deployment model without
    changing the Pepper module code.
    """
    
    def __init__(self, config: PepperAuthConfig):
        self.mode = config.mode
        
        if self.mode == "proxy":
            self.handler = ProxyAuth(
                fingerprint_header=config.proxy.fingerprint_header,
                trusted_proxies=config.proxy.trusted_proxies,
                dn_header=config.proxy.dn_header,
                verify_header=config.proxy.verify_header
            )
        elif self.mode == "mtls":
            self.handler = MTLSAuth()
        else:
            raise ValueError(f"Unknown auth mode: {self.mode}")
    
    async def get_client_fingerprint(self, request: Request) -> str:
        return await self.handler.get_client_fingerprint(request)
    
    async def get_client_dn(self, request: Request) -> str | None:
        return await self.handler.get_client_dn(request)

# Dependency - initialized at startup
_pepper_auth: PepperAuthHandler | None = None

def init_pepper_auth(config: PepperAuthConfig):
    global _pepper_auth
    _pepper_auth = PepperAuthHandler(config)

async def require_pepper_auth(request: Request) -> str:
    """Dependency that returns client certificate fingerprint"""
    if not _pepper_auth:
        raise RuntimeError("Pepper auth not initialized")
    return await _pepper_auth.get_client_fingerprint(request)
```

---

## Database Schema

### Keyserver Tables (ks_)

```sql
-- Keyserver clients (API token authenticated)
CREATE TABLE ks_clients (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id VARCHAR(64) NOT NULL UNIQUE,        -- Issued client ID (used in JWT sub)
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ,
    metadata JSONB,                               -- Optional client info
    
    INDEX idx_ks_clients_client_id (client_id)
);

-- Public keys
CREATE TABLE ks_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    fingerprint VARCHAR(64) NOT NULL UNIQUE,      -- SHA-256 of public key
    name VARCHAR(255),                            -- Human-readable name
    email VARCHAR(255),                           -- Optional email
    public_key_bundle BYTEA NOT NULL,             -- Serialized PublicKeyBundle
    self_signature BYTEA NOT NULL,                -- Signature proving ownership
    algorithm VARCHAR(50) NOT NULL,               -- e.g., "ML-KEM-768+ML-DSA-65"
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at TIMESTAMPTZ,
    revocation_reason TEXT,
    owner_client_id VARCHAR(64) NOT NULL REFERENCES ks_clients(client_id),
    
    INDEX idx_ks_keys_fingerprint (fingerprint),
    INDEX idx_ks_keys_name (name),
    INDEX idx_ks_keys_email (email),
    INDEX idx_ks_keys_owner (owner_client_id)
);

-- Access log
CREATE TABLE ks_access_log (
    id BIGSERIAL PRIMARY KEY,
    key_fingerprint VARCHAR(64) NOT NULL,
    action VARCHAR(20) NOT NULL,                  -- 'upload', 'download', 'search', 'revoke'
    client_id VARCHAR(64) NOT NULL,
    ip_address INET,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    INDEX idx_ks_access_log_time (timestamp)
);
```

### Telemetry Tables (tm_)

```sql
-- Telemetry clients (API token authenticated) - SEPARATE from Keyserver!
CREATE TABLE tm_clients (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id VARCHAR(64) NOT NULL UNIQUE,        -- Issued client ID (used in JWT sub)
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ,
    metadata JSONB,                               -- Optional client info (version, OS, etc.)
    
    INDEX idx_tm_clients_client_id (client_id)
);

-- Telemetry events
CREATE TABLE tm_events (
    id BIGSERIAL PRIMARY KEY,
    event_type VARCHAR(50) NOT NULL,              -- 'encrypt', 'decrypt', 'keygen', etc.
    client_id VARCHAR(64) NOT NULL REFERENCES tm_clients(client_id),
    version VARCHAR(20),                          -- openssl_encrypt version
    algorithm VARCHAR(100),                       -- Algorithm used
    success BOOLEAN NOT NULL,
    error_type VARCHAR(100),
    duration_ms INTEGER,
    metadata JSONB,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    INDEX idx_tm_events_type (event_type),
    INDEX idx_tm_events_timestamp (timestamp),
    INDEX idx_tm_events_client (client_id)
);

-- Aggregated daily statistics
CREATE TABLE tm_daily_stats (
    date DATE PRIMARY KEY,
    total_events BIGINT NOT NULL DEFAULT 0,
    unique_clients BIGINT NOT NULL DEFAULT 0,
    events_by_type JSONB NOT NULL DEFAULT '{}',
    events_by_algorithm JSONB NOT NULL DEFAULT '{}',
    avg_duration_ms JSONB NOT NULL DEFAULT '{}'
);
```

### Pepper Tables (pp_)

```sql
-- Pepper clients (mTLS authenticated via certificate fingerprint)
CREATE TABLE pp_clients (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cert_fingerprint VARCHAR(64) NOT NULL UNIQUE, -- mTLS certificate SHA-256
    cert_dn VARCHAR(500),                         -- Certificate subject DN
    name VARCHAR(255),                            -- Human-readable name (user-set)
    totp_secret_encrypted BYTEA,                  -- Encrypted TOTP secret
    totp_verified BOOLEAN NOT NULL DEFAULT FALSE, -- Whether TOTP setup is complete
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ,
    
    INDEX idx_pp_clients_fingerprint (cert_fingerprint)
);

-- Pepper storage
CREATE TABLE pp_peppers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id UUID NOT NULL REFERENCES pp_clients(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,                   -- Identifier for this pepper
    pepper_encrypted BYTEA NOT NULL,              -- Client-encrypted pepper blob
    description TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_accessed_at TIMESTAMPTZ,
    access_count BIGINT NOT NULL DEFAULT 0,
    
    UNIQUE(client_id, name),
    INDEX idx_pp_peppers_client (client_id)
);

-- Dead man's switch configuration
CREATE TABLE pp_deadman (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id UUID NOT NULL REFERENCES pp_clients(id) ON DELETE CASCADE UNIQUE,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    interval_seconds BIGINT NOT NULL,
    grace_period_seconds BIGINT NOT NULL,
    last_checkin TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    next_deadline TIMESTAMPTZ NOT NULL,
    panic_triggered BOOLEAN NOT NULL DEFAULT FALSE,
    panic_triggered_at TIMESTAMPTZ,
    
    INDEX idx_pp_deadman_deadline (next_deadline) WHERE enabled AND NOT panic_triggered
);

-- Panic audit log
CREATE TABLE pp_panic_log (
    id BIGSERIAL PRIMARY KEY,
    client_id UUID NOT NULL REFERENCES pp_clients(id) ON DELETE CASCADE,
    trigger_type VARCHAR(20) NOT NULL,            -- 'manual', 'deadman', 'emergency'
    peppers_wiped INTEGER NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ip_address INET,
    notes TEXT
);

-- TOTP backup codes
CREATE TABLE pp_totp_backup_codes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id UUID NOT NULL REFERENCES pp_clients(id) ON DELETE CASCADE,
    code_hash VARCHAR(128) NOT NULL,              -- Argon2 hashed backup code
    used_at TIMESTAMPTZ,
    
    INDEX idx_pp_totp_backup_client (client_id)
);
```

### Integrity Tables (in_)

```sql
-- Integrity clients (API token authenticated)
CREATE TABLE in_clients (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id VARCHAR(64) NOT NULL UNIQUE,        -- Issued client ID (used in JWT sub)
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ,
    metadata JSONB,                               -- Optional client info
    
    INDEX idx_in_clients_client_id (client_id)
);

-- Metadata hashes for integrity verification
CREATE TABLE in_metadata_hashes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id VARCHAR(64) NOT NULL REFERENCES in_clients(client_id) ON DELETE CASCADE,
    file_id VARCHAR(128) NOT NULL,                -- Client-generated ID (e.g., filename hash)
    metadata_hash VARCHAR(64) NOT NULL,           -- SHA-256 of encrypted file metadata
    algorithm VARCHAR(50),                        -- Algorithm used (for info, e.g., "symmetric-aes256")
    description TEXT,                             -- Optional description
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    verified_at TIMESTAMPTZ,                      -- Last successful verification
    verification_count BIGINT NOT NULL DEFAULT 0,
    
    UNIQUE(client_id, file_id),
    INDEX idx_in_hashes_client (client_id),
    INDEX idx_in_hashes_file (file_id)
);

-- Integrity verification log (optional, for audit)
CREATE TABLE in_verification_log (
    id BIGSERIAL PRIMARY KEY,
    client_id VARCHAR(64) NOT NULL,
    file_id VARCHAR(128) NOT NULL,
    result VARCHAR(20) NOT NULL,                  -- 'match', 'mismatch', 'not_found'
    expected_hash VARCHAR(64),
    actual_hash VARCHAR(64),
    ip_address INET,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    INDEX idx_in_verification_log_time (timestamp),
    INDEX idx_in_verification_log_client (client_id)
);
```

---

## API Endpoints

### Core Endpoints

```
GET  /health                    # Health check (no auth)
GET  /ready                     # Readiness check (DB connectivity)
GET  /metrics                   # Prometheus metrics (optional auth)
GET  /info                      # Server info (enabled modules, version)
```

### Keyserver Module (/api/v1/keys)

```
# Registration (no auth required)
POST   /api/v1/keys/register           # Register → returns Keyserver API token

# Authenticated endpoints (Keyserver Bearer token ONLY)
POST   /api/v1/keys                    # Upload a new public key
GET    /api/v1/keys/{fingerprint}      # Get key by fingerprint
GET    /api/v1/keys/search             # Search by name/email
DELETE /api/v1/keys/{fingerprint}      # Revoke own key
GET    /api/v1/keys/{fingerprint}/status  # Check revocation status
GET    /api/v1/keys/mine               # List own uploaded keys

# Public (no auth)
GET    /api/v1/keys/{fingerprint}/public  # Get key (read-only, no logging)
```

### Telemetry Module (/api/v1/telemetry)

```
# Registration (no auth required)
POST   /api/v1/telemetry/register      # Register → returns Telemetry API token

# Authenticated endpoints (Telemetry Bearer token ONLY)
POST   /api/v1/telemetry/events        # Submit telemetry event(s)
GET    /api/v1/telemetry/my-stats      # Get own statistics

# Public (no auth)
GET    /api/v1/telemetry/stats         # Get aggregated statistics
```

### Pepper Module (/api/v1/pepper)

All endpoints require mTLS (via proxy header or direct).

```
# Client management (auto-register on first request)
GET    /api/v1/pepper/profile          # Get own profile
PUT    /api/v1/pepper/profile          # Update profile (name)
DELETE /api/v1/pepper/profile          # Delete account and all peppers [TOTP required]

# TOTP management
POST   /api/v1/pepper/totp/setup       # Setup TOTP (returns secret + QR)
POST   /api/v1/pepper/totp/verify      # Verify TOTP setup with code
DELETE /api/v1/pepper/totp             # Disable TOTP [TOTP required]
POST   /api/v1/pepper/totp/backup      # Generate new backup codes [TOTP required]

# Pepper CRUD
POST   /api/v1/pepper/peppers          # Create new pepper
GET    /api/v1/pepper/peppers          # List all peppers (metadata only)
GET    /api/v1/pepper/peppers/{name}   # Get specific pepper (encrypted blob)
PUT    /api/v1/pepper/peppers/{name}   # Update pepper
DELETE /api/v1/pepper/peppers/{name}   # Delete specific pepper

# Dead man's switch
GET    /api/v1/pepper/deadman          # Get deadman config & status
PUT    /api/v1/pepper/deadman          # Configure deadman (interval, grace)
POST   /api/v1/pepper/deadman/checkin  # Check in (reset timer)
DELETE /api/v1/pepper/deadman          # Disable deadman

# Panic
POST   /api/v1/pepper/panic            # Wipe ALL peppers [TOTP required]
POST   /api/v1/pepper/panic/{name}     # Wipe specific pepper [TOTP required]
```

### Integrity Module (/api/v1/integrity)

```
# Registration (no auth required)
POST   /api/v1/integrity/register      # Register → returns Integrity API token

# Authenticated endpoints (Integrity Bearer token ONLY)

# Hash management
POST   /api/v1/integrity/hashes        # Store metadata hash for a file
GET    /api/v1/integrity/hashes        # List all stored hashes (metadata only)
GET    /api/v1/integrity/hashes/{file_id}  # Get hash for specific file
PUT    /api/v1/integrity/hashes/{file_id}  # Update hash (e.g., after re-encryption)
DELETE /api/v1/integrity/hashes/{file_id}  # Delete hash

# Verification
POST   /api/v1/integrity/verify        # Verify metadata hash matches stored
POST   /api/v1/integrity/verify/batch  # Verify multiple files at once

# Bulk operations
DELETE /api/v1/integrity/hashes        # Delete all hashes for client
GET    /api/v1/integrity/stats         # Get verification statistics
```

**Verification Request/Response:**

```json
// POST /api/v1/integrity/verify
{
  "file_id": "sha256-of-filename-or-path",
  "metadata_hash": "sha256-of-current-metadata"
}

// Response
{
  "file_id": "...",
  "match": true,           // or false
  "stored_hash": "...",
  "provided_hash": "...",
  "last_updated": "2024-01-15T10:30:00Z"
}

// If mismatch detected:
{
  "file_id": "...",
  "match": false,
  "stored_hash": "abc123...",
  "provided_hash": "def456...",
  "warning": "INTEGRITY VIOLATION: Metadata has been modified!"
}
```

---

## Route Implementation Examples

### Keyserver Routes (modules/keyserver/routes.py)

```python
from fastapi import APIRouter, Depends, HTTPException
from .auth import get_keyserver_auth, require_keyserver_auth
from .schemas import RegisterResponse, KeyUploadRequest, KeyResponse
from .service import KeyserverService

router = APIRouter()

@router.post("/register", response_model=RegisterResponse)
async def register():
    """
    Register a new Keyserver client.
    Returns a token that can ONLY be used for Keyserver endpoints.
    """
    auth = get_keyserver_auth()
    return await auth.register_client()

@router.post("", response_model=KeyResponse)
async def upload_key(
    request: KeyUploadRequest,
    client_id: str = Depends(require_keyserver_auth)  # Validates Keyserver token
):
    """Upload a public key. Requires Keyserver token."""
    service = KeyserverService()
    return await service.upload_key(client_id, request)

@router.get("/{fingerprint}", response_model=KeyResponse)
async def get_key(
    fingerprint: str,
    client_id: str = Depends(require_keyserver_auth)
):
    """Get key by fingerprint. Requires Keyserver token."""
    service = KeyserverService()
    return await service.get_key(fingerprint, client_id)

@router.delete("/{fingerprint}")
async def revoke_key(
    fingerprint: str,
    client_id: str = Depends(require_keyserver_auth)
):
    """Revoke own key. Requires Keyserver token."""
    service = KeyserverService()
    return await service.revoke_key(fingerprint, client_id)
```

### Telemetry Routes (modules/telemetry/routes.py)

```python
from fastapi import APIRouter, Depends
from .auth import get_telemetry_auth, require_telemetry_auth
from .schemas import RegisterResponse, TelemetryEventRequest, StatsResponse
from .service import TelemetryService

router = APIRouter()

@router.post("/register", response_model=RegisterResponse)
async def register():
    """
    Register a new Telemetry client.
    Returns a token that can ONLY be used for Telemetry endpoints.
    """
    auth = get_telemetry_auth()
    return await auth.register_client()

@router.post("/events")
async def submit_events(
    request: TelemetryEventRequest,
    client_id: str = Depends(require_telemetry_auth)  # Validates Telemetry token
):
    """Submit telemetry events. Requires Telemetry token."""
    service = TelemetryService()
    return await service.record_events(client_id, request.events)

@router.get("/stats", response_model=StatsResponse)
async def get_stats():
    """Get aggregated statistics. No auth required."""
    service = TelemetryService()
    return await service.get_public_stats()
```

### Pepper Routes (modules/pepper/routes.py)

```python
from fastapi import APIRouter, Depends, HTTPException, Header
from typing import Optional
from .auth import require_pepper_auth
from .schemas import ProfileResponse, PepperRequest, PepperResponse, DeadmanConfig
from .service import PepperService, DeadmanService, TOTPService

router = APIRouter()

@router.get("/profile", response_model=ProfileResponse)
async def get_profile(
    cert_fingerprint: str = Depends(require_pepper_auth)
):
    """Get own profile. Auto-registers on first request."""
    service = PepperService()
    return await service.get_or_create_profile(cert_fingerprint)

@router.post("/peppers", response_model=PepperResponse)
async def create_pepper(
    request: PepperRequest,
    cert_fingerprint: str = Depends(require_pepper_auth)
):
    """Create a new pepper."""
    service = PepperService()
    return await service.create_pepper(cert_fingerprint, request)

@router.post("/deadman/checkin")
async def deadman_checkin(
    cert_fingerprint: str = Depends(require_pepper_auth)
):
    """Check in to reset deadman timer."""
    service = DeadmanService()
    return await service.checkin(cert_fingerprint)

@router.post("/panic")
async def panic_all(
    cert_fingerprint: str = Depends(require_pepper_auth),
    x_totp_code: Optional[str] = Header(None, alias="X-TOTP-Code")
):
    """Wipe ALL peppers. Requires TOTP if configured."""
    service = PepperService()
    totp_service = TOTPService()
    
    client = await service.get_client(cert_fingerprint)
    if not await totp_service.verify_code(client, x_totp_code):
        raise HTTPException(403, "TOTP code required")
    
    return await service.panic_all(cert_fingerprint)
```

### Integrity Routes (modules/integrity/routes.py)

```python
from fastapi import APIRouter, Depends, HTTPException
from .auth import get_integrity_auth, require_integrity_auth
from .schemas import (
    RegisterResponse, 
    HashCreateRequest, 
    HashResponse, 
    VerifyRequest, 
    VerifyResponse,
    BatchVerifyRequest,
    BatchVerifyResponse
)
from .service import IntegrityService

router = APIRouter()

@router.post("/register", response_model=RegisterResponse)
async def register():
    """
    Register a new Integrity client.
    Returns a token that can ONLY be used for Integrity endpoints.
    """
    auth = get_integrity_auth()
    return await auth.register_client()

@router.post("/hashes", response_model=HashResponse)
async def store_hash(
    request: HashCreateRequest,
    client_id: str = Depends(require_integrity_auth)
):
    """Store metadata hash for a file."""
    service = IntegrityService()
    return await service.store_hash(client_id, request)

@router.get("/hashes", response_model=list[HashResponse])
async def list_hashes(
    client_id: str = Depends(require_integrity_auth)
):
    """List all stored hashes for this client."""
    service = IntegrityService()
    return await service.list_hashes(client_id)

@router.get("/hashes/{file_id}", response_model=HashResponse)
async def get_hash(
    file_id: str,
    client_id: str = Depends(require_integrity_auth)
):
    """Get hash for a specific file."""
    service = IntegrityService()
    return await service.get_hash(client_id, file_id)

@router.put("/hashes/{file_id}", response_model=HashResponse)
async def update_hash(
    file_id: str,
    request: HashCreateRequest,
    client_id: str = Depends(require_integrity_auth)
):
    """Update hash for a file (e.g., after re-encryption)."""
    service = IntegrityService()
    return await service.update_hash(client_id, file_id, request)

@router.delete("/hashes/{file_id}")
async def delete_hash(
    file_id: str,
    client_id: str = Depends(require_integrity_auth)
):
    """Delete hash for a specific file."""
    service = IntegrityService()
    return await service.delete_hash(client_id, file_id)

@router.post("/verify", response_model=VerifyResponse)
async def verify_hash(
    request: VerifyRequest,
    client_id: str = Depends(require_integrity_auth)
):
    """
    Verify metadata hash matches stored value.
    
    Use this during decryption to detect tampering:
    1. Read encrypted file metadata
    2. Compute hash of metadata
    3. Call this endpoint to verify
    4. If mismatch → ABORT decryption (possible attack!)
    """
    service = IntegrityService()
    return await service.verify_hash(client_id, request)

@router.post("/verify/batch", response_model=BatchVerifyResponse)
async def verify_batch(
    request: BatchVerifyRequest,
    client_id: str = Depends(require_integrity_auth)
):
    """Verify multiple files at once."""
    service = IntegrityService()
    return await service.verify_batch(client_id, request)
```

### Integrity Service (modules/integrity/service.py)

```python
from datetime import datetime, timezone
from fastapi import HTTPException
from sqlalchemy import select, delete, func
from sqlalchemy.ext.asyncio import AsyncSession
import hashlib

from .models import INClient, INMetadataHash, INVerificationLog
from .schemas import HashCreateRequest, VerifyRequest

class IntegrityService:
    def __init__(self, db_session: AsyncSession):
        self.db = db_session
    
    async def store_hash(self, client_id: str, request: HashCreateRequest) -> dict:
        """Store or update metadata hash for a file"""
        # Check if hash already exists
        existing = await self.get_hash_record(client_id, request.file_id)
        
        if existing:
            raise HTTPException(
                status_code=409,
                detail=f"Hash for file_id '{request.file_id}' already exists. Use PUT to update."
            )
        
        hash_record = INMetadataHash(
            client_id=client_id,
            file_id=request.file_id,
            metadata_hash=request.metadata_hash,
            algorithm=request.algorithm,
            description=request.description
        )
        self.db.add(hash_record)
        await self.db.commit()
        
        return self._hash_to_response(hash_record)
    
    async def verify_hash(self, client_id: str, request: VerifyRequest) -> dict:
        """Verify metadata hash against stored value"""
        stored = await self.get_hash_record(client_id, request.file_id)
        
        if not stored:
            # Log verification attempt
            await self._log_verification(
                client_id, request.file_id, 'not_found',
                None, request.metadata_hash
            )
            raise HTTPException(
                status_code=404,
                detail=f"No hash stored for file_id '{request.file_id}'"
            )
        
        match = stored.metadata_hash == request.metadata_hash
        
        # Update verification stats
        stored.verified_at = datetime.now(timezone.utc)
        stored.verification_count += 1
        
        # Log verification
        await self._log_verification(
            client_id, request.file_id,
            'match' if match else 'mismatch',
            stored.metadata_hash, request.metadata_hash
        )
        
        await self.db.commit()
        
        response = {
            "file_id": request.file_id,
            "match": match,
            "stored_hash": stored.metadata_hash,
            "provided_hash": request.metadata_hash,
            "last_updated": stored.updated_at.isoformat()
        }
        
        if not match:
            response["warning"] = "INTEGRITY VIOLATION: Metadata has been modified!"
        
        return response
    
    async def verify_batch(self, client_id: str, request) -> dict:
        """Verify multiple files at once"""
        results = []
        all_match = True
        
        for item in request.files:
            try:
                result = await self.verify_hash(client_id, item)
                results.append(result)
                if not result["match"]:
                    all_match = False
            except HTTPException as e:
                results.append({
                    "file_id": item.file_id,
                    "match": False,
                    "error": e.detail
                })
                all_match = False
        
        return {
            "all_match": all_match,
            "total": len(request.files),
            "matched": sum(1 for r in results if r.get("match", False)),
            "results": results
        }
    
    async def get_hash_record(self, client_id: str, file_id: str):
        """Get hash record from database"""
        stmt = select(INMetadataHash).where(
            INMetadataHash.client_id == client_id,
            INMetadataHash.file_id == file_id
        )
        result = await self.db.execute(stmt)
        return result.scalar_one_or_none()
    
    async def _log_verification(
        self, client_id: str, file_id: str, result: str,
        expected: str | None, actual: str
    ):
        """Log verification attempt"""
        log = INVerificationLog(
            client_id=client_id,
            file_id=file_id,
            result=result,
            expected_hash=expected,
            actual_hash=actual
        )
        self.db.add(log)
    
    def _hash_to_response(self, record: INMetadataHash) -> dict:
        return {
            "file_id": record.file_id,
            "metadata_hash": record.metadata_hash,
            "algorithm": record.algorithm,
            "description": record.description,
            "created_at": record.created_at.isoformat(),
            "updated_at": record.updated_at.isoformat(),
            "verified_at": record.verified_at.isoformat() if record.verified_at else None,
            "verification_count": record.verification_count
        }
```

---

## Server Entrypoints

### Main Server (server.py)

```python
from contextlib import asynccontextmanager
from fastapi import FastAPI
import uvicorn
import logging

from config import Settings, validate_config
from core.database import init_db, close_db
from modules import load_modules

logger = logging.getLogger(__name__)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    settings = app.state.settings
    
    # Validate configuration
    validate_config(settings)
    
    # Initialize database
    await init_db(settings.database)
    
    # Load enabled modules
    loaded = load_modules(app, settings)
    logger.info(f"Loaded modules: {', '.join(loaded)}")
    
    yield
    
    # Shutdown
    await close_db()

def create_app(config_path: str = "config.yml") -> FastAPI:
    settings = Settings.from_yaml(config_path)
    
    app = FastAPI(
        title="openssl_encrypt Server",
        version="1.0.0",
        lifespan=lifespan
    )
    app.state.settings = settings
    
    # Add core routes
    @app.get("/health")
    async def health():
        return {"status": "ok"}
    
    @app.get("/info")
    async def info():
        return {
            "version": "1.0.0",
            "modules": {
                "keyserver": settings.modules.keyserver.enabled,
                "telemetry": settings.modules.telemetry.enabled,
                "pepper": settings.modules.pepper.enabled
            }
        }
    
    return app

app = create_app()

if __name__ == "__main__":
    settings = app.state.settings
    uvicorn.run(
        "server:app",
        host=settings.server.host,
        port=settings.server.port,
        workers=settings.server.workers
    )
```

### Module Loader (modules/__init__.py)

```python
from fastapi import FastAPI
from config import Settings
import logging

logger = logging.getLogger(__name__)

def load_modules(app: FastAPI, settings: Settings) -> list[str]:
    """Load enabled modules and return list of loaded module names"""
    loaded = []
    
    if settings.modules.keyserver.enabled:
        from .keyserver import router as keyserver_router
        from .keyserver.auth import init_keyserver_auth
        
        init_keyserver_auth(settings.modules.keyserver)
        app.include_router(
            keyserver_router,
            prefix="/api/v1/keys",
            tags=["keyserver"]
        )
        loaded.append("keyserver")
        logger.info("Keyserver module loaded")
    
    if settings.modules.telemetry.enabled:
        from .telemetry import router as telemetry_router
        from .telemetry.auth import init_telemetry_auth
        
        init_telemetry_auth(settings.modules.telemetry)
        app.include_router(
            telemetry_router,
            prefix="/api/v1/telemetry",
            tags=["telemetry"]
        )
        loaded.append("telemetry")
        logger.info("Telemetry module loaded")
    
    if settings.modules.pepper.enabled:
        from .pepper import router as pepper_router
        from .pepper.auth import init_pepper_auth
        from .pepper.deadman import DeadmanWatcher
        
        init_pepper_auth(settings.modules.pepper.auth)
        app.include_router(
            pepper_router,
            prefix="/api/v1/pepper",
            tags=["pepper"]
        )
        
        # Start deadman watcher if enabled
        if settings.modules.pepper.deadman.enabled:
            watcher = DeadmanWatcher(
                db_session_factory=get_db_session_factory(),
                config=settings.modules.pepper.deadman
            )
            
            @app.on_event("startup")
            async def start_deadman():
                await watcher.start()
            
            @app.on_event("shutdown")
            async def stop_deadman():
                await watcher.stop()
        
        loaded.append("pepper")
        logger.info(f"Pepper module loaded (auth mode: {settings.modules.pepper.auth.mode})")
    
    if settings.modules.integrity.enabled:
        from .integrity import router as integrity_router
        from .integrity.auth import init_integrity_auth
        
        init_integrity_auth(settings.modules.integrity)
        app.include_router(
            integrity_router,
            prefix="/api/v1/integrity",
            tags=["integrity"]
        )
        loaded.append("integrity")
        logger.info("Integrity module loaded")
    
    return loaded
```

### Pepper mTLS Server (pepper_server.py) - Optional

```python
"""
Separate entrypoint for Pepper with direct mTLS.
Only used when pepper.auth.mode = "mtls"
"""
from fastapi import FastAPI
import uvicorn
import ssl

from config import Settings
from core.database import init_db
from modules.pepper import router as pepper_router
from modules.pepper.auth import init_pepper_auth
from modules.pepper.deadman import DeadmanWatcher

def create_pepper_app(config_path: str = "config.yml") -> FastAPI:
    settings = Settings.from_yaml(config_path)
    
    if settings.modules.pepper.auth.mode != "mtls":
        raise RuntimeError(
            "pepper_server.py is only for mTLS mode. "
            "For proxy mode, use server.py with Nginx."
        )
    
    app = FastAPI(title="openssl_encrypt Pepper Server (mTLS)")
    app.state.settings = settings
    
    @app.on_event("startup")
    async def startup():
        await init_db(settings.database)
        init_pepper_auth(settings.modules.pepper.auth)
    
    app.include_router(pepper_router, prefix="/api/v1/pepper", tags=["pepper"])
    
    return app

app = create_pepper_app()

if __name__ == "__main__":
    settings = app.state.settings
    mtls_config = settings.modules.pepper.auth.mtls
    
    uvicorn.run(
        "pepper_server:app",
        host=mtls_config.host,
        port=mtls_config.port,
        ssl_certfile=str(mtls_config.tls.cert),
        ssl_keyfile=str(mtls_config.tls.key),
        ssl_ca_certs=str(mtls_config.tls.client_ca),
        ssl_cert_reqs=ssl.CERT_REQUIRED
    )
```

---

## Dead Man's Switch Implementation

### Background Task (modules/pepper/deadman.py)

```python
import asyncio
from datetime import datetime, timezone, timedelta
from sqlalchemy import select, delete, func
from sqlalchemy.ext.asyncio import AsyncSession
import logging

from .models import PPDeadman, PPPepper, PPPanicLog

logger = logging.getLogger(__name__)

def parse_duration(duration_str: str) -> timedelta:
    """Parse duration string like '7d', '24h', '30m' to timedelta"""
    unit = duration_str[-1]
    value = int(duration_str[:-1])
    
    if unit == 'd':
        return timedelta(days=value)
    elif unit == 'h':
        return timedelta(hours=value)
    elif unit == 'm':
        return timedelta(minutes=value)
    elif unit == 's':
        return timedelta(seconds=value)
    else:
        raise ValueError(f"Unknown duration unit: {unit}")

class DeadmanWatcher:
    """
    Background task that monitors dead man's switches.
    
    Runs periodically and triggers panic for clients who haven't
    checked in within their configured interval + grace period.
    """
    
    def __init__(self, db_session_factory, config):
        self.db_session_factory = db_session_factory
        self.check_interval = parse_duration(config.check_interval)
        self._task: asyncio.Task | None = None
        self._running = False
    
    async def start(self):
        """Start the background watcher"""
        self._running = True
        self._task = asyncio.create_task(self._watch_loop())
        logger.info(f"Deadman watcher started (check interval: {self.check_interval})")
    
    async def stop(self):
        """Stop the background watcher gracefully"""
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info("Deadman watcher stopped")
    
    async def _watch_loop(self):
        """Main loop checking for expired deadman switches"""
        while self._running:
            try:
                expired_count = await self._check_expired()
                if expired_count > 0:
                    logger.warning(f"Triggered {expired_count} deadman panic(s)")
            except Exception as e:
                logger.error(f"Deadman check failed: {e}", exc_info=True)
            
            await asyncio.sleep(self.check_interval.total_seconds())
    
    async def _check_expired(self) -> int:
        """Find and trigger expired deadman switches. Returns count."""
        async with self.db_session_factory() as session:
            now = datetime.now(timezone.utc)
            
            # Find expired deadman switches
            stmt = select(PPDeadman).where(
                PPDeadman.enabled == True,
                PPDeadman.panic_triggered == False,
                PPDeadman.next_deadline < now
            )
            result = await session.execute(stmt)
            expired = result.scalars().all()
            
            for deadman in expired:
                await self._trigger_panic(session, deadman, now)
            
            await session.commit()
            return len(expired)
    
    async def _trigger_panic(
        self,
        session: AsyncSession,
        deadman: PPDeadman,
        now: datetime
    ):
        """Execute panic for a single client"""
        client_id = deadman.client_id
        
        # Count peppers before deletion
        count_stmt = select(func.count()).select_from(PPPepper).where(
            PPPepper.client_id == client_id
        )
        pepper_count = (await session.execute(count_stmt)).scalar() or 0
        
        # Delete all peppers
        delete_stmt = delete(PPPepper).where(PPPepper.client_id == client_id)
        await session.execute(delete_stmt)
        
        # Mark deadman as triggered
        deadman.panic_triggered = True
        deadman.panic_triggered_at = now
        
        # Log the panic
        log = PPPanicLog(
            client_id=client_id,
            trigger_type='deadman',
            peppers_wiped=pepper_count,
            notes=f"Automatic trigger: deadline was {deadman.next_deadline.isoformat()}"
        )
        session.add(log)
        
        logger.warning(
            f"DEADMAN PANIC: client={client_id}, "
            f"peppers_wiped={pepper_count}, "
            f"deadline={deadman.next_deadline.isoformat()}"
        )
```

### Deadman Service (modules/pepper/service.py - partial)

```python
from datetime import datetime, timezone, timedelta
from fastapi import HTTPException
from sqlalchemy import select
from uuid import UUID

from .models import PPDeadman, PPClient
from .deadman import parse_duration

class DeadmanService:
    def __init__(self, config, db_session):
        self.config = config
        self.db = db_session
        self.default_interval = parse_duration(config.default_interval)
        self.default_grace = parse_duration(config.grace_period)
    
    async def get_status(self, client_id: UUID) -> dict:
        """Get deadman switch status for client"""
        stmt = select(PPDeadman).where(PPDeadman.client_id == client_id)
        result = await self.db.execute(stmt)
        deadman = result.scalar_one_or_none()
        
        if not deadman:
            return {"configured": False}
        
        now = datetime.now(timezone.utc)
        time_remaining = max(0, (deadman.next_deadline - now).total_seconds())
        
        return {
            "configured": True,
            "enabled": deadman.enabled,
            "interval_seconds": deadman.interval_seconds,
            "grace_period_seconds": deadman.grace_period_seconds,
            "last_checkin": deadman.last_checkin.isoformat(),
            "next_deadline": deadman.next_deadline.isoformat(),
            "time_remaining_seconds": int(time_remaining),
            "panic_triggered": deadman.panic_triggered,
            "panic_triggered_at": deadman.panic_triggered_at.isoformat() if deadman.panic_triggered_at else None
        }
    
    async def configure(
        self,
        client_id: UUID,
        interval_seconds: int | None = None,
        grace_period_seconds: int | None = None,
        enabled: bool = True
    ) -> dict:
        """Configure or update deadman switch"""
        stmt = select(PPDeadman).where(PPDeadman.client_id == client_id)
        result = await self.db.execute(stmt)
        deadman = result.scalar_one_or_none()
        
        now = datetime.now(timezone.utc)
        interval = interval_seconds or int(self.default_interval.total_seconds())
        grace = grace_period_seconds or int(self.default_grace.total_seconds())
        
        if deadman:
            # Update existing
            deadman.interval_seconds = interval
            deadman.grace_period_seconds = grace
            deadman.enabled = enabled
            if enabled and deadman.panic_triggered:
                # Re-enable after panic - reset everything
                deadman.panic_triggered = False
                deadman.panic_triggered_at = None
                deadman.last_checkin = now
            deadman.next_deadline = now + timedelta(seconds=interval + grace)
        else:
            # Create new
            deadman = PPDeadman(
                client_id=client_id,
                enabled=enabled,
                interval_seconds=interval,
                grace_period_seconds=grace,
                last_checkin=now,
                next_deadline=now + timedelta(seconds=interval + grace)
            )
            self.db.add(deadman)
        
        await self.db.commit()
        return await self.get_status(client_id)
    
    async def checkin(self, client_id: UUID) -> dict:
        """Check in - reset the deadman timer"""
        stmt = select(PPDeadman).where(PPDeadman.client_id == client_id)
        result = await self.db.execute(stmt)
        deadman = result.scalar_one_or_none()
        
        if not deadman:
            raise HTTPException(404, "Deadman switch not configured")
        
        if not deadman.enabled:
            raise HTTPException(400, "Deadman switch is disabled")
        
        if deadman.panic_triggered:
            raise HTTPException(410, "Panic already triggered - reconfigure to reset")
        
        now = datetime.now(timezone.utc)
        deadman.last_checkin = now
        deadman.next_deadline = now + timedelta(
            seconds=deadman.interval_seconds + deadman.grace_period_seconds
        )
        
        await self.db.commit()
        return await self.get_status(client_id)
    
    async def disable(self, client_id: UUID) -> dict:
        """Disable deadman switch"""
        stmt = select(PPDeadman).where(PPDeadman.client_id == client_id)
        result = await self.db.execute(stmt)
        deadman = result.scalar_one_or_none()
        
        if not deadman:
            raise HTTPException(404, "Deadman switch not configured")
        
        deadman.enabled = False
        await self.db.commit()
        
        return {"message": "Deadman switch disabled"}
```

---

## TOTP Implementation (modules/pepper/totp.py)

```python
import pyotp
import qrcode
import qrcode.image.svg
from io import BytesIO
import secrets
from datetime import datetime, timezone
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from fastapi import HTTPException
from sqlalchemy import select, delete

from .models import PPClient, PPTOTPBackupCode

ph = PasswordHasher()

class TOTPService:
    def __init__(self, config, db_session):
        self.issuer = config.issuer
        self.backup_codes_count = config.backup_codes_count
        self.db = db_session
        self._encryption_key = None  # TODO: Load from config/secrets
    
    async def setup(self, client: PPClient) -> dict:
        """Initialize TOTP setup - returns secret and QR code"""
        if client.totp_secret_encrypted and client.totp_verified:
            raise HTTPException(400, "TOTP already configured. Disable first to reconfigure.")
        
        # Generate secret
        secret = pyotp.random_base32()
        
        # Generate provisioning URI
        totp = pyotp.TOTP(secret)
        uri = totp.provisioning_uri(
            name=client.name or client.cert_fingerprint[:16],
            issuer_name=self.issuer
        )
        
        # Generate QR code as SVG
        qr = qrcode.QRCode(version=1, box_size=10, border=4)
        qr.add_data(uri)
        qr.make(fit=True)
        
        img = qr.make_image(image_factory=qrcode.image.svg.SvgImage)
        buffer = BytesIO()
        img.save(buffer)
        qr_svg = buffer.getvalue().decode()
        
        # Store secret (not yet verified)
        client.totp_secret_encrypted = self._encrypt_secret(secret)
        client.totp_verified = False
        await self.db.commit()
        
        return {
            "secret": secret,
            "qr_svg": qr_svg,
            "uri": uri,
            "message": "Scan QR code with your authenticator app, then verify with POST /totp/verify"
        }
    
    async def verify_setup(self, client: PPClient, code: str) -> dict:
        """Verify TOTP setup with a code"""
        if not client.totp_secret_encrypted:
            raise HTTPException(400, "TOTP not set up. Call POST /totp/setup first.")
        
        if client.totp_verified:
            raise HTTPException(400, "TOTP already verified")
        
        secret = self._decrypt_secret(client.totp_secret_encrypted)
        totp = pyotp.TOTP(secret)
        
        if not totp.verify(code, valid_window=1):
            raise HTTPException(403, "Invalid TOTP code")
        
        client.totp_verified = True
        await self.db.commit()
        
        # Generate initial backup codes
        backup_codes = await self.generate_backup_codes(client.id)
        
        return {
            "message": "TOTP verified and enabled",
            "backup_codes": backup_codes,
            "backup_codes_warning": "Save these backup codes securely. They will not be shown again."
        }
    
    async def verify_code(self, client: PPClient, code: str | None) -> bool:
        """
        Verify a TOTP code for an operation.
        Returns True if verification passes or TOTP not configured.
        """
        if not client.totp_secret_encrypted or not client.totp_verified:
            return True  # TOTP not configured, allow operation
        
        if not code:
            return False  # TOTP required but not provided
        
        secret = self._decrypt_secret(client.totp_secret_encrypted)
        totp = pyotp.TOTP(secret)
        
        # Check TOTP code
        if totp.verify(code, valid_window=1):
            return True
        
        # Check backup codes
        return await self._verify_backup_code(client.id, code)
    
    async def disable(self, client: PPClient, code: str) -> dict:
        """Disable TOTP (requires valid code)"""
        if not await self.verify_code(client, code):
            raise HTTPException(403, "Invalid TOTP code")
        
        client.totp_secret_encrypted = None
        client.totp_verified = False
        
        # Delete backup codes
        await self.db.execute(
            delete(PPTOTPBackupCode).where(PPTOTPBackupCode.client_id == client.id)
        )
        
        await self.db.commit()
        
        return {"message": "TOTP disabled"}
    
    async def generate_backup_codes(self, client_id) -> list[str]:
        """Generate new backup codes (invalidates old ones)"""
        # Delete existing codes
        await self.db.execute(
            delete(PPTOTPBackupCode).where(PPTOTPBackupCode.client_id == client_id)
        )
        
        codes = []
        for _ in range(self.backup_codes_count):
            # Generate 8-character alphanumeric code
            code = secrets.token_hex(4).upper()
            codes.append(code)
            
            backup = PPTOTPBackupCode(
                client_id=client_id,
                code_hash=ph.hash(code)
            )
            self.db.add(backup)
        
        await self.db.commit()
        return codes
    
    async def _verify_backup_code(self, client_id, code: str) -> bool:
        """Check if code matches an unused backup code"""
        stmt = select(PPTOTPBackupCode).where(
            PPTOTPBackupCode.client_id == client_id,
            PPTOTPBackupCode.used_at == None
        )
        result = await self.db.execute(stmt)
        backup_codes = result.scalars().all()
        
        for backup in backup_codes:
            try:
                ph.verify(backup.code_hash, code.upper())
                # Mark as used
                backup.used_at = datetime.now(timezone.utc)
                await self.db.commit()
                return True
            except VerifyMismatchError:
                continue
        
        return False
    
    def _encrypt_secret(self, secret: str) -> bytes:
        """Encrypt TOTP secret for storage"""
        # TODO: Implement proper encryption with Fernet or similar
        # For now, just encode (NOT SECURE - implement properly!)
        return secret.encode()
    
    def _decrypt_secret(self, encrypted: bytes) -> str:
        """Decrypt TOTP secret"""
        # TODO: Implement proper decryption
        return encrypted.decode()
```

---

## Deployment Configurations

### Option 1: Proxy Mode (External Nginx/Caddy/HAProxy terminates mTLS)

```
┌─────────────────────────────────────────────────────────────────┐
│                          Internet                                │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                   External Reverse Proxy :443                    │
│                   (Nginx/Caddy/HAProxy - NOT in Docker)          │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  TLS Termination                                          │  │
│  │  + Optional mTLS verification for /api/v1/pepper/*        │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                                │
                    proxy_pass http://127.0.0.1:8080
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│              Docker: openssl_encrypt_server :8080                │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐  │
│  │  Keyserver  │  │  Telemetry  │  │  Pepper (proxy mode)    │  │
│  │  (own JWT)  │  │  (own JWT)  │  │  (reads X-Client-Cert-*)│  │
│  └─────────────┘  └─────────────┘  └─────────────────────────┘  │
│         │                │                      │                │
│         │    INDEPENDENT TOKENS                 │                │
│         └────────────────┼──────────────────────┘                │
│                          ▼                                       │
│              Docker: ┌──────────┐                                │
│                      │PostgreSQL│                                │
│                      └──────────┘                                │
└─────────────────────────────────────────────────────────────────┘
```

**External Nginx Configuration (example):**

This configuration is for your existing external Nginx - NOT part of Docker deployment.

```nginx
server {
    listen 443 ssl http2;
    server_name api.example.com;
    
    # Server TLS
    ssl_certificate /etc/nginx/certs/server.crt;
    ssl_certificate_key /etc/nginx/certs/server.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;
    ssl_prefer_server_ciphers on;
    
    # Client CA for mTLS (optional verification)
    ssl_client_certificate /etc/nginx/certs/client-ca.crt;
    ssl_verify_client optional;
    ssl_verify_depth 2;
    
    # === Keyserver: Token auth only, no client cert needed ===
    location /api/v1/keys {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    
    # === Telemetry: Token auth only, no client cert needed ===
    location /api/v1/telemetry {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    
    # === Pepper: mTLS required ===
    location /api/v1/pepper {
        # Require valid client certificate
        if ($ssl_client_verify != SUCCESS) {
            return 403 '{"error": "Client certificate required"}';
        }
        
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Pass certificate info to backend
        proxy_set_header X-Client-Cert-Verify $ssl_client_verify;
        proxy_set_header X-Client-Cert-Fingerprint $ssl_client_fingerprint;
        proxy_set_header X-Client-Cert-DN $ssl_client_s_dn;
    }
    
    # Health checks (no auth)
    location /health {
        proxy_pass http://127.0.0.1:8080;
    }
    
    location /ready {
        proxy_pass http://127.0.0.1:8080;
    }
    
    location /info {
        proxy_pass http://127.0.0.1:8080;
    }
}
```

**docker-compose.yml:**

```yaml
version: '3.8'

services:
  server:
    build: .
    restart: unless-stopped
    ports:
      - "127.0.0.1:8080:8080"   # Only localhost - external proxy connects here
    environment:
      - CONFIG_PATH=/app/config.yml
      - KEYSERVER_TOKEN_SECRET=${KEYSERVER_TOKEN_SECRET}
      - TELEMETRY_TOKEN_SECRET=${TELEMETRY_TOKEN_SECRET}
    volumes:
      - ./config.yml:/app/config.yml:ro
    networks:
      - internal
    depends_on:
      db:
        condition: service_healthy

  db:
    image: postgres:16-alpine
    restart: unless-stopped
    environment:
      POSTGRES_USER: openssl_encrypt
      POSTGRES_PASSWORD: ${DB_PASSWORD}
      POSTGRES_DB: openssl_encrypt
    volumes:
      - postgres_data:/var/lib/postgresql/data
    networks:
      - internal
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U openssl_encrypt"]
      interval: 5s
      timeout: 5s
      retries: 5

networks:
  internal:
    internal: true

volumes:
  postgres_data:
```

**Note:** Server binds to `127.0.0.1:8080` - configure your external Nginx/Caddy/HAProxy to proxy to this address.

**config.yml (proxy mode):**

```yaml
server:
  host: 0.0.0.0
  port: 8080
  workers: 4

database:
  url: postgresql+asyncpg://openssl_encrypt:${DB_PASSWORD}@db:5432/openssl_encrypt
  pool_size: 20
  max_overflow: 10

logging:
  level: INFO
  format: json

modules:
  keyserver:
    enabled: true
    max_key_size_kb: 100
    require_self_signature: true
    token:
      secret: ${KEYSERVER_TOKEN_SECRET}
      algorithm: HS256
      expiry_days: 365
      issuer: "openssl_encrypt_keyserver"
      
  telemetry:
    enabled: true
    retention_days: 365
    token:
      secret: ${TELEMETRY_TOKEN_SECRET}
      algorithm: HS256
      expiry_days: 365
      issuer: "openssl_encrypt_telemetry"
      
  pepper:
    enabled: true
    auth:
      mode: proxy
      proxy:
        fingerprint_header: X-Client-Cert-Fingerprint
        dn_header: X-Client-Cert-DN
        verify_header: X-Client-Cert-Verify
        trusted_proxies:
          - 172.16.0.0/12
          - 192.168.0.0/16
    deadman:
      enabled: true
      check_interval: 1h
      default_interval: 7d
      grace_period: 24h
    totp:
      enabled: true
      issuer: "openssl_encrypt"
      backup_codes_count: 10
    max_peppers_per_client: 100
```

---

### Option 2: mTLS Mode (Pepper handles TLS directly, no proxy needed)

```
┌─────────────────────────────────────────────────────────────────┐
│                          Internet                                │
└─────────────────────────────────────────────────────────────────┘
           │                                      │
           │ (optional: external proxy            │ (direct mTLS)
           │  for Keyserver/Telemetry)            │
           ▼                                      ▼
┌─────────────────────────────┐      ┌───────────────────────────┐
│  External Proxy (optional)  │      │  Docker: Pepper :8444     │
│  or direct :8080            │      │  (Direct mTLS)            │
└─────────────────────────────┘      └───────────────────────────┘
           │                                      │
           ▼                                      │
┌─────────────────────────────┐                   │
│  Docker: Main Server :8080  │                   │
│  Keyserver + Telemetry      │                   │
└─────────────────────────────┘                   │
           │                                      │
           └──────────────┬───────────────────────┘
                          ▼
               Docker: ┌──────────┐
                       │PostgreSQL│
                       └──────────┘
```

**docker-compose.mtls.yml:**

```yaml
version: '3.8'

services:
  # Main server for Keyserver + Telemetry
  server:
    build: .
    restart: unless-stopped
    command: ["python", "server.py"]
    ports:
      - "127.0.0.1:8080:8080"   # Keyserver + Telemetry (external proxy or direct)
    environment:
      - CONFIG_PATH=/app/config.yml
      - KEYSERVER_TOKEN_SECRET=${KEYSERVER_TOKEN_SECRET}
      - TELEMETRY_TOKEN_SECRET=${TELEMETRY_TOKEN_SECRET}
    volumes:
      - ./config.mtls.yml:/app/config.yml:ro
    networks:
      - internal
    depends_on:
      db:
        condition: service_healthy

  # Separate Pepper server with direct mTLS (no proxy needed)
  pepper-server:
    build: .
    restart: unless-stopped
    command: ["python", "pepper_server.py"]
    ports:
      - "8444:8444"            # Direct mTLS - no proxy, exposed directly
    environment:
      - CONFIG_PATH=/app/config.yml
    volumes:
      - ./config.mtls.yml:/app/config.yml:ro
      - ./certs/pepper:/certs:ro
    networks:
      - internal
    depends_on:
      db:
        condition: service_healthy

  db:
    image: postgres:16-alpine
    restart: unless-stopped
    environment:
      POSTGRES_USER: openssl_encrypt
      POSTGRES_PASSWORD: ${DB_PASSWORD}
      POSTGRES_DB: openssl_encrypt
    volumes:
      - postgres_data:/var/lib/postgresql/data
    networks:
      - internal
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U openssl_encrypt"]
      interval: 5s
      timeout: 5s
      retries: 5

networks:
  internal:
    internal: true

volumes:
  postgres_data:
```

**Note:** 
- Keyserver/Telemetry on `127.0.0.1:8080` - use external proxy if needed
- Pepper on `0.0.0.0:8444` - direct mTLS, no proxy required

**config.mtls.yml:**

```yaml
server:
  host: 0.0.0.0
  port: 8080
  workers: 4

database:
  url: postgresql+asyncpg://openssl_encrypt:${DB_PASSWORD}@db:5432/openssl_encrypt

modules:
  keyserver:
    enabled: true
    token:
      secret: ${KEYSERVER_TOKEN_SECRET}
      algorithm: HS256
      expiry_days: 365
      issuer: "openssl_encrypt_keyserver"
      
  telemetry:
    enabled: true
    token:
      secret: ${TELEMETRY_TOKEN_SECRET}
      algorithm: HS256
      expiry_days: 365
      issuer: "openssl_encrypt_telemetry"
      
  pepper:
    enabled: true
    auth:
      mode: mtls
      mtls:
        host: 0.0.0.0
        port: 8444
        tls:
          cert: /certs/server.crt
          key: /certs/server.key
          client_ca: /certs/client-ca.crt
    deadman:
      enabled: true
      check_interval: 1h
      default_interval: 7d
      grace_period: 24h
    totp:
      enabled: true
      issuer: "openssl_encrypt"
      backup_codes_count: 10
```

---

## Testing

### Token Isolation Tests (tests/test_token_isolation.py)

```python
"""
Tests to verify that Keyserver and Telemetry tokens are completely independent.
"""
import pytest
from httpx import AsyncClient

class TestTokenIsolation:
    """Verify tokens cannot be used across modules"""
    
    async def test_keyserver_token_rejected_by_telemetry(self, client: AsyncClient):
        """Keyserver token must not work on Telemetry endpoints"""
        # Register with Keyserver
        ks_response = await client.post("/api/v1/keys/register")
        assert ks_response.status_code == 201
        ks_token = ks_response.json()["token"]
        
        # Try to use Keyserver token on Telemetry endpoint
        tm_response = await client.post(
            "/api/v1/telemetry/events",
            headers={"Authorization": f"Bearer {ks_token}"},
            json={"events": []}
        )
        assert tm_response.status_code == 401
        assert "not valid for this service" in tm_response.json()["detail"]
    
    async def test_telemetry_token_rejected_by_keyserver(self, client: AsyncClient):
        """Telemetry token must not work on Keyserver endpoints"""
        # Register with Telemetry
        tm_response = await client.post("/api/v1/telemetry/register")
        assert tm_response.status_code == 201
        tm_token = tm_response.json()["token"]
        
        # Try to use Telemetry token on Keyserver endpoint
        ks_response = await client.get(
            "/api/v1/keys/mine",
            headers={"Authorization": f"Bearer {tm_token}"}
        )
        assert ks_response.status_code == 401
        assert "not valid for this service" in ks_response.json()["detail"]
    
    async def test_modified_token_rejected(self, client: AsyncClient):
        """Token with modified issuer claim must be rejected"""
        # This test verifies that even if someone decodes a token,
        # changes the issuer, and re-encodes it, it will be rejected
        # because the signature won't match (different secrets)
        pass  # Implement with actual JWT manipulation
    
    async def test_each_module_has_own_client_table(self, client: AsyncClient, db):
        """Verify clients are stored in separate tables"""
        # Register in both modules
        await client.post("/api/v1/keys/register")
        await client.post("/api/v1/telemetry/register")
        
        # Check separate tables
        ks_count = await db.execute("SELECT COUNT(*) FROM ks_clients")
        tm_count = await db.execute("SELECT COUNT(*) FROM tm_clients")
        
        assert ks_count.scalar() == 1
        assert tm_count.scalar() == 1
```

### Keyserver Tests (tests/test_keyserver.py)

```python
import pytest
from httpx import AsyncClient

class TestKeyserver:
    async def test_register(self, client: AsyncClient):
        response = await client.post("/api/v1/keys/register")
        assert response.status_code == 201
        data = response.json()
        assert "client_id" in data
        assert "token" in data
        assert "expires_at" in data
        assert data["token_type"] == "Bearer"
    
    async def test_upload_requires_auth(self, client: AsyncClient):
        response = await client.post("/api/v1/keys", json={})
        assert response.status_code == 401
    
    async def test_upload_key(self, client: AsyncClient, keyserver_token: str):
        response = await client.post(
            "/api/v1/keys",
            headers={"Authorization": f"Bearer {keyserver_token}"},
            json={
                "name": "Test Key",
                "email": "test@example.com",
                "public_key_bundle": "base64...",
                "self_signature": "base64...",
                "algorithm": "ML-KEM-768+ML-DSA-65"
            }
        )
        assert response.status_code == 201
        assert "fingerprint" in response.json()
```

### Pepper Tests (tests/test_pepper.py)

```python
import pytest
from httpx import AsyncClient

class TestPepper:
    async def test_requires_client_cert(self, client: AsyncClient):
        """Without client cert headers, should get 403"""
        response = await client.get("/api/v1/pepper/profile")
        assert response.status_code == 403
    
    async def test_auto_register(self, client: AsyncClient, pepper_headers: dict):
        """First request should auto-register client"""
        response = await client.get(
            "/api/v1/pepper/profile",
            headers=pepper_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert "cert_fingerprint" in data
        assert "created_at" in data
    
    async def test_create_pepper(self, client: AsyncClient, pepper_headers: dict):
        response = await client.post(
            "/api/v1/pepper/peppers",
            headers=pepper_headers,
            json={
                "name": "my-secret-pepper",
                "pepper_encrypted": "base64-encrypted-data...",
                "description": "Test pepper"
            }
        )
        assert response.status_code == 201
    
    async def test_deadman_checkin(self, client: AsyncClient, pepper_headers: dict):
        # First configure deadman
        await client.put(
            "/api/v1/pepper/deadman",
            headers=pepper_headers,
            json={"interval_seconds": 86400}  # 1 day
        )
        
        # Then check in
        response = await client.post(
            "/api/v1/pepper/deadman/checkin",
            headers=pepper_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert data["time_remaining_seconds"] > 86000
    
    async def test_panic_requires_totp(
        self,
        client: AsyncClient,
        pepper_headers: dict,
        pepper_with_totp  # Fixture that sets up TOTP
    ):
        # Without TOTP code
        response = await client.post(
            "/api/v1/pepper/panic",
            headers=pepper_headers
        )
        assert response.status_code == 403
        
        # With valid TOTP code
        response = await client.post(
            "/api/v1/pepper/panic",
            headers={**pepper_headers, "X-TOTP-Code": "123456"}  # Mock valid code
        )
        assert response.status_code == 200
```

### Integrity Tests (tests/test_integrity.py)

```python
import pytest
from httpx import AsyncClient

class TestIntegrity:
    async def test_register(self, client: AsyncClient):
        """Register returns unique token"""
        response = await client.post("/api/v1/integrity/register")
        assert response.status_code == 201
        data = response.json()
        assert "client_id" in data
        assert "token" in data
        assert data["token_type"] == "Bearer"
    
    async def test_store_hash(self, client: AsyncClient, integrity_token: str):
        """Store metadata hash for a file"""
        response = await client.post(
            "/api/v1/integrity/hashes",
            headers={"Authorization": f"Bearer {integrity_token}"},
            json={
                "file_id": "abc123def456",
                "metadata_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "algorithm": "symmetric-aes256-gcm"
            }
        )
        assert response.status_code == 201
        data = response.json()
        assert data["file_id"] == "abc123def456"
    
    async def test_verify_match(self, client: AsyncClient, integrity_token: str, stored_hash):
        """Verification returns match=true for correct hash"""
        response = await client.post(
            "/api/v1/integrity/verify",
            headers={"Authorization": f"Bearer {integrity_token}"},
            json={
                "file_id": stored_hash["file_id"],
                "metadata_hash": stored_hash["metadata_hash"]
            }
        )
        assert response.status_code == 200
        data = response.json()
        assert data["match"] == True
        assert "warning" not in data
    
    async def test_verify_mismatch_detected(self, client: AsyncClient, integrity_token: str, stored_hash):
        """Verification detects tampering"""
        response = await client.post(
            "/api/v1/integrity/verify",
            headers={"Authorization": f"Bearer {integrity_token}"},
            json={
                "file_id": stored_hash["file_id"],
                "metadata_hash": "tampered_hash_value_different_from_stored"
            }
        )
        assert response.status_code == 200
        data = response.json()
        assert data["match"] == False
        assert "INTEGRITY VIOLATION" in data["warning"]
        assert data["stored_hash"] != data["provided_hash"]
    
    async def test_verify_not_found(self, client: AsyncClient, integrity_token: str):
        """Verification fails for unknown file"""
        response = await client.post(
            "/api/v1/integrity/verify",
            headers={"Authorization": f"Bearer {integrity_token}"},
            json={
                "file_id": "nonexistent_file",
                "metadata_hash": "somehash"
            }
        )
        assert response.status_code == 404
    
    async def test_batch_verify(self, client: AsyncClient, integrity_token: str, multiple_hashes):
        """Batch verification returns results for all files"""
        response = await client.post(
            "/api/v1/integrity/verify/batch",
            headers={"Authorization": f"Bearer {integrity_token}"},
            json={
                "files": [
                    {"file_id": "file1", "metadata_hash": "hash1"},
                    {"file_id": "file2", "metadata_hash": "hash2"},
                    {"file_id": "file3", "metadata_hash": "wrong_hash"}
                ]
            }
        )
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 3
        assert data["matched"] == 2
        assert data["all_match"] == False
    
    async def test_integrity_token_rejected_by_keyserver(self, client: AsyncClient, integrity_token: str):
        """Integrity token cannot be used on Keyserver"""
        response = await client.get(
            "/api/v1/keys/mine",
            headers={"Authorization": f"Bearer {integrity_token}"}
        )
        assert response.status_code == 401
        assert "not valid for this service" in response.json()["detail"]
```

---

## Migration Steps

### Phase 1: Project Setup (Day 1-2)
1. Create new repository `openssl_encrypt_server`
2. Set up project structure as defined
3. Implement `config.py` with Pydantic Settings
4. Implement startup validation (token secret uniqueness for all 3 token-based modules)
5. Implement `core/database.py` (SQLAlchemy async)
6. Implement `core/auth/token.py` (base TokenAuth class)
7. Implement `core/auth/proxy.py` and `core/auth/mtls.py`
8. Create base Dockerfile
9. Write core module tests

### Phase 2: Keyserver Migration (Day 3-4)
1. Create `modules/keyserver/models.py` with `ks_clients`, `ks_keys`, `ks_access_log`
2. Create `modules/keyserver/auth.py` with Keyserver-specific TokenAuth
3. Port existing Keyserver routes to `modules/keyserver/routes.py`
4. Add `/register` endpoint for token issuance
5. Create Alembic migration for keyserver tables
6. Test all Keyserver functionality
7. Write data migration script if needed

### Phase 3: Telemetry Migration (Day 5-6)
1. Create `modules/telemetry/models.py` with `tm_clients`, `tm_events`, `tm_daily_stats`
2. Create `modules/telemetry/auth.py` with Telemetry-specific TokenAuth
3. Port existing Telemetry routes to `modules/telemetry/routes.py`
4. Add `/register` endpoint for token issuance
5. Create Alembic migration for telemetry tables
6. Test all Telemetry functionality
7. **Test token isolation** (critical!)

### Phase 4: Pepper Module (Day 7-10)
1. Create `modules/pepper/models.py` with all `pp_*` tables
2. Implement `modules/pepper/auth.py` with PepperAuthHandler
3. Implement client auto-registration
4. Implement TOTP setup and verification
5. Implement pepper CRUD operations
6. Implement DeadmanWatcher background task
7. Implement panic functionality
8. Create Alembic migrations
9. Write comprehensive tests

### Phase 5: Integrity Module (Day 11-12)
1. Create `modules/integrity/models.py` with `in_clients`, `in_metadata_hashes`, `in_verification_log`
2. Create `modules/integrity/auth.py` with Integrity-specific TokenAuth
3. Implement hash CRUD operations
4. Implement verification endpoint with match/mismatch detection
5. Implement batch verification
6. Create Alembic migrations
7. Write tests including tampering detection scenarios
8. **Test token isolation** (all 3 token-based modules must be independent!)

### Phase 6: Integration & Deployment (Day 13-14)
1. Create unified Alembic migration chain
2. Test module enable/disable combinations
3. Test both deployment modes (proxy/mtls)
4. Create `docker-compose.yml` (proxy mode)
5. Create `docker-compose.mtls.yml` (mTLS mode)
6. Write deployment documentation
7. Create Nginx config examples

---

## Summary

| Module | Auth | Client Table | Token Issuer | Features |
|--------|------|--------------|--------------|----------|
| Keyserver | JWT (own secret) | `ks_clients` | `openssl_encrypt_keyserver` | Upload, search, revoke PQC public keys |
| Telemetry | JWT (own secret) | `tm_clients` | `openssl_encrypt_telemetry` | Anonymous usage statistics |
| Pepper | mTLS | `pp_clients` | N/A (cert-based) | Encrypted pepper storage, TOTP, dead man's switch, panic |
| Integrity | JWT (own secret) | `in_clients` | `openssl_encrypt_integrity` | Metadata hash storage, tampering detection |

**Token Independence Guarantees:**
- Different JWT signing secrets (validated at startup)
- Different issuer claims (validated during verification)
- Separate client database tables
- Cross-module token usage is cryptographically impossible

**Deployment Options:**
- **Proxy Mode:** Single port (8080), Nginx handles mTLS for Pepper routes
- **mTLS Mode:** Separate port (8444) for Pepper with direct TLS termination

---

## Appendix: Integrity Client Plugin

The Integrity module requires a client-side plugin in openssl_encrypt to be useful.

### Plugin Configuration

```yaml
# ~/.openssl_encrypt/config.yml
plugins:
  integrity:
    enabled: true
    server: https://api.example.com
    token: ${INTEGRITY_TOKEN}  # From /api/v1/integrity/register
    
    # When to verify
    verify_on_decrypt: true     # Check hash before decryption
    verify_on_encrypt: false    # Optional: verify after encryption
    
    # Behavior on mismatch
    on_mismatch: abort          # abort | warn | ignore
    
    # What to hash
    hash_fields:
      - salt
      - algorithm
      - kdf
      - kdf_params
      - encrypted_key           # For asymmetric
      - signature               # For signed files
```

### Client Flow: Encryption

```python
# After encryption, before writing file:
metadata_hash = sha256(
    salt + algorithm + kdf + kdf_params + ...
)

file_id = sha256(filepath)  # Or user-defined ID

# Store hash on server
POST /api/v1/integrity/hashes
{
    "file_id": file_id,
    "metadata_hash": metadata_hash,
    "algorithm": "symmetric-aes256-gcm"
}
```

### Client Flow: Decryption

```python
# Before decryption:
1. Read encrypted file metadata
2. Compute hash of metadata
3. Query server:
   POST /api/v1/integrity/verify
   {
       "file_id": file_id,
       "metadata_hash": computed_hash
   }
4. If response.match == false:
   → ABORT! "Integrity violation detected!"
5. Else: proceed with decryption
```

### Attacks Prevented

| Attack | How it works | How Integrity prevents it |
|--------|--------------|---------------------------|
| Algorithm Downgrade | Attacker changes `algorithm: ML-KEM-768` → `algorithm: RSA-2048` | Hash mismatch detected |
| KDF Weakening | Attacker reduces `iterations: 1000000` → `iterations: 1000` | Hash mismatch detected |
| Salt Manipulation | Attacker modifies salt to enable rainbow table attack | Hash mismatch detected |
| Metadata Injection | Attacker adds malicious fields to metadata | Hash mismatch detected |
| Version Rollback | Attacker replaces file with older (weaker) encrypted version | Different hash stored |

### Limitations

- **Requires server connectivity** during decrypt (can cache for offline)
- **Doesn't protect file content** - only metadata integrity
- **Trust in server** - if server compromised, hashes can be modified
- **File ID collision** - need unique, stable file identifiers

### Future Enhancement: Signed Hashes

For higher security, server could sign returned hashes:

```json
{
    "file_id": "...",
    "metadata_hash": "...",
    "server_signature": "...",  // Signed by server's private key
    "timestamp": "..."
}
```

Client verifies signature with server's public key → protects against server database tampering.
