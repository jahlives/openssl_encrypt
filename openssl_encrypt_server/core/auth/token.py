#!/usr/bin/env python3
"""
JWT-based token authentication for module isolation.

Each module (Keyserver, Telemetry) gets its own TokenAuth instance with:
- Unique secret key
- Unique issuer string
- Separate client table

This ensures complete token isolation between modules - a Keyserver token
cannot be used for Telemetry endpoints and vice versa.
"""

import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Optional, Type

import jwt
from fastapi import HTTPException, Request, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from ..database import get_db_session

logger = logging.getLogger(__name__)

security = HTTPBearer(auto_error=False)


class TokenPayload(BaseModel):
    """JWT Token payload structure"""

    sub: str  # Client ID
    iss: str  # Issuer (module identifier)
    exp: datetime  # Expiration
    iat: datetime  # Issued at
    jti: str  # Unique token ID


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

    def __init__(self, config: TokenConfig, client_model: Type[Any]):
        """
        Initialize token auth handler.

        Args:
            config: Token configuration
            client_model: SQLAlchemy model for client table
        """
        self.secret = config.secret
        self.algorithm = config.algorithm
        self.expiry_days = config.expiry_days
        self.issuer = config.issuer
        self.client_model = client_model

        logger.info(f"TokenAuth initialized for issuer: {self.issuer}")

    def generate_client_id(self) -> str:
        """Generate unique client ID (32 hex characters)"""
        return secrets.token_hex(16)

    def create_token(self, client_id: str) -> tuple[str, datetime]:
        """
        Create JWT token for client.

        Args:
            client_id: Client identifier

        Returns:
            tuple: (token string, expiry datetime)
        """
        now = datetime.now(timezone.utc)
        expiry = now + timedelta(days=self.expiry_days)

        payload = {
            "sub": client_id,
            "iss": self.issuer,
            "exp": expiry,
            "iat": now,
            "jti": secrets.token_hex(8),
        }

        token = jwt.encode(payload, self.secret, algorithm=self.algorithm)

        logger.debug(f"Created token for client {client_id[:8]}... (issuer: {self.issuer})")

        return token, expiry

    def verify_token(self, token: str) -> TokenPayload:
        """
        Verify and decode JWT token.

        Args:
            token: JWT token string

        Returns:
            TokenPayload: Decoded and validated payload

        Raises:
            HTTPException: If token is invalid, expired, or wrong issuer
        """
        try:
            data = jwt.decode(
                token,
                self.secret,
                algorithms=[self.algorithm],
                issuer=self.issuer,  # Validates issuer claim
            )
            return TokenPayload(**data)

        except jwt.ExpiredSignatureError:
            logger.warning("Token expired")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token expired",
                headers={"WWW-Authenticate": "Bearer"},
            )
        except jwt.InvalidIssuerError:
            # This happens if someone tries to use a token from another module
            logger.warning(f"Invalid issuer (expected: {self.issuer})")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token not valid for this service",
                headers={"WWW-Authenticate": "Bearer"},
            )
        except jwt.InvalidTokenError as e:
            logger.warning(f"Invalid token: {e}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Invalid token: {str(e)}",
                headers={"WWW-Authenticate": "Bearer"},
            )

    async def register_client(self, metadata: Optional[dict] = None) -> dict:
        """
        Register a new client and issue token.

        Args:
            metadata: Optional client metadata (version, platform, etc.)

        Returns:
            dict: Registration response with token
        """
        client_id = self.generate_client_id()
        token, expiry = self.create_token(client_id)

        async with get_db_session() as session:
            client = self.client_model(client_id=client_id, metadata=metadata or {})
            session.add(client)
            await session.commit()

        logger.info(f"Registered new client {client_id[:8]}... (issuer: {self.issuer})")

        return {
            "client_id": client_id,
            "token": token,
            "expires_at": expiry.isoformat(),
            "token_type": "Bearer",
        }

    async def get_client(self, client_id: str, session: AsyncSession):
        """
        Get client from database.

        Args:
            client_id: Client identifier
            session: Database session

        Returns:
            Client model instance or None
        """
        stmt = select(self.client_model).where(self.client_model.client_id == client_id)
        result = await session.execute(stmt)
        return result.scalar_one_or_none()

    async def update_last_seen(self, client_id: str):
        """
        Update client's last_seen timestamp.

        Args:
            client_id: Client identifier
        """
        try:
            async with get_db_session() as session:
                stmt = (
                    update(self.client_model)
                    .where(self.client_model.client_id == client_id)
                    .values(last_seen_at=datetime.now(timezone.utc))
                )
                await session.execute(stmt)
                await session.commit()
        except Exception as e:
            logger.warning(f"Failed to update last_seen for {client_id[:8]}...: {e}")

    def create_dependency(self) -> Callable:
        """
        Create FastAPI dependency for this auth instance.

        Returns:
            Callable: FastAPI dependency function

        Usage:
            keyserver_auth = TokenAuth(keyserver_config, KSClient)
            require_keyserver_auth = keyserver_auth.create_dependency()

            @router.get("/keys")
            async def list_keys(client_id: str = Depends(require_keyserver_auth)):
                ...
        """

        async def verify_token_dependency(
            request: Request,
            credentials: HTTPAuthorizationCredentials = Security(security),
        ) -> str:
            """FastAPI dependency that validates token and returns client_id"""
            if not credentials:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Authorization header required",
                    headers={"WWW-Authenticate": "Bearer"},
                )

            payload = self.verify_token(credentials.credentials)

            # Update last seen (fire and forget)
            try:
                await self.update_last_seen(payload.sub)
            except Exception:
                pass  # Don't fail request if update fails

            return payload.sub  # Return client_id

        return verify_token_dependency
