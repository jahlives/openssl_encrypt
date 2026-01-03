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
    """Token configuration with support for access and refresh tokens"""

    secret: str
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 60  # 1 hour (reduced from 365 days)
    refresh_token_expire_days: int = 7     # 7 days for refresh tokens
    issuer: str
    enable_sliding_expiration: bool = True  # Auto-extend tokens on use


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
        self.access_token_expire_minutes = config.access_token_expire_minutes
        self.refresh_token_expire_days = config.refresh_token_expire_days
        self.enable_sliding_expiration = config.enable_sliding_expiration
        self.issuer = config.issuer
        self.client_model = client_model

        logger.info(
            f"TokenAuth initialized for issuer: {self.issuer} "
            f"(access: {self.access_token_expire_minutes}min, "
            f"refresh: {self.refresh_token_expire_days}days, "
            f"sliding: {self.enable_sliding_expiration})"
        )

    def generate_client_id(self) -> str:
        """Generate unique client ID (32 hex characters)"""
        return secrets.token_hex(16)

    def create_token(
        self,
        client_id: str,
        token_type: str = "access"
    ) -> tuple[str, datetime]:
        """
        Create JWT token for client (access or refresh).

        Args:
            client_id: Client identifier
            token_type: "access" or "refresh" (default: "access")

        Returns:
            tuple: (token string, expiry datetime)
        """
        now = datetime.now(timezone.utc)

        if token_type == "refresh":
            expiry = now + timedelta(days=self.refresh_token_expire_days)
        else:  # access token
            expiry = now + timedelta(minutes=self.access_token_expire_minutes)

        payload = {
            "sub": client_id,
            "iss": self.issuer,
            "exp": expiry,
            "iat": now,
            "jti": secrets.token_hex(8),
            "type": token_type,  # Distinguish token types
        }

        token = jwt.encode(payload, self.secret, algorithm=self.algorithm)

        logger.debug(
            f"Created {token_type} token for client {client_id[:8]}... "
            f"(issuer: {self.issuer}, expires: {expiry.isoformat()})"
        )

        return token, expiry

    def create_token_pair(self, client_id: str) -> dict:
        """
        Create both access and refresh tokens for client.

        Args:
            client_id: Client identifier

        Returns:
            dict with access_token, refresh_token, and expiry info
        """
        access_token, access_expiry = self.create_token(client_id, "access")
        refresh_token, refresh_expiry = self.create_token(client_id, "refresh")

        logger.info(f"Created token pair for client {client_id[:8]}...")

        return {
            "access_token": access_token,
            "access_token_expires_at": access_expiry.isoformat(),
            "refresh_token": refresh_token,
            "refresh_token_expires_at": refresh_expiry.isoformat(),
            "token_type": "Bearer"
        }

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

    def refresh_access_token(self, refresh_token: str) -> dict:
        """
        Use refresh token to get new access token (sliding expiration).

        Args:
            refresh_token: Valid refresh token

        Returns:
            dict with new access_token and refresh_token

        Raises:
            HTTPException: If refresh token invalid or wrong type
        """
        # Verify refresh token
        try:
            payload = self.verify_token(refresh_token)
        except HTTPException:
            raise  # Re-raise auth errors

        # Validate token type
        token_data = jwt.decode(
            refresh_token,
            self.secret,
            algorithms=[self.algorithm],
            issuer=self.issuer
        )

        if token_data.get("type") != "refresh":
            logger.warning(f"Attempted to refresh with non-refresh token: {payload.sub[:8]}...")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token type. Refresh token required.",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Create new token pair (sliding expiration)
        new_tokens = self.create_token_pair(payload.sub)

        logger.info(f"Refreshed tokens for client {payload.sub[:8]}... (sliding expiration)")

        return {
            "client_id": payload.sub,
            **new_tokens
        }

    async def register_client(self, metadata: Optional[dict] = None) -> dict:
        """
        Register a new client and issue token pair.

        Args:
            metadata: Optional client metadata (version, platform, etc.)

        Returns:
            dict: Registration response with access and refresh tokens
        """
        client_id = self.generate_client_id()
        tokens = self.create_token_pair(client_id)

        async with get_db_session() as session:
            client = self.client_model(client_id=client_id, metadata=metadata or {})
            session.add(client)
            await session.commit()

        logger.info(f"Registered new client {client_id[:8]}... (issuer: {self.issuer})")

        return {
            "client_id": client_id,
            **tokens
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
