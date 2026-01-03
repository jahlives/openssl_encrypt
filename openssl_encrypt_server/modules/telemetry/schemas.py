#!/usr/bin/env python3
"""
Telemetry Pydantic Schemas

Request/response validation for telemetry endpoints.
"""

from datetime import datetime
from typing import Dict, List, Optional

from pydantic import BaseModel, Field


class RegisterResponse(BaseModel):
    """Response for client registration with access and refresh tokens"""

    client_id: str
    token: str  # Deprecated: kept for backward compatibility, same as access_token
    access_token: Optional[str] = None  # Explicit access token (1-hour expiry)
    refresh_token: Optional[str] = None  # Refresh token for sliding expiration (7-day expiry)
    expires_at: str  # ISO 8601 datetime (access token expiry)
    refresh_expires_at: Optional[str] = None  # ISO 8601 datetime (refresh token expiry)
    token_type: str = "Bearer"


class TelemetryEventSchema(BaseModel):
    """Single telemetry event"""

    timestamp: str = Field(..., description="Event timestamp (ISO 8601)")
    operation: str = Field(..., description="Operation: encrypt or decrypt")
    mode: str = Field(..., description="Mode: symmetric or asymmetric")
    format_version: int = Field(..., description="File format version (4-8)")

    hash_algorithms: List[str] = Field(..., description="Hash algorithms used")
    kdf_algorithms: List[str] = Field(..., description="KDF algorithms used")
    kdf_parameters: Optional[Dict[str, Dict[str, int]]] = Field(
        default=None, description="KDF parameters"
    )

    encryption_algorithm: str = Field(..., description="Encryption algorithm")

    cascade_enabled: bool = Field(default=False, description="Cascade encryption enabled")
    cascade_cipher_count: Optional[int] = Field(
        default=None, description="Number of cascade ciphers"
    )

    pqc_kem_algorithm: Optional[str] = Field(default=None, description="PQC KEM algorithm")
    pqc_signing_algorithm: Optional[str] = Field(
        default=None, description="PQC signing algorithm"
    )

    hsm_plugin_used: Optional[str] = Field(default=None, description="HSM plugin name")

    success: bool = Field(default=True, description="Operation success")
    error_category: Optional[str] = Field(default=None, description="Error category if failed")


class TelemetryBatchRequest(BaseModel):
    """Batch telemetry upload request"""

    events: List[TelemetryEventSchema] = Field(
        ..., min_length=1, max_length=1000, description="List of telemetry events (max 1000)"
    )


class TelemetryBatchResponse(BaseModel):
    """Batch telemetry upload response"""

    received: int = Field(..., description="Number of events received")
    processed: int = Field(..., description="Number of events successfully processed")


class StatsResponse(BaseModel):
    """Public statistics response"""

    total_operations: int
    total_clients: int
    algorithms: Dict[str, int]
    operations: Dict[str, int]
    success_rate: float


class ErrorResponse(BaseModel):
    """Standard error response"""

    detail: str
    success: bool = False
