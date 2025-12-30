#!/usr/bin/env python3
"""
Pydantic schemas for telemetry events.
"""

from datetime import datetime
from typing import Dict, List, Optional

from pydantic import BaseModel, Field


class TelemetryEventSchema(BaseModel):
    """Single telemetry event (matches TelemetryEvent from client)."""

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
    pqc_signing_algorithm: Optional[str] = Field(default=None, description="PQC signing algorithm")

    hsm_plugin_used: Optional[str] = Field(default=None, description="HSM plugin name")

    success: bool = Field(default=True, description="Operation success")
    error_category: Optional[str] = Field(default=None, description="Error category if failed")

    class Config:
        json_schema_extra = {
            "example": {
                "timestamp": "2025-12-30T12:00:00Z",
                "operation": "encrypt",
                "mode": "symmetric",
                "format_version": 8,
                "hash_algorithms": ["sha512", "blake2b"],
                "kdf_algorithms": ["argon2"],
                "kdf_parameters": {"argon2": {"time_cost": 3, "memory_cost": 65536}},
                "encryption_algorithm": "aes-256-gcm",
                "cascade_enabled": False,
                "success": True,
            }
        }


class TelemetryBatchRequest(BaseModel):
    """Batch telemetry upload request."""

    events: List[TelemetryEventSchema] = Field(
        ..., min_length=1, max_length=1000, description="List of telemetry events (max 1000)"
    )

    class Config:
        json_schema_extra = {
            "example": {"events": [TelemetryEventSchema.Config.json_schema_extra["example"]]}
        }


class TelemetryBatchResponse(BaseModel):
    """Batch telemetry upload response."""

    received: int = Field(..., description="Number of events received")
    processed: int = Field(..., description="Number of events successfully processed")

    class Config:
        json_schema_extra = {"example": {"received": 10, "processed": 10}}
