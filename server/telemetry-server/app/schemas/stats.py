#!/usr/bin/env python3
"""
Pydantic schemas for public statistics.
"""

from typing import Dict, List

from pydantic import BaseModel, Field


class AlgorithmStat(BaseModel):
    """Algorithm usage statistics."""

    algorithm: str = Field(..., description="Algorithm name")
    count: int = Field(..., description="Usage count")
    percentage: float = Field(..., description="Percentage of total")


class StatisticsResponse(BaseModel):
    """Public statistics response."""

    total_operations: int = Field(..., description="Total operations")
    total_clients: int = Field(..., description="Total unique clients (anonymized count)")

    modes: List[AlgorithmStat] = Field(..., description="Mode distribution")
    encryption_algorithms: List[AlgorithmStat] = Field(
        ..., description="Encryption algorithm distribution"
    )
    hash_algorithms: List[AlgorithmStat] = Field(..., description="Hash algorithm distribution")
    kdf_algorithms: List[AlgorithmStat] = Field(..., description="KDF algorithm distribution")
    pqc_algorithms: List[AlgorithmStat] = Field(..., description="PQC algorithm distribution")

    format_versions: Dict[int, int] = Field(..., description="Format version counts")
    success_rate: float = Field(..., description="Success rate (0.0 - 1.0)")

    class Config:
        json_schema_extra = {
            "example": {
                "total_operations": 10000,
                "total_clients": 500,
                "modes": [
                    {"algorithm": "symmetric", "count": 9000, "percentage": 90.0},
                    {"algorithm": "asymmetric", "count": 1000, "percentage": 10.0},
                ],
                "encryption_algorithms": [
                    {"algorithm": "aes-256-gcm", "count": 6000, "percentage": 60.0},
                    {"algorithm": "chacha20-poly1305", "count": 3000, "percentage": 30.0},
                ],
                "hash_algorithms": [
                    {"algorithm": "sha512", "count": 8000, "percentage": 80.0},
                    {"algorithm": "blake2b", "count": 5000, "percentage": 50.0},
                ],
                "kdf_algorithms": [
                    {"algorithm": "argon2", "count": 7000, "percentage": 70.0},
                    {"algorithm": "scrypt", "count": 2000, "percentage": 20.0},
                ],
                "pqc_algorithms": [{"algorithm": "ML-KEM-768", "count": 500, "percentage": 5.0}],
                "format_versions": {8: 8000, 7: 1500, 6: 500},
                "success_rate": 0.985,
            }
        }
