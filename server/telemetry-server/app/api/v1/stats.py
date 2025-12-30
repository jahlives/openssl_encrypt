#!/usr/bin/env python3
"""
Statistics API - Public telemetry statistics.
"""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from ...database import get_db
from ...schemas import StatisticsResponse
from ...services import StatsService, TelemetryService

router = APIRouter()


@router.get("/stats", response_model=StatisticsResponse, status_code=200)
def get_public_statistics(db: Session = Depends(get_db)):
    """
    Get public telemetry statistics.

    PUBLIC ENDPOINT (no authentication required).

    Returns:
        StatisticsResponse: Aggregated statistics
    """
    # Get total operations
    total_operations = TelemetryService.get_total_operations(db)

    # Get unique client count
    total_clients = StatsService.get_unique_client_count(db)

    # Get algorithm statistics
    modes = StatsService.get_algorithm_stats(db, "mode")
    encryption_algorithms = StatsService.get_algorithm_stats(db, "encryption_algorithm")
    hash_algorithms = StatsService.get_array_field_stats(db, "hash_algorithms")
    kdf_algorithms = StatsService.get_array_field_stats(db, "kdf_algorithms")
    pqc_algorithms = StatsService.get_pqc_stats(db)

    # Get format version counts
    format_versions = StatsService.get_format_version_counts(db)

    # Get success rate
    success_rate = TelemetryService.get_success_rate(db)

    return StatisticsResponse(
        total_operations=total_operations,
        total_clients=total_clients,
        modes=modes,
        encryption_algorithms=encryption_algorithms,
        hash_algorithms=hash_algorithms,
        kdf_algorithms=kdf_algorithms,
        pqc_algorithms=pqc_algorithms,
        format_versions=format_versions,
        success_rate=success_rate,
    )
