#!/usr/bin/env python3
"""
Statistics Service - Aggregates and provides telemetry statistics.
"""

import json
from collections import Counter
from typing import Dict, List

from sqlalchemy import func
from sqlalchemy.orm import Session

from ..models import APIKey, TelemetryRaw
from ..schemas import AlgorithmStat


class StatsService:
    """Service for statistics aggregation."""

    @staticmethod
    def get_algorithm_stats(db: Session, field: str, top_n: int = 10) -> List[AlgorithmStat]:
        """
        Gets top N algorithm statistics for a field.

        Args:
            db: Database session
            field: Field name (encryption_algorithm, etc.)
            top_n: Number of top items to return

        Returns:
            List[AlgorithmStat]: Algorithm statistics
        """
        total = db.query(TelemetryRaw).count()
        if total == 0:
            return []

        # Query field counts
        results = (
            db.query(getattr(TelemetryRaw, field), func.count(TelemetryRaw.id))
            .group_by(getattr(TelemetryRaw, field))
            .order_by(func.count(TelemetryRaw.id).desc())
            .limit(top_n)
            .all()
        )

        stats = []
        for algorithm, count in results:
            if algorithm:  # Skip None values
                stats.append(
                    AlgorithmStat(
                        algorithm=algorithm, count=count, percentage=round(count / total * 100, 2)
                    )
                )

        return stats

    @staticmethod
    def get_array_field_stats(db: Session, field: str, top_n: int = 10) -> List[AlgorithmStat]:
        """
        Gets statistics for JSON array fields (hash_algorithms, kdf_algorithms).

        Args:
            db: Database session
            field: Field name
            top_n: Number of top items to return

        Returns:
            List[AlgorithmStat]: Algorithm statistics
        """
        # Get all records
        records = db.query(getattr(TelemetryRaw, field)).all()

        # Count algorithms across all records
        counter = Counter()
        for (json_str,) in records:
            try:
                algorithms = json.loads(json_str) if json_str else []
                counter.update(algorithms)
            except (json.JSONDecodeError, TypeError):
                continue

        total_uses = sum(counter.values())
        if total_uses == 0:
            return []

        # Get top N
        stats = []
        for algorithm, count in counter.most_common(top_n):
            stats.append(
                AlgorithmStat(
                    algorithm=algorithm,
                    count=count,
                    percentage=round(count / total_uses * 100, 2),
                )
            )

        return stats

    @staticmethod
    def get_pqc_stats(db: Session) -> List[AlgorithmStat]:
        """
        Gets PQC algorithm statistics (combines KEM and signing).

        Args:
            db: Database session

        Returns:
            List[AlgorithmStat]: PQC algorithm statistics
        """
        total = db.query(TelemetryRaw).count()
        if total == 0:
            return []

        # Count KEM algorithms
        kem_results = (
            db.query(TelemetryRaw.pqc_kem_algorithm, func.count(TelemetryRaw.id))
            .filter(TelemetryRaw.pqc_kem_algorithm.isnot(None))
            .group_by(TelemetryRaw.pqc_kem_algorithm)
            .all()
        )

        # Count signing algorithms
        sign_results = (
            db.query(TelemetryRaw.pqc_signing_algorithm, func.count(TelemetryRaw.id))
            .filter(TelemetryRaw.pqc_signing_algorithm.isnot(None))
            .group_by(TelemetryRaw.pqc_signing_algorithm)
            .all()
        )

        # Combine counts
        counter = Counter()
        for algorithm, count in kem_results:
            counter[algorithm] += count
        for algorithm, count in sign_results:
            counter[algorithm] += count

        # Convert to stats
        stats = []
        for algorithm, count in counter.most_common():
            stats.append(
                AlgorithmStat(
                    algorithm=algorithm, count=count, percentage=round(count / total * 100, 2)
                )
            )

        return stats

    @staticmethod
    def get_format_version_counts(db: Session) -> Dict[int, int]:
        """
        Gets format version counts.

        Args:
            db: Database session

        Returns:
            Dict[int, int]: Format version -> count mapping
        """
        results = (
            db.query(TelemetryRaw.format_version, func.count(TelemetryRaw.id))
            .group_by(TelemetryRaw.format_version)
            .all()
        )

        return {version: count for version, count in results}

    @staticmethod
    def get_unique_client_count(db: Session) -> int:
        """
        Gets count of unique clients (anonymized).

        Args:
            db: Database session

        Returns:
            int: Count of unique API keys (proxy for clients)
        """
        return db.query(APIKey).count()
