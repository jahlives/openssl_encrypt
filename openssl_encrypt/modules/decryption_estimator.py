"""
Decryption time and memory estimation module.

This module provides functionality to estimate the computational cost (time and memory)
of decryption operations based on metadata configuration. This helps detect potential
DoS attacks where malicious actors inflate metadata values to overwhelm the system.
"""

from typing import Dict, List, Tuple

try:
    from .benchmark_constants import HASH_BENCHMARK_DATA, KDF_BENCHMARK_DATA, WARNING_THRESHOLDS
except ImportError:
    # Fallback if benchmark_constants.py doesn't exist yet
    HASH_BENCHMARK_DATA = {}
    KDF_BENCHMARK_DATA = {}
    WARNING_THRESHOLDS = {"time_seconds": 10, "memory_kb": 1048576}


class DecryptionEstimate:
    """Container for estimation results with breakdown and warnings."""

    def __init__(self):
        """Initialize empty estimate."""
        self.total_time_seconds = 0.0
        self.peak_memory_kb = 0
        self.breakdown: List[Tuple[str, float, int]] = []  # (name, time, memory)
        self.warnings: List[str] = []

    def add_operation(self, name: str, time_sec: float, memory_kb: int):
        """
        Add an operation to the estimate.

        Args:
            name: Human-readable operation name
            time_sec: Estimated time in seconds
            memory_kb: Estimated memory in kilobytes
        """
        self.total_time_seconds += time_sec
        self.peak_memory_kb = max(self.peak_memory_kb, memory_kb)
        self.breakdown.append((name, time_sec, memory_kb))

    def exceeds_thresholds(self) -> bool:
        """
        Check if estimate exceeds warning thresholds.

        Returns:
            True if time or memory exceeds thresholds
        """
        return (
            self.total_time_seconds > WARNING_THRESHOLDS["time_seconds"]
            or self.peak_memory_kb > WARNING_THRESHOLDS["memory_kb"]
        )


def estimate_hash_operation(algo_name: str, rounds: int) -> Tuple[float, int]:
    """
    Estimate time and memory for a hash operation.

    Args:
        algo_name: Name of hash algorithm (e.g., "sha256", "blake2b")
        rounds: Number of rounds to perform

    Returns:
        Tuple of (time_seconds, memory_kb)
    """
    if rounds == 0:
        return (0.0, 0)

    # Normalize algorithm name (handle variations)
    algo_name = algo_name.lower().replace("-", "_").replace("sha3", "sha3")

    if algo_name not in HASH_BENCHMARK_DATA:
        # Unknown algorithm, return minimal estimate
        return (0.0, 64)

    bench = HASH_BENCHMARK_DATA[algo_name]
    time_per_10k = bench.get("time_per_10k_rounds", 0.01)

    # Scale from benchmark (per 10k rounds) to actual rounds
    estimated_time = (rounds / 10000.0) * time_per_10k

    # Hash operations use minimal memory (just for hash state)
    memory_kb = 64

    return (estimated_time, memory_kb)


def estimate_pbkdf2(config: Dict) -> Tuple[float, int]:
    """
    Estimate PBKDF2 KDF operation.

    Args:
        config: PBKDF2 configuration dictionary

    Returns:
        Tuple of (time_seconds, memory_kb)
    """
    rounds = config.get("rounds", 0)
    if rounds == 0:
        return (0.0, 0)

    bench = KDF_BENCHMARK_DATA.get("pbkdf2", {})
    time_per_100k = bench.get("time_per_100k_iterations", 0.03)
    memory_kb = bench.get("memory_kb", 512)

    time_seconds = (rounds / 100000.0) * time_per_100k

    return (time_seconds, memory_kb)


def estimate_argon2(config: Dict) -> Tuple[float, int]:
    """
    Estimate Argon2 KDF operation.

    Args:
        config: Argon2 configuration dictionary

    Returns:
        Tuple of (time_seconds, memory_kb)
    """
    if not config.get("enabled", False):
        return (0.0, 0)

    rounds = config.get("rounds", 1)
    time_cost = config.get("time_cost", 3)
    memory_cost = config.get("memory_cost", 65536)  # in KB

    bench = KDF_BENCHMARK_DATA.get("argon2", {})
    base_time = bench.get("base_time", 0.037)
    time_per_timecost = bench.get("time_per_timecost", 0.007)

    # Time estimate: base time + additional time per time_cost unit above 3
    time_per_round = base_time + max(0, time_cost - 3) * time_per_timecost
    time_seconds = rounds * time_per_round

    # Memory is directly the memory_cost parameter
    memory_kb = memory_cost

    return (time_seconds, memory_kb)


def estimate_scrypt(config: Dict) -> Tuple[float, int]:
    """
    Estimate Scrypt KDF operation.

    Args:
        config: Scrypt configuration dictionary

    Returns:
        Tuple of (time_seconds, memory_kb)
    """
    if not config.get("enabled", False):
        return (0.0, 0)

    rounds = config.get("rounds", 1)
    n = config.get("n", 16384)

    bench = KDF_BENCHMARK_DATA.get("scrypt", {})
    time_n_16384 = bench.get("time_n_16384", 0.03)
    time_multiplier = bench.get("time_multiplier_per_doubling", 2.0)
    memory_per_n = bench.get("memory_per_n", 128)

    # Time scales exponentially with n (doubling n ~doubles time)
    # Calculate how many doublings from base n=16384
    if n <= 0:
        return (0.0, 0)

    doublings = max(0, (n // 16384).bit_length() - 1)
    time_per_round = time_n_16384 * (time_multiplier**doublings)
    time_seconds = rounds * time_per_round

    # Memory scales with n
    memory_kb = (n * memory_per_n) // 1024

    return (time_seconds, memory_kb)


def estimate_balloon(config: Dict) -> Tuple[float, int]:
    """
    Estimate Balloon KDF operation.

    Args:
        config: Balloon configuration dictionary

    Returns:
        Tuple of (time_seconds, memory_kb)
    """
    if not config.get("enabled", False):
        return (0.0, 0)

    rounds = config.get("rounds", 1)
    space_cost = config.get("space_cost", 16)
    time_cost = config.get("time_cost", 20)

    bench = KDF_BENCHMARK_DATA.get("balloon", {})
    base_time = bench.get("time_per_round", 0.045)
    memory_per_space_cost = bench.get("memory_per_space_cost", 32)

    # Balloon time complexity is theoretically O(space_cost * time_cost)
    # However, in practice, large space_cost values exhibit sublinear scaling
    # due to memory access patterns and caching effects.
    # Benchmark used: space_cost=16, time_cost=20, parallel_cost=4
    #
    # Use power scaling for space_cost: time ∝ space_cost^0.85
    # This provides accurate estimates for large space_cost values
    # (empirically validated: 3.7% error for space_cost=65536)
    space_scale = (space_cost / 16) ** 0.85
    time_scale = time_cost / 20

    # Total time scales with both space_cost and time_cost
    time_per_round = base_time * space_scale * time_scale
    time_seconds = rounds * time_per_round

    memory_kb = space_cost * memory_per_space_cost

    return (time_seconds, memory_kb)


def estimate_hkdf(config: Dict) -> Tuple[float, int]:
    """
    Estimate HKDF KDF operation.

    Args:
        config: HKDF configuration dictionary

    Returns:
        Tuple of (time_seconds, memory_kb)
    """
    if not config.get("enabled", False):
        return (0.0, 0)

    rounds = config.get("rounds", 1)

    bench = KDF_BENCHMARK_DATA.get("hkdf", {})
    time_per_round = bench.get("time_per_round", 0.0001)
    memory_kb = bench.get("memory_kb", 128)

    time_seconds = rounds * time_per_round

    return (time_seconds, memory_kb)


def estimate_randomx(config: Dict) -> Tuple[float, int]:
    """
    Estimate RandomX KDF operation.

    Args:
        config: RandomX configuration dictionary

    Returns:
        Tuple of (time_seconds, memory_kb)
    """
    if not config.get("enabled", False):
        return (0.0, 0)

    rounds = config.get("rounds", 1)
    mode = config.get("mode", "light")

    randomx_bench = KDF_BENCHMARK_DATA.get("randomx", {})

    # Check if RandomX is available or use fallback
    if randomx_bench.get("optional") and randomx_bench.get("estimated"):
        # Use fallback estimates
        mode_bench = randomx_bench.get(mode, randomx_bench.get("light", {}))
    else:
        mode_bench = randomx_bench.get(mode, {})

    time_per_round = mode_bench.get("time_per_round", 0.5 if mode == "light" else 2.0)
    memory_kb = mode_bench.get("memory_kb", 262144 if mode == "light" else 2097152)

    time_seconds = rounds * time_per_round

    return (time_seconds, memory_kb)


def estimate_decryption_cost(metadata: Dict) -> DecryptionEstimate:
    """
    Calculate time and memory estimates from encrypted file metadata.

    This is the main estimation function that parses metadata and calculates
    total computational cost by analyzing hash chains and KDF operations.

    Args:
        metadata: Parsed metadata dictionary from encrypted file

    Returns:
        DecryptionEstimate object with breakdown and warnings
    """
    estimate = DecryptionEstimate()

    # Extract derivation_config (v5/v6) or fall back to root level (v3)
    format_version = metadata.get("format_version", 3)

    if format_version >= 4:
        # Modern format (v4, v5, v6)
        derivation_config = metadata.get("derivation_config", {})
        hash_config = derivation_config.get("hash_config", {})
        kdf_config = derivation_config.get("kdf_config", {})
    else:
        # Legacy v3 format
        hash_config = metadata.get("hash_config", {})
        kdf_config = {}

        # PBKDF2 stored at root level in v3
        pbkdf2_iterations = metadata.get("pbkdf2_iterations", 0)
        if pbkdf2_iterations > 0:
            kdf_config["pbkdf2"] = {"rounds": pbkdf2_iterations}

    # Phase 1: Hash Chain Operations
    for algo_name, algo_config in hash_config.items():
        if isinstance(algo_config, dict):
            rounds = algo_config.get("rounds", 0)
        else:
            # Legacy format: direct integer value
            rounds = algo_config if isinstance(algo_config, int) else 0

        if rounds > 0:
            time_sec, memory_kb = estimate_hash_operation(algo_name, rounds)
            estimate.add_operation(
                f"Hash: {algo_name.upper()} ({rounds:,} rounds)", time_sec, memory_kb
            )

    # Phase 2: KDF Operations
    kdf_estimators = {
        "pbkdf2": estimate_pbkdf2,
        "argon2": estimate_argon2,
        "scrypt": estimate_scrypt,
        "balloon": estimate_balloon,
        "hkdf": estimate_hkdf,
        "randomx": estimate_randomx,
    }

    for kdf_name, estimator_func in kdf_estimators.items():
        if kdf_name in kdf_config:
            time_sec, memory_kb = estimator_func(kdf_config[kdf_name])
            if time_sec > 0:
                config = kdf_config[kdf_name]
                rounds = config.get("rounds", 1)
                estimate.add_operation(
                    f"KDF: {kdf_name.upper()} ({rounds} rounds)", time_sec, memory_kb
                )

    # Generate warnings if thresholds exceeded
    if estimate.exceeds_thresholds():
        estimate.warnings.append(
            "⚠️  WARNING: Estimated decryption time or memory exceeds safe thresholds!"
        )
        estimate.warnings.append(
            "⚠️  This may indicate malicious metadata designed to DoS your system."
        )

        if estimate.total_time_seconds > WARNING_THRESHOLDS["time_seconds"]:
            threshold = WARNING_THRESHOLDS["time_seconds"]
            estimate.warnings.append(
                f"⚠️  Time: {estimate.total_time_seconds:.1f}s " f"(threshold: {threshold}s)"
            )

        if estimate.peak_memory_kb > WARNING_THRESHOLDS["memory_kb"]:
            mb = estimate.peak_memory_kb / 1024
            threshold_mb = WARNING_THRESHOLDS["memory_kb"] / 1024
            estimate.warnings.append(f"⚠️  Memory: {mb:.0f} MB (threshold: {threshold_mb:.0f} MB)")

    return estimate


def format_time(seconds: float) -> str:
    """
    Format time duration in human-readable format.

    Args:
        seconds: Time in seconds

    Returns:
        Formatted string (e.g., "250ms", "1.5s", "2m 30s")
    """
    if seconds < 1.0:
        return f"{seconds*1000:.0f}ms"
    elif seconds < 60:
        return f"{seconds:.1f}s"
    else:
        minutes = int(seconds // 60)
        secs = seconds % 60
        return f"{minutes}m {secs:.0f}s"


def format_memory(kb: int) -> str:
    """
    Format memory size in human-readable format.

    Args:
        kb: Memory in kilobytes

    Returns:
        Formatted string (e.g., "512 KB", "64.5 MB", "2.00 GB")
    """
    if kb < 1024:
        return f"{kb} KB"
    elif kb < 1024 * 1024:
        return f"{kb/1024:.1f} MB"
    else:
        return f"{kb/(1024*1024):.2f} GB"
