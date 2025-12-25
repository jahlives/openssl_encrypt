#!/usr/bin/env python3
"""
Benchmark script for measuring hash and KDF operation performance.

This script measures the time and memory consumption of all hash algorithms
and KDF operations supported by openssl_encrypt. The results are used to
generate static benchmark constants for the decryption estimation system.

Usage:
    python -m openssl_encrypt.scripts.benchmark_operations

Output:
    Generates benchmark_constants.py with measured performance data
"""

import hashlib
import os
import platform
import sys
import time
import tracemalloc
from typing import Dict, Tuple

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import cryptography libraries
try:
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
except ImportError:
    print("Error: cryptography library not installed")
    sys.exit(1)

# Import argon2
try:
    import argon2

    ARGON2_AVAILABLE = True
except ImportError:
    ARGON2_AVAILABLE = False
    print("Warning: argon2-cffi not available, skipping Argon2 benchmark")

# Import optional libraries
try:
    import blake3

    BLAKE3_AVAILABLE = True
except ImportError:
    BLAKE3_AVAILABLE = False
    print("Warning: blake3 not available, will use fallback estimate")

try:
    import pywhirlpool

    WHIRLPOOL_AVAILABLE = True
except ImportError:
    WHIRLPOOL_AVAILABLE = False
    print("Warning: whirlpool not available, skipping Whirlpool benchmark")

try:
    from openssl_encrypt.modules.randomx import check_randomx_support, randomx_kdf

    RANDOMX_AVAILABLE = check_randomx_support()
    if not RANDOMX_AVAILABLE:
        print("Warning: RandomX library not installed, skipping RandomX benchmark")
except ImportError:
    RANDOMX_AVAILABLE = False
    print("Warning: RandomX module not available, skipping RandomX benchmark")

# Import local modules for KDF benchmarking
try:
    from openssl_encrypt.modules.balloon import balloon_m

    BALLOON_AVAILABLE = True
except ImportError:
    BALLOON_AVAILABLE = False
    print("Warning: Balloon KDF not available")


def benchmark_hash_algorithm(algo_name: str, hash_func, rounds: int = 10000) -> float:
    """
    Benchmark a hash algorithm for N rounds.

    Args:
        algo_name: Name of the algorithm
        hash_func: Hash function to benchmark
        rounds: Number of rounds to perform

    Returns:
        Time in seconds for the specified rounds
    """
    print(f"  Benchmarking {algo_name} for {rounds:,} rounds...", end=" ", flush=True)

    data = b"test_password_for_benchmarking_12345"

    start = time.perf_counter()
    result = data
    for _ in range(rounds):
        result = hash_func(result).digest()
    elapsed = time.perf_counter() - start

    print(f"{elapsed:.4f}s")
    return elapsed


def benchmark_kdf_with_memory(kdf_name: str, kdf_func, **kwargs) -> Tuple[float, int]:
    """
    Benchmark a KDF operation with memory tracking.

    Args:
        kdf_name: Name of the KDF
        kdf_func: KDF function to benchmark
        **kwargs: Parameters to pass to KDF function

    Returns:
        Tuple of (time_seconds, peak_memory_kb)
    """
    print(f"  Benchmarking {kdf_name}...", end=" ", flush=True)

    tracemalloc.start()
    start_memory = tracemalloc.get_traced_memory()[0]

    start = time.perf_counter()
    try:
        kdf_func(**kwargs)  # Execute KDF function
    except Exception as e:
        print(f"FAILED ({e})")
        tracemalloc.stop()
        return (0.0, 0)

    elapsed = time.perf_counter() - start
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    peak_memory_kb = (peak - start_memory) / 1024

    print(f"{elapsed:.4f}s, {peak_memory_kb:.1f} KB")
    return (elapsed, int(peak_memory_kb))


def benchmark_hash_algorithms() -> Dict[str, Dict]:
    """Benchmark all hash algorithms."""
    print("\n" + "=" * 60)
    print("BENCHMARKING HASH ALGORITHMS (per 10,000 rounds)")
    print("=" * 60)

    results = {}

    # SHA-2 family
    results["sha224"] = {"time_per_10k_rounds": benchmark_hash_algorithm("SHA-224", hashlib.sha224)}

    results["sha256"] = {"time_per_10k_rounds": benchmark_hash_algorithm("SHA-256", hashlib.sha256)}

    results["sha384"] = {"time_per_10k_rounds": benchmark_hash_algorithm("SHA-384", hashlib.sha384)}

    results["sha512"] = {"time_per_10k_rounds": benchmark_hash_algorithm("SHA-512", hashlib.sha512)}

    # SHA-3 family
    results["sha3_224"] = {
        "time_per_10k_rounds": benchmark_hash_algorithm("SHA3-224", hashlib.sha3_224)
    }

    results["sha3_256"] = {
        "time_per_10k_rounds": benchmark_hash_algorithm("SHA3-256", hashlib.sha3_256)
    }

    results["sha3_384"] = {
        "time_per_10k_rounds": benchmark_hash_algorithm("SHA3-384", hashlib.sha3_384)
    }

    results["sha3_512"] = {
        "time_per_10k_rounds": benchmark_hash_algorithm("SHA3-512", hashlib.sha3_512)
    }

    # BLAKE2b
    results["blake2b"] = {
        "time_per_10k_rounds": benchmark_hash_algorithm("BLAKE2b", hashlib.blake2b)
    }

    # BLAKE3
    if BLAKE3_AVAILABLE:

        def blake3_hash(data):
            return blake3.blake3(data)

        results["blake3"] = {"time_per_10k_rounds": benchmark_hash_algorithm("BLAKE3", blake3_hash)}
    else:
        # Fallback: BLAKE3 is typically ~20% faster than BLAKE2b
        results["blake3"] = {
            "time_per_10k_rounds": results["blake2b"]["time_per_10k_rounds"] * 0.8,
            "estimated": True,
        }
        print(f"  BLAKE3: {results['blake3']['time_per_10k_rounds']:.4f}s (estimated)")

    # SHAKE family (extendable-output functions)
    def shake128_hash(data):
        class ShakeWrapper:
            def __init__(self, h):
                self.h = h

            def digest(self):
                return self.h.digest(32)

        return ShakeWrapper(hashlib.shake_128(data))

    results["shake128"] = {
        "time_per_10k_rounds": benchmark_hash_algorithm("SHAKE-128", shake128_hash)
    }

    def shake256_hash(data):
        class ShakeWrapper:
            def __init__(self, h):
                self.h = h

            def digest(self):
                return self.h.digest(32)

        return ShakeWrapper(hashlib.shake_256(data))

    results["shake256"] = {
        "time_per_10k_rounds": benchmark_hash_algorithm("SHAKE-256", shake256_hash)
    }

    # Whirlpool (optional)
    if WHIRLPOOL_AVAILABLE:

        def whirlpool_hash(data):
            class WhirlpoolWrapper:
                def __init__(self, h):
                    self.h = h

                def digest(self):
                    return bytes.fromhex(self.h.hexdigest())

            return WhirlpoolWrapper(pywhirlpool.new(data))

        results["whirlpool"] = {
            "time_per_10k_rounds": benchmark_hash_algorithm("Whirlpool", whirlpool_hash),
            "optional": True,
        }

    return results


def benchmark_pbkdf2() -> Dict:
    """Benchmark PBKDF2 KDF."""
    print("\n  Benchmarking PBKDF2 (100,000 iterations)...")

    def pbkdf2_func():
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"salt" * 4,
            iterations=100000,
            backend=default_backend(),
        )
        return kdf.derive(b"password")

    time_sec, memory_kb = benchmark_kdf_with_memory("PBKDF2", pbkdf2_func)

    return {
        "time_per_100k_iterations": time_sec,
        "memory_kb": max(memory_kb, 512),  # Minimum estimate
    }


def benchmark_argon2() -> Dict:
    """Benchmark Argon2 KDF."""
    if not ARGON2_AVAILABLE:
        # Provide conservative fallback estimates
        return {
            "base_time": 0.250,
            "time_per_timecost": 0.083,
            "memory_per_kb": 1.0,
            "estimated": True,
        }

    print("\n  Benchmarking Argon2id...")

    def argon2_func():
        ph = argon2.PasswordHasher(
            time_cost=3,
            memory_cost=65536,  # 64 MB
            parallelism=4,
            hash_len=32,
            salt_len=16,
            type=argon2.Type.ID,
        )
        return ph.hash(b"password")

    base_time, base_memory = benchmark_kdf_with_memory("Argon2 (base)", argon2_func)

    # Benchmark with higher time_cost to measure scaling
    def argon2_func_higher():
        ph = argon2.PasswordHasher(
            time_cost=4,
            memory_cost=65536,
            parallelism=4,
            hash_len=32,
            salt_len=16,
            type=argon2.Type.ID,
        )
        return ph.hash(b"password")

    higher_time, _ = benchmark_kdf_with_memory("Argon2 (time_cost=4)", argon2_func_higher)

    time_per_timecost = higher_time - base_time

    return {
        "base_time": base_time,
        "time_per_timecost": time_per_timecost,
        "memory_per_kb": 1.0,  # Memory directly corresponds to memory_cost parameter
    }


def benchmark_scrypt() -> Dict:
    """Benchmark Scrypt KDF."""
    print("\n  Benchmarking Scrypt...")

    def scrypt_func():
        return hashlib.scrypt(
            password=b"password",
            salt=b"salt" * 4,
            n=16384,
            r=8,
            p=1,
            maxmem=128 * 1024 * 1024,  # 128 MB
            dklen=32,
        )

    time_sec, memory_kb = benchmark_kdf_with_memory("Scrypt (n=16384)", scrypt_func)

    # Benchmark with n=32768 to measure scaling
    def scrypt_func_double():
        return hashlib.scrypt(
            password=b"password",
            salt=b"salt" * 4,
            n=32768,
            r=8,
            p=1,
            maxmem=256 * 1024 * 1024,
            dklen=32,
        )

    time_double, memory_double = benchmark_kdf_with_memory("Scrypt (n=32768)", scrypt_func_double)

    time_multiplier = time_double / time_sec if time_sec > 0 else 2.0

    return {
        "time_n_16384": time_sec,
        "time_multiplier_per_doubling": time_multiplier,
        "memory_per_n": memory_kb * 1024 // 16384,  # Memory in KB per n value
    }


def benchmark_balloon() -> Dict:
    """Benchmark Balloon KDF using balloon_m (parallel variant used in actual code)."""
    if not BALLOON_AVAILABLE:
        return {
            "time_per_round": 8.0,  # Conservative fallback based on user feedback
            "memory_per_space_cost": 1024,
            "estimated": True,
        }

    print("\n  Benchmarking Balloon (balloon_m with parallel_cost=4)...")

    def balloon_func():
        return balloon_m(
            password="password",
            salt="salt" * 4,
            space_cost=16,  # Default from config
            time_cost=20,  # Default from config
            parallel_cost=4,  # Default from config (this makes it MUCH slower!)
            delta=3,  # Default from balloon_m signature
        )

    time_sec, memory_kb = benchmark_kdf_with_memory("Balloon_m", balloon_func)

    # Calculate memory per space_cost unit (space_cost=16 was used)
    # With parallel_cost=4, memory is multiplied by number of parallel instances
    # Each instance uses space_cost * hash_size bytes
    memory_per_space_cost = max(int(memory_kb / 16), 32) if memory_kb > 0 else 32

    return {"time_per_round": time_sec, "memory_per_space_cost": memory_per_space_cost}


def benchmark_hkdf() -> Dict:
    """Benchmark HKDF KDF."""
    print("\n  Benchmarking HKDF...")

    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    def hkdf_func():
        kdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"salt" * 4,
            info=b"openssl_encrypt_hkdf",
            backend=default_backend(),
        )
        return kdf.derive(b"password")

    time_sec, memory_kb = benchmark_kdf_with_memory("HKDF", hkdf_func)

    return {"time_per_round": time_sec, "memory_kb": max(memory_kb, 128)}


def benchmark_randomx() -> Dict:
    """Benchmark RandomX KDF."""
    if not RANDOMX_AVAILABLE:
        return {
            "light": {"time_per_round": 0.525, "memory_kb": 262144},
            "fast": {"time_per_round": 2.340, "memory_kb": 2097152},
            "optional": True,
            "estimated": True,
        }

    print("\n  Benchmarking RandomX...")

    # Light mode
    def randomx_light_func():
        return randomx_kdf(password=b"password", salt=b"salt" * 4, mode="light", rounds=1)

    light_time, light_memory = benchmark_kdf_with_memory("RandomX (light)", randomx_light_func)

    # Fast mode (if memory available)
    def randomx_fast_func():
        return randomx_kdf(password=b"password", salt=b"salt" * 4, mode="fast", rounds=1)

    try:
        fast_time, fast_memory = benchmark_kdf_with_memory("RandomX (fast)", randomx_fast_func)
    except Exception:  # Fallback if fast mode fails (e.g., insufficient memory)
        fast_time, fast_memory = light_time * 4, 2097152  # Estimate

    return {
        "light": {"time_per_round": light_time, "memory_kb": max(light_memory, 262144)},
        "fast": {"time_per_round": fast_time, "memory_kb": max(fast_memory, 2097152)},
        "optional": True,
    }


def benchmark_kdf_operations() -> Dict[str, Dict]:
    """Benchmark all KDF operations."""
    print("\n" + "=" * 60)
    print("BENCHMARKING KDF OPERATIONS")
    print("=" * 60)

    results = {}

    results["pbkdf2"] = benchmark_pbkdf2()
    results["argon2"] = benchmark_argon2()
    results["scrypt"] = benchmark_scrypt()
    results["balloon"] = benchmark_balloon()
    results["hkdf"] = benchmark_hkdf()
    results["randomx"] = benchmark_randomx()

    return results


def get_system_info() -> Dict[str, str]:
    """Collect system information."""
    return {
        "cpu": platform.processor() or platform.machine(),
        "python_version": platform.python_version(),
        "platform": platform.platform(),
        "measured_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }


def generate_constants_file(hash_results: Dict, kdf_results: Dict, system_info: Dict):
    """Generate benchmark_constants.py file with results."""
    output_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "modules",
        "benchmark_constants.py",
    )

    print("\n" + "=" * 60)
    print(f"GENERATING: {output_path}")
    print("=" * 60)

    with open(output_path, "w") as f:
        f.write('"""\n')
        f.write("Static benchmark data for decryption estimation system.\n")
        f.write("\n")
        f.write("This file is AUTO-GENERATED by scripts/benchmark_operations.py\n")
        f.write("Do not edit manually.\n")
        f.write("\n")
        for key, value in system_info.items():
            f.write(f"{key}: {value}\n")
        f.write('"""\n\n')

        # Hash algorithms
        f.write("HASH_BENCHMARK_DATA = {\n")
        for algo_name, data in sorted(hash_results.items()):
            f.write(f'    "{algo_name}": {{\n')
            for key, value in data.items():
                if isinstance(value, bool):
                    f.write(f'        "{key}": {value},\n')
                elif isinstance(value, (int, float)):
                    f.write(f'        "{key}": {value},\n')
            f.write("    },\n")
        f.write("}\n\n")

        # KDF operations
        f.write("KDF_BENCHMARK_DATA = {\n")
        for kdf_name, data in sorted(kdf_results.items()):
            f.write(f'    "{kdf_name}": {{\n')
            for key, value in data.items():
                if isinstance(value, bool):
                    f.write(f'        "{key}": {value},\n')
                elif isinstance(value, dict):
                    f.write(f'        "{key}": {{\n')
                    for sub_key, sub_value in value.items():
                        if isinstance(sub_value, bool):
                            f.write(f'            "{sub_key}": {sub_value},\n')
                        else:
                            f.write(f'            "{sub_key}": {sub_value},\n')
                    f.write("        },\n")
                else:
                    f.write(f'        "{key}": {value},\n')
            f.write("    },\n")
        f.write("}\n\n")

        # Warning thresholds
        f.write("# Thresholds for warnings\n")
        f.write("WARNING_THRESHOLDS = {\n")
        f.write('    "time_seconds": 10,\n')
        f.write('    "memory_kb": 1048576  # 1GB\n')
        f.write("}\n")

    print(f"✓ Generated {output_path}")


def main():
    """Main benchmarking function."""
    print("=" * 60)
    print("OpenSSL Encrypt - Performance Benchmarking Script")
    print("=" * 60)
    print("\nThis script will measure the performance of all hash algorithms")
    print("and KDF operations. Results will be saved to benchmark_constants.py")
    print("\nPress Ctrl+C to cancel.\n")

    try:
        time.sleep(2)
    except KeyboardInterrupt:
        print("\nCancelled.")
        sys.exit(0)

    # Collect system info
    system_info = get_system_info()
    print(f"\nSystem: {system_info['platform']}")
    print(f"CPU: {system_info['cpu']}")
    print(f"Python: {system_info['python_version']}")

    # Run benchmarks
    hash_results = benchmark_hash_algorithms()
    kdf_results = benchmark_kdf_operations()

    # Generate output file
    generate_constants_file(hash_results, kdf_results, system_info)

    print("\n" + "=" * 60)
    print("BENCHMARKING COMPLETE")
    print("=" * 60)
    print("\nNext steps:")
    print("1. Review generated benchmark_constants.py")
    print("2. Implement decryption_estimator.py module")
    print("3. Integrate into crypt_core.py")


if __name__ == "__main__":
    main()
