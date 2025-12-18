#!/usr/bin/env python3
"""
RandomX Key Derivation Function Implementation

This module provides RandomX-based key derivation functionality for the
OpenSSL Encrypt tool. RandomX is a proof-of-work algorithm optimized for
general-purpose CPUs with memory-hard properties.

RandomX operates in two modes:
- Light mode: 256MB RAM, slower performance
- Fast mode: 2GB RAM, faster performance
"""

import hashlib
import logging
import secrets
from typing import Optional

# Set up module-level logger
logger = logging.getLogger(__name__)


# Safely test RandomX import to avoid illegal instruction crashes
def _test_randomx_import():
    """Test if RandomX can be imported without causing illegal instruction errors."""
    import subprocess
    import sys

    try:
        # Test RandomX import in a subprocess to catch fatal errors
        result = subprocess.run(
            [sys.executable, "-c", 'import randomx; print("SUCCESS")'],
            capture_output=True,
            text=True,
            timeout=10,
        )

        return result.returncode == 0 and "SUCCESS" in result.stdout
    except (subprocess.TimeoutExpired, subprocess.SubprocessError, FileNotFoundError):
        return False


def _test_pyrx_import():
    """Test if pyrx can be imported without causing illegal instruction errors."""
    import subprocess
    import sys

    try:
        # Test pyrx import in a subprocess to catch fatal errors
        result = subprocess.run(
            [sys.executable, "-c", 'import pyrx; print("SUCCESS")'],
            capture_output=True,
            text=True,
            timeout=10,
        )

        return result.returncode == 0 and "SUCCESS" in result.stdout
    except (subprocess.TimeoutExpired, subprocess.SubprocessError, FileNotFoundError):
        return False


# Try to import RandomX library (try RandomX package first, then pyrx as fallback)
try:
    # First test if RandomX import is safe
    if _test_randomx_import():
        import randomx

        RANDOMX_AVAILABLE = True
        RANDOMX_LIBRARY = "randomx"
        logger.info("RandomX library loaded successfully")
    else:
        raise ImportError("RandomX import test failed - likely CPU incompatibility")
except (ImportError, SystemError, OSError, Exception) as e:
    logger.warning(f"RandomX import failed: {e}")
    try:
        # Test if pyrx import is safe before attempting it
        if _test_pyrx_import():
            import pyrx

            # Check if this is the correct RandomX pyrx library (not the schema validator)
            if hasattr(pyrx, "get_rx_hash"):
                randomx = pyrx  # Use pyrx as randomx for compatibility
                RANDOMX_AVAILABLE = True
                RANDOMX_LIBRARY = "pyrx"
                logger.info("RandomX (pyrx) library loaded successfully")
            else:
                RANDOMX_AVAILABLE = False
                RANDOMX_LIBRARY = None
                randomx = None
                logger.warning(
                    "Wrong pyrx library detected (schema validator instead of RandomX). "
                    "Install correct RandomX: pip install RandomX"
                )
        else:
            raise ImportError("pyrx import test failed - likely CPU incompatibility")
    except (ImportError, SystemError, OSError, Exception) as e:
        RANDOMX_AVAILABLE = False
        RANDOMX_LIBRARY = None
        randomx = None
        logger.warning(f"RandomX library not available or incompatible with CPU architecture: {e}")
        logger.warning("Install with: pip install RandomX")

# RandomX mode configurations
RANDOMX_MODES = {
    "light": {"memory_mb": 256, "description": "Low memory usage (256MB), slower performance"},
    "fast": {"memory_mb": 2080, "description": "High memory usage (2GB), faster performance"},
}

# Default configuration
DEFAULT_RANDOMX_CONFIG = {
    "enabled": False,
    "rounds": 1,
    "mode": "light",
    "height": 1,
    "hash_len": 32,
}


def check_randomx_support() -> bool:
    """
    Check if RandomX is available and functional.

    Returns:
        bool: True if RandomX is available, False otherwise
    """
    return RANDOMX_AVAILABLE


def get_randomx_memory_requirement(mode: str) -> int:
    """
    Get memory requirement in MB for specified RandomX mode.

    Args:
        mode: RandomX mode ('light' or 'fast')

    Returns:
        int: Memory requirement in MB

    Raises:
        ValueError: If mode is invalid
    """
    if mode not in RANDOMX_MODES:
        raise ValueError(f"Invalid RandomX mode: {mode}. Use 'light' or 'fast'")
    return RANDOMX_MODES[mode]["memory_mb"]


def get_randomx_mode_description(mode: str) -> str:
    """
    Get description for specified RandomX mode.

    Args:
        mode: RandomX mode ('light' or 'fast')

    Returns:
        str: Mode description

    Raises:
        ValueError: If mode is invalid
    """
    if mode not in RANDOMX_MODES:
        raise ValueError(f"Invalid RandomX mode: {mode}. Use 'light' or 'fast'")
    return RANDOMX_MODES[mode]["description"]


def get_randomx_config() -> dict:
    """
    Get default RandomX configuration.

    Returns:
        dict: Default RandomX configuration
    """
    return DEFAULT_RANDOMX_CONFIG.copy()


def _generate_seed_hash(salt: bytes, round_num: int) -> bytes:
    """
    Generate a seed hash for RandomX based on salt and round number.

    Args:
        salt: Salt bytes
        round_num: Current round number

    Returns:
        bytes: 32-byte seed hash for RandomX
    """
    # Create a unique seed by combining salt with round number
    round_bytes = round_num.to_bytes(4, "little")
    combined = salt + round_bytes + b"randomx_kdf_seed"
    return hashlib.sha256(combined).digest()


def randomx_kdf(
    password: bytes,
    salt: bytes,
    rounds: int = 1,
    mode: str = "light",
    height: int = 1,
    hash_len: int = 32,
) -> bytes:
    """
    RandomX-based key derivation function with dynamic salt generation.

    This function implements RandomX KDF with the following salt strategy:
    - Round 1: Use initial salt (from previous KDF in chain)
    - Round 2+: Use hash output from previous round as salt

    Args:
        password: Input password/key material
        salt: Initial salt (from previous KDF in chain)
        rounds: Number of RandomX rounds (default: 1)
        mode: 'light' (256MB) or 'fast' (2GB) mode (default: 'light')
        height: RandomX block height parameter (default: 1)
        hash_len: Output hash length in bytes (default: 32)

    Returns:
        bytes: Derived key of specified length

    Raises:
        ImportError: If RandomX (pyrx) is not available
        ValueError: If parameters are invalid
        RuntimeError: If RandomX operation fails
    """
    if not RANDOMX_AVAILABLE:
        raise ImportError("RandomX (pyrx) library not available. Install with: pip install pyrx")

    # Validate parameters
    if not isinstance(password, bytes):
        raise ValueError("Password must be bytes")
    if not isinstance(salt, bytes):
        raise ValueError("Salt must be bytes")
    if rounds < 1:
        raise ValueError("Rounds must be >= 1")
    if mode not in RANDOMX_MODES:
        raise ValueError(f"Invalid mode: {mode}. Use 'light' or 'fast'")
    if height < 1:
        raise ValueError("Height must be >= 1")
    if hash_len < 1 or hash_len > 256:
        raise ValueError("Hash length must be between 1 and 256 bytes")

    logger.info(
        f"RandomX KDF: {rounds} rounds in {mode} mode "
        f"({get_randomx_memory_requirement(mode)}MB RAM)"
    )

    current_hash = password
    current_salt = salt

    try:
        for round_num in range(rounds):
            if round_num == 0:
                # First round: use initial salt from KDF chain
                salt_for_round = current_salt
            else:
                # Subsequent rounds: use previous hash as salt
                salt_for_round = current_hash

            # Generate seed hash for RandomX
            seed_hash = _generate_seed_hash(salt_for_round, round_num)

            # Generate RandomX hash for this round
            try:
                if RANDOMX_LIBRARY == "randomx":
                    # Using RandomX package from PyPI
                    vm = randomx.RandomX(seed_hash, full_mem=(mode == "fast"))
                    current_hash = vm.calculate_hash(current_hash)
                else:
                    # Using pyrx library (fallback)
                    # Note: pyrx.get_rx_hash takes (message, seed_hash, height) parameters
                    current_hash = randomx.get_rx_hash(
                        current_hash, seed_hash, height  # message  # seed_hash  # height
                    )
            except Exception as e:
                logger.error(f"RandomX hash generation failed in round {round_num + 1}: {e}")
                raise RuntimeError(f"RandomX operation failed: {e}")

            logger.debug(f"RandomX round {round_num + 1}/{rounds} completed")

    except Exception as e:
        logger.error(f"RandomX KDF failed: {e}")
        raise RuntimeError(f"RandomX KDF operation failed: {e}")

    # Return truncated hash of requested length
    result = current_hash[:hash_len]
    logger.info(f"RandomX KDF completed successfully, output length: {len(result)} bytes")

    return result


def verify_randomx_kdf(
    password: bytes,
    salt: bytes,
    expected_hash: bytes,
    rounds: int = 1,
    mode: str = "light",
    height: int = 1,
) -> bool:
    """
    Verify a password against a RandomX KDF hash.

    Args:
        password: Input password to verify
        salt: Salt used for original hash
        expected_hash: Expected hash result
        rounds: Number of RandomX rounds used
        mode: RandomX mode used ('light' or 'fast')
        height: RandomX height parameter used

    Returns:
        bool: True if password matches, False otherwise
    """
    try:
        # Import secure comparison from secure_ops if available
        try:
            from .secure_ops import verify_mac

            use_secure_compare = True
        except ImportError:
            # Fallback to basic comparison
            import hmac

            use_secure_compare = False

        # Generate hash with same parameters
        computed_hash = randomx_kdf(
            password=password,
            salt=salt,
            rounds=rounds,
            mode=mode,
            height=height,
            hash_len=len(expected_hash),
        )

        # Secure comparison to prevent timing attacks
        if use_secure_compare:
            return verify_mac(expected_hash, computed_hash)
        else:
            return hmac.compare_digest(expected_hash, computed_hash)

    except Exception as e:
        logger.error(f"RandomX verification failed: {e}")
        return False


def get_randomx_info() -> dict:
    """
    Get information about RandomX availability and configuration.

    Returns:
        dict: RandomX information including availability and modes
    """
    info = {
        "available": RANDOMX_AVAILABLE,
        "modes": RANDOMX_MODES.copy(),
        "default_config": get_randomx_config(),
    }

    if RANDOMX_AVAILABLE:
        info["library"] = RANDOMX_LIBRARY
        if RANDOMX_LIBRARY == "randomx":
            info["version"] = getattr(randomx, "__version__", "unknown")
        else:
            info["version"] = getattr(randomx, "__version__", "unknown")
    else:
        if randomx is None:
            info["error"] = "RandomX library not installed"
            info["install_command"] = "pip install RandomX"
        else:
            info["error"] = "Wrong pyrx library installed (schema validator instead of RandomX)"
            info["install_command"] = "pip uninstall pyrx && pip install RandomX"

    return info


# For backward compatibility and module testing
def test_randomx_functionality():
    """
    Test basic RandomX functionality if available.

    Returns:
        bool: True if test passes, False otherwise
    """
    if not RANDOMX_AVAILABLE:
        logger.warning("RandomX not available for testing")
        return False

    try:
        # Simple test
        test_password = b"test_password_123"
        test_salt = secrets.token_bytes(32)

        result = randomx_kdf(
            password=test_password, salt=test_salt, rounds=1, mode="light", hash_len=32
        )

        # Verify the result
        if len(result) == 32:
            logger.info("RandomX functionality test passed")
            return True
        else:
            logger.error(f"RandomX test failed: unexpected output length {len(result)}")
            return False

    except Exception as e:
        logger.error(f"RandomX functionality test failed: {e}")
        return False


if __name__ == "__main__":
    # Module self-test when run directly
    logging.basicConfig(level=logging.INFO)

    print("RandomX Module Information:")
    info = get_randomx_info()
    for key, value in info.items():
        print(f"  {key}: {value}")

    if RANDOMX_AVAILABLE:
        print("\nRunning RandomX functionality test...")
        success = test_randomx_functionality()
        print(f"Test result: {'PASS' if success else 'FAIL'}")
    else:
        print("\nRandomX not available - install with: pip install pyrx")
