"""
ML-KEM CLI Support Module

This module provides support for ML-KEM algorithm names in CLI mode.
It's automatically imported by the crypt module.
"""

import logging
import re
import sys
from typing import Optional

# Configure logger
logger = logging.getLogger(__name__)


def _get_security_level(algorithm_name: str) -> Optional[str]:
    """Extract security level from algorithm name"""
    if not isinstance(algorithm_name, str):
        return None

    # Try to extract the security level from the algorithm name
    match = re.search(r"(\d+)", algorithm_name)
    if match:
        return match.group(1)
    return None


def convert_ml_kem_to_kyber(algorithm_name: str) -> str:
    """
    Convert ML-KEM algorithm name to Kyber equivalent

    Args:
        algorithm_name: ML-KEM algorithm name (e.g., "ml-kem-1024-hybrid")

    Returns:
        str: Kyber equivalent (e.g., "kyber1024-hybrid") or original name if not ML-KEM
    """
    if not isinstance(algorithm_name, str):
        return algorithm_name

    # Convert ML-KEM-hybrid to Kyber-hybrid for CLI
    if algorithm_name.lower().startswith("ml-kem-") and "-hybrid" in algorithm_name.lower():
        security_level = _get_security_level(algorithm_name)
        if security_level:
            return f"kyber{security_level}-hybrid"

    return algorithm_name


# Monkey patch the command-line argument parsing in crypt_cli
def apply_patches():
    """Apply ML-KEM support patches to the crypt_cli module"""
    try:
        from . import crypt_cli

        # Store the original main function
        original_main = crypt_cli.main

        def patched_main():
            """Patched main function that handles ML-KEM algorithm names"""
            # Convert ML-KEM algorithm names in command-line arguments
            if len(sys.argv) > 1:
                for i, arg in enumerate(sys.argv):
                    if arg == "--algorithm" and i + 1 < len(sys.argv):
                        algorithm = sys.argv[i + 1]
                        if algorithm.lower().startswith("ml-kem-"):
                            kyber_algorithm = convert_ml_kem_to_kyber(algorithm)
                            if kyber_algorithm != algorithm:
                                logger.info(
                                    f"Converting '{algorithm}' to '{kyber_algorithm}' for CLI compatibility"
                                )
                                sys.argv[i + 1] = kyber_algorithm

            # Call the original main function
            return original_main()

        # Apply the patch
        crypt_cli.main = patched_main
        logger.debug("ML-KEM CLI patches applied successfully")
        return True
    except Exception as e:
        logger.error(f"Failed to apply ML-KEM CLI patches: {e}")
        return False
