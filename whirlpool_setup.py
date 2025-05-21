"""
Post-installation script for setting up the Whirlpool module compatibility.

This script handles Python 3.13+ compatibility for the Whirlpool hash module,
which is used for certain cryptographic operations in the openssl_encrypt package.
"""

import sys
import os
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("whirlpool_setup")

# Check Python version first to provide clear messaging about compatibility
python_version = sys.version_info
if python_version.major == 3 and python_version.minor >= 13:
    logger.info(f"Detected Python {python_version.major}.{python_version.minor} - "
                "Setting up Whirlpool with Python 3.13 compatibility")

# Import and run the setup function
from openssl_encrypt.modules.setup_whirlpool import setup_whirlpool

if __name__ == "__main__":
    success = setup_whirlpool()
    if success:
        logger.info("Whirlpool module setup completed successfully")
    else:
        logger.warning("Whirlpool module setup encountered issues. Some hashing "
                     "functionality may be limited. Check above logs for details.")