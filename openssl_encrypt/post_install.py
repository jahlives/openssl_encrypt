"""
Post-installation script for the openssl_encrypt package.
This script is executed after the package is installed to perform additional setup.
"""

import logging
import os
import sys

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("post_install")


def main():
    """Main function to run post-installation tasks."""
    logger.info("Running post-installation setup for openssl_encrypt...")

    try:
        from openssl_encrypt.modules.setup_whirlpool import setup_whirlpool

        result = setup_whirlpool()
        if result:
            logger.info("Whirlpool module setup completed successfully.")
        else:
            logger.warning(
                "Whirlpool module setup completed with warnings. "
                "Some functionality may be limited. "
                "See documentation for manual setup instructions."
            )
    except Exception as e:
        logger.error(f"Error during Whirlpool setup: {e}")
        logger.info(
            "You may need to manually set up the Whirlpool module. "
            "See the documentation for instructions."
        )

    logger.info("Post-installation setup complete.")


if __name__ == "__main__":
    main()
