"""
Module to handle the compatibility of Whirlpool hash library across Python versions.
"""

import glob
import importlib.util
import logging
import os
import platform
import site
import subprocess
import sys
import sysconfig
from pathlib import Path

# Set up logging - let the parent module configure the level
logger = logging.getLogger("setup_whirlpool")


def find_whirlpool_modules():
    """Find all Whirlpool modules installed in the system."""
    whirlpool_modules = []

    # Get all site-packages directories
    site_packages = set()
    site_packages.add(sysconfig.get_path("purelib"))
    site_packages.add(sysconfig.get_path("platlib"))

    # Add user site-packages
    user_site = site.getusersitepackages()
    if isinstance(user_site, str):
        site_packages.add(user_site)
    elif isinstance(user_site, list):
        site_packages.update(user_site)

    # In Flatpak, also check the app-specific site-packages
    if is_flatpak_environment():
        site_packages.add("/app/lib/python3.11/site-packages")
        site_packages.add("/app/lib/python3.12/site-packages")
        site_packages.add("/app/lib/python3.13/site-packages")

    # Check for modules in all site-packages
    for site_pkg in site_packages:
        if not os.path.exists(site_pkg):
            continue

        # Look for any whirlpool-related files
        whirlpool_files = []
        pattern = os.path.join(site_pkg, "whirlpool*.so")
        whirlpool_files.extend(glob.glob(pattern))

        pattern = os.path.join(site_pkg, "pywhirlpool*.so")
        whirlpool_files.extend(glob.glob(pattern))

        # For Python 3.11+, look for the py311 variant
        pattern = os.path.join(site_pkg, "whirlpool-py311*.so")
        whirlpool_files.extend(glob.glob(pattern))

        # For Windows
        pattern = os.path.join(site_pkg, "whirlpool*.pyd")
        whirlpool_files.extend(glob.glob(pattern))

        pattern = os.path.join(site_pkg, "pywhirlpool*.pyd")
        whirlpool_files.extend(glob.glob(pattern))

        # Add all found modules to the list
        whirlpool_modules.extend(whirlpool_files)

    return whirlpool_modules


def create_whirlpool_symlink():
    """Create a symbolic link to the appropriate Whirlpool module."""
    # In Flatpak or read-only environments, skip symlink creation
    if is_flatpak_environment():
        logger.debug("Flatpak environment detected, skipping symlink creation")
        return False

    whirlpool_modules = find_whirlpool_modules()
    logger.debug(f"Found Whirlpool modules: {whirlpool_modules}")

    if not whirlpool_modules:
        logger.warning("No Whirlpool modules found. Attempting to install...")
        install_whirlpool()
        # Refresh the list after installation
        whirlpool_modules = find_whirlpool_modules()

    if not whirlpool_modules:
        logger.warning("Failed to find or install any Whirlpool modules")
        return False

    # Get Python version
    python_version = sys.version_info

    # Check if we already have a working module
    try:
        # Try to import whirlpool directly
        import whirlpool

        logger.debug("Whirlpool module already working, no action needed")
        return True
    except ImportError:
        pass

    # Choose the most appropriate module based on version
    chosen_module = None
    target_name = None

    # Try to find the best match for the current Python version
    version_suffix = f"cpython-{python_version.major}{python_version.minor}"

    # First preference: direct match for this Python version
    for module in whirlpool_modules:
        if version_suffix in module and "whirlpool" in module.lower():
            chosen_module = module
            break

    # If no direct match, try the py311 or py313 version for Python 3.11+
    if not chosen_module and (
        python_version.major > 3 or (python_version.major == 3 and python_version.minor >= 11)
    ):
        # First check for Python 3.13 specific module
        if python_version.major == 3 and python_version.minor >= 13:
            for module in whirlpool_modules:
                if "whirlpool-py313" in module.lower() or "whirlpool_py313" in module.lower():
                    chosen_module = module
                    break

        # If no Python 3.13 specific module, fall back to Python 3.11 module
        if not chosen_module:
            for module in whirlpool_modules:
                if "whirlpool-py311" in module.lower() or "whirlpool_py311" in module.lower():
                    chosen_module = module
                    break

    # Fall back to any whirlpool module
    if not chosen_module:
        for module in whirlpool_modules:
            if "whirlpool" in module.lower():
                chosen_module = module
                break

    if not chosen_module:
        logger.warning("Could not find a suitable Whirlpool module")
        return False

    # Determine the target name for the link
    module_dir = os.path.dirname(chosen_module)
    if os.name == "nt":  # Windows
        target_name = os.path.join(module_dir, f"whirlpool.{version_suffix}.pyd")
    else:  # Unix/Linux/Mac
        target_name = os.path.join(
            module_dir, f"whirlpool.{version_suffix}-{platform.machine()}-linux-gnu.so"
        )

    logger.debug(f"Creating symbolic link from {chosen_module} to {target_name}")

    try:
        # Remove existing file if it exists
        if os.path.exists(target_name):
            os.remove(target_name)

        # Create the symlink (or copy on Windows)
        if os.name == "nt":
            # Windows doesn't handle symlinks well, so copy the file
            import shutil

            shutil.copy2(chosen_module, target_name)
        else:
            os.symlink(chosen_module, target_name)

        logger.debug("Successfully created Whirlpool module link")

        # Verify the link works
        try:
            # Clear any previous import attempts
            if "whirlpool" in sys.modules:
                del sys.modules["whirlpool"]

            # Try importing again
            import whirlpool

            logger.debug("Verified Whirlpool module can now be imported")
            return True
        except ImportError as e:
            logger.error(f"Created link but import still fails: {e}")
            return False

    except Exception as e:
        logger.error(f"Error creating Whirlpool link: {e}")
        return False


def is_flatpak_environment():
    """Check if we're running in a Flatpak environment."""
    # Check for Flatpak environment variables
    return (
        os.environ.get("FLATPAK_ID") is not None
        or os.environ.get("FLATPAK_DEST") is not None
        or "/app/" in sys.executable
        or "/var/lib/flatpak/" in sys.executable
    )


def install_whirlpool():
    """Attempt to install the appropriate Whirlpool package."""
    # Don't attempt installation in Flatpak environment
    if is_flatpak_environment():
        logger.debug("Running in Flatpak environment, skipping auto-installation")
        return False

    python_version = sys.version_info

    try:
        # For Python 3.13+, install the compatible fork specifically for 3.13
        if python_version.major > 3 or (python_version.major == 3 and python_version.minor >= 13):
            # Check if whirlpool-py313 is available in PyPI
            try:
                logger.debug("Checking for whirlpool-py313 package in PyPI")
                import pip._vendor.requests as requests

                response = requests.get("https://pypi.org/pypi/whirlpool-py313/json")
                if response.status_code == 200:
                    logger.info("Installing whirlpool-py313 for Python 3.13+")
                    subprocess.check_call(
                        [sys.executable, "-m", "pip", "install", "whirlpool-py313"]
                    )
                else:
                    # If whirlpool-py313 doesn't exist, try py311 version which may be compatible
                    logger.info("whirlpool-py313 not found, installing whirlpool-py311 as fallback")
                    subprocess.check_call(
                        [sys.executable, "-m", "pip", "install", "whirlpool-py311"]
                    )
            except Exception:
                # If package checking fails, try the py311 version
                logger.info(
                    "Failed to check whirlpool-py313, installing whirlpool-py311 for Python 3.13+"
                )
                subprocess.check_call([sys.executable, "-m", "pip", "install", "whirlpool-py311"])

        # For Python 3.11-3.12, install the 3.11 compatible fork
        elif python_version.major == 3 and python_version.minor >= 11:
            logger.info("Installing whirlpool-py311 for Python 3.11-3.12")
            subprocess.check_call([sys.executable, "-m", "pip", "install", "whirlpool-py311"])

        else:
            # For older Python versions, install the original package
            logger.info("Installing Whirlpool for Python 3.10 and below")
            subprocess.check_call([sys.executable, "-m", "pip", "install", "Whirlpool"])

        return True
    except subprocess.SubprocessError as e:
        logger.error(f"Failed to install Whirlpool package: {e}")
        return False


def setup_whirlpool():
    """Main function to set up Whirlpool compatibility."""
    try:
        # First try to import normally
        import whirlpool

        logger.debug("Whirlpool module already working, no action needed")
        return True
    except ImportError:
        pass

    # Try to import whirlpool_py311 directly (common in Flatpak/pre-installed)
    try:
        import whirlpool_py311 as whirlpool

        # Add it to sys.modules so future imports work
        sys.modules["whirlpool"] = whirlpool
        logger.debug("whirlpool_py311 module found and aliased as whirlpool")
        return True
    except ImportError:
        # Need to create the symlink
        return create_whirlpool_symlink()


if __name__ == "__main__":
    setup_whirlpool()
