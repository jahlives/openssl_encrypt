"""Custom build backend that wraps setuptools to build liboqs dependencies."""
import os
import shutil
import subprocess
import sys

# Import setuptools build_meta - do this FIRST before any other imports
from setuptools import build_meta

# Re-export ALL attributes from setuptools.build_meta
# This ensures we provide the complete PEP 517 interface
__all__ = [
    'build_wheel',
    'get_requires_for_build_wheel',
    'prepare_metadata_for_build_wheel',
    'build_sdist',
    'get_requires_for_build_sdist',
]


def check_liboqs():
    """Check if liboqs-python is installed."""
    try:
        result = subprocess.run(
            [sys.executable, '-c', 'import oqs; print(oqs.oqs_python_version())'],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            version = result.stdout.strip()
            print(f"✓ liboqs-python {version} already installed", flush=True)
            return True
    except Exception:
        pass
    return False


def build_liboqs():
    """Check for liboqs dependencies and show installation message."""
    print("\n" + "="*60, flush=True)
    print("Custom build backend: Checking liboqs dependencies", flush=True)
    print("="*60, flush=True)

    if check_liboqs():
        print("✓ liboqs dependencies satisfied", flush=True)
        print("="*60 + "\n", flush=True)
        return

    print("✗ liboqs-python not found", flush=True)
    print("\nNote: Optional cryptographic libraries not installed.", flush=True)
    print("PQC algorithms will not be available.", flush=True)
    print("\nTo enable PQC support after installation, run:", flush=True)
    print("  openssl-encrypt install-dependencies", flush=True)
    print("="*60 + "\n", flush=True)


# Re-export unmodified functions from setuptools.build_meta
get_requires_for_build_wheel = build_meta.get_requires_for_build_wheel
get_requires_for_build_sdist = build_meta.get_requires_for_build_sdist
prepare_metadata_for_build_wheel = build_meta.prepare_metadata_for_build_wheel
build_sdist = build_meta.build_sdist


def build_wheel(wheel_directory, config_settings=None, metadata_directory=None):
    """Build wheel - check liboqs but don't fail if missing."""
    build_liboqs()
    return build_meta.build_wheel(wheel_directory, config_settings, metadata_directory)
