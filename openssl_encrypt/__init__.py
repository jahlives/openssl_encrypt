"""
openssl_encrypt - Secure file encryption and decryption package
"""

import os
import sys
import subprocess
from pathlib import Path

# Version will be set by setup.py
try:
    from .version import __version__, __git_commit__
except ImportError:
    __version__ = "unknown"
    __git_commit__ = "unknown"

# Required dependency versions
REQUIRED_LIBOQS_VERSION = "0.12.0"
REQUIRED_LIBOQS_PYTHON_VERSION = "0.12.0"


def _check_and_build_dependencies():
    """
    Check if liboqs dependencies are installed with correct versions.
    If not, and if we're in development mode, offer to build them.
    """
    # Check if we should skip this check (for CI, containers, etc.)
    if os.environ.get('SKIP_LIBOQS_CHECK', '').lower() in ('1', 'true', 'yes'):
        return

    # Check if we've already checked in this process
    if hasattr(_check_and_build_dependencies, '_checked'):
        return
    _check_and_build_dependencies._checked = True

    # Enable verbose mode with environment variable
    verbose = os.environ.get('LIBOQS_CHECK_VERBOSE', '').lower() in ('1', 'true', 'yes')

    from .versions import check_liboqs_version, check_liboqs_python_version

    liboqs_ok, liboqs_ver, liboqs_msg = check_liboqs_version()
    liboqs_python_ok, liboqs_python_ver, liboqs_python_msg = check_liboqs_python_version()

    if liboqs_ok and liboqs_python_ok:
        # All good, return silently (or verbosely if requested)
        if verbose:
            print(f"✓ liboqs dependencies satisfied:", file=sys.stderr)
            print(f"  {liboqs_msg}", file=sys.stderr)
            print(f"  {liboqs_python_msg}", file=sys.stderr)
        return

    # Dependencies are missing or wrong version
    print("\n" + "=" * 60, file=sys.stderr)
    print("WARNING: liboqs dependencies not satisfied", file=sys.stderr)
    print("=" * 60, file=sys.stderr)
    print(liboqs_msg, file=sys.stderr)
    print(liboqs_python_msg, file=sys.stderr)
    print("=" * 60, file=sys.stderr)

    # Check if we're in development/editable install mode
    package_path = Path(__file__).parent.parent
    build_script = package_path / "scripts" / "build_local_deps.sh"

    if build_script.exists():
        print("\nBuild script found. You can build dependencies by running:", file=sys.stderr)
        print(f"  {build_script}", file=sys.stderr)
        print("\nOr install automatically with:", file=sys.stderr)
        print(f"  python {package_path / 'setup.py'} develop", file=sys.stderr)

        # For interactive sessions, offer to build automatically
        if sys.stdin.isatty() and not os.environ.get('CI'):
            print("\nWould you like to build dependencies now? (y/N): ", end='', file=sys.stderr, flush=True)
            try:
                response = input().strip().lower()
                if response in ('y', 'yes'):
                    print("\nBuilding dependencies...", file=sys.stderr)
                    env = os.environ.copy()
                    env['LIBOQS_INSTALL_PREFIX'] = os.path.expanduser('~/.local')
                    env['LIBOQS_VERSION'] = REQUIRED_LIBOQS_VERSION
                    env['LIBOQS_PYTHON_VERSION'] = REQUIRED_LIBOQS_PYTHON_VERSION

                    try:
                        subprocess.check_call(['/bin/bash', str(build_script)], env=env)
                        print("\n✓ Dependencies built successfully!", file=sys.stderr)
                        print("Please restart your Python session to use the new libraries.", file=sys.stderr)
                    except subprocess.CalledProcessError as e:
                        print(f"\n✗ Build failed: {e}", file=sys.stderr)
                        print("Please install manually (see INSTALLATION.md)", file=sys.stderr)
            except (EOFError, KeyboardInterrupt):
                print("\nSkipping automatic build.", file=sys.stderr)
    else:
        print("\nPlease install liboqs dependencies manually:", file=sys.stderr)
        print(f"  liboqs {REQUIRED_LIBOQS_VERSION}", file=sys.stderr)
        print(f"  liboqs-python {REQUIRED_LIBOQS_PYTHON_VERSION}", file=sys.stderr)
        print("\nSee openssl_encrypt/docs/INSTALLATION.md for instructions", file=sys.stderr)

    print("=" * 60, file=sys.stderr)
    print("Continuing with possibly limited functionality...\n", file=sys.stderr)


# Check dependencies on import
try:
    _check_and_build_dependencies()
except Exception as e:
    # Don't fail the import if dependency check fails
    print(f"Warning: Failed to check liboqs dependencies: {e}", file=sys.stderr)


__all__ = ['__version__', '__git_commit__']
