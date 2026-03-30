"""
Version requirements and verification for external dependencies
"""

import sys

try:
    from .modules.crypt_utils import eprint
except ImportError:
    # Fallback when run as __main__ or outside package context
    def eprint(*args, **kwargs):
        print(*args, file=sys.stderr, **kwargs)


LIBOQS_VERSION = "0.12.0"
LIBOQS_PYTHON_VERSION = "0.12.0"


def check_liboqs_version():
    """
    Check if liboqs is installed with correct version
    Tries common installation paths if not found in PKG_CONFIG_PATH

    Returns:
        tuple: (installed: bool, version: str or None, message: str)
    """
    import os
    import subprocess
    import sys

    # On Windows, check for liboqs DLL directly (no pkg-config)
    if sys.platform == "win32":
        win_prefixes = [
            os.environ.get("LIBOQS_INSTALL_PREFIX", r"C:\liboqs"),
            r"C:\liboqs",
        ]
        for prefix in win_prefixes:
            dll_path = os.path.join(prefix, "bin", "oqs.dll")
            if os.path.exists(dll_path):
                # Try to get version from cmake package config
                cmake_config = os.path.join(prefix, "lib", "cmake", "liboqs", "liboqsConfig.cmake")
                version = None
                if os.path.exists(cmake_config):
                    try:
                        with open(cmake_config) as f:
                            for line in f:
                                if "PACKAGE_VERSION" in line and "set" in line.lower():
                                    parts = line.split('"')
                                    if len(parts) >= 2:
                                        version = parts[1]
                                        break
                    except Exception:
                        pass
                if version is None:
                    # Check pkg-config file if available
                    pc_file = os.path.join(prefix, "lib", "pkgconfig", "liboqs.pc")
                    if os.path.exists(pc_file):
                        try:
                            with open(pc_file) as f:
                                for line in f:
                                    if line.startswith("Version:"):
                                        version = line.split(":", 1)[1].strip()
                                        break
                        except Exception:
                            pass
                if version == LIBOQS_VERSION:
                    return (True, version, f"✓ liboqs {version}")
                elif version:
                    return (
                        False,
                        version,
                        f"✗ liboqs version mismatch: found {version}, need {LIBOQS_VERSION}",
                    )
                else:
                    # DLL exists but can't determine version — assume OK
                    return (
                        True,
                        "unknown",
                        f"✓ liboqs found at {prefix} (version unknown)",
                    )
        # No DLL found on Windows
        return (None, None, "✗ liboqs not found (checked C:\\liboqs)")

    # Common paths where liboqs might be installed (Unix)
    common_pkgconfig_paths = [
        None,  # Use default PKG_CONFIG_PATH first
        os.path.expanduser("~/.local/lib64/pkgconfig"),
        os.path.expanduser("~/.local/lib/pkgconfig"),
        "/usr/local/lib64/pkgconfig",
        "/usr/local/lib/pkgconfig",
    ]

    pkg_config_not_found = False
    for pkg_path in common_pkgconfig_paths:
        try:
            env = os.environ.copy()
            if pkg_path is not None:
                # Add this path to PKG_CONFIG_PATH
                existing_path = env.get("PKG_CONFIG_PATH", "")
                if existing_path:
                    env["PKG_CONFIG_PATH"] = f"{pkg_path}:{existing_path}"
                else:
                    env["PKG_CONFIG_PATH"] = pkg_path

            result = subprocess.run(
                ["pkg-config", "--modversion", "liboqs"],
                capture_output=True,
                text=True,
                timeout=5,
                env=env,
            )
            if result.returncode == 0:
                version = result.stdout.strip()
                if version == LIBOQS_VERSION:
                    return (True, version, f"✓ liboqs {version}")
                else:
                    return (
                        False,
                        version,
                        f"✗ liboqs version mismatch: found {version}, need {LIBOQS_VERSION}",
                    )
        except FileNotFoundError:
            pkg_config_not_found = True
            break  # No point trying other paths if pkg-config doesn't exist
        except subprocess.TimeoutExpired:
            continue  # Try next path
        except Exception:
            continue  # Try next path

    # If pkg-config is not found, we can't verify via pkg-config
    # But if liboqs-python works, that means liboqs is available
    # This is common in containerized/sandboxed environments like flatpak
    if pkg_config_not_found:
        return (None, None, "✗ pkg-config not found, cannot verify liboqs")

    return (False, None, "✗ liboqs not found via pkg-config")


def check_liboqs_python_version():
    """
    Check if liboqs-python is installed with correct version

    Returns:
        tuple: (installed: bool, version: str or None, message: str)
    """
    try:
        import oqs

        version = oqs.oqs_python_version()
        if version == LIBOQS_PYTHON_VERSION:
            return (True, version, f"✓ liboqs-python {version}")
        else:
            return (
                False,
                version,
                f"✗ liboqs-python version mismatch: found {version}, need {LIBOQS_PYTHON_VERSION}",
            )
    except ImportError:
        return (False, None, "✗ liboqs-python not installed")
    except Exception as e:
        return (False, None, f"✗ Error checking liboqs-python: {e}")


def check_all_dependencies(verbose=True):
    """
    Check all external dependencies

    Args:
        verbose: If True, print status messages

    Returns:
        bool: True if all dependencies are satisfied
    """
    all_ok = True

    # Check liboqs
    liboqs_ok, liboqs_ver, liboqs_msg = check_liboqs_version()
    if verbose:
        eprint(liboqs_msg)

    # Check liboqs-python
    liboqs_python_ok, liboqs_python_ver, liboqs_python_msg = check_liboqs_python_version()
    if verbose:
        eprint(liboqs_python_msg)

    # If liboqs check returned None (pkg-config not available),
    # but liboqs-python works, consider that sufficient
    # This is common in sandboxed environments like flatpak
    if liboqs_ok is None and liboqs_python_ok:
        all_ok = True
    elif liboqs_ok is None:
        # pkg-config not available and liboqs-python doesn't work
        all_ok = False
    else:
        # Normal case: both must be OK
        all_ok = liboqs_ok and liboqs_python_ok

    return all_ok


def get_installation_instructions():
    """Get manual installation instructions"""
    return f"""
Manual Installation Instructions:
==================================

1. Install build dependencies:
   - Ubuntu/Debian: sudo apt-get install cmake ninja-build libssl-dev python3-dev
   - Fedora/RHEL: sudo dnf install cmake ninja-build openssl-devel python3-devel
   - macOS: brew install cmake ninja openssl

2. Build and install liboqs {LIBOQS_VERSION}:
   git clone --branch {LIBOQS_VERSION} https://github.com/open-quantum-safe/liboqs.git
   cd liboqs
   mkdir build && cd build
   cmake -GNinja -DCMAKE_INSTALL_PREFIX=$HOME/.local -DBUILD_SHARED_LIBS=ON ..
   ninja && ninja install

3. Install liboqs-python {LIBOQS_PYTHON_VERSION}:
   # Note: Use lib64 on 64-bit systems, lib on others
   export PKG_CONFIG_PATH=$HOME/.local/lib64/pkgconfig:$HOME/.local/lib/pkgconfig:$PKG_CONFIG_PATH
   export LD_LIBRARY_PATH=$HOME/.local/lib64:$HOME/.local/lib:$LD_LIBRARY_PATH
   pip install git+https://github.com/open-quantum-safe/liboqs-python.git@{LIBOQS_PYTHON_VERSION}

4. Add to your shell profile (~/.bashrc or ~/.zshrc):
   export LD_LIBRARY_PATH="$HOME/.local/lib64:$HOME/.local/lib:$LD_LIBRARY_PATH"
   export PKG_CONFIG_PATH="$HOME/.local/lib64/pkgconfig:$HOME/.local/lib/pkgconfig:$PKG_CONFIG_PATH"

5. Verify installation:
   python -m openssl_encrypt.versions
"""


def main():
    """Main entry point for command-line usage"""
    eprint("Checking openssl_encrypt dependencies...")
    eprint("=" * 50)

    all_ok = check_all_dependencies(verbose=True)

    eprint("=" * 50)

    if all_ok:
        eprint("\n✓ All dependencies satisfied")
        return 0
    else:
        eprint("\n✗ Some dependencies are missing or have incorrect versions")
        eprint(get_installation_instructions())
        return 1


if __name__ == "__main__":
    import sys

    sys.exit(main())
