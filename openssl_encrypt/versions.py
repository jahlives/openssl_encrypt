"""
Version requirements and verification for external dependencies
"""

LIBOQS_VERSION = "0.12.0"
LIBOQS_PYTHON_VERSION = "0.12.0"

def check_liboqs_version():
    """
    Check if liboqs is installed with correct version

    Returns:
        tuple: (installed: bool, version: str or None, message: str)
    """
    import subprocess

    try:
        result = subprocess.run(
            ['pkg-config', '--modversion', 'liboqs'],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            version = result.stdout.strip()
            if version == LIBOQS_VERSION:
                return (True, version, f"✓ liboqs {version}")
            else:
                return (False, version, f"✗ liboqs version mismatch: found {version}, need {LIBOQS_VERSION}")
        else:
            return (False, None, "✗ liboqs not found via pkg-config")
    except FileNotFoundError:
        return (False, None, "✗ pkg-config not found, cannot verify liboqs")
    except subprocess.TimeoutExpired:
        return (False, None, "✗ pkg-config timeout")
    except Exception as e:
        return (False, None, f"✗ Error checking liboqs: {e}")

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
            return (False, version, f"✗ liboqs-python version mismatch: found {version}, need {LIBOQS_PYTHON_VERSION}")
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
        print(liboqs_msg)
    all_ok = all_ok and liboqs_ok

    # Check liboqs-python
    liboqs_python_ok, liboqs_python_ver, liboqs_python_msg = check_liboqs_python_version()
    if verbose:
        print(liboqs_python_msg)
    all_ok = all_ok and liboqs_python_ok

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
   export PKG_CONFIG_PATH=$HOME/.local/lib/pkgconfig:$PKG_CONFIG_PATH
   export LD_LIBRARY_PATH=$HOME/.local/lib:$LD_LIBRARY_PATH
   pip install git+https://github.com/open-quantum-safe/liboqs-python.git@{LIBOQS_PYTHON_VERSION}

4. Add to your shell profile (~/.bashrc or ~/.zshrc):
   export LD_LIBRARY_PATH="$HOME/.local/lib:$LD_LIBRARY_PATH"
   export PKG_CONFIG_PATH="$HOME/.local/lib/pkgconfig:$PKG_CONFIG_PATH"

5. Verify installation:
   python -m openssl_encrypt.versions
"""

def main():
    """Main entry point for command-line usage"""
    print("Checking openssl_encrypt dependencies...")
    print("=" * 50)

    all_ok = check_all_dependencies(verbose=True)

    print("=" * 50)

    if all_ok:
        print("\n✓ All dependencies satisfied")
        return 0
    else:
        print("\n✗ Some dependencies are missing or have incorrect versions")
        print(get_installation_instructions())
        return 1

if __name__ == '__main__':
    import sys
    sys.exit(main())
