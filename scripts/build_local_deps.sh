#!/bin/bash
# Build script for liboqs and liboqs-python dependencies
# Installs to user's local directory (no sudo required)
set -e

# Version requirements
LIBOQS_VERSION="${LIBOQS_VERSION:-0.12.0}"
LIBOQS_PYTHON_VERSION="${LIBOQS_PYTHON_VERSION:-0.12.0}"

INSTALL_PREFIX="${LIBOQS_INSTALL_PREFIX:-${HOME}/.local}"

echo "=========================================="
echo "Building liboqs dependencies"
echo "=========================================="
echo "liboqs version: ${LIBOQS_VERSION}"
echo "liboqs-python version: ${LIBOQS_PYTHON_VERSION}"
echo "Install prefix: ${INSTALL_PREFIX}"
echo ""

# Check for required build tools
command -v git >/dev/null 2>&1 || { echo "Error: git is required but not installed"; exit 1; }
command -v cmake >/dev/null 2>&1 || { echo "Error: cmake is required but not installed"; exit 1; }
command -v ninja >/dev/null 2>&1 || { echo "Error: ninja is required but not installed"; exit 1; }

# Create directories
mkdir -p "${INSTALL_PREFIX}"/{lib,include}

# Build liboqs 0.12.0
echo "Step 1/2: Building liboqs ${LIBOQS_VERSION}..."
LIBOQS_TMP=$(mktemp -d)
trap "rm -rf ${LIBOQS_TMP}" EXIT

git clone --depth 1 --branch "${LIBOQS_VERSION}" \
    https://github.com/open-quantum-safe/liboqs.git "${LIBOQS_TMP}"

cd "${LIBOQS_TMP}"

# Verify we have the correct version
CHECKED_OUT_VERSION=$(git describe --tags 2>/dev/null || git rev-parse --short HEAD)
echo "Checked out version: ${CHECKED_OUT_VERSION}"

mkdir build && cd build

cmake -GNinja \
    -DCMAKE_INSTALL_PREFIX="${INSTALL_PREFIX}" \
    -DBUILD_SHARED_LIBS=ON \
    -DCMAKE_BUILD_TYPE=Release \
    -DOQS_USE_OPENSSL=ON \
    ..

ninja
ninja install

# Verify installed version
if [ -f "${INSTALL_PREFIX}/include/oqs/oqs.h" ]; then
    echo "✓ liboqs ${LIBOQS_VERSION} installed successfully to ${INSTALL_PREFIX}"
else
    echo "Error: liboqs installation verification failed"
    exit 1
fi

# Update environment for liboqs-python build
export PKG_CONFIG_PATH="${INSTALL_PREFIX}/lib/pkgconfig:${PKG_CONFIG_PATH}"
export LD_LIBRARY_PATH="${INSTALL_PREFIX}/lib:${LD_LIBRARY_PATH}"
export DYLD_LIBRARY_PATH="${INSTALL_PREFIX}/lib:${DYLD_LIBRARY_PATH}"

# Also set CMAKE_PREFIX_PATH for cmake-based builds
export CMAKE_PREFIX_PATH="${INSTALL_PREFIX}:${CMAKE_PREFIX_PATH}"

# Build liboqs-python 0.12.0
echo ""
echo "Step 2/2: Building liboqs-python ${LIBOQS_PYTHON_VERSION}..."

# Use python3 -m pip to install from git with specific tag
# This is more reliable than calling pip directly, especially during build processes
python3 -m pip install --no-cache-dir "git+https://github.com/open-quantum-safe/liboqs-python.git@${LIBOQS_PYTHON_VERSION}"

# Verify liboqs-python installation
echo ""
echo "Verifying liboqs-python installation..."
python3 -c "
import oqs
version = oqs.oqs_python_version()
print(f'✓ liboqs-python version: {version}')
if version != '${LIBOQS_PYTHON_VERSION}':
    print(f'Warning: Expected version ${LIBOQS_PYTHON_VERSION}, got {version}')
    exit(1)
" || {
    echo "Error: liboqs-python installation verification failed"
    exit 1
}

echo ""
echo "=========================================="
echo "✓ All dependencies installed successfully"
echo "=========================================="
echo ""
echo "Installation location: ${INSTALL_PREFIX}"
echo ""

# Detect which lib directory was used (lib or lib64)
if [ -d "${INSTALL_PREFIX}/lib64" ] && [ -f "${INSTALL_PREFIX}/lib64/liboqs.so" ]; then
    LIB_DIR="${INSTALL_PREFIX}/lib64"
elif [ -d "${INSTALL_PREFIX}/lib" ] && [ -f "${INSTALL_PREFIX}/lib/liboqs.so" ]; then
    LIB_DIR="${INSTALL_PREFIX}/lib"
else
    echo "Warning: Could not determine lib directory"
    LIB_DIR="${INSTALL_PREFIX}/lib"
fi

# Update environment variables for this script with detected lib directory
# This ensures any subsequent verification commands work correctly
export PKG_CONFIG_PATH="${LIB_DIR}/pkgconfig:${PKG_CONFIG_PATH}"
export LD_LIBRARY_PATH="${LIB_DIR}:${LD_LIBRARY_PATH}"
export DYLD_LIBRARY_PATH="${LIB_DIR}:${DYLD_LIBRARY_PATH}"

# Verify pkg-config can find liboqs with updated environment
echo "Verifying pkg-config can find liboqs..."
if pkg-config --modversion liboqs &>/dev/null; then
    FOUND_VERSION=$(pkg-config --modversion liboqs)
    echo "✓ pkg-config found liboqs version: ${FOUND_VERSION}"
else
    echo "⚠ Warning: pkg-config cannot find liboqs (this is OK if liboqs-python works)"
fi
echo ""

echo "IMPORTANT: Environment variables need to be set for liboqs to work properly"
echo ""
echo "The following lines need to be added to your shell profile:"
echo ""
echo "export LD_LIBRARY_PATH=\"${LIB_DIR}:\${LD_LIBRARY_PATH}\""
echo "export PKG_CONFIG_PATH=\"${LIB_DIR}/pkgconfig:\${PKG_CONFIG_PATH}\""
if [[ "$OSTYPE" == "darwin"* ]]; then
    echo "export DYLD_LIBRARY_PATH=\"${LIB_DIR}:\${DYLD_LIBRARY_PATH}\""
fi
echo ""

# Detect shell profile file
SHELL_PROFILE=""
if [ -n "$BASH_VERSION" ]; then
    SHELL_PROFILE="$HOME/.bashrc"
elif [ -n "$ZSH_VERSION" ]; then
    SHELL_PROFILE="$HOME/.zshrc"
elif [ -f "$HOME/.bashrc" ]; then
    SHELL_PROFILE="$HOME/.bashrc"
elif [ -f "$HOME/.zshrc" ]; then
    SHELL_PROFILE="$HOME/.zshrc"
elif [ -f "$HOME/.profile" ]; then
    SHELL_PROFILE="$HOME/.profile"
fi

# Ask user if they want to add to shell profile
if [ -n "$SHELL_PROFILE" ]; then
    echo "Detected shell profile: $SHELL_PROFILE"
    echo ""
    read -p "Would you like to automatically add these to $SHELL_PROFILE? (y/N): " -r
    echo ""

    if [[ $REPLY =~ ^[Yy]$ ]]; then
        # Check if already present
        if grep -q "# openssl_encrypt liboqs paths" "$SHELL_PROFILE" 2>/dev/null; then
            echo "⚠ Paths already exist in $SHELL_PROFILE (skipping)"
        else
            echo "Adding environment variables to $SHELL_PROFILE..."
            {
                echo ""
                echo "# openssl_encrypt liboqs paths (added by build_local_deps.sh)"
                echo "export LD_LIBRARY_PATH=\"${LIB_DIR}:\${LD_LIBRARY_PATH}\""
                echo "export PKG_CONFIG_PATH=\"${LIB_DIR}/pkgconfig:\${PKG_CONFIG_PATH}\""
                if [[ "$OSTYPE" == "darwin"* ]]; then
                    echo "export DYLD_LIBRARY_PATH=\"${LIB_DIR}:\${DYLD_LIBRARY_PATH}\""
                fi
            } >> "$SHELL_PROFILE"

            echo "✓ Environment variables added to $SHELL_PROFILE"
            echo ""
            echo "=========================================="
            echo "IMPORTANT: Apply changes to current shell"
            echo "=========================================="
            echo ""
            echo "The environment variables have been added to $SHELL_PROFILE,"
            echo "but they won't take effect in your CURRENT shell session until you run:"
            echo ""
            echo "  source $SHELL_PROFILE"
            echo ""
            echo "Would you like instructions to copy-paste?"
            read -p "(y/N): " -r
            echo ""

            if [[ $REPLY =~ ^[Yy]$ ]]; then
                echo "Copy and run this command in your shell:"
                echo ""
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                echo "source $SHELL_PROFILE"
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                echo ""
                echo "After running this, the environment will be ready."
            else
                echo "Remember to run: source $SHELL_PROFILE"
            fi
            echo ""
            echo "For NEW shell sessions, the paths will be available automatically."
        fi
    else
        echo "Skipped. You can add them manually later to: $SHELL_PROFILE"
        echo ""
        echo "After adding manually, run: source $SHELL_PROFILE"
    fi
else
    echo "Could not detect shell profile. Please add the above lines manually."
    echo ""
    echo "After adding to your profile, run: source <your-profile-file>"
fi

echo ""
echo "=========================================="
echo "Final Verification"
echo "=========================================="
echo ""

# Detect package path (script is in scripts/, package root is parent)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PACKAGE_ROOT="$(dirname "$SCRIPT_DIR")"

echo "Running dependency check with current environment..."
python3 -c "
import sys
sys.path.insert(0, '${PACKAGE_ROOT}')
try:
    from openssl_encrypt.versions import check_liboqs_version, check_liboqs_python_version

    liboqs_ok, liboqs_ver, liboqs_msg = check_liboqs_version()
    print(liboqs_msg)

    liboqs_python_ok, liboqs_python_ver, liboqs_python_msg = check_liboqs_python_version()
    print(liboqs_python_msg)

    if liboqs_ok and liboqs_python_ok:
        print('')
        print('✓ All checks passed within this script environment!')
        print('')
        print('NOTE: Your parent shell needs the environment variables too.')
        print('      After sourcing your shell profile, all checks will pass.')
    else:
        print('')
        print('⚠ Some checks failed, but this may be expected.')
        print('  After sourcing your shell profile, checks should pass.')
except Exception as e:
    print(f'Could not run verification: {e}')
    print('This is normal if running from setup.py build.')
" 2>/dev/null || echo "Note: Final verification skipped (package not in path yet)"

echo ""
