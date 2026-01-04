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
echo "IMPORTANT: Add these lines to your shell profile (~/.bashrc or ~/.zshrc):"
echo ""
echo "export LD_LIBRARY_PATH=\"${INSTALL_PREFIX}/lib:\${LD_LIBRARY_PATH}\""
echo "export PKG_CONFIG_PATH=\"${INSTALL_PREFIX}/lib/pkgconfig:\${PKG_CONFIG_PATH}\""
echo ""
echo "For macOS, also add:"
echo "export DYLD_LIBRARY_PATH=\"${INSTALL_PREFIX}/lib:\${DYLD_LIBRARY_PATH}\""
echo ""
