# Installation Guide

## Quick Install

```bash
pip install openssl_encrypt
```

The installation will automatically build and install required dependencies (liboqs and liboqs-python) to `~/.local`.

## Dependencies

### Required External Dependencies

This package requires specific versions of external cryptographic libraries:

- **liboqs 0.12.0** - Post-quantum cryptography library (built from source)
- **liboqs-python 0.12.0** - Python bindings for liboqs (built from source)

### Build Tools Required

Before installing, ensure you have the following build tools:

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install cmake ninja-build libssl-dev python3-dev git gcc g++
```

**Fedora/RHEL:**
```bash
sudo dnf install cmake ninja-build openssl-devel python3-devel git gcc-c++
```

**macOS:**
```bash
brew install cmake ninja openssl git
```

## Installation Process

### Automatic Installation (Recommended)

When you run `pip install openssl_encrypt`, the setup script will:

1. Check if liboqs 0.12.0 is already installed
2. Check if liboqs-python 0.12.0 is already installed
3. If not found, automatically:
   - Clone and build liboqs 0.12.0 from source
   - Install it to `~/.local` (no sudo required)
   - Build and install liboqs-python 0.12.0
   - Verify installations

### Environment Setup

After installation, add these lines to your shell profile (`~/.bashrc` or `~/.zshrc`):

```bash
# For liboqs library loading
export LD_LIBRARY_PATH="$HOME/.local/lib:$LD_LIBRARY_PATH"
export PKG_CONFIG_PATH="$HOME/.local/lib/pkgconfig:$PKG_CONFIG_PATH"

# For macOS, also add:
export DYLD_LIBRARY_PATH="$HOME/.local/lib:$DYLD_LIBRARY_PATH"
```

Then reload your shell:
```bash
source ~/.bashrc  # or source ~/.zshrc
```

## Manual Installation

If automatic installation fails, you can install dependencies manually:

### Step 1: Install liboqs 0.12.0

```bash
# Clone liboqs
git clone --branch 0.12.0 https://github.com/open-quantum-safe/liboqs.git
cd liboqs

# Build and install
mkdir build && cd build
cmake -GNinja \
    -DCMAKE_INSTALL_PREFIX=$HOME/.local \
    -DBUILD_SHARED_LIBS=ON \
    -DCMAKE_BUILD_TYPE=Release \
    -DOQS_USE_OPENSSL=ON \
    ..

ninja
ninja install
cd ../..
```

### Step 2: Install liboqs-python 0.12.0

```bash
# Set environment for build
export PKG_CONFIG_PATH="$HOME/.local/lib/pkgconfig:$PKG_CONFIG_PATH"
export LD_LIBRARY_PATH="$HOME/.local/lib:$LD_LIBRARY_PATH"

# Install liboqs-python
pip install git+https://github.com/open-quantum-safe/liboqs-python.git@0.12.0
```

### Step 3: Install openssl_encrypt

```bash
pip install openssl_encrypt
```

## Verification

Verify that all dependencies are installed correctly:

```bash
# Check dependency versions
python -m openssl_encrypt.versions

# Or use the CLI command
openssl-encrypt-check-deps
```

Expected output:
```
Checking openssl_encrypt dependencies...
==================================================
✓ liboqs 0.12.0
✓ liboqs-python 0.12.0
==================================================

✓ All dependencies satisfied
```

## Development Installation

For development, clone the repository and install in editable mode:

```bash
git clone https://gitlab.rm-rf.ch/world/openssl_encrypt.git
cd openssl_encrypt

# Install in development mode (will build dependencies)
pip install -e .

# Or install with dev dependencies
pip install -e ".[dev]"
```

## Troubleshooting

### liboqs build fails

**Problem:** cmake or ninja not found
```bash
# Install build tools (see "Build Tools Required" above)
```

**Problem:** OpenSSL development headers not found
```bash
# Ubuntu/Debian
sudo apt-get install libssl-dev

# Fedora/RHEL
sudo dnf install openssl-devel

# macOS
brew install openssl
```

### liboqs-python build fails

**Problem:** liboqs not found during liboqs-python build
```bash
# Ensure PKG_CONFIG_PATH is set
export PKG_CONFIG_PATH="$HOME/.local/lib/pkgconfig:$PKG_CONFIG_PATH"

# Verify liboqs is installed
pkg-config --modversion liboqs
```

**Problem:** ImportError when importing oqs module
```bash
# Ensure LD_LIBRARY_PATH is set
export LD_LIBRARY_PATH="$HOME/.local/lib:$LD_LIBRARY_PATH"

# Verify library is present
ls -la $HOME/.local/lib/liboqs*
```

### Version mismatch

**Problem:** Wrong version of liboqs or liboqs-python installed
```bash
# Uninstall existing versions
pip uninstall liboqs-python

# Remove liboqs manually if needed
rm -rf $HOME/.local/lib/liboqs*
rm -rf $HOME/.local/include/oqs

# Reinstall with correct version
pip install --force-reinstall --no-cache-dir openssl_encrypt
```

## Docker Installation

For a clean environment, use Docker:

```dockerfile
FROM python:3.11-slim

# Install build dependencies
RUN apt-get update && apt-get install -y \
    cmake ninja-build libssl-dev git gcc g++ \
    && rm -rf /var/lib/apt/lists/*

# Install openssl_encrypt
RUN pip install --no-cache-dir openssl_encrypt

# Set environment variables
ENV LD_LIBRARY_PATH="/root/.local/lib:$LD_LIBRARY_PATH"
ENV PKG_CONFIG_PATH="/root/.local/lib/pkgconfig:$PKG_CONFIG_PATH"

CMD ["openssl-encrypt", "--help"]
```

## CI/CD Integration

For GitHub Actions or GitLab CI:

```yaml
- name: Install dependencies
  run: |
    sudo apt-get update
    sudo apt-get install -y cmake ninja-build libssl-dev

- name: Install openssl_encrypt
  run: |
    pip install openssl_encrypt
    echo "$HOME/.local/lib" >> $GITHUB_PATH

- name: Verify installation
  run: |
    export LD_LIBRARY_PATH="$HOME/.local/lib:$LD_LIBRARY_PATH"
    python -m openssl_encrypt.versions
```

## Support

If you encounter issues:

1. Check the [troubleshooting section](#troubleshooting)
2. Verify your environment meets the requirements
3. Open an issue at: https://gitlab.rm-rf.ch/world/openssl_encrypt/-/issues

Include the output of:
```bash
python -m openssl_encrypt.versions
pkg-config --modversion liboqs
pip list | grep -i liboqs
```
