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

**About build output:**
- Full compiler output (cmake, ninja, gcc) is shown during builds
- This includes all build progress (e.g., `[1/156] Building C object...`)
- If dependencies are already installed with correct versions, build is skipped
- Build time: ~3-5 minutes depending on your system

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

## Advanced Configuration

### Environment Variables

**SKIP_LIBOQS_CHECK** - Skip automatic dependency checking on import
```bash
# Useful for CI/CD or containerized environments where dependencies are pre-installed
export SKIP_LIBOQS_CHECK=1
python -c "import openssl_encrypt"  # No dependency check
```

**LIBOQS_CHECK_VERBOSE** - Enable verbose output for dependency checks
```bash
# Shows detailed status even when dependencies are satisfied
export LIBOQS_CHECK_VERBOSE=1
python -c "import openssl_encrypt"
# Output:
# ✓ liboqs dependencies satisfied:
#   ✓ liboqs 0.12.0
#   ✓ liboqs-python 0.12.0
```

### Import-Time Dependency Checking

The package automatically checks dependencies when imported:

```python
import openssl_encrypt  # Checks dependencies on first import
```

If dependencies are missing:
- **Non-interactive**: Shows warning message with installation instructions
- **Interactive terminal**: Offers to build dependencies automatically
  ```
  WARNING: liboqs dependencies not satisfied
  ✗ liboqs not found via pkg-config
  ✗ liboqs-python not installed

  Would you like to build dependencies now? (y/N):
  ```

This check runs once per Python process and can be disabled with `SKIP_LIBOQS_CHECK=1`.

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

**Note about editable installs:**
- The setup process automatically checks and builds dependencies during installation
- Due to PEP 517 isolated builds, `pip install -e .` may not show build output in real-time
- Dependencies ARE being checked - they're just not visible during pip's isolated build
- To see verbose output, import the package after installation:
  ```bash
  LIBOQS_CHECK_VERBOSE=1 python -c "import openssl_encrypt"
  ```
- Or use `python setup.py develop` to see all build output (requires setuptools)

**Manual dependency build for developers:**
```bash
# Run the build script directly with environment control
export LIBOQS_VERSION=0.12.0
export LIBOQS_PYTHON_VERSION=0.12.0
export LIBOQS_INSTALL_PREFIX=$HOME/.local
bash scripts/build_local_deps.sh
```

## Troubleshooting

### Missing setuptools

**Problem:** `ModuleNotFoundError: No module named 'setuptools'` when running `setup.py` directly

```bash
# Install setuptools in your environment
pip install setuptools wheel
```

Note: This is only needed if you run `setup.py` directly. Regular `pip install` handles this automatically.

### Dependencies not being built

**Problem:** Ran `pip install` but dependencies weren't built

Check if dependencies are already installed with correct versions:
```bash
pkg-config --modversion liboqs  # Should show 0.12.0
python -c "import oqs; print(oqs.oqs_python_version())"  # Should show 0.12.0
```

If correct versions are already installed, the build is automatically skipped. To force rebuild:
```bash
# Remove existing installations
pip uninstall liboqs-python
rm -rf $HOME/.local/lib/liboqs* $HOME/.local/include/oqs

# Reinstall
pip install --force-reinstall --no-cache-dir openssl_encrypt
```

### Import warnings about dependencies

**Problem:** Warning messages appear when importing openssl_encrypt

This is normal if dependencies are missing. The package will still import but post-quantum features won't work.

To suppress the check (not recommended):
```bash
export SKIP_LIBOQS_CHECK=1
```

To see more details:
```bash
export LIBOQS_CHECK_VERBOSE=1
python -c "import openssl_encrypt"
```

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
