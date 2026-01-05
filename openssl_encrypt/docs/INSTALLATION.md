# Installation Guide

## 🚀 Quick Install (Recommended for Most Users)

**Want to get started immediately without build tools?** Use Flatpak:

```bash
# Download and install (all dependencies included)
flatpak install --user https://gitlab.rm-rf.ch/world/openssl_encrypt/-/packages/latest/openssl-encrypt-flatpak.flatpak

# Run GUI
flatpak run com.opensslencrypt.OpenSSLEncrypt --gui

# Or CLI
flatpak run com.opensslencrypt.OpenSSLEncrypt encrypt -i myfile.txt
```

- ✅ **All crypto libraries pre-built** (no cmake, gcc, or rust needed)
- ✅ **Sandboxed and secure** (isolated from system)
- ✅ **Automatic updates** available
- ✅ **Works immediately** on any Linux distribution

📖 **Details:** See [Method 4: Flatpak Installation](#method-4-flatpak-installation-containerized)

---

## Table of Contents
- [Quick Install](#-quick-install-recommended-for-most-users)
- [Prerequisites](#prerequisites)
- [Installation Methods](#installation-methods)
  - [Method 1: PyPI + install-dependencies](#method-1-pypi--install-dependencies)
  - [Method 2: Local Development Install](#method-2-local-development-install)
  - [Method 3: Manual Dependency Build](#method-3-manual-dependency-build)
  - [Method 4: Flatpak Installation (Containerized)](#method-4-flatpak-installation-containerized)
- [Virtual Environment](#virtual-environment)
- [Verification](#verification)
- [Advanced Configuration](#advanced-configuration)
- [Troubleshooting](#troubleshooting)

---

## Prerequisites

### Build Tools Required

Before installing, ensure you have the following build tools installed:

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install -y \
    cmake ninja-build \
    libssl-dev python3-dev \
    git gcc g++ \
    rustc cargo  # For Threefish cipher (optional)
```

**Fedora/RHEL:**
```bash
sudo dnf install -y \
    cmake ninja-build \
    openssl-devel python3-devel \
    git gcc-c++ \
    rust cargo  # For Threefish cipher (optional)
```

**macOS:**
```bash
brew install cmake ninja openssl git
# Rust for Threefish (optional)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

### Recommended: Use Virtual Environment

**We strongly recommend using a virtual environment** to avoid conflicts with system packages:

```bash
# Create virtual environment
python3 -m venv ~/.venvs/openssl_encrypt

# Activate it
source ~/.venvs/openssl_encrypt/bin/activate

# Your prompt will change to show: (.venvs/openssl_encrypt) user@host:~$
```

To deactivate later:
```bash
deactivate
```

> **Note:** All installation commands below assume you're in an activated virtual environment.
> If you choose to install system-wide (not recommended), you may need `--user` flag or `sudo`.

---

## Installation Methods

### Method 1: PyPI + install-dependencies (Recommended)

This is the **preferred approach** for most users. It installs the base package first, then builds optional crypto libraries.

#### Step 1: Install Base Package

```bash
# In activated venv
pip install openssl_encrypt
```

This installs:
- ✅ Core encryption functionality (AES, ChaCha20, etc.)
- ✅ All Python dependencies
- ⏭️ **Skips** post-quantum (liboqs) and Threefish (requires build tools)

#### Step 2: Install Optional Crypto Libraries

```bash
openssl-encrypt install-dependencies
```

Or non-interactively:
```bash
openssl-encrypt install-dependencies --yes
```

This command will:
1. ✅ Check for required build tools (cmake, ninja, gcc, cargo)
2. ✅ Build and install **liboqs 0.12.0** (post-quantum cryptography)
3. ✅ Build and install **liboqs-python 0.12.0** (Python bindings)
4. ✅ Build and install **threefish_native** (large-block cipher)
5. ✅ Prompt to add environment variables to your shell profile

**Interactive shell profile setup:**
```
Would you like to automatically add these to ~/.bashrc? (y/N): y
✓ Environment variables added to ~/.bashrc

To apply changes immediately, run:
  source ~/.bashrc
```

#### Step 3: Apply Environment Variables

```bash
source ~/.bashrc  # or ~/.zshrc
```

**What gets added to your shell profile:**
```bash
# openssl_encrypt liboqs paths (added by build_local_deps.sh)
export LD_LIBRARY_PATH="$HOME/.local/lib64:$LD_LIBRARY_PATH"
export PKG_CONFIG_PATH="$HOME/.local/lib64/pkgconfig:$PKG_CONFIG_PATH"
```

> **Note:** The script automatically detects whether `lib` or `lib64` is used on your system.

#### Advantages of This Method
- ✅ Fastest to get started (base package installs in seconds)
- ✅ Can use core features immediately without build tools
- ✅ Interactive setup guides you through environment configuration
- ✅ Easy to retry if build fails
- ✅ Clear separation between base and optional features

---

### Method 2: Local Development Install

For contributors or users who want to modify the code:

#### Step 1: Clone Repository

```bash
git clone https://gitlab.rm-rf.ch/world/openssl_encrypt.git
cd openssl_encrypt
```

#### Step 2: Create and Activate Virtual Environment

```bash
# Create venv in project directory
python3 -m venv .venv

# Activate it
source .venv/bin/activate
```

#### Step 3: Install in Editable Mode

```bash
# Install package in editable/development mode
pip install -e .

# Or with dev dependencies (testing, linting, etc.)
pip install -e ".[dev]"
```

This installs the base package. Crypto libraries are NOT built automatically during `pip install -e .`.

#### Step 4: Build Crypto Libraries

```bash
# Option A: Use the install-dependencies command (recommended)
openssl-encrypt install-dependencies --yes

# Option B: Run build script directly
./scripts/build_local_deps.sh
```

#### Step 5: Apply Environment Variables

```bash
source ~/.bashrc  # After adding paths in Step 4
```

#### Development Workflow
```bash
# Make changes to code
vim openssl_encrypt/modules/crypt_core.py

# Changes are immediately available (editable install)
python3 -m openssl_encrypt encrypt -i myfile.txt

# Run tests
pytest tests/

# Run linters
black openssl_encrypt/
pylint openssl_encrypt/
```

---

### Method 3: Manual Dependency Build

For advanced users who want full control over the build process:

#### Step 1: Build liboqs (C library)

```bash
# Clone liboqs
git clone --branch 0.12.0 https://github.com/open-quantum-safe/liboqs.git
cd liboqs

# Configure with CMake
mkdir build && cd build
cmake -GNinja \
    -DCMAKE_INSTALL_PREFIX=$HOME/.local \
    -DBUILD_SHARED_LIBS=ON \
    -DCMAKE_BUILD_TYPE=Release \
    -DOQS_USE_OPENSSL=ON \
    ..

# Build and install
ninja
ninja install

cd ../..
```

**Verify liboqs installation:**
```bash
# Should show: 0.12.0
pkg-config --modversion liboqs

# Or search common paths
ls -la ~/.local/lib64/liboqs.so*
ls -la ~/.local/include/oqs/
```

#### Step 2: Build liboqs-python (Python bindings)

```bash
# Set environment for build (adjust lib64 vs lib for your system)
export PKG_CONFIG_PATH="$HOME/.local/lib64/pkgconfig:$HOME/.local/lib/pkgconfig:$PKG_CONFIG_PATH"
export LD_LIBRARY_PATH="$HOME/.local/lib64:$HOME/.local/lib:$LD_LIBRARY_PATH"

# Install liboqs-python from git
pip install "git+https://github.com/open-quantum-safe/liboqs-python.git@0.12.0"
```

**Verify liboqs-python:**
```bash
python3 -c "import oqs; print(f'liboqs-python: {oqs.oqs_python_version()}')"
# Should output: liboqs-python: 0.12.0
```

#### Step 3: Build Threefish (Rust extension)

Threefish provides 256-bit and 512-bit post-quantum security levels.

**Prerequisites:**
```bash
# Install Rust toolchain if not already installed
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
```

**Build and install:**
```bash
# Navigate to threefish directory
cd openssl_encrypt/threefish_native

# Build with maturin
pip install maturin
maturin develop --release

# Or build wheel for distribution
maturin build --release
pip install target/wheels/openssl_encrypt_threefish-*.whl

cd ../..
```

**Verify Threefish:**
```bash
python3 -c "import threefish_native; print('Threefish: OK')"
```

#### Step 4: Install openssl_encrypt

```bash
# If using venv
pip install openssl_encrypt

# Or for development
pip install -e .
```

#### Step 5: Add Environment Variables to Shell Profile

Add to `~/.bashrc` or `~/.zshrc`:

```bash
# openssl_encrypt liboqs paths
export LD_LIBRARY_PATH="$HOME/.local/lib64:$HOME/.local/lib:$LD_LIBRARY_PATH"
export PKG_CONFIG_PATH="$HOME/.local/lib64/pkgconfig:$HOME/.local/lib/pkgconfig:$PKG_CONFIG_PATH"

# For macOS, also add:
# export DYLD_LIBRARY_PATH="$HOME/.local/lib64:$HOME/.local/lib:$DYLD_LIBRARY_PATH"
```

**Apply changes:**
```bash
source ~/.bashrc  # or source ~/.zshrc
```

---

### Method 4: Flatpak Installation (Containerized)

**Best for:** Users who want a complete, self-contained installation without build tools

Flatpak provides a sandboxed application with all dependencies pre-built and included.

#### What's Included

- ✅ All post-quantum cryptography libraries (liboqs, liboqs-python)
- ✅ Threefish cipher support
- ✅ Flutter GUI with native Wayland/X11 support
- ✅ All Python dependencies
- ✅ Isolated from system packages (sandbox security)

#### Installation Options

**Option 1: Download from Package Registry (Recommended)**

1. **Download the latest package:**
   - Visit: https://gitlab.rm-rf.ch/world/openssl_encrypt/-/packages
   - Find the latest `openssl-encrypt-flatpak` package
   - Download the `.flatpak` file

2. **Install the downloaded package:**
   ```bash
   flatpak install --user com.opensslencrypt.OpenSSLEncrypt.flatpak
   ```

3. **Run the application:**
   ```bash
   # GUI mode (Flutter desktop app)
   flatpak run com.opensslencrypt.OpenSSLEncrypt --gui

   # CLI mode
   flatpak run com.opensslencrypt.OpenSSLEncrypt --help

   # Encrypt a file
   flatpak run com.opensslencrypt.OpenSSLEncrypt encrypt -i myfile.txt

   # Decrypt a file
   flatpak run com.opensslencrypt.OpenSSLEncrypt decrypt -i myfile.txt.enc
   ```

**Option 2: Add as Flatpak Remote Repository**

For automatic updates:

```bash
# Add the repository
flatpak remote-add --user openssl-encrypt-repo \
  https://gitlab.rm-rf.ch/world/openssl_encrypt/-/jobs/artifacts/main/raw/flatpak/public/repo?job=create-repository

# Install from repository
flatpak install --user openssl-encrypt-repo com.opensslencrypt.OpenSSLEncrypt

# Get automatic updates later
flatpak update com.opensslencrypt.OpenSSLEncrypt
```

**Option 3: Direct Install via URL**

```bash
# Install directly from URL (requires GitLab access)
flatpak install --user \
  https://gitlab.rm-rf.ch/world/openssl_encrypt/-/packages/latest/openssl-encrypt-flatpak.flatpak
```

**Option 4: Install via wget/curl**

```bash
# Download latest package
VERSION=$(curl -s "https://gitlab.rm-rf.ch/api/v4/projects/world%2Fopenssl_encrypt/packages" | \
          grep -o '"version":"[^"]*"' | head -1 | cut -d'"' -f4)

wget "https://gitlab.rm-rf.ch/world/openssl_encrypt/-/packages/generic/openssl-encrypt-flatpak/${VERSION}/com.opensslencrypt.OpenSSLEncrypt.flatpak"

# Install
flatpak install --user com.opensslencrypt.OpenSSLEncrypt.flatpak
```

#### Prerequisites

Before installing Flatpak packages, ensure Flatpak is installed on your system:

**Ubuntu/Debian:**
```bash
sudo apt install flatpak
```

**Fedora/RHEL:**
```bash
sudo dnf install flatpak
```

**Arch Linux:**
```bash
sudo pacman -S flatpak
```

**Add Flathub for runtime dependencies:**
```bash
flatpak remote-add --if-not-exists flathub https://flathub.org/repo/flathub.flatpakrepo
```

#### Creating a Shell Alias (Optional)

For convenience, create an alias to use like a native command:

```bash
# Add to ~/.bashrc or ~/.zshrc
alias openssl-encrypt='flatpak run com.opensslencrypt.OpenSSLEncrypt'

# After sourcing your profile:
openssl-encrypt encrypt -i myfile.txt
openssl-encrypt --gui
```

#### Flatpak-Specific Features

**GUI Mode:**
The Flatpak includes a Flutter desktop application with:
- Native Wayland and X11 support
- Drag & drop file operations
- Real-time progress monitoring
- Configuration profiles
- Dark/light theme switching

**Sandboxing:**
The application runs in a secure sandbox with limited system access:
- Read/write access to your home directory
- Network access (for keyserver features)
- GPU acceleration for rendering
- Sound system access

**HSM/YubiKey Support:**
To use hardware security modules:
```bash
# Grant USB device access
flatpak override --user com.opensslencrypt.OpenSSLEncrypt \
  --device=<device-path>

# Example: YubiKey
flatpak override --user com.opensslencrypt.OpenSSLEncrypt \
  --device=/dev/bus/usb/001/002
```

#### Advantages of Flatpak

- ✅ **Zero build time** - Everything pre-compiled
- ✅ **No dependencies** - Self-contained package
- ✅ **Automatic updates** - Via Flatpak system
- ✅ **Sandboxed security** - Isolated from system
- ✅ **Cross-distribution** - Works on any Linux distro
- ✅ **No conflicts** - Doesn't affect system packages
- ✅ **GUI included** - Flutter desktop app pre-installed

#### Disadvantages

- ⚠️ **Larger download** - Includes all dependencies (~200-300MB)
- ⚠️ **Slower startup** - Sandbox initialization overhead
- ⚠️ **Limited system integration** - Runs in isolated environment
- ⚠️ **No editable install** - Not suitable for development

#### Troubleshooting Flatpak

**GUI mode fails with display errors:**
```bash
# For X11 systems, allow local connections
xhost +local:

# Then run GUI mode
flatpak run com.opensslencrypt.OpenSSLEncrypt --gui
```

**Permission denied downloading packages:**
- Ensure you're logged into GitLab
- For CLI access, create a Personal Access Token with `read_api` scope
- Use token in wget: `--header="PRIVATE-TOKEN: your_token"`

**Flatpak command not found:**
```bash
# Install Flatpak first (see Prerequisites above)
```

**Access to files outside home directory:**
```bash
# Grant access to specific directory
flatpak override --user com.opensslencrypt.OpenSSLEncrypt \
  --filesystem=/path/to/directory
```

**HSM/YubiKey not detected:**
```bash
# List USB devices
lsusb

# Grant access to specific device
flatpak override --user com.opensslencrypt.OpenSSLEncrypt \
  --device=/dev/bus/usb/<bus>/<device>

# Or grant all USB access (less secure)
flatpak override --user com.opensslencrypt.OpenSSLEncrypt \
  --device=all
```

#### Uninstalling Flatpak

```bash
# Remove the application
flatpak uninstall --user com.opensslencrypt.OpenSSLEncrypt

# Remove repository (if added)
flatpak remote-delete --user openssl-encrypt-repo

# Clean up unused runtimes
flatpak uninstall --unused
```

---

## Virtual Environment

### Why Use a Virtual Environment?

- ✅ **Isolated dependencies** - No conflicts with system packages
- ✅ **Easy cleanup** - Just delete the venv directory
- ✅ **Reproducible** - Consistent environment across machines
- ✅ **No sudo required** - Install packages without admin rights
- ✅ **Multiple versions** - Run different versions side-by-side

### Creating a Virtual Environment

```bash
# Method 1: In project directory (for development)
cd openssl_encrypt
python3 -m venv .venv
source .venv/bin/activate

# Method 2: In dedicated venv directory (for regular use)
python3 -m venv ~/.venvs/openssl_encrypt
source ~/.venvs/openssl_encrypt/bin/activate
```

### Managing Virtual Environments

```bash
# Activate venv
source ~/.venvs/openssl_encrypt/bin/activate

# Your prompt shows the active venv
(openssl_encrypt) user@host:~$

# Deactivate when done
deactivate

# Delete venv (complete uninstall)
rm -rf ~/.venvs/openssl_encrypt
```

### Installing Without Virtual Environment (Not Recommended)

If you choose to install system-wide or user-wide **without** a venv:

**User installation (no sudo required):**
```bash
pip install --user openssl_encrypt
openssl-encrypt install-dependencies --yes
```

**System-wide installation (requires sudo):**
```bash
sudo pip install openssl_encrypt
sudo openssl-encrypt install-dependencies --yes
```

⚠️ **Warning:** System-wide installation can:
- Conflict with distribution packages
- Break system tools that depend on specific versions
- Require sudo for updates/uninstall
- Make debugging harder

---

## Verification

### Check All Dependencies

```bash
# Comprehensive dependency check
python3 -m openssl_encrypt.versions
```

**Expected output:**
```
Checking openssl_encrypt dependencies...
==================================================
✓ liboqs 0.12.0
✓ liboqs-python 0.12.0
==================================================

✓ All dependencies satisfied
```

Or use the CLI command:
```bash
openssl-encrypt-check-deps
```

### Test Post-Quantum Algorithms

```bash
# List all available algorithms
openssl-encrypt list-available-algorithms | jq '.kems'

# Create a test encryption with ML-KEM
echo "test" > test.txt
openssl-encrypt encrypt -i test.txt --kem ml-kem-768 --sig ml-dsa-65
openssl-encrypt decrypt -i test.txt.enc -o decrypted.txt
diff test.txt decrypted.txt && echo "✓ Post-quantum encryption works!"
```

### Test Threefish Cipher

```bash
# List Threefish algorithms
openssl-encrypt list-available-algorithms | jq '.ciphers | with_entries(select(.key | contains("threefish")))'

# Test Threefish-512 encryption
echo "test" > test.txt
openssl-encrypt encrypt -i test.txt -c threefish-512
openssl-encrypt decrypt -i test.txt.enc -o decrypted.txt
diff test.txt decrypted.txt && echo "✓ Threefish cipher works!"
```

---

## Advanced Configuration

### Environment Variables

**SKIP_LIBOQS_CHECK** - Skip automatic dependency checking on import
```bash
# Useful for CI/CD or containerized environments
export SKIP_LIBOQS_CHECK=1
python3 -c "import openssl_encrypt"  # No dependency check
```

**LIBOQS_CHECK_VERBOSE** - Enable verbose output for dependency checks
```bash
# Shows detailed status even when dependencies are satisfied
export LIBOQS_CHECK_VERBOSE=1
python3 -c "import openssl_encrypt"
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

---

## Troubleshooting

### Cleanup Script

If you encounter issues or want to start fresh:

```bash
# Use the cleanup script to remove all liboqs installations
./scripts/cleanup_liboqs.sh
```

This will:
1. Scan for all liboqs and liboqs-python installations
2. Show what will be removed
3. Ask for confirmation
4. Remove pip packages and system libraries
5. Verify cleanup

### Common Issues

#### 1. "liboqs not found via pkg-config" (False Warning)

**Symptoms:** Warning appears but post-quantum algorithms work fine

**Cause:** PKG_CONFIG_PATH not set, but Python detection works

**Solution:** The package now automatically searches common paths. If you still see this:
```bash
# Add to shell profile
export PKG_CONFIG_PATH="$HOME/.local/lib64/pkgconfig:$HOME/.local/lib/pkgconfig:$PKG_CONFIG_PATH"
source ~/.bashrc
```

#### 2. "ImportError: liboqs.so.7: cannot open shared object file"

**Cause:** LD_LIBRARY_PATH not set

**Solution:**
```bash
# Temporary fix
export LD_LIBRARY_PATH="$HOME/.local/lib64:$HOME/.local/lib:$LD_LIBRARY_PATH"

# Permanent fix - add to ~/.bashrc
echo 'export LD_LIBRARY_PATH="$HOME/.local/lib64:$HOME/.local/lib:$LD_LIBRARY_PATH"' >> ~/.bashrc
source ~/.bashrc
```

#### 3. Version Mismatch

**Problem:** Wrong version of liboqs or liboqs-python installed

**Solution:**
```bash
# Use cleanup script
./scripts/cleanup_liboqs.sh

# Reinstall
openssl-encrypt install-dependencies --yes
```

#### 4. Build Tools Missing

**Problem:** cmake, ninja, or gcc not found

**Ubuntu/Debian:**
```bash
sudo apt-get install cmake ninja-build gcc g++ git
```

**Fedora/RHEL:**
```bash
sudo dnf install cmake ninja-build gcc-c++ git
```

**macOS:**
```bash
brew install cmake ninja git
xcode-select --install  # For gcc/clang
```

#### 5. Rust/Cargo Missing (for Threefish)

**Problem:** cargo: command not found

**Solution:**
```bash
# Install Rust toolchain
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env

# Verify
rustc --version
cargo --version
```

#### 6. Permission Denied During Build

**Problem:** Permission errors when building liboqs

**Solution:** The build installs to `~/.local` (no sudo required). If you see permission errors:
```bash
# Ensure .local directory is writable
mkdir -p ~/.local/{lib,lib64,include,bin}
chmod -R u+w ~/.local

# Try again
openssl-encrypt install-dependencies --yes
```

#### 7. Virtual Environment Activation Issues

**Problem:** `source .venv/bin/activate` gives "Permission denied"

**Solution:**
```bash
# The activate script should be sourced, not executed
source .venv/bin/activate  # ✅ Correct
./.venv/bin/activate        # ❌ Wrong

# If file doesn't exist, recreate venv
rm -rf .venv
python3 -m venv .venv
source .venv/bin/activate
```

#### 8. Dependencies Not Being Built

**Problem:** Ran `pip install` but dependencies weren't built

**Explanation:** Check if dependencies are already installed with correct versions:
```bash
pkg-config --modversion liboqs  # Should show 0.12.0
python3 -c "import oqs; print(oqs.oqs_python_version())"  # Should show 0.12.0
```

If correct versions are already installed, the build is automatically skipped. To force rebuild:
```bash
# Remove existing installations
./scripts/cleanup_liboqs.sh

# Reinstall
openssl-encrypt install-dependencies --yes
```

#### 9. liboqs Build Fails

**Problem:** OpenSSL development headers not found

**Solution:**
```bash
# Ubuntu/Debian
sudo apt-get install libssl-dev

# Fedora/RHEL
sudo dnf install openssl-devel

# macOS
brew install openssl
```

#### 10. liboqs-python Build Fails

**Problem:** liboqs not found during liboqs-python build

**Solution:**
```bash
# Ensure PKG_CONFIG_PATH is set
export PKG_CONFIG_PATH="$HOME/.local/lib64/pkgconfig:$HOME/.local/lib/pkgconfig:$PKG_CONFIG_PATH"

# Verify liboqs is installed
pkg-config --modversion liboqs
ls -la ~/.local/lib64/liboqs.so*
```

---

## Docker Installation

For a clean, reproducible environment:

**Dockerfile:**
```dockerfile
FROM python:3.11-slim

# Install build dependencies
RUN apt-get update && apt-get install -y \
    cmake ninja-build libssl-dev git gcc g++ \
    rustc cargo \
    && rm -rf /var/lib/apt/lists/*

# Install openssl_encrypt base
RUN pip install --no-cache-dir openssl_encrypt

# Build optional crypto libraries
RUN openssl-encrypt install-dependencies --yes

# Set environment variables
ENV LD_LIBRARY_PATH="/root/.local/lib64:/root/.local/lib:$LD_LIBRARY_PATH"
ENV PKG_CONFIG_PATH="/root/.local/lib64/pkgconfig:/root/.local/lib/pkgconfig:$PKG_CONFIG_PATH"

# Verify installation
RUN python3 -m openssl_encrypt.versions

CMD ["openssl-encrypt", "--help"]
```

**Build and run:**
```bash
docker build -t openssl-encrypt .
docker run --rm openssl-encrypt openssl-encrypt list-available-algorithms
```

---

## CI/CD Integration

### GitHub Actions

```yaml
name: Test openssl-encrypt

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'

      - name: Install build dependencies
        run: |
          sudo apt-get update
          sudo apt-get install -y cmake ninja-build libssl-dev gcc g++ git
          curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
          source $HOME/.cargo/env

      - name: Install openssl_encrypt
        run: |
          pip install openssl_encrypt
          openssl-encrypt install-dependencies --yes

      - name: Set environment
        run: |
          echo "LD_LIBRARY_PATH=$HOME/.local/lib64:$HOME/.local/lib:$LD_LIBRARY_PATH" >> $GITHUB_ENV
          echo "PKG_CONFIG_PATH=$HOME/.local/lib64/pkgconfig:$HOME/.local/lib/pkgconfig:$PKG_CONFIG_PATH" >> $GITHUB_ENV

      - name: Verify installation
        run: |
          python3 -m openssl_encrypt.versions
          openssl-encrypt list-available-algorithms
```

### GitLab CI

```yaml
test:
  image: python:3.11
  before_script:
    - apt-get update
    - apt-get install -y cmake ninja-build libssl-dev gcc g++ git
    - curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    - source $HOME/.cargo/env
    - pip install openssl_encrypt
    - openssl-encrypt install-dependencies --yes
    - export LD_LIBRARY_PATH="$HOME/.local/lib64:$HOME/.local/lib:$LD_LIBRARY_PATH"
    - export PKG_CONFIG_PATH="$HOME/.local/lib64/pkgconfig:$HOME/.local/lib/pkgconfig:$PKG_CONFIG_PATH"
  script:
    - python3 -m openssl_encrypt.versions
    - openssl-encrypt list-available-algorithms
```

---

## Support

If you encounter issues:

1. Check the [Troubleshooting](#troubleshooting) section
2. Run the verification commands
3. Use the cleanup script: `./scripts/cleanup_liboqs.sh`
4. Open an issue at: https://gitlab.rm-rf.ch/world/openssl_encrypt/-/issues

Include the output of:
```bash
python3 -m openssl_encrypt.versions
pkg-config --modversion liboqs 2>&1
python3 -c "import oqs; print(oqs.oqs_python_version())" 2>&1
pip list | grep -iE "(liboqs|threefish|openssl.encrypt)"
echo "PKG_CONFIG_PATH=$PKG_CONFIG_PATH"
echo "LD_LIBRARY_PATH=$LD_LIBRARY_PATH"
```
