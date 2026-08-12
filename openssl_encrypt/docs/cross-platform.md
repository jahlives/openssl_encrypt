# Cross-Platform Installation and Build Guide

This documentation explains how to install and build openssl_encrypt for Windows, macOS, and Linux.

> **The desktop GUI now lives in its own project.** The Flutter GUI is
> maintained and released separately as **openssl_encrypt_gui**
> (https://gitlab.rm-rf.ch/world/openssl_encrypt_gui) and is no longer built
> from this repository. Where sections below say `cd desktop_gui` and
> `flutter build …`, run those in a checkout of `openssl_encrypt_gui` instead;
> its README is the source of truth for building the GUI on each platform. This
> repository builds the CLI only. The combined GUI + CLI Flatpak is also built
> from `openssl_encrypt_gui`.

## Overview

| Platform | Build System | CLI Packaging | Native Deps |
|----------|--------------|---------------|-------------|
| Linux (Flatpak) | flatpak-builder | Python directly | liboqs from source |
| Linux (Source) | pip install | Python package | liboqs from source |
| Windows | pip install / PyInstaller (optional) | Python package or standalone | liboqs with MSVC |
| macOS | pip install / PyInstaller (optional) | Python package or standalone | liboqs with clang |

## Installation Methods

There are multiple ways to install openssl_encrypt, from easiest to most advanced:

### Option 1: Flatpak (Recommended for Linux)
```bash
# Add the repository
flatpak remote-add --if-not-exists openssl-encrypt https://flatpak.rm-rf.ch/openssl-encrypt.flatpakrepo

# Install
flatpak install openssl-encrypt com.opensslencrypt.OpenSSLEncrypt
```
Includes all dependencies (Python, liboqs, Flutter GUI) in a sandboxed environment.

### Option 2: Install from PyPI (Easiest for Windows/macOS)
```bash
pip install openssl-encrypt
```
Note: This provides core functionality but does not include post-quantum algorithms (requires building liboqs separately).

### Option 3: Install from Source (Recommended for Full Features)
```bash
# Clone the repository
git clone https://github.com/jahlives/openssl_encrypt.git
# Alternative: git clone https://gitlab.rm-rf.ch/world/openssl_encrypt.git

cd openssl_encrypt

# Install dependencies and the package
pip install -r requirements-prod.txt
pip install .
```
Requires building liboqs separately for post-quantum support (see platform-specific instructions below).

### Option 4: Build Standalone Executables (Advanced)
For users who want a single-file executable without Python installed, follow the platform-specific build instructions below using PyInstaller.

## Local Building

### Windows (PowerShell as Admin)

```powershell
# 1. Install Visual Studio Build Tools
# https://visualstudio.microsoft.com/visual-cpp-build-tools/
# Select "Desktop development with C++" workload

# 2. Install Python 3.11 or newer (3.11–3.14 supported)
# https://www.python.org/downloads/

# 3. Build liboqs
git clone --branch 0.12.0 https://github.com/open-quantum-safe/liboqs.git
cd liboqs
mkdir build && cd build
cmake .. -G "NMake Makefiles" `
    -DCMAKE_BUILD_TYPE=Release `
    -DBUILD_SHARED_LIBS=ON `
    -DOQS_BUILD_ONLY_LIB=ON `
    -DOQS_DIST_BUILD=ON `
    -DOQS_USE_OPENSSL=OFF `
    -DCMAKE_INSTALL_PREFIX=C:\liboqs
nmake
nmake install
cd ..\..

# 4. Clone openssl_encrypt repository
git clone https://github.com/jahlives/openssl_encrypt.git
# Alternative: git clone https://gitlab.rm-rf.ch/world/openssl_encrypt.git
cd openssl_encrypt

# 5. Install liboqs-python against the built liboqs
# IMPORTANT: Set environment variables BEFORE running pip install
$env:LIBOQS_INSTALL_PATH = "C:\liboqs"
$env:CMAKE_PREFIX_PATH = "C:\liboqs"
$env:CFLAGS = "-IC:\liboqs\include"
$env:LDFLAGS = "-LC:\liboqs\lib"

# Build liboqs-python from source (uses the set variables)
pip install git+https://github.com/open-quantum-safe/liboqs-python.git@0.12.0

# Verify it works
python -c "import oqs; print(oqs.get_enabled_kem_mechanisms())"

# 6. Install remaining Python dependencies
pip install -r requirements-prod.txt
pip install .

# 7. (Optional) Create PyInstaller bundle for standalone executable
# Skip this if you just want to use the package directly
pip install pyinstaller
pyinstaller --onefile openssl_encrypt/crypt.py --name openssl-encrypt `
    --add-binary "C:\liboqs\bin\oqs.dll;."

# 8. Build Flutter GUI
cd desktop_gui
flutter build windows --release
```

### macOS

```bash
# 1. Install Xcode Command Line Tools
xcode-select --install

# 2. Install dependencies
brew install cmake ninja openssl

# 3. Build liboqs
git clone --branch 0.12.0 https://github.com/open-quantum-safe/liboqs.git
cd liboqs && mkdir build && cd build
cmake .. -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_SHARED_LIBS=ON \
    -DOQS_BUILD_ONLY_LIB=ON \
    -DOQS_DIST_BUILD=ON \
    -DOQS_USE_OPENSSL=ON \
    -DCMAKE_INSTALL_PREFIX=/usr/local/liboqs
ninja
sudo ninja install
cd ../..

# 4. Clone openssl_encrypt repository
git clone https://github.com/jahlives/openssl_encrypt.git
# Alternative: git clone https://gitlab.rm-rf.ch/world/openssl_encrypt.git
cd openssl_encrypt

# 5. Install liboqs-python against the built liboqs
# IMPORTANT: Set environment variables BEFORE running pip install
export LIBOQS_INSTALL_PATH=/usr/local/liboqs
export CMAKE_PREFIX_PATH=/usr/local/liboqs
export CFLAGS="-I/usr/local/liboqs/include"
export LDFLAGS="-L/usr/local/liboqs/lib"
export DYLD_LIBRARY_PATH=/usr/local/liboqs/lib:$DYLD_LIBRARY_PATH

# Build liboqs-python from source
pip install git+https://github.com/open-quantum-safe/liboqs-python.git@0.12.0

# Verify it works
python -c "import oqs; print(oqs.get_enabled_kem_mechanisms())"

# 6. Install remaining Python dependencies
pip install -r requirements-prod.txt
pip install .

# 7. (Optional) Create PyInstaller bundle for standalone executable
# Skip this if you just want to use the package directly
pip install pyinstaller
pyinstaller --onefile openssl_encrypt/crypt.py --name openssl-encrypt \
    --add-binary "/usr/local/liboqs/lib/liboqs.dylib:."

# 8. Build Flutter GUI
cd desktop_gui
flutter build macos --release
```

### Linux

```bash
# 1. Install dependencies
sudo apt update
sudo apt install -y cmake ninja-build libgtk-3-dev libssl-dev \
    libzbar0 libzbar-dev libpcsclite-dev

# 2. Build liboqs
git clone --branch 0.12.0 https://github.com/open-quantum-safe/liboqs.git
cd liboqs && mkdir build && cd build
cmake .. -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_SHARED_LIBS=ON \
    -DOQS_BUILD_ONLY_LIB=ON \
    -DOQS_DIST_BUILD=ON \
    -DOQS_USE_OPENSSL=ON \
    -DCMAKE_INSTALL_PREFIX=/usr/local/liboqs
ninja
sudo ninja install
cd ../..

# 3. Clone openssl_encrypt repository
git clone https://github.com/jahlives/openssl_encrypt.git
# Alternative: git clone https://gitlab.rm-rf.ch/world/openssl_encrypt.git
cd openssl_encrypt

# 4. Install liboqs-python against the built liboqs
export LIBOQS_INSTALL_PATH=/usr/local/liboqs
export CMAKE_PREFIX_PATH=/usr/local/liboqs
export CFLAGS="-I/usr/local/liboqs/include"
export LDFLAGS="-L/usr/local/liboqs/lib"
export LD_LIBRARY_PATH=/usr/local/liboqs/lib:$LD_LIBRARY_PATH

# Build liboqs-python from source
pip install git+https://github.com/open-quantum-safe/liboqs-python.git@0.12.0

# Verify it works
python -c "import oqs; print(oqs.get_enabled_kem_mechanisms())"

# 5. Install remaining Python dependencies
pip install -r requirements-prod.txt
pip install .

# 6. (Optional) Create PyInstaller bundle for standalone executable
# Skip this if you just want to use the package directly
pip install pyinstaller
pyinstaller --onefile openssl_encrypt/crypt.py --name openssl-encrypt \
    --add-binary "/usr/local/liboqs/lib/liboqs.so:." \
    --add-binary "/usr/local/liboqs/lib/liboqs.so.6:."

# 7. Build Flutter GUI
cd desktop_gui
flutter build linux --release

# 8. Or simply build Flatpak (recommended):
cd flatpak
./build-flatpak.sh --build-flutter --local-install
```

### Troubleshooting: liboqs-python

If `import oqs` fails:

```bash
# Check if the library is found
# Linux:
ldd $(python -c "import oqs; print(oqs.__file__)")
export LD_LIBRARY_PATH=/usr/local/liboqs/lib:$LD_LIBRARY_PATH

# macOS:
otool -L $(python -c "import oqs; print(oqs.__file__)")
export DYLD_LIBRARY_PATH=/usr/local/liboqs/lib:$DYLD_LIBRARY_PATH

# Windows (PowerShell):
$env:PATH = "C:\liboqs\bin;$env:PATH"
```

If the build fails:

```bash
# Ensure cmake can find liboqs
cmake --find-package -DNAME=liboqs -DCOMPILER_ID=GNU -DLANGUAGE=C -DMODE=EXIST

# Manually specify the path
pip install --no-cache-dir \
    --config-settings=cmake.define.liboqs_DIR=/usr/local/liboqs/lib/cmake/liboqs \
    git+https://github.com/open-quantum-safe/liboqs-python.git@0.12.0
```

## Known Issues

### Windows

- **YubiKey/HSM**: PCSC support must be installed separately
- **Paths**: Long paths can cause problems (Windows limit)
- **RandomX**: Should work, but performance may vary depending on CPU features (AVX2)

### macOS

- **Gatekeeper**: Unsigned apps are blocked → Right-click → Open
- **ARM vs Intel**: The build is currently ARM64 only (M1/M2/M3)
- **liboqs dylib**: Must be embedded in the App Bundle

### General

- **liboqs-python**: Must be built against the correct liboqs version
- **PyInstaller**: Hidden imports must be explicitly specified
- **Large bundles**: ~100-150MB per platform due to Python runtime

## Dependency Matrix

```
openssl_encrypt
├── Python 3.11+
│   ├── cryptography (OpenSSL bindings)
│   ├── argon2-cffi (KDF)
│   ├── blake3 (Hash)
│   ├── liboqs-python → liboqs (C library)
│   │   └── HQC, ML-KEM, CROSS, MAYO
│   ├── PyYAML
│   ├── Pillow, qrcode, pyzbar (Steganography)
│   └── RandomX (optional, Anti-ASIC KDF)
└── Flutter GUI
    └── Dart
```
