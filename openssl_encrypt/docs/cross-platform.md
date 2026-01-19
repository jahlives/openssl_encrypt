# Cross-Platform Build Guide

This documentation explains how to build openssl_encrypt for Windows, macOS, and Linux.

## Overview

| Platform | Build System | CLI Packaging | Native Deps |
|----------|--------------|---------------|-------------|
| Linux (Flatpak) | flatpak-builder | Python directly | liboqs from source |
| Linux (Tarball) | GitHub Actions | PyInstaller | liboqs from source |
| Windows | GitHub Actions | PyInstaller | liboqs with MSVC |
| macOS | GitHub Actions | PyInstaller | liboqs with clang |

## Local Building

### Windows (PowerShell as Admin)

```powershell
# 1. Install Visual Studio Build Tools
# https://visualstudio.microsoft.com/visual-cpp-build-tools/
# Select "Desktop development with C++" workload

# 2. Install Python 3.12
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

# 4. Install liboqs-python against the built liboqs
# IMPORTANT: Set environment variables BEFORE running pip install
$env:LIBOQS_INSTALL_PATH = "C:\liboqs"
$env:CMAKE_PREFIX_PATH = "C:\liboqs"
$env:CFLAGS = "-IC:\liboqs\include"
$env:LDFLAGS = "-LC:\liboqs\lib"

# Build liboqs-python from source (uses the set variables)
pip install git+https://github.com/open-quantum-safe/liboqs-python.git@0.12.0

# Verify it works
python -c "import oqs; print(oqs.get_enabled_kem_mechanisms())"

# 5. Install remaining Python dependencies
pip install -r requirements-prod.txt
pip install .

# 6. Create PyInstaller bundle
pip install pyinstaller
pyinstaller --onefile openssl_encrypt/crypt.py --name openssl-encrypt `
    --add-binary "C:\liboqs\bin\oqs.dll;."

# 7. Build Flutter GUI
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

# 4. Install liboqs-python against the built liboqs
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

# 5. Install remaining Python dependencies
pip install -r requirements-prod.txt
pip install .

# 6. Create PyInstaller bundle
pip install pyinstaller
pyinstaller --onefile openssl_encrypt/crypt.py --name openssl-encrypt \
    --add-binary "/usr/local/liboqs/lib/liboqs.dylib:."

# 7. Build Flutter GUI
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

# 3. Install liboqs-python against the built liboqs
export LIBOQS_INSTALL_PATH=/usr/local/liboqs
export CMAKE_PREFIX_PATH=/usr/local/liboqs
export CFLAGS="-I/usr/local/liboqs/include"
export LDFLAGS="-L/usr/local/liboqs/lib"
export LD_LIBRARY_PATH=/usr/local/liboqs/lib:$LD_LIBRARY_PATH

# Build liboqs-python from source
pip install git+https://github.com/open-quantum-safe/liboqs-python.git@0.12.0

# Verify it works
python -c "import oqs; print(oqs.get_enabled_kem_mechanisms())"

# 4. Install remaining Python dependencies
pip install -r requirements-prod.txt
pip install .

# 5. Create PyInstaller bundle (optional, Flatpak is recommended)
pip install pyinstaller
pyinstaller --onefile openssl_encrypt/crypt.py --name openssl-encrypt \
    --add-binary "/usr/local/liboqs/lib/liboqs.so:." \
    --add-binary "/usr/local/liboqs/lib/liboqs.so.6:."

# 6. Build Flutter GUI
cd desktop_gui
flutter build linux --release

# 7. Or simply build Flatpak (recommended):
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
├── Python 3.12
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
