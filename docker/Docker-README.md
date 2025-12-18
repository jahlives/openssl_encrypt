# Docker Usage for openssl_encrypt

This directory contains Docker configuration for running openssl_encrypt in a containerized environment with full Post-Quantum Cryptography (PQC) support.

## Features

- **Complete PQC Support**: Includes liboqs library with ML-KEM, HQC, ML-DSA, SLH-DSA, and FN-DSA algorithms
- **Multi-stage Build**: Optimized for smaller runtime image (~200MB vs ~800MB build image)
- **Security**: Runs as non-root user
- **Persistent Storage**: Keystore data persists between container runs

## Quick Start

### 1. Build the Image

From the project root directory:
```bash
# Option 1: Use the build script (recommended)
docker/docker-build.sh

# Option 2: Build manually
docker build -f docker/Dockerfile -t openssl-encrypt:latest .
```

This script builds the Docker image with all PQC dependencies. The build process:
- Compiles liboqs from source for latest PQC algorithms
- Installs Python bindings
- Creates optimized runtime image

### 2. Basic Usage

```bash
# Encrypt a file
docker run --rm -v $(pwd):/data openssl-encrypt:latest encrypt myfile.txt

# Decrypt a file
docker run --rm -v $(pwd):/data openssl-encrypt:latest decrypt myfile.txt.enc

# Use Post-Quantum algorithms
docker run --rm -v $(pwd):/data openssl-encrypt:latest encrypt --algorithm ml-kem-768-hybrid myfile.txt

# Interactive shell
docker run --rm -it -v $(pwd):/data openssl-encrypt:latest bash
```

### 3. Using Docker Compose

```bash
# Encrypt with docker-compose
docker-compose run --rm openssl-encrypt encrypt myfile.txt

# GUI mode (Linux with X11)
xhost +local:docker
docker-compose run --rm openssl-encrypt-gui
```

## Available Algorithms

The Docker image includes support for all standard and post-quantum algorithms:

### Standard Algorithms
- `fernet`, `fernet-balloon`
- `aes-gcm`, `aes-gcm-siv`, `aes-ocb3`, `aes-siv`
- `chacha20-poly1305`, `xchacha20-poly1305`

### Post-Quantum Algorithms (via liboqs)
- **ML-KEM**: `ml-kem-512`, `ml-kem-768`, `ml-kem-1024`
- **HQC**: `hqc-128`, `hqc-192`, `hqc-256`
- **Hybrid modes**: Combine PQC with classical algorithms
  - `ml-kem-768-hybrid-aes-gcm`
  - `hqc-256-hybrid-xchacha`
  - And many more combinations

### Digital Signatures (for future features)
- **ML-DSA**: `ml-dsa-44`, `ml-dsa-65`, `ml-dsa-87`
- **SLH-DSA**: `slh-dsa-sha2-128f`, `slh-dsa-sha2-192f`, `slh-dsa-sha2-256f`
- **FN-DSA**: `fn-dsa-512`, `fn-dsa-1024`

## Volume Mounts

### Working Directory
```bash
-v $(pwd):/data
```
Mount current directory to `/data` for file operations.

### Keystore Persistence
The keystore data is automatically persisted using Docker volumes. If you need to access it directly:

```bash
docker volume inspect openssl_encrypt_keystore_data
```

## Security Considerations

- Container runs as non-root user `crypt`
- All sensitive operations happen inside the container
- Keystore data is isolated in Docker volumes
- No network access required for encryption/decryption

## Troubleshooting

### Build Issues
If the build fails, try:
```bash
# Clean Docker cache
docker system prune -a

# Rebuild from scratch
docker build --no-cache -t openssl-encrypt:latest .
```

### GUI Issues (Linux)
For GUI mode, ensure X11 forwarding is enabled:
```bash
xhost +local:docker
export DISPLAY=:0
```

### Permission Issues
If you get permission errors with mounted volumes:
```bash
# Fix ownership (replace 1000:1000 with your user:group)
sudo chown -R 1000:1000 $(pwd)
```

## Advanced Usage

### Custom liboqs Version
To build with a specific liboqs version:
```bash
docker build --build-arg LIBOQS_VERSION=0.10.1 -t openssl-encrypt:latest .
```

### Development Mode
Mount source code for development:
```bash
docker run --rm -it \
  -v $(pwd):/data \
  -v $(pwd)/openssl_encrypt:/usr/local/lib/python3.11/site-packages/openssl_encrypt \
  openssl-encrypt:latest bash
```

### Performance Testing
For performance testing with larger files:
```bash
docker run --rm \
  -v $(pwd):/data \
  --memory=2g \
  --cpus=2.0 \
  openssl-encrypt:latest encrypt --algorithm ml-kem-1024-hybrid largefile.dat
```

## Image Size

- **Build image**: ~800MB (includes compilers, cmake, git)
- **Runtime image**: ~200MB (optimized for production)
- **Compressed**: ~80MB when pushed to registry

## Publishing to Registry

To publish to Docker Hub or other registry:
```bash
# Tag for registry
docker tag openssl-encrypt:latest yourusername/openssl-encrypt:latest

# Push to registry
docker push yourusername/openssl-encrypt:latest
```
