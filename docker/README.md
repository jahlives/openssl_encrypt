# Docker Base Image Management

This directory contains tools for building and managing the `python-liboqs` base image used by GitLab CI pipelines.

## Overview

Instead of complex automated Docker-in-Docker builds in GitLab CI, we use a simple local build script that:
- Builds the base image locally with full control and debugging capability
- Pushes to GitLab Container Registry manually when needed
- Avoids CI complexity and Docker daemon connectivity issues

## Quick Start

### 1. Login to GitLab Container Registry

```bash
# Use your GitLab username and personal access token with 'write_registry' scope
docker login registry.gitlab.com
```

### 2. Build and Push Base Image

```bash
# Run the build script
./docker/build-base-image.sh
```

This will:
- Build `python:3.13-alpine` with liboqs 0.12.0 compiled from source
- Install Python liboqs bindings
- Test the image with basic PQC operations
- Push multiple tags to the registry

### 3. Available Tags

The script creates several tags for flexibility:

- `registry.gitlab.com/world/openssl_encrypt/python-liboqs:3.13-alpine` (default)
- `registry.gitlab.com/world/openssl_encrypt/python-liboqs:latest`
- `registry.gitlab.com/world/openssl_encrypt/python-liboqs:python3.13-liboqs0.12.0`
- `registry.gitlab.com/world/openssl_encrypt/python-liboqs:20241206` (date stamp)

## When to Rebuild

The base image rarely needs rebuilding. Consider rebuilding when:

- **New liboqs version** - Update `LIBOQS_VERSION` in the script
- **New Python version** - Update `PYTHON_VERSION` in the script  
- **Security updates** - Rebuild monthly for Alpine security patches
- **CI failures** - If the base image becomes corrupted or unavailable

## GitLab CI Integration

Your GitLab CI pipeline automatically uses the base image:

```yaml
variables:
  DOCKER_IMAGE: registry.gitlab.com/world/openssl_encrypt/python-liboqs:3.13-alpine

test:
  image: $DOCKER_IMAGE
  script:
    - python -m pytest  # liboqs already available!
```

## Local Development

You can also use the base image locally for development:

```bash
# Pull the latest base image
docker pull registry.gitlab.com/world/openssl_encrypt/python-liboqs:latest

# Run interactively
docker run -it --rm \
  -v $(pwd):/workspace \
  registry.gitlab.com/world/openssl_encrypt/python-liboqs:latest \
  sh

# Inside container - liboqs is ready to use
python -c "import oqs; print(f'KEMs: {len(oqs.get_enabled_KEM_mechanisms())}')"
```

## Troubleshooting

### Build Issues

If the build fails:

1. **Check Docker daemon**: `docker info`
2. **Check registry login**: `docker login registry.gitlab.com`
3. **Check internet connectivity**: The build downloads liboqs from GitHub
4. **Clear Docker cache**: `docker system prune -a`

### Registry Issues

If push fails:

1. **Check personal access token** has `write_registry` scope
2. **Verify project permissions** - you need Developer/Maintainer role
3. **Try manual push**: `docker push registry.gitlab.com/world/openssl_encrypt/python-liboqs:latest`

### CI Issues

If CI fails to pull the image:

1. **Check image exists**: Visit GitLab → Packages & Registries → Container Registry
2. **Check CI variables**: Ensure `DOCKER_IMAGE` matches the pushed image name
3. **Check GitLab runner permissions**: Runner needs access to container registry

## Technical Details

### Image Contents

The base image includes:

- **Python 3.13 Alpine Linux** - Minimal, secure base
- **liboqs 0.12.0** - Compiled with all PQC algorithms enabled
- **Python bindings** - `oqs` module ready to import
- **Runtime libraries** - All dependencies for PQC operations
- **Clean environment** - Build tools removed for smaller image

### Build Process

1. Start with `python:3.13-alpine`
2. Install build dependencies (cmake, ninja, gcc, etc.)
3. Clone liboqs 0.12.0 with submodules
4. Compile with CMake + Ninja (optimized build)
5. Install Python bindings from GitHub
6. Clean up build artifacts (reduces image size by ~500MB)
7. Verify installation with test imports and operations

### Size Optimization

The build process creates a ~200MB runtime image by:
- Using Alpine Linux (minimal base)
- Removing build tools after compilation
- Cleaning package caches
- Multi-stage build approach (only runtime artifacts kept)

This is much smaller than keeping build tools (~700MB+) but still includes all PQC functionality.