#!/bin/bash
# Build and push python-liboqs base image for CI testing
# This script builds the base image locally and pushes it to GitLab Container Registry

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Configuration
PYTHON_VERSION="3.13"
LIBOQS_VERSION="0.12.0"
REGISTRY="registry.rm-rf.ch"
PROJECT_PATH="world/openssl_encrypt"
IMAGE_NAME="python-liboqs"
TAG="${PYTHON_VERSION}-alpine"

# Full image name (lowercase for registry compatibility)
FULL_IMAGE="${REGISTRY}/${PROJECT_PATH}/${IMAGE_NAME}:${TAG}"

echo "========================================="
echo "Building Python liboqs Base Image"
echo "========================================="
echo "Python version: ${PYTHON_VERSION}"
echo "liboqs version: ${LIBOQS_VERSION}"
echo "Target image: ${FULL_IMAGE}"
echo ""

# Detect and setup container runtime (Docker or Podman)
echo "Detecting container runtime..."

if command -v docker &> /dev/null && docker info &> /dev/null; then
    echo "✓ Using Docker"
    CONTAINER_CMD="docker"
elif command -v podman &> /dev/null; then
    echo "✓ Using Podman (rootless alternative to Docker)"
    # Create alias within script scope
    alias docker=podman
    CONTAINER_CMD="podman"
else
    echo "❌ Neither Docker nor Podman is available"
    echo ""
    echo "Please install one of the following:"
    echo "  Docker: https://docs.docker.com/get-docker/"
    echo "  Podman: https://podman.io/getting-started/installation"
    exit 1
fi

# Check if user is logged in to GitLab Container Registry
echo "Checking ${REGISTRY} authentication..."
if ! ${CONTAINER_CMD} info | grep -q "Username:" 2>/dev/null; then
    # For podman, check differently as it may not show Username in info
    if [[ "$CONTAINER_CMD" == "podman" ]]; then
        echo "⚠️  Please login to GitLab Container Registry first:"
        echo "   podman login ${REGISTRY}"
    else
        echo "⚠️  Please login to GitLab Container Registry first:"
        echo "   docker login ${REGISTRY}"
    fi
    echo ""
    echo "Use your GitLab username and a personal access token with 'write_registry' scope"
    exit 1
fi

# Create Dockerfile for base image
echo "Creating Dockerfile for python-liboqs base image..."
cat > Dockerfile.base << EOF
FROM python:${PYTHON_VERSION}-alpine

# Install build dependencies for liboqs (Alpine Linux packages)
RUN apk add --no-cache \\
    git gcc g++ cmake ninja make go \\
    python3-dev openssl-dev musl-dev \\
    linux-headers

# Clone and build liboqs ${LIBOQS_VERSION}
WORKDIR /build
RUN git clone --recurse-submodules --branch ${LIBOQS_VERSION} https://github.com/open-quantum-safe/liboqs.git
WORKDIR /build/liboqs
RUN mkdir build && cd build && \\
    cmake -GNinja -DCMAKE_INSTALL_PREFIX=/usr/local .. && \\
    ninja && \\
    ninja install

# Install Python liboqs bindings
RUN pip install --no-cache-dir git+https://github.com/open-quantum-safe/liboqs-python.git@${LIBOQS_VERSION}

# Clean up build artifacts but keep runtime libraries
RUN apk del git gcc g++ cmake ninja make go && \\
    rm -rf /build /var/cache/apk/*

# Update library cache
RUN ldconfig /usr/local/lib

# Verify liboqs installation
RUN python -c "import oqs; print('liboqs version:', oqs.oqs_version())" && \\
    python -c "import oqs; print('Available KEMs:', len(oqs.get_enabled_KEM_mechanisms()))"

# Add build metadata
LABEL org.opencontainers.image.title="Python liboqs Base Image"
LABEL org.opencontainers.image.description="Python ${PYTHON_VERSION} Alpine with liboqs ${LIBOQS_VERSION} for PQC testing"
LABEL org.opencontainers.image.version="${LIBOQS_VERSION}"
LABEL org.opencontainers.image.created="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
LABEL org.opencontainers.image.source="https://gitlab.rm-rf.ch/world/openssl_encrypt"

WORKDIR /
EOF

echo "✓ Dockerfile created"

# Build the base image
echo ""
echo "Building base image (this may take 10-15 minutes)..."
echo "Building: ${FULL_IMAGE}"

${CONTAINER_CMD} build \
    --file Dockerfile.base \
    --tag "${FULL_IMAGE}" \
    --tag "${FULL_IMAGE%:*}:latest" \
    --tag "${FULL_IMAGE%:*}:python${PYTHON_VERSION}-liboqs${LIBOQS_VERSION}" \
    --tag "${FULL_IMAGE%:*}:$(date +%Y%m%d)" \
    --build-arg PYTHON_VERSION="${PYTHON_VERSION}" \
    --build-arg LIBOQS_VERSION="${LIBOQS_VERSION}" \
    .

echo "✓ Build completed successfully!"

# Test the built image
echo ""
echo "Testing built image..."
${CONTAINER_CMD} run --rm "${FULL_IMAGE}" python -c "
import oqs
print('✓ liboqs version:', oqs.oqs_version())
print('✓ Available KEMs:', len(oqs.get_enabled_KEM_mechanisms()))
print('✓ Available Signatures:', len(oqs.get_enabled_sig_mechanisms()))

# Test basic KEM operations
kem = oqs.KeyEncapsulation('Kyber512')
pk, sk = kem.generate_keypair()
ct, ss1 = kem.encap(pk)
ss2 = kem.decap(sk, ct)
assert ss1 == ss2
print('✓ Basic KEM test passed')
print('✓ Base image is working correctly!')
"

echo "✓ Image test passed!"

# Push all tags to registry
echo ""
echo "Pushing images to GitLab Container Registry..."
${CONTAINER_CMD} push "${FULL_IMAGE}"
${CONTAINER_CMD} push "${FULL_IMAGE%:*}:latest"
${CONTAINER_CMD} push "${FULL_IMAGE%:*}:python${PYTHON_VERSION}-liboqs${LIBOQS_VERSION}"
${CONTAINER_CMD} push "${FULL_IMAGE%:*}:$(date +%Y%m%d)"

echo ""
echo "========================================="
echo "✅ SUCCESS: Base image built and pushed!"
echo "========================================="
echo "Image: ${FULL_IMAGE}"
echo "Additional tags:"
echo "  - ${FULL_IMAGE%:*}:latest"
echo "  - ${FULL_IMAGE%:*}:python${PYTHON_VERSION}-liboqs${LIBOQS_VERSION}"
echo "  - ${FULL_IMAGE%:*}:$(date +%Y%m%d)"
echo ""
echo "Your CI pipelines can now use this fresh base image."
echo "The image will be available for about 2-3 minutes after pushing."

# Cleanup
rm -f Dockerfile.base
echo "✓ Cleanup completed"
