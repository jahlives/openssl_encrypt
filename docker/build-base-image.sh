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

# Handle authentication to GitLab Container Registry
echo "Setting up ${REGISTRY} authentication..."

# Check for GitLab token in environment variables
if [[ -n "$GITLAB_TOKEN" ]]; then
    echo "✓ Using GitLab token from GITLAB_TOKEN environment variable"
    # Login using token (username can be arbitrary with token auth)
    echo "$GITLAB_TOKEN" | ${CONTAINER_CMD} login ${REGISTRY} --username gitlab-ci-token --password-stdin
    if [[ $? -ne 0 ]]; then
        echo "❌ Failed to authenticate with GitLab token"
        echo "Please check that your GITLAB_TOKEN is valid and has 'write_registry' scope"
        exit 1
    fi
elif [[ -n "$GITLAB_USER" && -n "$GITLAB_PASSWORD" ]]; then
    echo "✓ Using GitLab credentials from environment variables"
    echo "$GITLAB_PASSWORD" | ${CONTAINER_CMD} login ${REGISTRY} --username "$GITLAB_USER" --password-stdin
    if [[ $? -ne 0 ]]; then
        echo "❌ Failed to authenticate with GitLab credentials"
        exit 1
    fi
else
    # Check if already logged in
    if ${CONTAINER_CMD} info | grep -q "Username:" 2>/dev/null; then
        echo "✓ Already authenticated to registry"
    else
        echo "⚠️  Authentication required for GitLab Container Registry"
        echo ""
        echo "Choose one of the following options:"
        echo ""
        echo "1. Use GitLab Personal Access Token (RECOMMENDED):"
        echo "   export GITLAB_TOKEN='glpat-your-token-here'"
        echo "   ./docker/build-base-image.sh"
        echo ""
        echo "2. Use username/password:"
        echo "   export GITLAB_USER='your-username'"
        echo "   export GITLAB_PASSWORD='your-token-or-password'"
        echo "   ./docker/build-base-image.sh"
        echo ""
        echo "3. Manual login:"
        if [[ "$CONTAINER_CMD" == "podman" ]]; then
            echo "   podman login ${REGISTRY}"
        else
            echo "   docker login ${REGISTRY}"
        fi
        echo ""
        echo "To create a GitLab Personal Access Token:"
        echo "  1. Go to GitLab → User Settings → Access Tokens"
        echo "  2. Name: 'Docker Registry Access'"
        echo "  3. Scopes: ✓ write_registry (and optionally read_registry)"
        echo "  4. Copy the token and use as GITLAB_TOKEN"
        exit 1
    fi
fi

# Create Dockerfile for base image
echo "Creating Dockerfile for python-liboqs base image..."
cat > Dockerfile.base << EOF
# Build stage
FROM python:${PYTHON_VERSION}-alpine AS builder

# Install build dependencies for liboqs (Alpine Linux packages)
RUN apk add --no-cache \\
    git gcc g++ cmake ninja make go \\
    python3-dev openssl-dev musl-dev \\
    linux-headers pkgconfig

# Clone and build liboqs ${LIBOQS_VERSION}
WORKDIR /build
RUN git clone --recurse-submodules --branch ${LIBOQS_VERSION} https://github.com/open-quantum-safe/liboqs.git
WORKDIR /build/liboqs
RUN mkdir build && cd build && \\
    cmake -GNinja \\
          -DCMAKE_INSTALL_PREFIX=/usr/local \\
          -DBUILD_SHARED_LIBS=ON \\
          -DOQS_BUILD_ONLY_LIB=ON \\
          .. && \\
    ninja && \\
    ninja install

# Install Python liboqs bindings
RUN export LD_LIBRARY_PATH="/usr/local/lib" && \\
    export PKG_CONFIG_PATH="/usr/local/lib/pkgconfig" && \\
    export OQS_INSTALL_PATH="/usr/local" && \\
    pip install --no-cache-dir git+https://github.com/open-quantum-safe/liboqs-python.git@${LIBOQS_VERSION}

# Runtime stage
FROM python:${PYTHON_VERSION}-alpine

# Install minimal runtime dependencies and build tools needed for Python packages
RUN apk add --no-cache git cmake pkgconfig gcc g++ musl-dev python3-dev

# Copy liboqs libraries and Python bindings from builder
COPY --from=builder /usr/local/lib/liboqs.so* /usr/local/lib/
COPY --from=builder /usr/local/lib/pkgconfig/liboqs.pc /usr/local/lib/pkgconfig/
COPY --from=builder /usr/local/include/oqs/ /usr/local/include/oqs/
COPY --from=builder /usr/local/lib/python*/site-packages/*oqs* /usr/local/lib/python${PYTHON_VERSION}/site-packages/

# Set environment variables for liboqs discovery
ENV LD_LIBRARY_PATH="/usr/local/lib"
ENV PKG_CONFIG_PATH="/usr/local/lib/pkgconfig"
ENV OQS_INSTALL_PATH="/usr/local"

# Verify liboqs installation
RUN python -c "import oqs; print('liboqs version:', oqs.oqs_version())" && \\
    python -c "import oqs; print('Available KEMs:', len(oqs.get_enabled_kem_mechanisms()))"

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
print('✓ Available KEMs:', len(oqs.get_enabled_kem_mechanisms()))
print('✓ Available Signatures:', len(oqs.get_enabled_sig_mechanisms()))

# Test basic KEM operations  
kem = oqs.KeyEncapsulation('Kyber512')
public_key = kem.generate_keypair()
ciphertext, shared_secret_1 = kem.encap_secret(public_key)
shared_secret_2 = kem.decap_secret(ciphertext)
assert shared_secret_1 == shared_secret_2
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
