#!/bin/bash
# Script to run unittests locally using the Docker base image

set -e

IMAGE="registry.rm-rf.ch/world/openssl_encrypt/python-liboqs:3.13-alpine"

# Parse command line arguments to pass to pytest
PYTEST_ARGS="$@"
if [[ -n "$PYTEST_ARGS" ]]; then
    echo "Running unittests locally using image: $IMAGE"
    echo "pytest arguments: $PYTEST_ARGS"
else
    echo "Running unittests locally using image: $IMAGE"
    echo "Usage: $0 [-k filter] [other pytest options]"
fi
echo "=============================================="

# Check if image exists locally
if ! podman images --format "{{.Repository}}:{{.Tag}}" | grep -q "$IMAGE"; then
    echo "Image not found locally. Please build it first with:"
    echo "./docker/build-base-image.sh"
    exit 1
fi

echo "Mounting current directory and running tests..."

# Run container with the current project directory mounted
# Use --userns=keep-id to preserve file permissions
podman run --rm -it \
    --userns=keep-id \
    -v "$(pwd):/workspace:Z" \
    -w "/workspace" \
    "$IMAGE" \
    sh -c "
        echo 'Verifying dependencies are available...'
        python -c 'import cryptography; print(\"✓ cryptography available:\", cryptography.__version__)' || echo '❌ cryptography missing'
        python -c 'import argon2; print(\"✓ argon2 available\")' || echo '❌ argon2 missing'
        python -c 'import yaml; print(\"✓ PyYAML available\")' || echo '❌ PyYAML missing'
        python -c 'import PIL; print(\"✓ Pillow available\")' || echo '❌ Pillow missing'
        python -c 'import numpy; print(\"✓ numpy available\")' || echo '❌ numpy missing'
        python -c 'import blake3; print(\"✓ blake3 available\")' || echo '❌ blake3 missing'
        python -c 'import qrcode; print(\"✓ qrcode available\")' || echo '❌ qrcode missing'
        python -c 'import pyzbar; print(\"✓ pyzbar available\")' || echo '❌ pyzbar missing'
        python -c 'import randomx; print(\"✓ RandomX available\")' || echo '❌ RandomX missing'
        python -c 'import pytest; print(\"✓ pytest available\")' || echo '❌ pytest missing'
        python -c 'import oqs; print(\"✓ liboqs available:\", oqs.oqs_version())' || echo '❌ liboqs missing'

        echo ''
        echo 'Running unittests...'
        # Ensure PYTEST_CURRENT_TEST is set for test mode detection
        export PYTEST_CURRENT_TEST=1
        python -m pytest openssl_encrypt/unittests/unittests.py -v --tb=short $PYTEST_ARGS
    "
