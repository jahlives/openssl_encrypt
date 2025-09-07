#!/bin/bash
# Script to run unittests locally using the Docker base image

set -e

IMAGE="registry.rm-rf.ch/world/openssl_encrypt/python-liboqs:3.13-alpine"

echo "Running unittests locally using image: $IMAGE"
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
        echo 'Installing project dependencies...'
        pip install -r requirements.txt --break-system-packages || {
            echo 'Failed to install dependencies'
            echo 'Available packages:'
            pip list
            echo 'Requirements file content:'
            cat requirements.txt
            exit 1
        }
        
        echo ''
        echo 'Checking missing dependencies...'
        python -c 'import jsonschema; print(\"✓ jsonschema available\")' || echo '❌ jsonschema missing'
        python -c 'import whirlpool; print(\"✓ whirlpool available\")' || echo '❌ whirlpool missing'
        
        echo ''
        echo 'Running unittests...'
        python -m pytest openssl_encrypt/unittests/ -v --tb=short
    "