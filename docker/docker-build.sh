#!/bin/bash
# Build script for openssl_encrypt Docker image with PQC support

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "Building openssl_encrypt Docker image with PQC support..."
echo "This may take several minutes as it compiles liboqs from source."

# Build the Docker image (use parent directory as context)
docker build -f Dockerfile -t openssl-encrypt:latest ..

echo ""
echo "Build completed successfully!"
echo ""
echo "Usage examples:"
echo ""
echo "# Encrypt a file:"
echo "docker run --rm -v \$(pwd):/data openssl-encrypt:latest encrypt myfile.txt"
echo ""
echo "# Decrypt a file:"
echo "docker run --rm -v \$(pwd):/data openssl-encrypt:latest decrypt myfile.txt.enc"
echo ""
echo "# Use PQC algorithms:"
echo "docker run --rm -v \$(pwd):/data openssl-encrypt:latest encrypt --algorithm ml-kem-768-hybrid myfile.txt"
echo ""
echo "# Interactive mode:"
echo "docker run --rm -it -v \$(pwd):/data openssl-encrypt:latest"
echo ""
echo "# Using docker-compose:"
echo "docker-compose run --rm openssl-encrypt encrypt myfile.txt"
echo ""
echo "# GUI mode (Linux with X11):"
echo "xhost +local:docker"
echo "docker-compose run --rm openssl-encrypt-gui"
echo ""
echo "# Check PQC support:"
echo "docker run --rm openssl-encrypt:latest --help"
echo ""

# Test that the image works
echo "Testing the built image..."
if docker run --rm openssl-encrypt:latest --help >/dev/null 2>&1; then
    echo "✓ Image test passed!"
else
    echo "✗ Image test failed!"
    exit 1
fi

echo ""
echo "Build and test completed successfully!"
echo "The image 'openssl-encrypt:latest' is ready to use."
