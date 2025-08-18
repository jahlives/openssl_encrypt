#!/bin/bash

# Clean Flutter startup script that suppresses Python warnings
export PYTHONWARNINGS=ignore
export PYTHONNOUSERSITE=1
export PYTHONDONTWRITEBYTECODE=1

echo "🚀 Starting OpenSSL Encrypt Mobile (Clean Mode)"
echo "   - Python warnings suppressed"
echo "   - Environment optimized"
echo ""

flutter run -d linux "$@"
