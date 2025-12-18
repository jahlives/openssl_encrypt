#!/bin/bash
# Example shell script for interacting with openssl_encrypt D-Bus service
# Uses busctl command-line tool

set -e

SERVICE="ch.rm-rf.openssl_encrypt"
OBJECT_PATH="/ch/rm_rf/openssl_encrypt/CryptoService"
INTERFACE="ch.rm-rf.openssl_encrypt.Crypto"

echo "=================================================="
echo "openssl_encrypt D-Bus Service - Shell Example"
echo "=================================================="

# Check if service is available
echo ""
echo "Checking if service is available..."
if busctl --user list | grep -q "$SERVICE"; then
    echo "✓ Service is running"
else
    echo "✗ Service not found"
    echo "  Start with: python3 -m openssl_encrypt.modules.dbus_service"
    exit 1
fi

# Get version
echo ""
echo "1. Getting service version..."
VERSION=$(busctl --user call "$SERVICE" "$OBJECT_PATH" "$INTERFACE" GetVersion)
echo "   Version: $VERSION"

# Get supported algorithms
echo ""
echo "2. Getting supported algorithms..."
ALGORITHMS=$(busctl --user call "$SERVICE" "$OBJECT_PATH" "$INTERFACE" GetSupportedAlgorithms)
echo "   Algorithms: $ALGORITHMS"

# Validate passwords
echo ""
echo "3. Validating passwords..."
for PASSWORD in "weak" "StrongPass123!" "short"; do
    echo -n "   Testing '$PASSWORD': "
    RESULT=$(busctl --user call "$SERVICE" "$OBJECT_PATH" "$INTERFACE" \
        ValidatePassword s "$PASSWORD")
    echo "$RESULT"
done

# Get properties
echo ""
echo "4. Getting service properties..."
ACTIVE_OPS=$(busctl --user get-property "$SERVICE" "$OBJECT_PATH" \
    "$INTERFACE" ActiveOperations)
echo "   Active operations: $ACTIVE_OPS"

MAX_OPS=$(busctl --user get-property "$SERVICE" "$OBJECT_PATH" \
    "$INTERFACE" MaxConcurrentOperations)
echo "   Max concurrent operations: $MAX_OPS"

TIMEOUT=$(busctl --user get-property "$SERVICE" "$OBJECT_PATH" \
    "$INTERFACE" DefaultTimeout)
echo "   Default timeout: $TIMEOUT"

# Monitor signals (in background)
echo ""
echo "5. Monitoring signals (10 seconds)..."
echo "   (This would capture Progress and OperationComplete signals)"
timeout 10s busctl --user monitor "$SERVICE" \
    --match "type='signal',interface='$INTERFACE'" \
    2>/dev/null || true

echo ""
echo "=================================================="
echo "Example completed!"
echo ""
echo "Note: For actual file encryption/decryption, use"
echo "the Python client library as busctl makes it"
echo "difficult to pass complex parameters."
echo "=================================================="
