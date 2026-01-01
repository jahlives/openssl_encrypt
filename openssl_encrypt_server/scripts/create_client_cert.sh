#!/bin/bash
#
# Create Client Certificate
#
# This script generates a client certificate signed by your CA.
# Run this for each user/device that needs access to pepper/integrity modules.
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERTS_DIR="${SCRIPT_DIR}/../certs"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}OpenSSL Encrypt - Client Certificate${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""

# Check if CA exists
if [ ! -f "${CERTS_DIR}/ca.crt" ] || [ ! -f "${CERTS_DIR}/ca.key" ]; then
    echo -e "${RED}ERROR: CA not found!${NC}"
    echo "Please run scripts/setup_ca.sh first to create the CA."
    exit 1
fi

cd "${CERTS_DIR}"

# Get client name
if [ -n "$1" ]; then
    CLIENT_NAME="$1"
else
    read -p "Client name (e.g., 'alice', 'server1', 'backup-tool'): " CLIENT_NAME
fi

if [ -z "${CLIENT_NAME}" ]; then
    echo -e "${RED}ERROR: Client name is required${NC}"
    exit 1
fi

# Sanitize client name (alphanumeric, dash, underscore only)
CLIENT_NAME=$(echo "${CLIENT_NAME}" | sed 's/[^a-zA-Z0-9_-]//g')

if [ -z "${CLIENT_NAME}" ]; then
    echo -e "${RED}ERROR: Invalid client name${NC}"
    exit 1
fi

# Check if client certificate already exists
if [ -f "${CLIENT_NAME}.crt" ] || [ -f "${CLIENT_NAME}.key" ]; then
    echo -e "${RED}ERROR: Client certificate already exists!${NC}"
    echo "Found: ${CLIENT_NAME}.crt or ${CLIENT_NAME}.key"
    echo ""
    echo "To regenerate, first remove or rename existing files:"
    echo "  mv ${CLIENT_NAME}.key ${CLIENT_NAME}.key.old"
    echo "  mv ${CLIENT_NAME}.crt ${CLIENT_NAME}.crt.old"
    exit 1
fi

echo ""
echo "Creating certificate for client: ${CLIENT_NAME}"
echo ""

# Optional: Get additional details
read -p "Organization (default: same as CA): " CLIENT_ORG
read -p "Organizational Unit (default: 'Clients'): " CLIENT_OU
CLIENT_OU=${CLIENT_OU:-"Clients"}

# Get ORG from CA cert if not provided
if [ -z "${CLIENT_ORG}" ]; then
    CLIENT_ORG=$(openssl x509 -in ca.crt -noout -subject | sed -n 's/.*O = \([^,]*\).*/\1/p')
fi

# Get Country/State/City from CA cert
COUNTRY=$(openssl x509 -in ca.crt -noout -subject | sed -n 's/.*C = \([^,]*\).*/\1/p')
STATE=$(openssl x509 -in ca.crt -noout -subject | sed -n 's/.*ST = \([^,]*\).*/\1/p')
CITY=$(openssl x509 -in ca.crt -noout -subject | sed -n 's/.*L = \([^,]*\).*/\1/p')

# Certificate validity (days)
VALIDITY_DAYS=825  # ~2 years (Apple/Google recommended max)

echo ""
echo "Certificate Details:"
echo "  Common Name: ${CLIENT_NAME}"
echo "  Organization: ${CLIENT_ORG}"
echo "  OU: ${CLIENT_OU}"
echo "  Validity: ${VALIDITY_DAYS} days (~2 years)"
echo ""
read -p "Continue? (y/n): " CONFIRM
if [ "${CONFIRM}" != "y" ]; then
    echo "Aborted."
    exit 1
fi

echo ""
echo -e "${GREEN}Step 1: Generating client private key...${NC}"
openssl genrsa -out "${CLIENT_NAME}.key" 4096

echo ""
echo -e "${GREEN}Step 2: Creating certificate signing request (CSR)...${NC}"
openssl req -new -key "${CLIENT_NAME}.key" -out "${CLIENT_NAME}.csr" \
    -subj "/C=${COUNTRY}/ST=${STATE}/L=${CITY}/O=${CLIENT_ORG}/OU=${CLIENT_OU}/CN=${CLIENT_NAME}"

echo ""
echo -e "${GREEN}Step 3: Signing certificate with CA...${NC}"
echo "You will be prompted for the CA key passphrase."
echo ""
openssl x509 -req -in "${CLIENT_NAME}.csr" -CA ca.crt -CAkey ca.key \
    -CAcreateserial -out "${CLIENT_NAME}.crt" -days ${VALIDITY_DAYS} -sha256

echo ""
echo -e "${GREEN}Step 4: Verifying certificate...${NC}"
openssl verify -CAfile ca.crt "${CLIENT_NAME}.crt"

# Clean up CSR
rm "${CLIENT_NAME}.csr"

# Set permissions
chmod 600 "${CLIENT_NAME}.key"
chmod 644 "${CLIENT_NAME}.crt"

# Calculate fingerprint
FINGERPRINT=$(openssl x509 -in "${CLIENT_NAME}.crt" -noout -fingerprint -sha256 | sed 's/SHA256 Fingerprint=//')
FINGERPRINT_NORMALIZED=$(echo "${FINGERPRINT}" | tr -d ':' | tr '[:upper:]' '[:lower:]')

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}Client Certificate Created!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo "Created files:"
echo "  ${CLIENT_NAME}.key - Client private key (give to client)"
echo "  ${CLIENT_NAME}.crt - Client certificate (give to client)"
echo ""
echo "Certificate fingerprint (SHA-256):"
echo "  ${FINGERPRINT}"
echo ""
echo "Normalized fingerprint (database ID):"
echo "  ${FINGERPRINT_NORMALIZED}"
echo ""
echo -e "${YELLOW}Distribution:${NC}"
echo ""
echo "Option 1: Create a bundle for the client"
echo "  tar czf ${CLIENT_NAME}-bundle.tar.gz ${CLIENT_NAME}.key ${CLIENT_NAME}.crt ca.crt"
echo "  # Send ${CLIENT_NAME}-bundle.tar.gz to client via secure channel"
echo ""
echo "Option 2: Manual distribution"
echo "  # Send these files to client:"
echo "  - ${CLIENT_NAME}.key (PRIVATE - keep secure!)"
echo "  - ${CLIENT_NAME}.crt (public)"
echo "  - ca.crt (public)"
echo ""
echo -e "${YELLOW}Client Usage:${NC}"
echo ""
echo "curl example:"
echo "  curl --cert ${CLIENT_NAME}.crt --key ${CLIENT_NAME}.key --cacert ca.crt \\"
echo "    https://server/api/v1/pepper/profile"
echo ""
echo "Python requests example:"
echo "  response = requests.get("
echo "      'https://server/api/v1/pepper/profile',"
echo "      cert=('${CLIENT_NAME}.crt', '${CLIENT_NAME}.key'),"
echo "      verify='ca.crt'"
echo "  )"
echo ""
echo -e "${YELLOW}Server Setup:${NC}"
echo ""
echo "The server will auto-register this client on first connection."
echo "Certificate fingerprint (ID): ${FINGERPRINT_NORMALIZED}"
echo ""
echo "To verify client connected, check database:"
echo "  SELECT cert_fingerprint, name FROM pp_clients;"
echo "  SELECT cert_fingerprint, name FROM in_clients;"
echo ""

# Offer to create bundle
echo ""
read -p "Create client bundle (tar.gz)? (y/n): " CREATE_BUNDLE
if [ "${CREATE_BUNDLE}" == "y" ]; then
    tar czf "${CLIENT_NAME}-bundle.tar.gz" "${CLIENT_NAME}.key" "${CLIENT_NAME}.crt" ca.crt
    echo ""
    echo -e "${GREEN}Created: ${CLIENT_NAME}-bundle.tar.gz${NC}"
    echo ""
    echo "Bundle contents:"
    tar tzf "${CLIENT_NAME}-bundle.tar.gz"
    echo ""
    echo "Send this file to the client via secure channel (encrypted email, etc.)"
    echo ""
fi

echo "Done!"
