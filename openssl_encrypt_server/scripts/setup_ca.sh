#!/bin/bash
#
# Setup Self-Signed Certificate Authority
#
# This script creates a private CA for signing client certificates.
# ONLY RUN THIS ONCE! Keep the CA key secure.
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERTS_DIR="${SCRIPT_DIR}/../certs"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}OpenSSL Encrypt - CA Setup${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""

# Create certs directory
mkdir -p "${CERTS_DIR}"
cd "${CERTS_DIR}"

# Check if CA already exists
if [ -f "ca.crt" ] || [ -f "ca.key" ]; then
    echo -e "${RED}ERROR: CA already exists!${NC}"
    echo "Found existing files:"
    ls -la ca.* 2>/dev/null || true
    echo ""
    echo "If you want to regenerate the CA, you must:"
    echo "  1. Backup existing CA: mv ca.key ca.key.old && mv ca.crt ca.crt.old"
    echo "  2. Reissue ALL client certificates"
    echo "  3. Update server configuration"
    echo ""
    exit 1
fi

echo "This script will create a new Certificate Authority (CA)."
echo "The CA will be used to sign client certificates for mTLS authentication."
echo ""
echo -e "${YELLOW}WARNING: The CA private key must be kept SECURE!${NC}"
echo "Anyone with access to ca.key can issue valid client certificates."
echo ""

# Prompt for CA details
read -p "Organization Name (e.g., 'MyCompany Inc'): " ORG_NAME
ORG_NAME=${ORG_NAME:-"OpenSSL Encrypt"}

read -p "Country Code (e.g., 'US'): " COUNTRY
COUNTRY=${COUNTRY:-"US"}

read -p "State/Province: " STATE
STATE=${STATE:-"California"}

read -p "City: " CITY
CITY=${CITY:-"San Francisco"}

read -p "CA Common Name (e.g., 'OpenSSL-Encrypt-CA'): " CA_CN
CA_CN=${CA_CN:-"OpenSSL-Encrypt-CA"}

echo ""
echo "CA Details:"
echo "  Organization: ${ORG_NAME}"
echo "  Country: ${COUNTRY}"
echo "  State: ${STATE}"
echo "  City: ${CITY}"
echo "  Common Name: ${CA_CN}"
echo ""
read -p "Continue? (y/n): " CONFIRM
if [ "${CONFIRM}" != "y" ]; then
    echo "Aborted."
    exit 1
fi

echo ""
echo -e "${GREEN}Step 1: Generating CA private key...${NC}"
echo "You will be prompted for a passphrase to encrypt the CA key."
echo ""

# Generate CA private key (with passphrase protection)
openssl genrsa -aes256 -out ca.key 4096

echo ""
echo -e "${GREEN}Step 2: Creating CA certificate (valid 10 years)...${NC}"
echo ""

# Create CA certificate
openssl req -x509 -new -nodes -key ca.key -sha256 -days 3650 -out ca.crt \
    -subj "/C=${COUNTRY}/ST=${STATE}/L=${CITY}/O=${ORG_NAME}/OU=Certificate Authority/CN=${CA_CN}"

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}CA Setup Complete!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo "Created files:"
echo "  ca.key - CA private key (KEEP SECRET!)"
echo "  ca.crt - CA certificate (public, distribute to server and clients)"
echo ""
echo -e "${YELLOW}IMPORTANT SECURITY STEPS:${NC}"
echo ""
echo "1. Backup the CA key to a secure location:"
echo "   cp ca.key ~/secure-backup/ca.key.$(date +%Y%m%d)"
echo ""
echo "2. Set strict permissions:"
echo "   chmod 600 ca.key"
echo "   chmod 644 ca.crt"
echo ""
echo "3. Add ca.crt to your .gitignore:"
echo "   echo 'certs/*.key' >> ../.gitignore"
echo ""
echo "4. Store the CA key passphrase in a password manager"
echo ""
echo "Next steps:"
echo "  - Use scripts/create_client_cert.sh to generate client certificates"
echo "  - Configure server to use certs/ca.crt for client verification"
echo ""

# Set permissions
chmod 600 ca.key
chmod 644 ca.crt

# Display CA info
echo "CA Certificate Details:"
echo "========================================"
openssl x509 -in ca.crt -noout -text | grep -A 2 "Subject:"
openssl x509 -in ca.crt -noout -text | grep -A 2 "Validity"
echo ""
