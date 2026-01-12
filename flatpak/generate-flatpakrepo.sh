#!/bin/bash
#
# Generate .flatpakrepo configuration file
# This script creates the repository configuration file that users
# need to add the Flatpak repository to their system.
#

set -e

REPO_NAME="openssl-encrypt"
FLATPAKREPO_FILE="${REPO_NAME}.flatpakrepo"
GPG_KEY_EMAIL="jahlives@gmx.ch"

GPG_KEY_BASE64=$(gpg --export "${GPG_KEY_EMAIL}" | base64 -w0)

echo "📝 Generating repository configuration file..."

# Generate .flatpakrepo file
cat > "$FLATPAKREPO_FILE" << EOF
[Flatpak Repo]
Title=OpenSSL Encrypt Repository
Url=https://flatpak.rm-rf.ch/
Homepage=https://gitlab.rm-rf.ch/world/openssl_encrypt
Comment=Military-grade encryption with post-quantum cryptography
Description=OpenSSL Encrypt applications repository with post-quantum cryptographic algorithms
GPGKey=${GPG_KEY_BASE64}
EOF

echo "✅ Generated ${FLATPAKREPO_FILE}"
echo ""
echo "📋 Repository Information:"
echo "   Repository Name: ${REPO_NAME}"
echo "   Configuration URL: https://flatpak.rm-rf.ch/${REPO_NAME}.flatpakrepo"
echo ""
echo "👥 For users to add this repository:"
echo "   flatpak remote-add --if-not-exists ${REPO_NAME} https://flatpak.rm-rf.ch/${REPO_NAME}.flatpakrepo"
echo ""
echo "📥 Install command:"
echo "   flatpak install ${REPO_NAME} com.opensslencrypt.OpenSSLEncrypt"
