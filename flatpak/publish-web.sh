#!/usr/bin/env bash

SERVER="gitlab.rm-rf.ch"
SERVER_USER="www-data"
SERVER_REPO="/var/www/flatpak-repo"
REPO_NAME="openssl-encrypt"

echo "🔧 Updating webfiles for Flatpak Repo"
rsync -avz ./flathub/ root@$SERVER:$SERVER_REPO/
if [ $? -ne 0 ]; then
      echo "❌ Error: Failed to upload to server"
      exit 1
fi

echo "🎉 Deployment complete!"
echo ""
echo "📦 Repository Information:"
echo "   Repository Name: ${REPO_NAME}"
echo "   Configuration URL: https://flatpak.rm-rf.ch/${REPO_NAME}.flatpakrepo"
echo ""
echo "👥 For users to add this repository:"
echo "   flatpak remote-add --if-not-exists ${REPO_NAME} https://flatpak.rm-rf.ch/${REPO_NAME}.flatpakrepo"
echo ""
echo "📥 Install commands:"
if [ -n "$DEFAULT_BRANCH" ]; then
    echo "   flatpak install ${REPO_NAME} com.opensslencrypt.OpenSSLEncrypt//${DEFAULT_BRANCH}"
    echo "   flatpak install ${REPO_NAME} com.opensslencrypt.OpenSSLEncrypt  # (latest stable)"
else
    echo "   flatpak install ${REPO_NAME} com.opensslencrypt.OpenSSLEncrypt"
fi
