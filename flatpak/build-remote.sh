#!/bin/bash

set -e  # Exit on any error

# Configuration
LOCAL_REPO="./repo"
BUILD_DIR="./build-dir"
MANIFEST="com.opensslencrypt.OpenSSLEncrypt.json"
SERVER="gitlab.rm-rf.ch"
SERVER_USER="www-data"
SERVER_REPO="/var/www/flatpak-repo"
GPG_KEY_ID="Tobi's Flatpak Repository (Flatpak Signing Key) <jahlives@gmx.ch>"

if [ ! -f "$MANIFEST" ]; then
      echo "❌ Error: Manifest file '$MANIFEST' not found!"
      exit 1
fi

echo "🏗  Building Flatpak application locally..."
find "$BUILD_DIR" -mindepth 1 -maxdepth 1 ! -name '.flatpak-builder' -exec rm -rf {} +

# Ensure directories exist
mkdir -p "$LOCAL_REPO"
mkdir -p "$BUILD_DIR"

# Initialize repo if needed
if [ ! -d "$LOCAL_REPO" ]; then
    ostree init --mode=archive-z2 --repo="$LOCAL_REPO"
fi

# Clean build if requested
if [ "$1" = "clean" ]; then
    rm -rf "$BUILD_DIR"
fi

# Build the application
flatpak-builder \
    --repo="$LOCAL_REPO" \
    --gpg-sign="$GPG_KEY_ID" \
    $([ "$1" = "clean" ] && echo "--force-clean") \
    "$BUILD_DIR" \
    "$MANIFEST"

echo "✅ Local build complete!"

# Update local repository summary
ostree summary -u --repo="$LOCAL_REPO" --gpg-sign="$GPG_KEY_ID"
flatpak build-update-repo --gpg-sign="$GPG_KEY_ID" "$LOCAL_REPO"

echo "📤 Uploading to server..."

# Upload to server
rsync -avz --progress \
    "$LOCAL_REPO/objects/" \
    "root@$SERVER:$SERVER_REPO/objects/"
if [ $? -ne 0 ]; then
      echo "❌ Error: Failed to upload to server"
      exit 1
fi
rsync -avz \
    "$LOCAL_REPO/refs/" \
    "root@$SERVER:$SERVER_REPO/refs/"
if [ $? -ne 0 ]; then
      echo "❌ Error: Failed to upload to server"
      exit 1
fi
rsync -avz \
    "$LOCAL_REPO/summary"* \
    "root@$SERVER:$SERVER_REPO/"
if [ $? -ne 0 ]; then
      echo "❌ Error: Failed to upload to server"
      exit 1
fi
# Update server
echo "🔧 Updating server repository..."
ssh "root@$SERVER" '
      cd '"$SERVER_REPO"'
      ostree summary -u --repo='"$SERVER_REPO"' --gpg-sign='"\"$GPG_KEY_ID\""'
      flatpak build-update-repo --gpg-sign='"\"$GPG_KEY_ID\""' '"$SERVER_REPO"'
      chown -R '"$SERVER_USER"':'"$SERVER_USER"' '"$SERVER_REPO"'
      echo "Server repository updated successfully!"
  '
# Sync webstuff for flatpak repo
echo "🔧 Updating webfiles for Flatpak Repo"
rsync -avz ./flathub/ root@$SERVER:$SERVER_REPO/
if [ $? -ne 0 ]; then
      echo "❌ Error: Failed to upload to server"
      exit 1
fi
echo "🎉 Deployment complete!"
echo ""
echo "Clients can now install with:"
echo "flatpak install your-repo com.opensslencrypt.OpenSSLEncrypt"
