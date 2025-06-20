#!/bin/bash
set -e

echo "🚀 Building OpenSSL Encrypt Flatpak package..."

# Check if flatpak-builder is installed
if ! command -v flatpak-builder &> /dev/null; then
    echo "❌ flatpak-builder not found. Installing..."
    # Try different package managers
    if command -v dnf &> /dev/null; then
        sudo dnf install -y flatpak-builder
    elif command -v apt &> /dev/null; then
        sudo apt update && sudo apt install -y flatpak-builder
    elif command -v pacman &> /dev/null; then
        sudo pacman -S flatpak-builder
    else
        echo "❌ Please install flatpak-builder manually for your distribution"
        exit 1
    fi
fi

# Add Flathub repository if not already added
echo "📦 Ensuring Flathub repository is available..."
flatpak remote-add --if-not-exists flathub https://flathub.org/repo/flathub.flatpakrepo

# Install required runtime and SDK
echo "📥 Installing required runtime and SDK..."
flatpak install -y flathub org.freedesktop.Platform//24.08 org.freedesktop.Sdk//24.08

# Clean up build directory but preserve cache
echo "🧹 Cleaning up build directory (preserving cache)..."
rm -rf build-dir repo

# Build the Flatpak (without --force-clean to preserve cache)
echo "🔨 Building Flatpak package..."
echo "ℹ️  Using build cache from .flatpak-builder/ (if exists)"
flatpak-builder --repo=repo build-dir com.opensslencrypt.OpenSSLEncrypt.json

# Update the repository summary (required for remote access)
echo "📋 Updating repository summary..."
flatpak build-update-repo repo

# Clean up any existing installation and remote
echo "🧹 Removing existing installation and remote..."
# First uninstall the specific app
flatpak --user uninstall -y com.opensslencrypt.OpenSSLEncrypt 2>/dev/null || true
# Then remove the remote
flatpak --user remote-delete openssl-encrypt-repo 2>/dev/null || true

# Add local repository
echo "📁 Adding local repository..."
REPO_PATH="$(pwd)/repo"
echo "Repository path: $REPO_PATH"
flatpak --user remote-add --no-gpg-verify openssl-encrypt-repo "$REPO_PATH"

# Install the built package
echo "💾 Installing the package..."
flatpak --user install -y openssl-encrypt-repo com.opensslencrypt.OpenSSLEncrypt

echo "✅ Build complete!"
echo ""
echo "🎯 To test the application:"
echo "   CLI: flatpak run com.opensslencrypt.OpenSSLEncrypt --help"
echo "   GUI: flatpak run com.opensslencrypt.OpenSSLEncrypt --gui"
echo ""
echo "🗑️  To uninstall:"
echo "   flatpak --user uninstall com.opensslencrypt.OpenSSLEncrypt"
echo "   flatpak --user remote-delete openssl-encrypt-repo"
