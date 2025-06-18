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
flatpak install -y flathub org.freedesktop.Platform//23.08 org.freedesktop.Sdk//23.08

# Clean up any previous builds
echo "🧹 Cleaning up previous builds..."
rm -rf build-dir .flatpak-builder repo

# Build the Flatpak
echo "🔨 Building Flatpak package..."
flatpak-builder --force-clean --repo=repo build-dir com.opensslencrypt.OpenSSLEncrypt.json

# Add local repository
echo "📁 Adding local repository..."
flatpak --user remote-add --if-not-exists --no-gpg-verify openssl-encrypt-repo repo

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
