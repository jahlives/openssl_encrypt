#!/bin/bash
set -e

echo "🚀 Building OpenSSL Encrypt Flatpak package..."

# Parse command line arguments
BUILD_FLUTTER=false
FORCE_CLEAN=false
LOCAL_INSTALL=false

for arg in "$@"; do
    case $arg in
        --build-flutter)
            BUILD_FLUTTER=true
            echo "🦋 Flutter build requested"
            ;;
        -f|--force)
            FORCE_CLEAN=true
            echo "🧹 Force clean requested"
            ;;
        --local-install)
            LOCAL_INSTALL=true
            echo "🏠 Local installation requested"
            ;;
        *)
            echo "Unknown argument: $arg"
            echo "Usage: $0 [--build-flutter] [-f|--force] [--local-install]"
            echo "  --build-flutter   Build Flutter desktop GUI before Flatpak"
            echo "  -f, --force       Force clean build cache"
            echo "  --local-install   Install locally for testing (user repo)"
            echo ""
            echo "Examples:"
            echo "  $0                          # Build only (for build-remote.sh)"
            echo "  $0 --local-install          # Build and install locally for testing"
            echo "  $0 --build-flutter --local-install  # Build with GUI and install locally"
            exit 1
            ;;
    esac
done

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

# Build Flutter desktop GUI if requested
if [[ "$BUILD_FLUTTER" == "true" ]]; then
    echo "🦋 Building Flutter desktop GUI..."
    
    # Store current directory
    FLATPAK_DIR="$(pwd)"
    
    # Change to desktop_gui directory
    cd ../desktop_gui
    
    # Check if Flutter is available
    if ! command -v flutter &> /dev/null; then
        echo "❌ Flutter not found. Please install Flutter SDK first."
        echo "   Visit: https://docs.flutter.dev/get-started/install/linux"
        exit 1
    fi
    
    # Clean previous builds only if force clean is requested
    if [[ "$FORCE_CLEAN" == "true" ]]; then
        echo "🧹 Cleaning previous Flutter builds..."
        flutter clean
    else
        echo "🏃 Skipping Flutter clean (preserving build cache)"
    fi
    
    # Get dependencies
    echo "📦 Getting Flutter dependencies..."
    flutter pub get
    
    # Build for Linux
    echo "🔨 Building Flutter for Linux release..."
    flutter build linux --release
    
    # Verify build output
    if [[ -f "build/linux/x64/release/bundle/openssl_encrypt_mobile" ]]; then
        echo "✅ Flutter build successful"
        echo "📁 Binary: $(pwd)/build/linux/x64/release/bundle/openssl_encrypt_mobile"
    else
        echo "❌ Flutter build failed - binary not found"
        exit 1
    fi
    
    # Return to flatpak directory
    cd "$FLATPAK_DIR"
    echo "📁 Returned to Flatpak directory: $(pwd)"
fi

# Clean up build directory and optionally cache
if [[ "$FORCE_CLEAN" == "true" ]]; then
    echo "🧹 Force cleaning build directory and cache..."
    rm -rf build-dir repo .flatpak-builder
    echo "🔨 Building Flatpak package (clean build)..."
    flatpak-builder --repo=repo build-dir com.opensslencrypt.OpenSSLEncrypt.json
else
    echo "🧹 Cleaning up repo directory (preserving build cache)..."
    rm -rf repo
    echo "🔨 Building Flatpak package with incremental build..."
    echo "ℹ️  Using build cache from .flatpak-builder/ (if exists)"
    flatpak-builder --force-clean --repo=repo build-dir com.opensslencrypt.OpenSSLEncrypt.json
fi

# Update the repository summary (required for remote access)
echo "📋 Updating repository summary..."
flatpak build-update-repo repo

# Only install locally if requested
if [[ "$LOCAL_INSTALL" == "true" ]]; then
    echo ""
    echo "🏠 Setting up local installation for testing..."
    
    # Clean up any existing local installation and remote
    echo "🧹 Removing existing local installation and remote..."
    # First uninstall the specific app
    flatpak --user uninstall -y com.opensslencrypt.OpenSSLEncrypt 2>/dev/null || true
    # Then remove the local remote (use consistent naming)
    flatpak --user remote-delete openssl-encrypt-local 2>/dev/null || true

    # Add local repository
    echo "📁 Adding local repository for testing..."
    REPO_PATH="$(pwd)/repo"
    echo "Repository path: $REPO_PATH"
    flatpak --user remote-add --no-gpg-verify openssl-encrypt-local "$REPO_PATH"

    # Install the built package
    echo "💾 Installing the package locally..."
    flatpak --user install -y openssl-encrypt-local com.opensslencrypt.OpenSSLEncrypt
    
    echo "✅ Local installation complete!"
    echo ""
    echo "🎯 To test the locally installed application:"
    echo "   CLI: flatpak run com.opensslencrypt.OpenSSLEncrypt --help"
    if [[ "$BUILD_FLUTTER" == "true" ]]; then
        echo "   GUI: flatpak run com.opensslencrypt.OpenSSLEncrypt --gui"
    else
        echo "   GUI: flatpak run com.opensslencrypt.OpenSSLEncrypt --gui"
        echo "   Note: Run with --build-flutter to include Flutter GUI"
    fi
    echo ""
    echo "🗑️  To uninstall local test version:"
    echo "   flatpak --user uninstall com.opensslencrypt.OpenSSLEncrypt"
    echo "   flatpak --user remote-delete openssl-encrypt-local"
else
    echo "✅ Build complete! Repository ready for build-remote.sh"
    echo ""
    echo "📦 Built repository: $(pwd)/repo"
    echo "🚀 To deploy to server: ./build-remote.sh [options]"
    echo "🏠 To test locally: $0 --local-install"
fi

echo ""
echo "🛠️  Build options:"
echo "   Build only:        $0"
echo "   With Flutter:      $0 --build-flutter"
echo "   Force clean:       $0 --force (or -f)"
echo "   Local testing:     $0 --local-install"
echo "   Combined example:  $0 --build-flutter --local-install --force"
