#!/bin/bash
set -e

echo "🚀 Building OpenSSL Encrypt Flatpak package..."

# Parse command line arguments
BUILD_FLUTTER=false
FORCE_CLEAN=false
LOCAL_INSTALL=false
DEV_INSTALL=false
FLATPAK_BRANCH="stable"

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
            echo "🏠 Local installation requested (stable branch)"
            ;;
        --dev-install)
            DEV_INSTALL=true
            LOCAL_INSTALL=true
            FLATPAK_BRANCH="development"
            echo "🧪 Development installation requested (development branch)"
            ;;
        *)
            echo "Unknown argument: $arg"
            echo "Usage: $0 [--build-flutter] [-f|--force] [--local-install|--dev-install]"
            echo "  --build-flutter   Build Flutter desktop GUI before Flatpak"
            echo "  -f, --force       Force clean build cache"
            echo "  --local-install   Install locally as stable branch (overwrites production)"
            echo "  --dev-install     Install locally as development branch (parallel to production)"
            echo ""
            echo "Examples:"
            echo "  $0                          # Build only (for build-remote.sh)"
            echo "  $0 --local-install          # Build and install as stable"
            echo "  $0 --dev-install            # Build and install as development (recommended for testing)"
            echo "  $0 --build-flutter --dev-install  # Build with GUI and install as development"
            exit 1
            ;;
    esac
done

# Check if flatpak-builder is installed
if ! command -v flatpak-builder &> /dev/null; then
    echo "❌ flatpak-builder not found."
    echo "📋 This script needs to install flatpak-builder to continue."

    # Ask for user consent before using sudo
    read -p "🔐 Do you want to install flatpak-builder with sudo? (y/N): " consent
    if [[ "$consent" != "y" && "$consent" != "Y" ]]; then
        echo "❌ User declined installation. Please install flatpak-builder manually:"
        if command -v dnf &> /dev/null; then
            echo "   sudo dnf install -y flatpak-builder"
        elif command -v apt &> /dev/null; then
            echo "   sudo apt update && sudo apt install -y flatpak-builder"
        elif command -v pacman &> /dev/null; then
            echo "   sudo pacman -S flatpak-builder"
        fi
        exit 1
    fi

    echo "📦 Installing flatpak-builder..."
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
echo "📦 Building for branch: $FLATPAK_BRANCH"
if [[ "$FORCE_CLEAN" == "true" ]]; then
    echo "🧹 Force cleaning build directory and cache..."
    rm -rf build-dir repo .flatpak-builder
    echo "🔨 Building Flatpak package (clean build)..."
    flatpak-builder --repo=repo --default-branch="$FLATPAK_BRANCH" build-dir com.opensslencrypt.OpenSSLEncrypt.json
else
    echo "🧹 Cleaning up repo directory (preserving build cache)..."
    rm -rf repo
    echo "🔨 Building Flatpak package with incremental build..."
    echo "ℹ️  Using build cache from .flatpak-builder/ (if exists)"
    flatpak-builder --force-clean --repo=repo --default-branch="$FLATPAK_BRANCH" build-dir com.opensslencrypt.OpenSSLEncrypt.json
fi

# Update the repository summary (required for remote access)
echo "📋 Updating repository summary..."
flatpak build-update-repo repo

# Only install locally if requested
if [[ "$LOCAL_INSTALL" == "true" ]]; then
    echo ""
    echo "🏠 Setting up local installation for testing..."

    # Use branch-specific remote name
    REMOTE_NAME="openssl-encrypt-$FLATPAK_BRANCH"
    BRANCH_DISPLAY="($FLATPAK_BRANCH branch)"

    # Clean up any existing local installation and remote for this branch
    echo "🧹 Removing existing $FLATPAK_BRANCH branch installation and remote..."
    # First uninstall the specific app branch
    flatpak --user uninstall -y com.opensslencrypt.OpenSSLEncrypt//$FLATPAK_BRANCH 2>/dev/null || true
    # Then remove the branch-specific remote
    flatpak --user remote-delete "$REMOTE_NAME" 2>/dev/null || true

    # Add local repository with branch-specific remote name
    echo "📁 Adding local repository for $FLATPAK_BRANCH branch..."
    REPO_PATH="$(pwd)/repo"
    echo "Repository path: $REPO_PATH"
    flatpak --user remote-add --no-gpg-verify "$REMOTE_NAME" "$REPO_PATH"

    # Install the built package with specific branch
    echo "💾 Installing the package locally as $FLATPAK_BRANCH branch..."
    flatpak --user install -y "$REMOTE_NAME" com.opensslencrypt.OpenSSLEncrypt//$FLATPAK_BRANCH

    echo "✅ Local installation complete $BRANCH_DISPLAY!"
    echo ""
    echo "🎯 To test the locally installed application:"
    echo "   CLI: flatpak run com.opensslencrypt.OpenSSLEncrypt//$FLATPAK_BRANCH --help"
    if [[ "$BUILD_FLUTTER" == "true" ]]; then
        echo "   GUI: flatpak run com.opensslencrypt.OpenSSLEncrypt//$FLATPAK_BRANCH --gui"
    else
        echo "   GUI: flatpak run com.opensslencrypt.OpenSSLEncrypt//$FLATPAK_BRANCH --gui"
        echo "   Note: Run with --build-flutter to include Flutter GUI"
    fi
    echo ""
    if [[ "$DEV_INSTALL" == "true" ]]; then
        echo "ℹ️  This is a development branch - it runs parallel to production!"
        echo "   Production (if installed): flatpak run com.opensslencrypt.OpenSSLEncrypt//stable"
        echo "   Development (this build):  flatpak run com.opensslencrypt.OpenSSLEncrypt//development"
    fi
    echo ""
    echo "🗑️  To uninstall this $FLATPAK_BRANCH version:"
    echo "   flatpak --user uninstall com.opensslencrypt.OpenSSLEncrypt//$FLATPAK_BRANCH"
    echo "   flatpak --user remote-delete $REMOTE_NAME"
else
    echo "✅ Build complete! Repository ready for build-remote.sh"
    echo ""
    echo "📦 Built repository: $(pwd)/repo"
    echo "🚀 To deploy to server: ./build-remote.sh [options]"
    echo "🏠 To test locally (stable):  $0 --local-install"
    echo "🧪 To test locally (dev):     $0 --dev-install"
fi

echo ""
echo "🛠️  Build options:"
echo "   Build only:              $0"
echo "   With Flutter:            $0 --build-flutter"
echo "   Force clean:             $0 --force (or -f)"
echo "   Stable branch install:   $0 --local-install"
echo "   Dev branch install:      $0 --dev-install (recommended for testing v1.3.0)"
echo "   Combined example:        $0 --build-flutter --dev-install --force"
