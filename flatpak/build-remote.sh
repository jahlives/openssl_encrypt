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

# Default values
DEFAULT_BRANCH=""
VERSION=""
CLEAN_BUILD=false

# Function to display usage
usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --default-branch BRANCH    Set the default branch for flatpak-builder"
    echo "  --version VERSION          Set the version tag in manifest (overrides default-branch for version)"
    echo "  --clean                    Clean build directory before building"
    echo "  -h, --help                 Show this help message"
    echo ""
    echo "Environment variables:"
    echo "  FLATPAK_DEFAULT_BRANCH     Default branch (can be overridden by --default-branch)"
    echo ""
    echo "Examples:"
    echo "  $0                                    # Build with default settings"
    echo "  $0 --clean                           # Clean build"
    echo "  $0 --default-branch 1.0.0            # Build with branch 1.0.0 and version 1.0.0"
    echo "  $0 --version 1.1.0                   # Build with version 1.1.0 (uses default branch)"
    echo "  $0 --default-branch master --version 1.2.0  # Build master branch but with version 1.2.0"
    echo "  $0 --default-branch stable --clean   # Clean build with stable branch"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --default-branch)
            DEFAULT_BRANCH="$2"
            shift 2
            ;;
        --version)
            VERSION="$2"
            shift 2
            ;;
        --clean|clean)
            CLEAN_BUILD=true
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "❌ Error: Unknown option '$1'"
            usage
            exit 1
            ;;
    esac
done

# Use environment variable if DEFAULT_BRANCH not set via command line
if [ -z "$DEFAULT_BRANCH" ] && [ -n "$FLATPAK_DEFAULT_BRANCH" ]; then
    DEFAULT_BRANCH="$FLATPAK_DEFAULT_BRANCH"
fi

# Determine version to use: explicit --version takes priority, then --default-branch, then nothing
MANIFEST_VERSION=""
if [ -n "$VERSION" ]; then
    MANIFEST_VERSION="$VERSION"
elif [ -n "$DEFAULT_BRANCH" ] && [ "$DEFAULT_BRANCH" != "master" ]; then
    MANIFEST_VERSION="$DEFAULT_BRANCH"
fi

if [ ! -f "$MANIFEST" ]; then
      echo "❌ Error: Manifest file '$MANIFEST' not found!"
      exit 1
fi

echo "🏗️  Building Flatpak application locally..."
if [ -n "$DEFAULT_BRANCH" ]; then
    echo "📋 Using default branch: $DEFAULT_BRANCH"
fi
if [ -n "$MANIFEST_VERSION" ]; then
    echo "📋 Using version tag: $MANIFEST_VERSION"
fi

# Update manifest version if specified
ORIGINAL_MANIFEST="$MANIFEST"
TEMP_MANIFEST="${MANIFEST}.tmp"

if [ -n "$MANIFEST_VERSION" ]; then
    echo "📝 Version will be set via flatpak build-commit-from: $MANIFEST_VERSION"
    echo "ℹ️  This will appear in the 'Version' column of 'flatpak remote-ls'"
fi

find "$BUILD_DIR" -mindepth 1 -maxdepth 1 ! -name '.flatpak-builder' -exec rm -rf {} +

# Ensure directories exist
mkdir -p "$LOCAL_REPO"
mkdir -p "$BUILD_DIR"

# Initialize repo if needed
if [ ! -d "$LOCAL_REPO" ]; then
    ostree init --mode=archive-z2 --repo="$LOCAL_REPO"
fi

# Clean build if requested
if [ "$CLEAN_BUILD" = true ]; then
    echo "🧹 Cleaning build directory..."
    rm -rf "$BUILD_DIR"
fi

# Build the application with optional default branch
BUILDER_ARGS=(
    --repo="$LOCAL_REPO"
    --gpg-sign="$GPG_KEY_ID"
)

# Add default branch if specified
if [ -n "$DEFAULT_BRANCH" ]; then
    BUILDER_ARGS+=(--default-branch="$DEFAULT_BRANCH")
fi

# Add force-clean if clean build requested
if [ "$CLEAN_BUILD" = true ]; then
    BUILDER_ARGS+=(--force-clean)
fi

# Add build directory and manifest
BUILDER_ARGS+=("$BUILD_DIR" "$MANIFEST")

echo "🔨 Running flatpak-builder with args: ${BUILDER_ARGS[*]}"
flatpak-builder "${BUILDER_ARGS[@]}"

echo "✅ Build complete!"

# Set version using flatpak build-commit-from if version is specified
if [ -n "$MANIFEST_VERSION" ]; then
    echo "📝 Setting version using flatpak build-commit-from: $MANIFEST_VERSION"
    
    # Get the app ID from manifest
    APP_ID="com.opensslencrypt.OpenSSLEncrypt"
    BRANCH_NAME="${DEFAULT_BRANCH:-master}"
    
    # Use flatpak build-commit-from to set version metadata properly
    echo "📋 Updating flatpak metadata with version: $MANIFEST_VERSION"
    
    # Create a temporary commit with the version metadata
    flatpak build-commit-from \
        --repo="$LOCAL_REPO" \
        --gpg-sign="$GPG_KEY_ID" \
        --subject="Export $APP_ID with version $MANIFEST_VERSION" \
        --body="Version: $MANIFEST_VERSION" \
        --app-version="$MANIFEST_VERSION" \
        "$LOCAL_REPO" \
        "app/$APP_ID/x86_64/$BRANCH_NAME"
        
    if [ $? -eq 0 ]; then
        echo "✅ Version metadata added successfully: $MANIFEST_VERSION"
    else
        echo "⚠️  Failed to add version metadata using flatpak build-commit-from"
        echo "    Trying alternative approach..."
        
        # Fallback: Use ostree to add app metadata
        ostree --repo="$LOCAL_REPO" commit \
            --branch="app/$APP_ID/x86_64/$BRANCH_NAME" \
            --add-metadata-string="xa.version=$MANIFEST_VERSION" \
            --add-metadata-string="xa.metadata.version=$MANIFEST_VERSION" \
            --gpg-sign="$GPG_KEY_ID" \
            --tree=ref="app/$APP_ID/x86_64/$BRANCH_NAME" \
            --no-bindings \
            --subject="Add version metadata: $MANIFEST_VERSION"
            
        if [ $? -eq 0 ]; then
            echo "✅ Version metadata added via ostree: $MANIFEST_VERSION"
        else
            echo "⚠️  Failed to add version metadata, but build completed successfully"
        fi
    fi
fi

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
# Clean up any temporary files (no file modifications needed with ostree approach)
if [ -n "$MANIFEST_VERSION" ]; then
    echo "✅ Build completed with version: $MANIFEST_VERSION"
fi

echo "🎉 Deployment complete!"
echo ""
echo "Clients can now install with:"
if [ -n "$DEFAULT_BRANCH" ]; then
    echo "flatpak install custom-repo com.opensslencrypt.OpenSSLEncrypt//$DEFAULT_BRANCH"
else
    echo "flatpak install custom-repo com.opensslencrypt.OpenSSLEncrypt"
fi

