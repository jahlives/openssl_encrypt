#!/bin/bash

set -e  # Exit on any error

# Configuration
LOCAL_REPO="/home/work/private/flatpak-shared-repo"
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
    echo "  $0 --default-branch 1.0.0            # Build with branch 1.0.0"
    echo "  $0 --default-branch stable --version 1.1.0  # Auto-creates branch 'stable-1.1.0'"
    echo "  $0 --default-branch master --version 1.2.0  # Auto-creates branch 'master-1.2.0'"
    echo "  $0 --default-branch nightly --version 1.3.0 # Auto-creates branch 'nightly-1.3.0'"
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


# Auto-adjust branch name if both branch and version are specified
if [ -n "$DEFAULT_BRANCH" ] && [ -n "$VERSION" ] && [ "$DEFAULT_BRANCH" != "$VERSION" ]; then
    # Always use VERSION-BRANCH format when both parameters are provided
    ORIGINAL_BRANCH="$DEFAULT_BRANCH"
    DEFAULT_BRANCH="${VERSION}-${DEFAULT_BRANCH}"
    echo "🔄 Auto-created descriptive branch name: $ORIGINAL_BRANCH → $DEFAULT_BRANCH"
    echo "   Users will see: Branch: $DEFAULT_BRANCH (version-branch format)"
    echo ""
fi

if [ ! -f "$MANIFEST" ]; then
      echo "❌ Error: Manifest file '$MANIFEST' not found!"
      exit 1
fi

# Update metainfo.xml with version if provided
if [ -n "$VERSION" ]; then
    METAINFO_FILE="com.opensslencrypt.OpenSSLEncrypt.metainfo.xml"
    if [ -f "$METAINFO_FILE" ]; then
        echo "📝 Updating metainfo.xml with version $VERSION"
        # Create a backup
        cp "$METAINFO_FILE" "${METAINFO_FILE}.backup"

        # Get current date in YYYY-MM-DD format
        CURRENT_DATE=$(date +%Y-%m-%d)

        # Replace entire releases section with only the current version
        echo "   Replacing releases section with version $VERSION only"

        # Use Python to safely handle XML manipulation
        python3 << EOF
import re

# Read the metainfo file
with open('$METAINFO_FILE', 'r') as f:
    content = f.read()

# Create new releases section
new_releases = '''  <releases>
    <release version="$VERSION" date="$CURRENT_DATE" type="stable">
      <description>
        <p>Version $VERSION build</p>
      </description>
    </release>
  </releases>'''

# Remove existing releases section and add new one
content = re.sub(r'  <releases>.*?</releases>', new_releases, content, flags=re.DOTALL)

# If no releases section existed, add it before content_rating
if '<releases>' not in content:
    content = re.sub(r'  <content_rating', new_releases + '\n  <content_rating', content)

# Write back to file
with open('$METAINFO_FILE', 'w') as f:
    f.write(content)
EOF
        echo "   Replaced releases section with version $VERSION"

        # Show what was added for verification
        echo "   New release entry:"
        grep -A 6 "<releases>" "$METAINFO_FILE"

        # Commit the metainfo.xml changes so flatpak-builder can use them
        echo "   Committing metainfo.xml changes to git..."
        git add "$METAINFO_FILE"
        if git commit -m "Update metainfo.xml with version $VERSION for flatpak build"; then
            echo "   ✅ Successfully committed metainfo.xml changes"
            echo "   ⏱️  Waiting 3 seconds for git changes to propagate..."
        else
            echo "   ⚠️  Git commit failed or no changes to commit"
        fi
    else
        echo "⚠️  Warning: Metainfo file not found at $METAINFO_FILE"
    fi
fi

echo "🏗️  Building Flatpak application locally..."
if [ -n "$DEFAULT_BRANCH" ]; then
    echo "📋 Using branch: $DEFAULT_BRANCH"
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
      echo "Waiting for filesystem sync..."
      sync
      echo "Updating ostree summary..."
      ostree summary -u --repo='"$SERVER_REPO"' --gpg-sign='"\"$GPG_KEY_ID\""'
      echo "Rebuilding flatpak repository and appstream metadata..."
      flatpak build-update-repo --gpg-sign='"\"$GPG_KEY_ID\""' '"$SERVER_REPO"'
      echo "Setting ownership..."
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
flatpak update --appstream custom-repo
echo ""
flatpak update --appstream custom-repo
echo "Clients can now install with:"
if [ -n "$DEFAULT_BRANCH" ]; then
    echo "flatpak install custom-repo com.opensslencrypt.OpenSSLEncrypt//$DEFAULT_BRANCH"
else
    echo "flatpak install custom-repo com.opensslencrypt.OpenSSLEncrypt"
fi
