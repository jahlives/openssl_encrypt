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
REPO_NAME="openssl-encrypt"  # Name for the .flatpakrepo file

GPG_KEY_BASE64=$(gpg --export "${GPG_KEY_ID}" | base64 -w0)

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

        # Ensure the current version is documented WITHOUT discarding the
        # curated release history: prepend a stub entry only if this version
        # is not already listed (the maintainer may have hand-written it).
        echo "   Ensuring metainfo lists version $VERSION (release history preserved)"

        # Use Python to safely handle XML manipulation
        python3 << EOF
import re

# Read the metainfo file
with open('$METAINFO_FILE', 'r') as f:
    content = f.read()

if 'version="$VERSION"' in content:
    print("   metainfo already lists $VERSION - leaving <releases> untouched")
else:
    new_entry = '''    <release version="$VERSION" date="$CURRENT_DATE" type="stable">
      <description>
        <p>Version $VERSION build</p>
      </description>
    </release>
'''
    if '  <releases>\n' in content:
        # Insert as the newest release, right after the <releases> open tag
        content = content.replace('  <releases>\n', '  <releases>\n' + new_entry, 1)
        print("   prepended release entry for $VERSION (existing history kept)")
    else:
        # No releases section yet - create one before content_rating
        new_releases = '  <releases>\n' + new_entry + '  </releases>'
        content = re.sub(r'  <content_rating', new_releases + '\n  <content_rating', content)
        print("   created <releases> section with $VERSION")

    with open('$METAINFO_FILE', 'w') as f:
        f.write(content)
EOF

        # Show the top of the releases list for verification
        echo "   Releases section (top):"
        grep -A 6 "<releases>" "$METAINFO_FILE"

        # Commit only if the version stamp actually changed the file, so that
        # building an already-documented version doesn't create a spurious commit.
        if ! git diff --quiet -- "$METAINFO_FILE"; then
            echo "   Committing metainfo.xml changes to git..."
            git add "$METAINFO_FILE"
            if git commit -m "Update metainfo.xml with version $VERSION for flatpak build" --no-verify; then
                echo "   ✅ Successfully committed metainfo.xml changes"
                echo "   ⏱️  Waiting 3 seconds for git changes to propagate..."
            else
                echo "   ⚠️  Git commit failed"
            fi
        else
            echo "   ✓ metainfo.xml already up to date for $VERSION - nothing to commit"
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
# Generate and upload .flatpakrepo file
echo "📝 Generating repository configuration file..."
FLATPAKREPO_FILE="${REPO_NAME}.flatpakrepo"

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

# Upload the .flatpakrepo file to server
echo "📤 Uploading repository configuration file..."
scp "$FLATPAKREPO_FILE" "root@$SERVER:$SERVER_REPO/"
if [ $? -ne 0 ]; then
    echo "❌ Error: Failed to upload .flatpakrepo file"
    exit 1
fi

# Clean up local file
rm "$FLATPAKREPO_FILE"
echo "✅ Repository configuration uploaded successfully"

# Sync webstuff for flatpak repo
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
