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
GPGKey=LS0tLS1CRUdJTiBQR1AgUFVCTElDIEtFWSBCTE9DSy0tLS0tCgptUUlOQkdoVHZUWUJFQURMTVBQcng2SkFidDlnRnJ4eVp5blpUNWxoYjhkcldjY0dGQWs2UzhwbEM4WVNFWHF3CmR5ZlQzZUJnSXJHcUZoVHlDY2ZFTU5Lc0pwTjFvdGpxckJwaEZmejFrZFh0SkJuYlhLWnZBNld6cDVNaEU0ZVUKa1p6N2ZwSTZMaGZKMlpQT2pGdzQvQzdqdTU2VHVwOE52RzYyaTJDR2NpUFJIY1Y0QXo1YXMweVhIdzE4QTgwdwo3MTI0WnN6cVYyL1Vibm1jWkNPT0h6RS9hVVY0ZVlFd2lPdnJzVzlhdld5VzF4TXQxYUNRK0dXTzZKelFTWWYxCjBvVitPL2NRa2pqdHB3M0VDRHFHQ2tkZ1IvYWtIYTFLakNhQkpIdnhGWk9Yd1c3WHV1MUp5YzZWVjg2SnYxTnkKVXM1YzVDSysvekNUNklWQXdEQjdrWDRMa2xzUEo5dEV1c1VVSlE2ekFhVWw2cFZ3WlFtRWlNT2pKdGxPWEttKwpncEM5ZzdaaHM1QzlIeCtEYnBwUWdwRWZyMDYyOGxDWk9FQlFIVHB4cTlwTnlnQTJYVmNUOGtxTEFGQTU1cVczCjRPMy9yTTB3dVJIRmdNR3Rna3FXTHZ5cXBFdlFpVEp6MnlCZnB5MWIyNGpuWmlETmQ4Z0NZK3ZWTmM0NjVGTzQKbktLWklycEgzYWozV2FKcFBpeEhzNkk4eHdCTVpMbmFBa2cvQ0I2amhDTTh5eWxwVU5CajZFWFRWVUwxMThvNwpaMzA0STJlbUxzd3F5OXlaVStySTdjL2ZqQStxWWNhSTZ3b2E4WmNnY0MzTzNGbFJJNzBrMDFSQm5SNWNxcW01CkVrSTlyU0NFL1R1c3VJRVhidUJvUU5rMXAwMys0amc5VXdIVy95R0lrbkFvcStkUVpSQ3N5ZnErcndBUkFRQUIKdEVGVWIySnBKM01nUm14aGRIQmhheUJTWlhCdmMybDBiM0o1SUNoR2JHRjBjR0ZySUZOcFoyNXBibWNnUzJWNQpLU0E4YW1Gb2JHbDJaWE5BWjIxNExtTm9Qb2tDVGdRVEFRb0FPQlloQkV0Z1N4bkxqSTZnaXhNQTN4NU1tZlQ3CmRpNDFCUUpvVTcwMkFoc0RCUXNKQ0FjQ0JoVUtDUWdMQWdRV0FnTUJBaDRCQWhlQUFBb0pFQjVNbWZUN2RpNDEKOVNJUC8zSG82SlEvTzJwMWIyNDVFMU5DOEhFK1dBQjI2dmY2ZFNad0RJQURSSzVRTllFSXVBd2hxYWZSMWYwOQo1K1VlRkx0TVlnU1JOM2J0YXkvUjMzejROeFJoZmYybjZnWm9QTXI5V1VEMklGakFyTjYxR0ZrWHRRK0lxU2d6CjJJUUtwcjFGN0t0d3Q0MldRdmh0cTRkNVcvNnhIRE5zWUc2MFhVWW1JcjdDS1dDYzMvWlRtN2pOZTEzRG91N2oKaUdqUWdza0N1clZCZkVLNEc5SUtMN0trc0Z6OWNiM3VDRTR6QmQ4QVV2RzBSZW80U0JwZWtHT0dqQW5WcEV3dgptV0N1cEZLeDNaR0FiUkJqeEtTcWZGZks1aVZ6cXQrUlB6QVNtSnlDelNoMmw1dEgrUHNIaE1HSzU3UTVRRmVnCjZKS09DSmU5NXFDQzJXazQvN0pVZjNOa0sxWnRYVS8rNHJQQnc3YVA0V0o3OUVQQllwQ3ovUjZWNjE3SjhrZWUKNjkrb0FVV2JEKzRmVnk0TnBET0hUemttVnc0TzR0c2taT0s2dk1kdUNUeFJUN1BjSGtIUnZoSUpvVnhLNzYrdQpic2JiVzUzOEZIRHJDcFVFVnBNNTZPNkQ0aGtzZnh3SzdldlJlMGpYRFo4NGJjMnk5ZGpOcWJhQ0dJbVhkTHBLCjlZSVB2VkVqajM0cE5VemFpaG90eE9RdklHakJnODZLNHVIUjVHWmZvc1R1TG5XblE4T1lPTzhPZlF0TDJlNnQKSG4vak9NUTBoT2tBQ3REd0d2QWhjaWV2bCtzdksyR3IweWlMeHM0OHppY2JOelNvOUN4NlYveHcrOGxQNGkyUgp3bm9sdS9GZ2YvL0hYK0Vtb3FvaVlncXkzNHorOFpKam5ndmJkaGFVNzNRSXJEa2x1UUlOQkdoVHZUWUJFQURICjNRYkZ6eHF4cFdHQUFKc2tiNU84MVBHdWZmWFByaytYRGNsZnJGNXBQZGJ4NFRWQWtDVGlaSFJzbEk1aXBSODIKUk4wREVNdncxSUY3QmFJVkFUdXdvVkI2V1hINEM0b0FJQWJ4aEhmS3pGdC9ib3E4bndYa0hXenJ3TG94T05nUApib2xVK1BsSzZjUzlZdnU2VGdVS0k5bUNDS2RhWGZqckQ0U1JtYzRCNG44WitIWEIzY2p5OTZ4TWttdnFhOHNsCm14bENSOWl1SVQzdWYzSkRxcWRLaVYvQWxoL3F2UFRRVDIyZ0tXZzdBeExiWUV2VjBEYmM0MGxPWDIxQ0FFU1UKRkhrcWdDU2VQRjhnNmlOQmdoWHpDVCtQNGlhQmtFODBxWTRNMXRKRkE1VHpXRW9SUGtDQWlEZTZZR3ZzZjRYMwpqbzlVOUlpUWxmM2UrU2NhV0tjWjFIaEFsUGNOUHM0Qmo2ZEJlL3lKREpNT1NlS1I5OGF5V2lSMUlLWVhoTnE1ClF0V2t6Y1pjZjhKbllnS2FXSnBESnNpN0dsK3diaWlPSENRQnRyMm5rcE5TaWdraXdRTkMrYVIwbmk4RUFrTmkKWGtJaUx4VTVKRFA3YThlVFdjSnYxNWo5elF5RmVJdWw4dFhrcSt3eUNJWmhEbno3V2pFYUc5MjBGVWcyWWRaNApXOERjVFZtV21JUVFMTTJnZENTNDgzT0JTOTJ3UktZajVXTzVWYnVUaGJrOElTakwwSTBwc1l6MFVzcCtmRWZnCk5wWmpBbkJKY09qaFRUdmlqY2dKd1Y2cHBSckJZYysrMVhtOFgyRnlENkk4eEFGa1Y5VjBxNDJxdG5uVlZHYlIKY1U0TXNhK2dCR3ZKdXlhanQ5Y2kxTjkrNWlaUlBpclR1d1AwNlB4dUxRQVJBUUFCaVFJMkJCZ0JDZ0FnRmlFRQpTMkJMR2N1TWpxQ0xFd0RmSGt5WjlQdDJMalVGQW1oVHZUWUNHd3dBQ2drUUhreVo5UHQyTGpXaEtoQUFsSDRXCmExZU1jY29FcHRyOURhbHEyL0QxVzV5TWFGbGk4YnNmQXVkTEkzQ3J0MXpiWEFIM0ZQUlR3bkdBSW4wM28yWlIKNG9VbU9pcDIya3lHc3ZmQ2ZlREZOOUs0aFZBUWFXb3lLYmR0OVNzZWhLTVBrWFNOREVNeVhqdFdvMzNFQld0dwpXaUpqeGIrekFlTHgyVFlhMTNXWmVtaU4vTFdwbmZNS3o3QjRwdDFxQnF2YzQ2K3pYejhocThFaXRJQ1dVM1VVCncxMmxFOGlYZG1SMVlHZkd0cFNmdlJwZHhzc3g4SUJ4ZFdNcTBBOFVBT2tLYk5VSmJzMUZwV01Ea3NOeU5rZ2gKdjVCUDlLNHk0bjVZeENZa2o5SEMwdm9RRGl2S2xtSmY0Q1ZqbTdoZUhDd2p2eS9ldUVJSE90cG10WWJ2ZmpvZgp2dVJJTTFFZXQ1bitJSjRUdzFnMTVTenFtOE1Kcm1QK0Z0a01ncVE2eE02VGRVM25lUGhJVm84VFlDV1hMamNDCnYyZXBxNkNGM2pDQzRsR3Q4UDVBQ0htemgzWGVKeDlOdWgxMlQvVDN1OFRseWYwQ3pXakpPaTQxL1k5RjNaNm0KaU4xK1Z0Zk9DSDB3cFBuRkUxSjR2ZEVvamhpMTF6NWw0ZW40SjhBRFFsQUUxam5BU09qMS9qeUJXb2ZVL0YrbwpVRm9BNC9BUlJtVm01bDVwQnoybjlYU3U2NUZtQ1l1TC90V0FLc0VvNUVLZStaR0NSTFNqUFpnRzRFRW5MWllBCld1MnBuVEo4bHdQdGdpUWZqOGFoeERtWkhNcTlMNUpvT0NQU1dRQXhWZGlrVVAxZ2ZvZXNtNEVkc3YvQUM0cGUKRnE2UnRGSysxbXR6OGc2QlMxVlUxbXNoeWJnK29Ua0JwTVNmdmhjPQo9Zks4YgotLS0tLUVORCBQR1AgUFVCTElDIEtFWSBCTE9DSy0tLS0tCg==
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
