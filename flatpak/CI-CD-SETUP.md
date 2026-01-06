# Flatpak CI/CD Setup Guide

This guide explains how to configure GitLab CI/CD for automated Flatpak builds and publishing.

---

## Table of Contents

1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [CI/CD Variables Setup](#cicd-variables-setup)
4. [Runner Configuration](#runner-configuration)
5. [Pipeline Jobs](#pipeline-jobs)
6. [Usage](#usage)
7. [Troubleshooting](#troubleshooting)

---

## Overview

The Flatpak CI/CD pipeline consists of two stages:

1. **`flatpak-build`** - Builds the Flatpak package with Flutter GUI (cached)
2. **`flatpak-publish`** - Signs and publishes to `/var/www/flatpak-repo` (manual)

Both stages have **clean** variants that rebuild everything from scratch without cache.

---

## Prerequisites

### 1. GPG Signing Key

You need the GPG key pair for signing Flatpak packages:
- **Key ID**: `Tobi's Flatpak Repository (Flatpak Signing Key) <jahlives@gmx.ch>`
- **Private key**: Required for signing (stored as CI/CD variable)
- **Public key**: Already embedded in `generate-flatpakrepo.sh`

### 2. Server Setup

Ensure the following exist on your GitLab runner host:
- `/var/www/flatpak-repo` - Public flatpak repository directory
- `/home/work/private/flatpak-shared-repo` - Local build repository
- `www-data:www-data` - Web server user/group for permissions

---

## CI/CD Variables Setup

Go to **Settings → CI/CD → Variables** and add:

| Variable Name | Type | Value | Protected | Masked |
|---------------|------|-------|-----------|--------|
| `FLATPAK_GPG_PRIVATE_KEY` | Variable | [Base64 GPG key] | ✅ Yes | ✅ Yes |
| `FLATPAK_GPG_KEY_ID` | Variable | `Tobi's Flatpak Repository (Flatpak Signing Key) <jahlives@gmx.ch>` | ❌ No | ❌ No |
| `FLATPAK_REPO_PATH` | Variable | `/var/www/flatpak-repo` | ❌ No | ❌ No |

### Exporting GPG Private Key

```bash
# Export the private key and encode it
gpg --export-secret-keys --armor "Tobi's Flatpak Repository (Flatpak Signing Key) <jahlives@gmx.ch>" | base64 -w0 > gpg-key.b64

# Copy the content of gpg-key.b64 and paste it into the CI/CD variable
cat gpg-key.b64

# Clean up (IMPORTANT!)
shred -vfz gpg-key.b64
```

**⚠️ Security Notes:**
- Mark `FLATPAK_GPG_PRIVATE_KEY` as **Protected** (only available on protected branches)
- Mark `FLATPAK_GPG_PRIVATE_KEY` as **Masked** (hidden in job logs)
- Delete the `gpg-key.b64` file securely after copying

---

## Runner Configuration

You need a GitLab runner with access to `/var/www/flatpak-repo`.

### Option A: Docker Executor with Volume Mounts (Recommended)

Edit `/etc/gitlab-runner/config.toml`:

```toml
[[runners]]
  name = "flatpak-docker-runner"
  url = "https://gitlab.rm-rf.ch/"
  token = "YOUR_RUNNER_TOKEN"
  executor = "docker"
  [runners.docker]
    image = "fedora:latest"
    privileged = false
    volumes = [
      "/cache",
      "/var/www/flatpak-repo:/var/www/flatpak-repo:rw",
      "/home/work/private/flatpak-shared-repo:/home/work/private/flatpak-shared-repo:rw"
    ]
  [runners.cache]
    Type = "s3"  # Or use local volume cache
```

**Register the runner:**
```bash
sudo gitlab-runner register \
  --url https://gitlab.rm-rf.ch/ \
  --registration-token YOUR_TOKEN \
  --name flatpak-docker-runner \
  --executor docker \
  --docker-image fedora:latest \
  --docker-volumes "/var/www/flatpak-repo:/var/www/flatpak-repo:rw" \
  --docker-volumes "/home/work/private/flatpak-shared-repo:/home/work/private/flatpak-shared-repo:rw" \
  --tag-list "amd64,high-cpu"
```

### Option B: Shell Executor

```toml
[[runners]]
  name = "flatpak-shell-runner"
  url = "https://gitlab.rm-rf.ch/"
  token = "YOUR_RUNNER_TOKEN"
  executor = "shell"
  [runners.custom_build_dir]
    enabled = true
```

**Requirements for shell executor:**
- User running gitlab-runner must have write access to `/var/www/flatpak-repo`
- Install: `flatpak`, `flatpak-builder`, `ostree`, `gnupg2`, `rsync`, `git`

```bash
# Install dependencies (Fedora/RHEL)
sudo dnf install -y flatpak flatpak-builder ostree gnupg2 rsync git

# Add gitlab-runner user to www-data group
sudo usermod -a -G www-data gitlab-runner

# Set permissions
sudo chmod g+w /var/www/flatpak-repo
```

---

## Pipeline Jobs

### 1. `flatpak-build` (Automatic with cache)

**Trigger:** Automatically on `releases/*` branches and version tags

**What it does:**
- Installs Fedora dependencies
- Installs Flutter SDK
- Builds Flutter desktop GUI (`flutter build linux`)
- Builds Flatpak with `.flatpak-builder/` cache
- Exports artifacts: `flatpak/repo/` and `flatpak/build-dir/`

**Duration:** ~15-20 minutes (first run), ~5-10 minutes (with cache)

**Cache:**
- Location: `flatpak/.flatpak-builder/`
- Size: 2-5 GB (includes liboqs, cmake, ninja, rust builds)
- Key: `flatpak-${CI_COMMIT_REF_SLUG}`

### 2. `flatpak-build:clean` (Manual, no cache)

**Trigger:** Manual only

**What it does:**
- Same as `flatpak-build` but:
  - Runs `flutter clean`
  - Passes `--force` flag to `build-flatpak.sh`
  - Disables cache completely

**When to use:**
- After Flutter SDK updates
- To verify reproducible builds
- When cache is corrupted

### 3. `flatpak-publish` (Manual, with GPG signing)

**Trigger:** Manual (appears after `flatpak-build` completes)

**What it does:**
- Imports GPG private key from CI variable
- Rebuilds Flatpak with GPG signing
- Updates local repo: `/home/work/private/flatpak-shared-repo`
- Syncs to public repo: `/var/www/flatpak-repo`
- Updates ostree summaries with GPG signatures
- Generates `.flatpakrepo` file
- Syncs web assets from `flathub/` directory

**Branch naming:**
- For tags: Uses tag name (e.g., `v1.4.0` → branch `v1.4.0`)
- For branches: Extracts last part (e.g., `releases/1.4.0` → branch `1.4.0`)

### 4. `flatpak-publish:clean` (Manual, full rebuild)

**Trigger:** Manual only

**What it does:**
- Rebuilds Flutter from scratch
- Clears `.flatpak-builder/` cache
- Then runs same publish flow as `flatpak-publish`

**When to use:**
- For production releases
- When you want to ensure a completely clean build
- To verify the build without any cached artifacts

---

## Usage

### Normal Workflow (with cache)

1. **Push to `releases/1.4.0` branch:**
   - `flatpak-build` runs automatically
   - Wait ~5-10 minutes for build to complete

2. **Review artifacts:**
   - Check job logs for any warnings
   - Download artifacts if you want to test locally

3. **Manually trigger `flatpak-publish`:**
   - Go to **CI/CD → Pipelines**
   - Click on the pipeline
   - Click **▶️** button next to `flatpak-publish`
   - Confirm the manual job

4. **Verify deployment:**
   ```bash
   # Check the repository
   flatpak remote-ls openssl-encrypt --columns=name,branch,version

   # Test installation
   flatpak install openssl-encrypt com.opensslencrypt.OpenSSLEncrypt//1.4.0
   ```

### Clean Build Workflow (no cache)

Use this for production releases:

1. **Manually trigger `flatpak-publish:clean`:**
   - This builds everything from scratch with GPG signing
   - Takes ~30-45 minutes

2. **Verify deployment:**
   ```bash
   flatpak install openssl-encrypt com.opensslencrypt.OpenSSLEncrypt//1.4.0
   flatpak run com.opensslencrypt.OpenSSLEncrypt//1.4.0 --version
   ```

### Testing Locally Before Publishing

If you want to test the Flatpak before publishing:

1. **Download artifacts from `flatpak-build` job:**
   - Go to job page
   - Click **Download** on the right side
   - Extract `flatpak/repo/` directory

2. **Install locally:**
   ```bash
   cd flatpak
   flatpak remote-add --user --no-gpg-verify test-repo ./repo
   flatpak install --user test-repo com.opensslencrypt.OpenSSLEncrypt
   flatpak run com.opensslencrypt.OpenSSLEncrypt --help
   ```

---

## Troubleshooting

### GPG Import Fails

**Error:** `gpg: invalid armor header`

**Solution:**
```bash
# Re-export and verify the base64 encoding
gpg --export-secret-keys --armor "Tobi's Flatpak Repository" | base64 -w0 > gpg-key.b64

# Test decoding
cat gpg-key.b64 | base64 -d | gpg --import

# If successful, update CI/CD variable
```

### Permission Denied on `/var/www/flatpak-repo`

**Error:** `rsync: failed to modify permissions on "/var/www/flatpak-repo": Permission denied`

**Solution for Docker runner:**
```bash
# Set proper permissions on host
sudo chmod 775 /var/www/flatpak-repo
sudo chown -R www-data:www-data /var/www/flatpak-repo

# Add gitlab-runner user to www-data group (if using shell executor)
sudo usermod -a -G www-data gitlab-runner
```

**Solution for Docker runner with volume mount:**
```toml
# Add :z or :Z for SELinux contexts (if using SELinux)
volumes = [
  "/var/www/flatpak-repo:/var/www/flatpak-repo:rw,z"
]
```

### Flutter Build Fails

**Error:** `Flutter SDK is not available`

**Solution:**
- Flutter is downloaded fresh in each build from `git clone`
- If GitHub is rate-limiting, you can:
  1. Mirror Flutter SDK internally
  2. Use a pre-built Docker image with Flutter
  3. Wait and retry

### Cache Size Too Large

**Issue:** `.flatpak-builder/` cache is 5+ GB

**Solution:**
```yaml
# In .gitlab-ci.yml, add cache cleanup
script:
  # Before building
  - find flatpak/.flatpak-builder/downloads -type f -mtime +30 -delete  # Delete old downloads
  - du -sh flatpak/.flatpak-builder/  # Show cache size
```

Or use distributed cache (S3, GCS):
```toml
# In /etc/gitlab-runner/config.toml
[runners.cache]
  Type = "s3"
  Shared = true
  [runners.cache.s3]
    ServerAddress = "s3.amazonaws.com"
    BucketName = "gitlab-cache"
    BucketLocation = "us-east-1"
```

### Flatpak Repository Signature Verification Fails

**Error:** `error: GPG signatures found, but none are in trusted keyring`

**Solution:**
```bash
# Re-import GPG public key on client side
wget https://flatpak.rm-rf.ch/openssl-encrypt.flatpakrepo
flatpak remote-modify --gpg-import=/path/to/public-key.gpg openssl-encrypt

# Or re-add the repository
flatpak remote-delete openssl-encrypt
flatpak remote-add openssl-encrypt https://flatpak.rm-rf.ch/openssl-encrypt.flatpakrepo
```

### Branch Name Mismatch

**Issue:** Installed as wrong branch name

**Problem:** The branch name is derived from CI variables:
- `$CI_COMMIT_TAG` (for tags like `v1.4.0`)
- `${CI_COMMIT_BRANCH##*/}` (for branches like `releases/1.4.0` → `1.4.0`)

**Solution:**
To customize branch naming, edit the `flatpak-publish` job:
```yaml
script:
  - FLATPAK_BRANCH="stable"  # Force specific branch name
  # Or use version from git tag
  - FLATPAK_BRANCH=$(git describe --tags --always)
```

---

## Advanced Configuration

### Using a Custom Docker Image

To speed up builds, create a Docker image with Flutter and flatpak-builder pre-installed:

```dockerfile
# Dockerfile
FROM fedora:latest

RUN dnf install -y flatpak flatpak-builder git xz \
    clang cmake ninja-build gtk3-devel \
    ostree gnupg2 rsync

# Install Flutter
RUN git clone https://github.com/flutter/flutter.git -b stable /opt/flutter
ENV PATH="/opt/flutter/bin:$PATH"
RUN flutter precache --linux

# Setup Flathub
RUN flatpak remote-add --if-not-exists flathub https://flathub.org/repo/flathub.flatpakrepo
RUN flatpak install -y flathub org.freedesktop.Platform//24.08 \
    org.freedesktop.Sdk//24.08 \
    org.freedesktop.Sdk.Extension.rust-stable//24.08
```

Build and push:
```bash
docker build -t registry.rm-rf.ch/world/openssl_encrypt/flatpak-builder:latest .
docker push registry.rm-rf.ch/world/openssl_encrypt/flatpak-builder:latest
```

Update `.gitlab-ci.yml`:
```yaml
flatpak-build:
  image: registry.rm-rf.ch/world/openssl_encrypt/flatpak-builder:latest
  before_script:
    # Much shorter since dependencies are pre-installed
    - flutter --version
```

### Parallel Branch Builds

To support multiple branches simultaneously (e.g., stable + nightly):

```yaml
flatpak-publish:stable:
  extends: flatpak-publish
  variables:
    FLATPAK_BRANCH: "stable"
  rules:
    - if: $CI_COMMIT_TAG =~ /^v[0-9]+\.[0-9]+\.[0-9]+$/

flatpak-publish:nightly:
  extends: flatpak-publish
  variables:
    FLATPAK_BRANCH: "nightly"
  rules:
    - if: $CI_COMMIT_BRANCH == "dev"
      when: manual
```

---

## Security Best Practices

1. **Protect GPG Key:**
   - Store in protected CI/CD variables only
   - Mark as masked in job logs
   - Rotate annually

2. **Limit Runner Access:**
   - Use dedicated runner for flatpak publishing
   - Restrict write access to `/var/www/flatpak-repo`
   - Use separate user account for runner

3. **Verify Signatures:**
   - Always sign with `--gpg-sign`
   - Test signature verification after publishing
   - Monitor for unsigned packages

4. **Audit Builds:**
   - Review job logs for suspicious activity
   - Keep artifacts for 1 week for audit trail
   - Monitor cache size and content

---

## Resources

- [Flatpak Documentation](https://docs.flatpak.org/)
- [flatpak-builder Manual](https://docs.flatpak.org/en/latest/flatpak-builder.html)
- [OSTree Documentation](https://ostreedev.github.io/ostree/)
- [GitLab CI/CD Documentation](https://docs.gitlab.com/ee/ci/)
- [Project Repository](https://gitlab.rm-rf.ch/world/openssl_encrypt)

---

## Support

If you encounter issues:

1. Check the [Troubleshooting](#troubleshooting) section
2. Review job logs in GitLab CI/CD
3. Check runner logs: `sudo journalctl -u gitlab-runner -f`
4. Open an issue on GitLab

---

**Last Updated:** 2026-01-06
**Maintainer:** Tobi <jahlives@gmx.ch>
