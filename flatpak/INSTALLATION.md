# Installing OpenSSL Encrypt Flatpak from GitLab

## Method 1: Download from Package Registry (Recommended)

1. **Go to the Package Registry**
   - Visit: https://gitlab.rm-rf.ch/world/openssl_encrypt/-/packages
   - Find the latest `openssl-encrypt-flatpak` package
   - Download the `.flatpak` file

2. **Install the downloaded package**
   ```bash
   flatpak install --user com.opensslencrypt.OpenSSLEncrypt.flatpak
   ```

3. **Run the application**
   ```bash
   # GUI mode
   flatpak run com.opensslencrypt.OpenSSLEncrypt --gui

   # CLI mode
   flatpak run com.opensslencrypt.OpenSSLEncrypt --help
   ```

## Method 2: Add as Flatpak Remote Repository

1. **Add the repository** (requires GitLab access)
   ```bash
   flatpak remote-add --user openssl-encrypt-repo \
     https://gitlab.rm-rf.ch/world/openssl_encrypt/-/jobs/artifacts/main/raw/flatpak/public/repo?job=create-repository
   ```

2. **Install from repository**
   ```bash
   flatpak install --user openssl-encrypt-repo com.opensslencrypt.OpenSSLEncrypt
   ```

3. **Get automatic updates**
   ```bash
   flatpak update com.opensslencrypt.OpenSSLEncrypt
   ```

## Method 3: Install via wget/curl

```bash
# Download latest package
VERSION=$(curl -s "https://gitlab.rm-rf.ch/api/v4/projects/world%2Fopenssl_encrypt/packages" | \
          grep -o '"version":"[^"]*"' | head -1 | cut -d'"' -f4)

wget "https://gitlab.rm-rf.ch/world/openssl_encrypt/-/packages/generic/openssl-encrypt-flatpak/${VERSION}/com.opensslencrypt.OpenSSLEncrypt.flatpak"

# Install
flatpak install --user com.opensslencrypt.OpenSSLEncrypt.flatpak
```

## Requirements

- Flatpak runtime installed on your system
- Access to your GitLab instance (gitlab.rm-rf.ch)
- For private packages: GitLab authentication token

## Troubleshooting

**Permission denied downloading packages:**
- Ensure you're logged into GitLab
- For CLI access, create a Personal Access Token with `read_api` scope
- Use token in wget: `--header="PRIVATE-TOKEN: your_token"`

**Flatpak not found:**
```bash
# Install Flatpak on your system first
# Fedora/RHEL
sudo dnf install flatpak

# Ubuntu/Debian
sudo apt install flatpak

# Add Flathub for dependencies
flatpak remote-add --if-not-exists flathub https://flathub.org/repo/flathub.flatpakrepo
```
