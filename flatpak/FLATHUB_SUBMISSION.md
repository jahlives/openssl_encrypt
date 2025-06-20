# Flathub Submission Guide

## Steps to submit to Flathub:

1. **Fork the Flathub repository**
   ```bash
   git clone https://github.com/flathub/flathub.git
   cd flathub
   git checkout -b add-openssl-encrypt
   ```

2. **Create application directory**
   ```bash
   mkdir com.opensslencrypt.OpenSSLEncrypt
   cd com.opensslencrypt.OpenSSLEncrypt
   ```

3. **Copy required files**
   - Copy `com.opensslencrypt.OpenSSLEncrypt.json` (manifest)
   - Copy `com.opensslencrypt.OpenSSLEncrypt.metainfo.xml`
   - Copy `com.opensslencrypt.OpenSSLEncrypt.desktop`
   - Copy icon files

4. **Update manifest for Flathub**
   - Remove `"type": "dir", "path": ".."` source
   - Add Git source pointing to your repository:
   ```json
   "sources": [
     {
       "type": "git",
       "url": "https://gitlab.com/your-username/openssl-encrypt.git",
       "tag": "v1.0.0-rc3"
     }
   ]
   ```

5. **Submit pull request**
   - Commit changes
   - Push to your fork
   - Create PR to Flathub

## Requirements for Flathub:
- ✅ Open source license (you have MIT)
- ✅ Stable release (tag required)
- ✅ Working desktop application
- ✅ Proper AppStream metadata
- ✅ No bundled proprietary software

## Review process:
- Flathub team reviews security and quality
- Usually takes 1-2 weeks
- May request changes to manifest
- Once approved, automatically published
