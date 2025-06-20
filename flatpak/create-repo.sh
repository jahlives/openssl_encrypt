#!/bin/bash
set -e

echo "🏗️ Creating self-hosted Flatpak repository..."

# Build the Flatpak if not already built
if [ ! -d "repo" ]; then
    echo "Building Flatpak first..."
    ./build-flatpak.sh
fi

# Create web-ready repository
echo "📦 Preparing web repository..."
mkdir -p web-repo
cp -r repo/* web-repo/

# Generate summary and metadata
echo "📋 Generating repository metadata..."
ostree summary -u --repo=web-repo

# Create installation instructions
cat > web-repo/install.sh << 'EOF'
#!/bin/bash
# Installation script for OpenSSL Encrypt Flatpak

REPO_URL="https://your-domain.com/flatpak-repo"  # Update this URL
APP_ID="com.opensslencrypt.OpenSSLEncrypt"

echo "🔐 Installing OpenSSL Encrypt Flatpak from custom repository..."

# Add the repository
flatpak remote-add --if-not-exists openssl-encrypt "$REPO_URL"

# Install the application
flatpak install openssl-encrypt "$APP_ID"

echo "✅ Installation complete!"
echo "🚀 Run with: flatpak run $APP_ID"
EOF

chmod +x web-repo/install.sh

# Create web page
cat > web-repo/index.html << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>OpenSSL Encrypt - Flatpak Repository</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; }
        .install-box { background: #f5f5f5; padding: 20px; border-radius: 8px; margin: 20px 0; }
        code { background: #e8e8e8; padding: 2px 4px; border-radius: 3px; }
        pre { background: #f0f0f0; padding: 15px; border-radius: 5px; overflow-x: auto; }
    </style>
</head>
<body>
    <h1>🔐 OpenSSL Encrypt - Flatpak Distribution</h1>

    <p>Military-grade encryption with post-quantum cryptography support.</p>

    <div class="install-box">
        <h2>📥 Quick Installation</h2>
        <pre><code>curl -sSL https://your-domain.com/flatpak-repo/install.sh | bash</code></pre>
    </div>

    <div class="install-box">
        <h2>🔧 Manual Installation</h2>
        <p>1. Add the repository:</p>
        <pre><code>flatpak remote-add --if-not-exists openssl-encrypt https://your-domain.com/flatpak-repo</code></pre>

        <p>2. Install the application:</p>
        <pre><code>flatpak install openssl-encrypt com.opensslencrypt.OpenSSLEncrypt</code></pre>

        <p>3. Run the application:</p>
        <pre><code>flatpak run com.opensslencrypt.OpenSSLEncrypt</code></pre>
    </div>

    <h2>✨ Features</h2>
    <ul>
        <li>🛡️ Military-grade symmetric encryption</li>
        <li>🔮 Post-quantum cryptography (ML-KEM, HQC)</li>
        <li>🔐 Advanced password protection</li>
        <li>🖥️ Both GUI and CLI interfaces</li>
        <li>🗃️ Secure file operations</li>
    </ul>

    <p><a href="https://gitlab.com/your-username/openssl-encrypt">📚 Documentation & Source Code</a></p>
</body>
</html>
EOF

echo "✅ Repository created in web-repo/"
echo "📂 Upload web-repo/ contents to your web server"
echo "🌐 Update URLs in install.sh and index.html"
echo "🚀 Users can then add your repository and install your app!"
