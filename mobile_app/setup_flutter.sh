#!/bin/bash
# Flutter setup script for OpenSSL Encrypt Mobile

echo "🚀 Setting up Flutter development environment for OpenSSL Encrypt Mobile"

# Check if Flutter is installed
if ! command -v flutter &> /dev/null; then
    echo "❌ Flutter not found. Please install Flutter first:"
    echo "   1. Download: https://storage.googleapis.com/flutter_infra_release/releases/stable/linux/flutter_linux_3.24.5-stable.tar.xz"
    echo "   2. Extract: tar xf flutter_linux_stable.tar.xz"
    echo "   3. Move: sudo mv flutter /opt/flutter"
    echo "   4. Add to PATH: echo 'export PATH=\"/opt/flutter/bin:\$PATH\"' >> ~/.bashrc"
    echo "   5. Reload: source ~/.bashrc"
    exit 1
fi

echo "✅ Flutter found: $(flutter --version | head -n1)"

# Check Flutter doctor
echo "🏥 Running Flutter doctor..."
flutter doctor

# Install required system packages for Android development
echo "📦 Installing system dependencies..."
sudo dnf install -y java-11-openjdk-devel wget unzip

# Create Android SDK directory
mkdir -p ~/android-sdk/cmdline-tools

# Download Android Command Line Tools
echo "📱 Setting up Android SDK..."
cd ~/android-sdk/cmdline-tools
if [ ! -f "commandlinetools-linux-latest.zip" ]; then
    wget https://dl.google.com/android/repository/commandlinetools-linux-9477386_latest.zip -O commandlinetools-linux-latest.zip
fi

# Extract command line tools
unzip -q commandlinetools-linux-latest.zip
mv cmdline-tools latest 2>/dev/null || echo "Command line tools already moved"

# Set environment variables
export ANDROID_HOME=~/android-sdk
export PATH=$PATH:$ANDROID_HOME/cmdline-tools/latest/bin
export PATH=$PATH:$ANDROID_HOME/platform-tools

# Add to bashrc if not already there
if ! grep -q "ANDROID_HOME" ~/.bashrc; then
    echo "export ANDROID_HOME=~/android-sdk" >> ~/.bashrc
    echo "export PATH=\$PATH:\$ANDROID_HOME/cmdline-tools/latest/bin" >> ~/.bashrc
    echo "export PATH=\$PATH:\$ANDROID_HOME/platform-tools" >> ~/.bashrc
fi

# Install Android SDK components
echo "⚙️ Installing Android SDK components..."
yes | sdkmanager --licenses 2>/dev/null || true
sdkmanager "platform-tools" "platforms;android-33" "build-tools;33.0.2" "emulator" "system-images;android-33;google_apis;x86_64"

# Create AVD for testing
echo "📟 Creating Android Virtual Device..."
avdmanager create avd -n "OpenSSL_Encrypt_Test" -k "system-images;android-33;google_apis;x86_64" --force

echo "🎉 Setup complete!"
echo ""
echo "Next steps:"
echo "1. Run 'flutter doctor' to verify setup"
echo "2. Run 'flutter create openssl_encrypt_mobile' to create project"
echo "3. Run 'emulator -avd OpenSSL_Encrypt_Test' to start Android emulator"
echo "4. Run 'flutter run' to test the app"
