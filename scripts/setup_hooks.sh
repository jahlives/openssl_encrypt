#!/bin/bash
# Script to set up pre-commit hooks for openssl_encrypt

# Check if pip is installed
if ! command -v pip &> /dev/null; then
    echo "Error: pip is not installed. Please install pip first."
    exit 1
fi

# Install pre-commit if not already installed
echo "Checking for pre-commit..."
if ! command -v pre-commit &> /dev/null; then
    echo "Installing pre-commit..."
    pip install pre-commit
else
    echo "pre-commit is already installed."
fi

# Install the required security tools
echo "Installing security scanning tools..."
pip install bandit pip-audit

# Install the git hooks
echo "Installing git hooks..."
pre-commit install

# Update hooks to the latest versions
echo "Updating pre-commit hooks..."
pre-commit autoupdate

# Run hooks once to validate setup
echo "Running initial security scan..."
pre-commit run --all-files || true

echo "Security scanning hooks setup complete!"
echo "See openssl_encrypt/docs/SECURITY_SCANNING_GUIDE.md for usage instructions."