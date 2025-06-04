#!/bin/bash
# Setup script for static code analysis tools
# This script installs and configures all static analysis tools for local development

set -e  # Exit on any error

echo "🔍 Setting up Static Code Analysis for openssl_encrypt"
echo "=================================================="

# Check if we're in the project root
if [ ! -f "pyproject.toml" ] || [ ! -d "openssl_encrypt" ]; then
    echo "❌ Error: Please run this script from the project root directory"
    exit 1
fi

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check Python version
python_version=$(python3 --version 2>&1 | grep -oE '[0-9]+\.[0-9]+')
echo "🐍 Python version: $python_version"

if ! python3 -c "import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)"; then
    echo "❌ Error: Python 3.8+ is required"
    exit 1
fi

# Install development dependencies
echo "📦 Installing development dependencies..."
pip install -r requirements-dev.txt

# Install additional static analysis tools
echo "🔧 Installing static analysis tools..."
pip install \
    pre-commit \
    black \
    isort \
    flake8 \
    flake8-bugbear \
    flake8-docstrings \
    flake8-import-order \
    flake8-security \
    flake8-bandit \
    bandit[toml] \
    pylint \
    pylint-json2html \
    mypy \
    types-PyYAML \
    types-requests \
    semgrep \
    radon \
    xenon \
    mccabe \
    pip-audit

# Setup pre-commit hooks
echo "🪝 Setting up pre-commit hooks..."
if command_exists pre-commit; then
    pre-commit install
    pre-commit install --hook-type pre-push
    echo "✅ Pre-commit hooks installed"
else
    echo "❌ Error: pre-commit not found after installation"
    exit 1
fi

# Create .gitignore entries for analysis reports (if not already present)
echo "📝 Updating .gitignore for analysis reports..."
cat >> .gitignore << 'EOF'

# Static analysis reports
pylint-report.*
mypy-report/
mypy-html/
semgrep-report.json
semgrep-security.json
semgrep-python.json
complexity-report.*
maintainability-report.*
halstead-report.json
raw-metrics.json
pip-audit-local.json
.bandit.baseline
EOF

# Create a Makefile for easy static analysis commands
echo "🛠️  Creating Makefile for static analysis..."
cat > Makefile << 'EOF'
# Makefile for openssl_encrypt static analysis and development

.PHONY: help format lint security type-check complexity test-all clean install-dev setup-analysis

help:
	@echo "Available commands:"
	@echo "  format          - Format code with black and isort"
	@echo "  lint            - Run all linting tools"
	@echo "  security        - Run security analysis"
	@echo "  type-check      - Run type checking with mypy"
	@echo "  complexity      - Analyze code complexity"
	@echo "  test-all        - Run all tests"
	@echo "  clean           - Clean analysis reports"
	@echo "  install-dev     - Install development dependencies"
	@echo "  setup-analysis  - Setup static analysis tools"

format:
	@echo "🎨 Formatting code..."
	black openssl_encrypt/ --line-length=100
	isort openssl_encrypt/ --profile black --line-length=100

lint:
	@echo "🔍 Running linting..."
	flake8 openssl_encrypt/ --max-line-length=100 --extend-ignore=E203,W503,E501
	pylint openssl_encrypt/ --output-format=colorized

security:
	@echo "🔒 Running security analysis..."
	bandit -r openssl_encrypt/ -c .bandit.yaml
	semgrep --config=auto openssl_encrypt/ || true
	pip-audit --requirement requirements-prod.txt

type-check:
	@echo "🔍 Running type checking..."
	mypy openssl_encrypt/ --config-file mypy.ini

complexity:
	@echo "📊 Analyzing code complexity..."
	radon cc openssl_encrypt/ -s
	radon mi openssl_encrypt/ -s

test-all:
	@echo "🧪 Running all tests..."
	python -m pytest openssl_encrypt/unittests/unittests.py -v

clean:
	@echo "🧹 Cleaning analysis reports..."
	rm -f pylint-report.* semgrep-*.json *-report.* pip-audit-local.json
	rm -rf mypy-report/ mypy-html/

install-dev:
	@echo "📦 Installing development dependencies..."
	pip install -r requirements-dev.txt

setup-analysis:
	@echo "🔧 Setting up static analysis..."
	./scripts/setup_static_analysis.sh
EOF

# Test basic functionality
echo "🧪 Testing static analysis tools..."

echo "  • Testing black..."
if black --check openssl_encrypt/ --line-length=100 >/dev/null 2>&1; then
    echo "    ✅ Black check passed"
else
    echo "    ⚠️  Black found formatting issues (run 'make format' to fix)"
fi

echo "  • Testing bandit..."
if bandit -r openssl_encrypt/ -c .bandit.yaml -q >/dev/null 2>&1; then
    echo "    ✅ Bandit security check passed"
else
    echo "    ⚠️  Bandit found security issues (run 'make security' for details)"
fi

echo "  • Testing pylint..."
if pylint openssl_encrypt/ --score=no --reports=no >/dev/null 2>&1; then
    echo "    ✅ Pylint check passed"
else
    echo "    ⚠️  Pylint found code quality issues (run 'make lint' for details)"
fi

# Show summary
echo ""
echo "🎉 Static Code Analysis Setup Complete!"
echo "============================================"
echo ""
echo "📋 What was installed:"
echo "  • Pre-commit hooks (run on every commit)"
echo "  • Black (code formatting)"
echo "  • isort (import sorting)"
echo "  • Flake8 (linting)"
echo "  • Bandit (security scanning)"
echo "  • Pylint (code quality)"
echo "  • MyPy (type checking)"
echo "  • Semgrep (advanced security)"
echo "  • Radon (complexity analysis)"
echo ""
echo "🚀 Quick start commands:"
echo "  make help          - Show all available commands"
echo "  make format        - Format code"
echo "  make lint          - Run linting"
echo "  make security      - Run security scans"
echo "  make test-all      - Run all tests"
echo ""
echo "🪝 Pre-commit hooks are now active:"
echo "  • They run automatically on 'git commit'"
echo "  • Run 'pre-commit run --all-files' to check all files now"
echo ""
echo "🔧 Configuration files created:"
echo "  • .pre-commit-config.yaml"
echo "  • .bandit.yaml"
echo "  • .pylintrc"
echo "  • mypy.ini"
echo "  • Makefile"
echo ""
echo "Happy coding! 🎯"