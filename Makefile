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
	python -m pytest -n auto --dist=worksteal openssl_encrypt/unittests/

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
