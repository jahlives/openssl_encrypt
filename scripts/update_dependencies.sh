#!/bin/bash
# Script to update dependencies using pip-tools

# Ensure pip-tools is installed
pip install -U pip-tools

# Update production dependencies
echo "Updating production dependencies..."
pip-compile --upgrade requirements-prod.in --output-file=requirements-prod.txt

# Update development dependencies
echo "Updating development dependencies..."
pip-compile --upgrade requirements-dev.in --output-file=requirements-dev.txt

# Sync the current environment with the latest dependencies
echo "Syncing development environment with updated dependencies..."
pip-sync requirements-dev.txt

echo "Dependency update complete!"
echo "Please review the changes in requirements-prod.txt and requirements-dev.txt files."
