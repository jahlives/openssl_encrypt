# Test Directory Structure

This directory contains tests for the OpenSSL Encrypt project, organized into the following subdirectories:

## dual_encryption/
Tests for the dual encryption functionality, including:
- `test_dual_encryption_architecture.py`: Tests the architecture of the dual encryption system
- `test_dual_encryption_cli.py`: Tests the command-line interface for dual encryption
- `test_dual_encryption_comprehensive.py`: Comprehensive tests for dual encryption
- `test_dual_encryption_fix.py`: Tests for specific dual encryption fixes
- `test_dual_encryption_keystore.py`: Tests dual encryption with keystores
- `test_dual_encryption_password_validation.py`: Tests password validation in dual encryption
- `test_dual_encryption_setup.py`: Tests the setup of dual encryption

## keystore/
Tests for the keystore functionality:
- `test_keystore_dual_encryption.py`: Tests dual encryption with the keystore
- `test_keystore_key.py`: Tests basic keystore key operations

## misc/
Miscellaneous tests:
- `test_embedded_key.py`: Tests for embedded key functionality

## Running Tests
Most tests can be run directly:
```
python -m tests.dual_encryption.test_dual_encryption_cli
```

Or through the unittest framework:
```
python -m unittest discover tests
```