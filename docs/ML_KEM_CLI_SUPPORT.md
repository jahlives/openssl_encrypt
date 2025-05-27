# ML-KEM CLI Support

## Overview

This document describes the patch that enables ML-KEM algorithm names to work correctly in the command-line interface (CLI) of the openssl_encrypt package.

## Background

The openssl_encrypt package supports both legacy Kyber algorithm names (e.g., `kyber1024-hybrid`) and standardized ML-KEM algorithm names (e.g., `ml-kem-1024-hybrid`). While both naming conventions work correctly in the API, there was an issue where ML-KEM names would fail with a "Security validation check failed" error when used in the CLI.

## Solution

A simple patch has been implemented that automatically converts ML-KEM algorithm names to their Kyber equivalents when used in the CLI. This allows users to use the standardized ML-KEM naming convention without modifying the core validation logic.

The patch consists of two files:
- `openssl_encrypt/modules/ml_kem_patch.py`: Contains the conversion logic
- `openssl_encrypt/crypt.py`: Imports and applies the patch

## Implementation Details

The patch works by intercepting command-line arguments before they're processed by the main CLI code. When it detects an ML-KEM algorithm name, it converts it to the equivalent Kyber name that the validation logic already understands.

For example:
- `ml-kem-512-hybrid` → `kyber512-hybrid`
- `ml-kem-768-hybrid` → `kyber768-hybrid`
- `ml-kem-1024-hybrid` → `kyber1024-hybrid`

This conversion happens transparently to the user, allowing them to use the standardized ML-KEM names in their commands while maintaining compatibility with the existing codebase.

## Usage

Simply use the ML-KEM algorithm names in your CLI commands as you would use Kyber names:

```bash
# Encryption with ML-KEM
python -m openssl_encrypt.crypt encrypt -i input.txt -o output.enc \
  --algorithm ml-kem-1024-hybrid --password test1234 --force-password

# Decryption with ML-KEM
python -m openssl_encrypt.crypt decrypt -i output.enc -o decrypted.txt \
  --algorithm ml-kem-1024-hybrid --password test1234 --force-password
```

## Supported Algorithms

The patch supports the following ML-KEM algorithm names:
- `ml-kem-512-hybrid`
- `ml-kem-768-hybrid`
- `ml-kem-1024-hybrid`

## Testing

The patch has been tested with all supported ML-KEM algorithm names, verifying that both encryption and decryption work correctly with the standardized names.

## Future Improvements

For a more comprehensive solution, the core validation logic could be updated to directly handle ML-KEM algorithm names without requiring this conversion patch. However, the current approach is non-invasive and maintains compatibility with the existing codebase.