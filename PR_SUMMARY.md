# PR Summary: Configurable Data Encryption for Kyber

## Summary

This PR adds the ability to select the symmetric encryption algorithm used for data encryption when using Kyber for key encapsulation. Previously, Kyber algorithms always used AES-GCM for data encryption, but this PR introduces a new `encryption_data` parameter that allows choosing from multiple symmetric algorithms.

## Changes Made

1. **New metadata format (version 5)**:
   - Added `encryption_data` field to the `encryption` section
   - Implemented `convert_metadata_v4_to_v5` and `convert_metadata_v5_to_v4` functions
   - Created `create_metadata_v5` function that replaces `create_metadata_v4`

2. **PQCipher enhancements**:
   - Modified to support multiple symmetric encryption algorithms
   - Added `encryption_data` parameter to the constructor
   - Updated the encrypt/decrypt methods to use the specified algorithm

3. **CLI enhancements**:
   - Added `--encryption-data` parameter to select the data encryption algorithm
   - Updated function calls in the CLI to pass the new parameter

4. **Documentation**:
   - Created `metadata_format_v5.md` that documents the new format
   - Added `pqc_data_encryption.md` with examples and usage information
   - Updated templates to include the new parameter

5. **Testing**:
   - Added unit tests to verify the new functionality
   - Created integration tests in `test_encryption_data.py`

## New Features

Users can now select one of the following algorithms for data encryption with Kyber:

- `aes-gcm` (default)
- `aes-gcm-siv`
- `aes-ocb3`
- `aes-siv`
- `chacha20-poly1305`
- `xchacha20-poly1305`

## Backward Compatibility

- All v4 and earlier encrypted files remain compatible
- The v5 format includes proper conversion functions
- Default behavior remains the same (AES-GCM) if no algorithm is specified

## Testing

The implementation was thoroughly tested with:

1. Unit tests in `unittests.py`:
   - `test_pqc_encryption_data_algorithms`: Tests each symmetric algorithm with PQCipher
   - `test_pqc_encryption_data_metadata`: Verifies metadata format and field presence

2. Integration tests in `test_encryption_data.py`:
   - Tests all combinations of Kyber variants and encryption algorithms
   - Verifies end-to-end encryption and decryption

## Usage

From the command line:
```bash
openssl_encrypt encrypt --algorithm kyber768-hybrid --encryption-data chacha20-poly1305 \
    --input myfile.txt --output myfile.enc
```

From the API:
```python
encrypt_file(
    input_file="myfile.txt",
    output_file="myfile.enc",
    password="password123",
    algorithm="kyber768-hybrid",
    encryption_data="xchacha20-poly1305"
)
```