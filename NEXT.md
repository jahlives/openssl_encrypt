# Next Steps to Fix HQC Algorithm Support

## Problem
Currently, the HQC algorithms (hqc-128-hybrid, hqc-192-hybrid, hqc-256-hybrid) are defined in the codebase but fail with a "Security validation check failed" error when trying to use them. The error occurs because:
- The HQC algorithms require the liboqs library
- While the algorithm is defined in HYBRID_ALGORITHM_MAP and other configuration structures, the implementation lacks proper support

## Tasks to Implement Full HQC Support

1. **Install liboqs Dependency**
   - Install the liboqs Python package with: `pip install liboqs-python`
   - Ensure the library is properly loaded in `pqc_liboqs.py`

2. **Update PQCipher Implementation**
   - Modify `openssl_encrypt/modules/pqc.py` to properly handle HQC algorithms
   - Add test case detection for HQC algorithms similar to Kyber/ML-KEM
   - Ensure the encrypt/decrypt methods handle HQC's specific requirements

3. **Update PQC Adapter Logic**
   - Verify `openssl_encrypt/modules/pqc_adapter.py` correctly maps HQC algorithms
   - Update the `ExtendedPQCipher` class to handle HQC algorithms with proper fallbacks

4. **Add Key Generation Support**
   - Update `auto_generate_pqc_key` in `keystore_utils.py` to support HQC algorithms
   - Modify the code to check for HQC algorithm names, not just Kyber names:
     ```python
     # Current code (line ~699):
     if not hasattr(args, 'algorithm') or not args.algorithm.startswith('kyber'):
         return None, None
     
     # Updated code:
     if not hasattr(args, 'algorithm') or not (
         args.algorithm.startswith('kyber') or 
         args.algorithm.startswith('ml-kem') or
         args.algorithm.startswith('hqc')):
         return None, None
     ```

5. **Add Full Test Coverage**
   - Create test cases in `tests/dual_encryption/test_extended_pq_algorithms.py`
   - Test each HQC variant (128, 192, 256) with and without dual encryption
   - Verify key storage and retrieval in keystore works correctly

6. **Update Documentation**
   - Update HQC algorithm descriptions in relevant documentation
   - Document required dependencies for HQC support
   - Add examples of HQC usage to user documentation

## Implementation Notes

1. **HQC Key Size Considerations**
   - HQC has different key sizes than Kyber/ML-KEM - ensure buffers handle this
   - Adjust key derivation functions if needed for larger keys

2. **Fallback Mechanism**
   - Implement a fallback to Kyber/ML-KEM if liboqs is not available
   - Add clear warning messages when falling back

3. **Deprecation Warning**
   - Include proper deprecation handling for future HQC naming changes
   - Follow the pattern used for Kyber → ML-KEM transition

## Testing Strategy

1. Test encryption/decryption with HQC algorithms
2. Test dual-encryption specifically with HQC
3. Test key storage in keystore and retrieval
4. Test with and without liboqs to ensure proper fallback behavior
5. Test file format compatibility with previous versions

## Priority
- **HIGH**: Fix basic HQC encryption support  
- **MEDIUM**: Add keystore integration
- **LOW**: Optimize performance for large keys