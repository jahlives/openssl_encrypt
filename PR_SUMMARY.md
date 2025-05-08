# Implement Format Version 4 with Hierarchical Metadata Structure

## Summary

- Introduces format_version 4 with a more organized hierarchical metadata structure
- Maintains backward compatibility with older formats (1-3)
- Improves code organization and extensibility
- Fixes KDF application and display for format version 4 files

## Changes

- Restructured metadata into logical sections: `derivation_config`, `hashes`, and `encryption`
- Added utility functions for converting between metadata formats
- Updated encryption/decryption functions to handle both old and new formats
- Implemented comprehensive test suite for the new format
- Added detailed documentation

### Recent Updates

- Enhanced `decrypt_file` to properly merge KDF configurations from the nested structure into hash_config
- Fixed issue where KDFs defined in format_version 4 metadata were not being applied during decryption
- Updated `generate_key` to correctly detect and use PBKDF2 in the nested format
- Fixed incorrect display of algorithm and KDF information for format_version 4 files

## Testing

- Implemented tests for format_version 4 encryption
- Added backward compatibility tests
- Tested cross-format decryption

## Documentation

- Added metadata_format_v4.md with comprehensive format documentation
- Created implementation summary with details on changes and benefits

## Benefits

- Better organized metadata structure for improved maintainability
- Easier to extend with new features in the future
- Fully backward compatible - older files can still be decrypted