# CLI Integration Guide for Algorithm Registries

This guide explains how to integrate the algorithm registries with the existing CLI and configuration tools.

## Overview

The algorithm registry system provides a unified interface for managing cryptographic algorithms. This guide shows how to integrate it with the CLI infrastructure.

## Helper Functions

The `openssl_encrypt.modules.registry.cli_helpers` module provides utility functions for CLI integration:

### Algorithm Discovery

```python
from openssl_encrypt.modules.registry import (
    get_available_ciphers,
    get_available_hashes,
    get_available_kdfs,
    get_available_kems,
    get_available_signatures,
)

# Get list of available algorithms
ciphers = get_available_ciphers()
# ['aes-256-gcm', 'aes-256-gcm-siv', 'aes-256-siv', ...]

kdfs = get_available_kdfs()
# ['argon2id', 'argon2i', 'argon2d', 'pbkdf2', 'scrypt', ...]

kems = get_available_kems()
# ['ml-kem-512', 'ml-kem-768', 'ml-kem-1024', 'hqc-128', ...]
```

### Algorithm Information

```python
from openssl_encrypt.modules.registry import get_cipher_info_dict, get_kdf_info_dict

# Get detailed information about ciphers
cipher_info = get_cipher_info_dict()
# {
#     'aes-256-gcm': {
#         'display_name': 'AES-256-GCM',
#         'description': 'AES-256 in Galois/Counter Mode...',
#         'security_level': 'STANDARD',
#         'key_size': 32,
#         'nonce_size': 12,
#         'tag_size': 16,
#         'available': True
#     },
#     ...
# }

# Get KDF information
kdf_info = get_kdf_info_dict()
```

### Validation

```python
from openssl_encrypt.modules.registry import validate_algorithm_name

# Validate user input
is_valid, error_msg = validate_algorithm_name("aes-256-gcm", "cipher")
if not is_valid:
    print(f"Error: {error_msg}")
```

### Help Text Generation

```python
from openssl_encrypt.modules.registry import format_algorithm_help

# Generate help text for CLI
cipher_help = format_algorithm_help("cipher")
kdf_help = format_algorithm_help("kdf")
kem_help = format_algorithm_help("kem")

# Output:
# Available Ciphers:
# ==================
#
#   ✓ aes-256-gcm     - AES-256 in Galois/Counter Mode
#   ✓ chacha20-poly1305 - ChaCha20-Poly1305 AEAD cipher
#   ...
```

### Recommendations

```python
from openssl_encrypt.modules.registry import (
    get_recommended_cipher,
    get_recommended_kdf,
    get_recommended_kem,
)

# Get recommended algorithms for default values
cipher = get_recommended_cipher()  # "aes-256-gcm"
kdf = get_recommended_kdf()        # "argon2id"
kem = get_recommended_kem()        # "ml-kem-768"
```

## Integration Examples

### CLI Argument Parsing

Update CLI argument parsing to use registry-provided choices:

```python
from openssl_encrypt.modules.registry import get_available_ciphers, get_recommended_cipher

# Old way (hardcoded):
parser.add_argument(
    '--cipher',
    choices=['aes-gcm', 'chacha20-poly1305', 'aes-gcm-siv'],
    default='aes-gcm',
    help='Cipher algorithm'
)

# New way (registry-based):
parser.add_argument(
    '--cipher',
    choices=get_available_ciphers(),
    default=get_recommended_cipher(),
    help='Cipher algorithm (see --list-ciphers for details)'
)

# Add help command
parser.add_argument(
    '--list-ciphers',
    action='store_true',
    help='List all available cipher algorithms'
)
```

### Configuration Wizard Integration

Update configuration wizard to use registry information:

```python
from openssl_encrypt.modules.registry import (
    get_kdf_info_dict,
    KDFRegistry,
    Argon2Params,
)

def configure_kdf_settings(self):
    """Configure KDF settings using registry."""
    kdf_info = get_kdf_info_dict()

    print("Available KDFs:")
    for name, info in kdf_info.items():
        if info['available']:
            print(f"  • {info['display_name']}: {info['description']}")

    # Use registry to get KDF instance
    registry = KDFRegistry.default()
    kdf = registry.get("argon2id")

    # Get default parameters from the KDF
    info = kdf.info()
    print(f"Default security level: {info.security_level.name}")
```

### Algorithm Selection Menu

Create interactive algorithm selection:

```python
from openssl_encrypt.modules.registry import get_cipher_info_dict

def select_cipher_interactive():
    """Interactive cipher selection menu."""
    cipher_info = get_cipher_info_dict()

    print("Select Cipher Algorithm:")
    print("=" * 40)

    ciphers = sorted(cipher_info.items(), key=lambda x: x[1]['security_level'])

    for idx, (name, info) in enumerate(ciphers, 1):
        if not info['available']:
            continue

        status = "✓"
        security = info['security_level']

        print(f"{idx}. {name:25s} [{security}]")
        print(f"   {info['description']}")
        print()

    choice = int(input("Enter number: "))
    selected = list(cipher_info.keys())[choice - 1]

    return selected
```

### Backward Compatibility

Maintain backward compatibility with existing code:

```python
from openssl_encrypt.modules.registry import CipherRegistry

def get_cipher_from_enum(encryption_algorithm_enum):
    """
    Bridge function to get cipher from old enum.

    Maintains backward compatibility with existing EncryptionAlgorithm enum.
    """
    # Map old enum values to new registry names
    ENUM_TO_REGISTRY = {
        'aes-gcm': 'aes-256-gcm',
        'aes-gcm-siv': 'aes-256-gcm-siv',
        'chacha20-poly1305': 'chacha20-poly1305',
        # ... add more mappings
    }

    old_name = encryption_algorithm_enum.value
    new_name = ENUM_TO_REGISTRY.get(old_name, old_name)

    registry = CipherRegistry.default()
    return registry.get(new_name)
```

## Migration Strategy

### Phase 1: Add Registry-Based Options (Completed ✓)
- ✓ Create CLI helper utilities
- ✓ Export helper functions from registry module
- ✓ Test all helper functions

### Phase 2: Update CLI Argument Parsing (Next Step)
- Add `--list-ciphers`, `--list-kdfs`, `--list-hashes` commands
- Update algorithm choices to use registry functions
- Add validation using `validate_algorithm_name()`

### Phase 3: Update Configuration Wizard
- Replace hardcoded KDF settings with registry-based configuration
- Use `get_kdf_info_dict()` for KDF selection
- Update security scoring to use registry metadata

### Phase 4: Gradual Migration
- Add deprecation warnings for old enum-based code
- Provide bridge functions for backward compatibility
- Update documentation with migration examples

### Phase 5: Full Registry Integration
- Remove old enum-based algorithm handling
- Update all algorithm references to use registries
- Complete migration documentation

## Benefits

### For Users
- **Discovery**: Easy to see all available algorithms with `--list-*` commands
- **Information**: Detailed algorithm information including security levels
- **Validation**: Clear error messages for invalid algorithm names

### For Developers
- **Centralized**: Single source of truth for algorithm information
- **Extensible**: Easy to add new algorithms without changing CLI code
- **Consistent**: Uniform interface across all algorithm types

### For Security
- **Metadata**: Security level classification built-in
- **Availability**: Automatic checking for required dependencies
- **Recommendations**: Default to secure, well-tested algorithms

## Testing

Test CLI integration:

```bash
# Test algorithm listing
python -m pytest tests/test_cli_integration.py -v

# Test helper functions
python3 << 'EOF'
from openssl_encrypt.modules.registry import (
    get_available_ciphers,
    get_recommended_cipher,
    validate_algorithm_name,
)

print("Ciphers:", get_available_ciphers())
print("Recommended:", get_recommended_cipher())
print("Valid:", validate_algorithm_name("aes-256-gcm", "cipher"))
EOF
```

## Next Steps

1. **Update CLI Parsers**: Modify `crypt_cli_subparser.py` to use registry helpers
2. **Add List Commands**: Implement `--list-ciphers`, `--list-kdfs`, etc.
3. **Update Config Wizard**: Replace hardcoded KDF settings in `config_wizard.py`
4. **Documentation**: Update user documentation with new commands
5. **Deprecation**: Add warnings for old algorithm specification methods

## Resources

- **Registry Documentation**: See `algorithm_registry_plan.md`
- **API Reference**: See module docstrings in `openssl_encrypt/modules/registry/`
- **Tests**: See `openssl_encrypt/unittests/registry/`

---

**Status**: Phase 6a Complete - CLI Helper Utilities Created ✓

**Next**: Phase 6b - Update CLI Argument Parsing
