# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Test Commands
- Install: `pip install openssl_encrypt`
- Dev install: `pip install -e ".[dev]"`
- Run all tests: `python -m openssl_encrypt.unittests.unittests`
- Run single test: `python -m openssl_encrypt.unittests.unittests TestClassName.test_method_name`
- Format code: `black openssl_encrypt`
- Lint code: `pylint openssl_encrypt`

## CRITICAL CODE BLOCK PROTECTION
- NEVER modify any code between markers `# START DO NOT CHANGE` and `# END DO NOT CHANGE`
- These markers indicate critical sections that must remain unchanged
- This is especially important in crypt_core.py where cryptographic operations are implemented
- If you need functionality in a protected block, find an alternative approach or ask for guidance
- No exceptions to this rule under any circumstances

## Code Style Guidelines
- Imports: standard library first, then third-party, then local modules
- Use type annotations for all function parameters and return values
- Classes: PascalCase, functions/variables: snake_case
- Error handling: use specific exceptions from `crypt_utils` when possible
- Docstrings: use Google style with parameter documentation
- Security: Never log/print keys, use secure_memory module for sensitive data
- Testing: Each algorithm needs separate test files with encryption/decryption tests
- Keep cryptographic operations in crypt_core.py, UI in separate modules