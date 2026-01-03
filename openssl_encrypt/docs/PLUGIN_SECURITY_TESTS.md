# Plugin Security Unit Tests

## Overview

The `test_plugin_security.py` file contains comprehensive unit tests that verify the plugin system's security boundaries remain intact. These tests use **malicious plugin patterns** to ensure that security features are not accidentally broken in future updates.

## Test Coverage

### ✅ 20 Security Tests Implemented

| Test Suite | Tests | Coverage |
|-----------|-------|----------|
| **TestSensitiveDataProtection** | 6 | Password, salt, keys, tokens never in context |
| **TestStaticCodeAnalysis** | 5 | Dangerous patterns blocked at load time |
| **TestNetworkAccessControl** | 1 | Network requires NETWORK_ACCESS capability |
| **TestSubprocessControl** | 1 | Subprocess requires EXECUTE_PROCESSES capability |
| **TestResourceLimits** | 1 | Execution timeout enforced |
| **TestCapabilityValidation** | 2 | Capability enforcement works correctly |
| **TestResultValidation** | 2 | Sensitive data blocked in results |
| **TestSecurityModes** | 2 | Strict vs permissive mode behavior |

---

## Test Details

### 1. TestSensitiveDataProtection

**Purpose:** Verify plugins cannot access sensitive cryptographic material

**Tests:**
- `test_password_not_in_context()` - Passwords never added to context
- `test_salt_not_in_context()` - Salts never added to context
- `test_secret_key_not_in_context()` - Secret keys never added to context
- `test_auth_token_not_in_context()` - Auth tokens never added to context
- `test_only_safe_metadata_in_context()` - Only safe metadata accessible
- `test_sensitive_key_patterns()` - Comprehensive pattern detection

**Security Property Verified:** 🔒 Zero-trust data exchange

---

### 2. TestStaticCodeAnalysis

**Purpose:** Verify dangerous code patterns are detected before plugin execution

**Tests:**
- `test_eval_pattern_blocked()` - eval() usage blocked
- `test_exec_pattern_blocked()` - exec() usage blocked
- `test_subprocess_pattern_blocked()` - subprocess usage blocked
- `test_compile_pattern_blocked()` - compile() usage blocked
- `test_file_size_limit()` - File size limit enforced (1 MB)

**Security Property Verified:** 🔍 Static code validation

**Example Blocked Patterns:**
```python
dangerous_patterns = [
    "eval(",
    "exec(",
    "subprocess",
    "compile(",
    "__import__",
    "ctypes",
]
```

---

### 3. TestNetworkAccessControl

**Purpose:** Verify network operations require explicit permission

**Tests:**
- `test_network_blocked_without_capability()` - socket.socket() blocked without NETWORK_ACCESS

**Security Property Verified:** 🌐 Capability-based network control

**How it works:**
```python
# Plugin without NETWORK_ACCESS capability
context = PluginSecurityContext(
    "plugin_id",
    capabilities={PluginCapability.READ_FILES}  # NO NETWORK_ACCESS
)

# Attempting socket.socket() raises SandboxViolationError
```

---

### 4. TestSubprocessControl

**Purpose:** Verify subprocess execution requires explicit permission

**Tests:**
- `test_subprocess_blocked_without_capability()` - subprocess.Popen() blocked without EXECUTE_PROCESSES

**Security Property Verified:** ⚙️ Capability-based process control

**How it works:**
```python
# Plugin without EXECUTE_PROCESSES capability
context = PluginSecurityContext(
    "plugin_id",
    capabilities={PluginCapability.READ_FILES}  # NO EXECUTE_PROCESSES
)

# Attempting subprocess.Popen() raises SandboxViolationError
```

---

### 5. TestResourceLimits

**Purpose:** Verify resource exhaustion is prevented

**Tests:**
- `test_execution_timeout_enforced()` - Plugin terminated after timeout (default: 30s)

**Security Property Verified:** ⏱️ Resource limit enforcement

**Test Parameters:**
- Timeout: 2 seconds (for testing)
- Plugin behavior: Sleep for 10 seconds
- Expected result: Terminated with timeout error

**Protection against:**
- Infinite loops
- Blocking operations
- Resource exhaustion DoS

---

### 6. TestCapabilityValidation

**Purpose:** Verify capability checking works correctly

**Tests:**
- `test_missing_capability_denied()` - Execution fails if capability missing
- `test_all_capabilities_granted()` - Execution succeeds if all capabilities present

**Security Property Verified:** 🔐 Capability enforcement

**Example:**
```python
plugin.get_required_capabilities():
    return {PluginCapability.READ_FILES, PluginCapability.NETWORK_ACCESS}

# Context with only READ_FILES → validation FAILS
# Context with both → validation SUCCEEDS
```

---

### 7. TestResultValidation

**Purpose:** Verify plugin results are validated for sensitive data

**Tests:**
- `test_sensitive_data_blocked_in_results()` - Sensitive keys blocked in result.data
- `test_safe_data_allowed_in_results()` - Safe data allowed in result.data

**Security Property Verified:** 🛡️ Output validation

**Example:**
```python
result.add_data("password", "secret")  # BLOCKED
result.add_data("file_count", 5)       # ALLOWED
```

---

### 8. TestSecurityModes

**Purpose:** Verify strict vs permissive mode behavior

**Tests:**
- `test_strict_mode_blocks_dangerous_patterns()` - Strict mode rejects dangerous code
- `test_permissive_mode_allows_with_warning()` - Permissive mode allows with warning

**Security Property Verified:** 🔧 Security mode enforcement

**Modes:**
- **Strict (default, production):** Block dangerous patterns at load time
- **Permissive (development only):** Allow with warnings

---

## Running the Tests

### Run all plugin security tests:
```bash
python3 -m pytest openssl_encrypt/unittests/test_plugin_security.py -v
```

### Run specific test class:
```bash
python3 -m pytest openssl_encrypt/unittests/test_plugin_security.py::TestSensitiveDataProtection -v
```

### Run specific test:
```bash
python3 -m pytest openssl_encrypt/unittests/test_plugin_security.py::TestSensitiveDataProtection::test_password_not_in_context -v
```

### Run with coverage:
```bash
python3 -m pytest openssl_encrypt/unittests/test_plugin_security.py --cov=openssl_encrypt.modules.plugin_system --cov-report=html
```

---

## Test Results

**Latest Test Run:**
```
============================= test session starts ==============================
platform linux -- Python 3.14.2, pytest-9.0.1, pluggy-1.6.0
collected 20 items

test_plugin_security.py::TestSensitiveDataProtection::test_auth_token_not_in_context PASSED [  5%]
test_plugin_security.py::TestSensitiveDataProtection::test_only_safe_metadata_in_context PASSED [ 10%]
test_plugin_security.py::TestSensitiveDataProtection::test_password_not_in_context PASSED [ 15%]
test_plugin_security.py::TestSensitiveDataProtection::test_salt_not_in_context PASSED [ 20%]
test_plugin_security.py::TestSensitiveDataProtection::test_secret_key_not_in_context PASSED [ 25%]
test_plugin_security.py::TestSensitiveDataProtection::test_sensitive_key_patterns PASSED [ 30%]
test_plugin_security.py::TestStaticCodeAnalysis::test_compile_pattern_blocked PASSED [ 35%]
test_plugin_security.py::TestStaticCodeAnalysis::test_eval_pattern_blocked PASSED [ 40%]
test_plugin_security.py::TestStaticCodeAnalysis::test_exec_pattern_blocked PASSED [ 45%]
test_plugin_security.py::TestStaticCodeAnalysis::test_file_size_limit PASSED [ 50%]
test_plugin_security.py::TestStaticCodeAnalysis::test_subprocess_pattern_blocked PASSED [ 55%]
test_plugin_security.py::TestNetworkAccessControl::test_network_blocked_without_capability PASSED [ 60%]
test_plugin_security.py::TestSubprocessControl::test_subprocess_blocked_without_capability PASSED [ 65%]
test_plugin_security.py::TestResourceLimits::test_execution_timeout_enforced PASSED [ 70%]
test_plugin_security.py::TestCapabilityValidation::test_all_capabilities_granted PASSED [ 75%]
test_plugin_security.py::TestCapabilityValidation::test_missing_capability_denied PASSED [ 80%]
test_plugin_security.py::TestResultValidation::test_safe_data_allowed_in_results PASSED [ 85%]
test_plugin_security.py::TestResultValidation::test_sensitive_data_blocked_in_results PASSED [ 90%]
test_plugin_security.py::TestSecurityModes::test_permissive_mode_allows_with_warning PASSED [ 95%]
test_plugin_security.py::TestSecurityModes::test_strict_mode_blocks_dangerous_patterns PASSED [100%]

============================== 20 passed in 0.14s ==============================
```

**Status:** ✅ ALL TESTS PASSING

---

## Continuous Security Testing

These tests serve as **regression tests** to ensure security features remain intact as the codebase evolves:

1. **Pre-commit testing:** Run before committing changes to plugin system
2. **CI/CD integration:** Include in automated test pipeline
3. **Security audit:** Reference for security compliance
4. **Developer education:** Examples of what plugins cannot do

---

## Security Properties Verified

| Property | Test Coverage | Status |
|----------|--------------|--------|
| Zero-trust data exchange | 6 tests | ✅ Verified |
| Static code validation | 5 tests | ✅ Verified |
| Capability enforcement | 4 tests | ✅ Verified |
| Resource limits | 1 test | ✅ Verified |
| Output validation | 2 tests | ✅ Verified |
| Security mode control | 2 tests | ✅ Verified |

---

## Related Documentation

- **Security Analysis:** `/docs/PLUGINS_SECURITY_VIOLATION_SUMMARY.md`
- **Plugin Development:** `/openssl_encrypt/plugins/PLUGIN_DEVELOPMENT.md`
- **Plugin System Code:**
  - `modules/plugin_system/plugin_base.py` - Base classes
  - `modules/plugin_system/plugin_manager.py` - Lifecycle management
  - `modules/plugin_system/plugin_sandbox.py` - Sandbox execution
  - `modules/plugin_system/plugin_config.py` - Configuration

---

## Adding New Security Tests

When adding new security features or discovering new attack vectors, add corresponding tests:

1. **Identify the attack vector** - What could go wrong?
2. **Create a test plugin** - Implement the malicious behavior
3. **Write the test** - Verify the attack is blocked
4. **Document the test** - Explain what it protects against
5. **Run all tests** - Ensure no regressions

**Example template:**
```python
def test_new_attack_vector(self):
    """Verify [attack type] is blocked"""
    # Create malicious plugin
    plugin_path = self._create_malicious_plugin("[malicious_code]")

    # Attempt to load/execute
    result = self.plugin_manager.load_plugin(plugin_path)

    # Verify blocked
    self.assertFalse(result.success)
    self.assertIn("expected_error", result.message.lower())
```

---

## Maintenance

**Review Schedule:** Quarterly or when plugin system changes

**Test Updates Needed When:**
- Adding new plugin capabilities
- Modifying security boundaries
- Discovering new attack vectors
- Changing sandbox implementation
- Updating static analysis patterns

---

*Last Updated: 2026-01-02*
*Test Suite Version: 1.0.0*
