# Comprehensive Test Plan for Security Fixes

This document outlines recommended unit tests for the 10 critical security fixes implemented.

**Summary: 95 new/adjusted tests recommended across 10 test suites**

---

## 1. Rate Limiting Tests (10 tests)
**File**: `openssl_encrypt_server/unittests/test_rate_limiting.py` (NEW)

### Tests:
1. `test_rate_limit_enforced_on_register_endpoint`
   - Verify 10 requests/hour limit on /register
   - 11th request returns 429 Too Many Requests

2. `test_rate_limit_enforced_on_keyserver_upload`
   - Verify 60 requests/minute on /api/v1/keys
   - 61st request blocked

3. `test_rate_limit_enforced_on_keyserver_search`
   - Verify 100 requests/minute on /api/v1/keys/search
   - Public endpoint still rate limited

4. `test_rate_limit_enforced_on_telemetry_events`
   - Verify 1000 requests/hour on /api/v1/telemetry/events
   - Batch endpoint limits enforced

5. `test_rate_limit_enforced_on_refresh_endpoint`
   - Verify 60 requests/hour on /refresh
   - Prevents token refresh abuse

6. `test_rate_limit_reset_after_window`
   - Submit 10 requests, wait 1 hour, verify counter reset
   - New requests accepted after window expires

7. `test_rate_limit_per_ip_address`
   - Verify different IPs have separate counters
   - Client A exhausting limit doesn't affect Client B

8. `test_rate_limit_response_headers`
   - Verify X-RateLimit-Limit header present
   - Verify X-RateLimit-Remaining decrements
   - Verify X-RateLimit-Reset timestamp

9. `test_rate_limit_different_endpoints_separate_counters`
   - Exhausting /register limit doesn't affect /keys
   - Each endpoint has independent counter

10. `test_rate_limit_429_response_format`
    - Verify 429 status code
    - Verify error message indicates rate limit
    - Verify Retry-After header present

---

## 2. Path Traversal Tests (8 tests)
**File**: `openssl_encrypt/unittests/test_plugin_path_security.py` (NEW)

### Tests:
1. `test_symlink_attack_blocked`
   - Create symlink pointing outside plugin directory
   - Verify access denied with appropriate error

2. `test_symlink_to_sensitive_file_blocked`
   - Create symlink to /etc/passwd or ~/.ssh/id_rsa
   - Verify blocked even if symlink in allowed directory

3. `test_realpath_resolution_prevents_traversal`
   - Path like "allowed_dir/../../etc/passwd"
   - Verify resolved to real path and blocked

4. `test_legitimate_symlink_within_plugin_dir`
   - Symlink within plugin's own directory
   - Verify still blocked (defense-in-depth: no symlinks)

5. `test_hardlink_attack_blocked`
   - Create hardlink to sensitive file within plugin dir
   - Verify inode tracking or detection mechanism

6. `test_absolute_path_outside_plugin_dir_blocked`
   - Attempt to access /tmp/sensitive_file
   - Verify blocked

7. `test_double_symlink_chain_blocked`
   - symlink1 -> symlink2 -> /etc/passwd
   - Verify chain resolution and blocking

8. `test_legitimate_file_access_still_works`
   - Normal file in plugin directory
   - Verify access granted (no regression)

---

## 3. Import Hook Tests (10 tests)
**File**: `openssl_encrypt/unittests/test_plugin_import_hooks.py` (NEW)

### Tests:
1. `test_direct_subprocess_import_blocked`
   - `import subprocess` in plugin code
   - Verify ImportError raised with security message

2. `test_from_import_blocked`
   - `from subprocess import Popen` in plugin
   - Verify ImportError raised

3. `test_dynamic_import_blocked`
   - `importlib.import_module("subprocess")` in plugin
   - Verify blocked

4. `test_import_during_execution_blocked`
   - Plugin tries to import socket during execute()
   - Verify blocked (not just at load time)

5. `test_all_dangerous_modules_blocked`
   - Test each module in BLOCKED_MODULES list
   - Verify all blocked: os, socket, ctypes, etc.

6. `test_safe_imports_allowed`
   - Import json, datetime, hashlib
   - Verify allowed modules still work

7. `test_import_hook_removed_after_execution`
   - Execute plugin, then check sys.meta_path
   - Verify import guard removed (no interference)

8. `test_multiple_plugins_dont_interfere`
   - Execute plugin A, then plugin B
   - Verify import guards don't accumulate

9. `test_import_hook_blocks_submodules`
   - `import os.path` attempt
   - Verify blocked (base module check)

10. `test_import_error_message_clarity`
    - Verify error message explains security policy
    - Check message format for user clarity

---

## 4. Subprocess Escape Tests (6 tests)
**File**: `openssl_encrypt/unittests/test_plugin_subprocess_blocking.py` (EXTEND)

### New Tests:
1. `test_os_system_blocked`
   - Plugin calls `os.system("ls")`
   - Verify RuntimeError with appropriate message

2. `test_os_popen_blocked`
   - Plugin calls `os.popen("cat /etc/passwd")`
   - Verify blocked

3. `test_os_spawnl_blocked`
   - Plugin calls `os.spawnl(os.P_WAIT, "/bin/sh"...)`
   - Verify blocked

4. `test_os_spawn_variants_all_blocked`
   - Test spawnle, spawnlp, spawnlpe, spawnv, spawnve, spawnvp, spawnvpe
   - Verify all 8 spawn variants blocked

5. `test_subprocess_popen_still_blocked`
   - Verify original subprocess.Popen block still works
   - No regression from new additions

6. `test_process_blocks_restored_after_execution`
   - Execute plugin, verify os.system works again outside sandbox
   - Check restoration mechanism

---

## 5. Capability Immutability Tests (5 tests)
**File**: `openssl_encrypt/unittests/test_plugin_capability_immutability.py` (NEW)

### Tests:
1. `test_capabilities_stored_as_frozenset`
   - Load plugin, check registration.capabilities type
   - Verify isinstance(capabilities, frozenset)

2. `test_capabilities_cannot_be_modified_after_registration`
   - Try to modify registration.capabilities
   - Verify AttributeError (frozenset is immutable)

3. `test_monkey_patching_get_required_capabilities_ineffective`
   - Load plugin, then plugin.get_required_capabilities = lambda: {"network"}
   - Execute plugin, verify original capabilities still enforced

4. `test_capability_check_uses_stored_frozenset`
   - Verify _check_capabilities() receives capabilities as parameter
   - Verify it doesn't call plugin.get_required_capabilities()

5. `test_capability_escalation_attack_prevented`
   - Plugin without network capability tries to add it at runtime
   - Verify capability check fails

---

## 6. Trusted Proxy Tests (10 tests)
**File**: `openssl_encrypt_server/unittests/test_proxy_auth.py` (NEW)

### Tests:
1. `test_default_trusted_proxies_localhost_only`
   - Create ProxyAuth with no config
   - Verify only 127.0.0.1 and ::1 trusted

2. `test_broad_network_rejected`
   - Try to add 10.0.0.0/8 as trusted proxy
   - Verify ValueError raised

3. `test_slash_24_network_accepted`
   - Add 192.168.1.0/24 as trusted proxy
   - Verify accepted

4. `test_slash_23_network_rejected`
   - Try to add 192.168.0.0/23 (512 IPs)
   - Verify rejected (< /24)

5. `test_localhost_ranges_always_allowed`
   - 127.0.0.0/8 should be allowed as exception
   - ::1/128 should be allowed

6. `test_untrusted_proxy_request_blocked`
   - Request from 1.2.3.4 (not in trusted list)
   - Verify 403 Forbidden

7. `test_trusted_proxy_request_accepted`
   - Request from 127.0.0.1
   - Verify fingerprint extracted successfully

8. `test_cert_verification_failure_blocked`
   - X-Client-Cert-Verify: FAILED
   - Verify 401 Unauthorized

9. `test_missing_cert_fingerprint_blocked`
   - No X-Client-Cert or X-Client-Cert-Fingerprint header
   - Verify 401 Unauthorized

10. `test_fingerprint_normalization`
    - Fingerprint with colons: "AA:BB:CC:..."
    - Verify normalized to lowercase without separators

---

## 7. TOTP Rate Limiting Tests (8 tests)
**File**: `openssl_encrypt_server/unittests/test_totp_rate_limiting.py` (NEW)

### Tests:
1. `test_totp_allows_5_attempts`
   - Submit 5 incorrect TOTP codes
   - Verify all 5 processed (not locked out)

2. `test_totp_locks_after_5_attempts`
   - Submit 6 incorrect TOTP codes
   - Verify 6th attempt returns 429 with lockout message

3. `test_totp_lockout_lasts_15_minutes`
   - Trigger lockout, wait 14 minutes, try again
   - Verify still locked
   - Wait 1 more minute, verify unlocked

4. `test_successful_verification_resets_counter`
   - Submit 3 incorrect codes, then 1 correct code
   - Verify counter reset (5 new attempts available)

5. `test_totp_rate_limit_per_client`
   - Client A exhausts attempts
   - Verify Client B unaffected

6. `test_totp_attempt_window_5_minutes`
   - Submit 3 attempts, wait 6 minutes, submit 3 more
   - Verify old attempts expired, no lockout

7. `test_totp_lockout_response_format`
   - Verify 429 status code
   - Verify message mentions lockout duration
   - Check for "Try again later" message

8. `test_totp_counter_cleanup`
   - Submit attempts, wait for window expiry
   - Verify old timestamps removed from counter

---

## 8. Security Logging Tests (8 tests)
**File**: `openssl_encrypt_server/unittests/test_security_logger.py` (NEW)

### Tests:
1. `test_security_events_logged_to_separate_file`
   - Trigger security event
   - Verify logged to security.log (not main log)

2. `test_security_log_json_format`
   - Trigger event, read log file
   - Verify valid JSON with required fields

3. `test_all_event_types_logged`
   - Test each SecurityEventType
   - Verify all logged correctly

4. `test_severity_levels_recorded`
   - Log events with different severities
   - Verify severity field correct

5. `test_totp_failure_logged`
   - Failed TOTP verification
   - Verify security_logger.log_event() called

6. `test_integrity_mismatch_logged`
   - Hash verification failure
   - Verify log_integrity_mismatch() called

7. `test_untrusted_proxy_logged`
   - Request from untrusted IP
   - Verify UNTRUSTED_PROXY event logged

8. `test_plugin_blocked_logged`
   - Plugin with dangerous pattern in strict mode
   - Verify plugin_blocked event logged

---

## 9. JWT Refresh Token Tests (15 tests)
**File**: `openssl_encrypt_server/unittests/test_jwt_refresh_tokens.py` (NEW)

### Tests:
1. `test_access_token_expires_after_1_hour`
   - Register client, wait 61 minutes (mocked time)
   - Use access token, verify expired error

2. `test_refresh_token_expires_after_7_days`
   - Register client, wait 8 days (mocked time)
   - Try to refresh, verify expired error

3. `test_refresh_endpoint_returns_new_token_pair`
   - Call /refresh with valid refresh token
   - Verify response contains new access_token and refresh_token

4. `test_refresh_token_creates_new_access_token`
   - Use refresh token, get new access token
   - Verify new access token works for API calls

5. `test_old_access_token_invalid_after_refresh`
   - Store old access token, refresh, try old token
   - Verify old token still expires naturally (no revocation needed)

6. `test_sliding_expiration_extends_tokens`
   - Register, wait 6 days, refresh
   - Verify new refresh token expires 7 days from refresh (not registration)

7. `test_access_token_cannot_be_used_to_refresh`
   - Try to call /refresh with access token
   - Verify 401 error: "Invalid token type"

8. `test_token_type_field_in_jwt`
   - Decode access token, verify type="access"
   - Decode refresh token, verify type="refresh"

9. `test_register_response_includes_both_tokens`
   - Call /register
   - Verify response has access_token and refresh_token fields

10. `test_backward_compatibility_token_field`
    - Call /register, check response.token
    - Verify token field equals access_token (backward compat)

11. `test_refresh_response_includes_expiry_times`
    - Call /refresh
    - Verify expires_at and refresh_expires_at present

12. `test_invalid_refresh_token_rejected`
    - Use random string as refresh token
    - Verify 401 error

13. `test_expired_refresh_token_rejected`
    - Use refresh token after 7 days
    - Verify proper expiry error message

14. `test_refresh_rate_limit_enforced`
    - Call /refresh 60 times in 1 hour
    - Verify 61st call blocked with 429

15. `test_multiple_refreshes_chain_correctly`
    - Refresh token, use new refresh token, repeat
    - Verify sliding expiration chain works

---

## 10. AST Analysis Tests (15 tests)
**File**: `openssl_encrypt/unittests/test_plugin_ast_analyzer.py` (NEW)

### Tests:
1. `test_direct_eval_call_detected`
   - Code: `result = eval("1 + 1")`
   - Verify violation detected with line number

2. `test_direct_exec_call_detected`
   - Code: `exec("import os")`
   - Verify detected

3. `test_compile_call_detected`
   - Code: `compile("code", "file", "exec")`
   - Verify detected

4. `test_dunder_import_detected`
   - Code: `__import__("subprocess")`
   - Verify detected

5. `test_getattr_builtins_bypass_detected`
   - Code: `getattr(__builtins__, "eval")`
   - Verify detected with "getattr_bypass" type

6. `test_builtins_subscript_access_detected`
   - Code: `__builtins__["exec"]`
   - Verify detected with "builtins_subscript" type

7. `test_sys_modules_access_detected`
   - Code: `sys.modules["subprocess"]`
   - Verify detected with "sys_modules_access" type

8. `test_os_system_call_detected`
   - Code: `os.system("ls")`
   - Verify detected with "dangerous_os_function" type

9. `test_subprocess_import_detected`
   - Code: `import subprocess`
   - Verify detected with "dangerous_import" type

10. `test_from_import_detected`
    - Code: `from subprocess import Popen`
    - Verify detected

11. `test_all_dangerous_modules_detected`
    - Test imports for: subprocess, os, socket, ctypes, etc.
    - Verify each detected

12. `test_safe_code_passes_analysis`
    - Safe plugin code with json, datetime imports
    - Verify is_safe=True, violations=[]

13. `test_syntax_error_handled`
    - Invalid Python: `def foo(`
    - Verify returns is_safe=False with syntax_error violation

14. `test_violation_includes_line_and_column`
    - Code with eval on line 5
    - Verify violation.line=5, violation.col>0

15. `test_strict_mode_blocks_critical_violations`
    - Analyze with strict_mode=True
    - Code with eval should return is_safe=False
    - Same code with strict_mode=False returns is_safe=True (warning only)

---

## Summary by Priority

### High Priority (Implement First):
1. **JWT Refresh Tokens** (15 tests) - New feature, needs comprehensive coverage
2. **TOTP Rate Limiting** (8 tests) - Critical authentication security
3. **AST Analysis** (15 tests) - Core security validation mechanism
4. **Import Hooks** (10 tests) - New defense layer

**Subtotal: 48 tests**

### Medium Priority:
5. **Rate Limiting** (10 tests) - DoS protection validation
6. **Path Traversal** (8 tests) - Filesystem security
7. **Trusted Proxy** (10 tests) - Authentication boundary

**Subtotal: 28 tests**

### Lower Priority (Extend Existing):
8. **Subprocess Escapes** (6 tests) - Extension of existing tests
9. **Capability Immutability** (5 tests) - Internal consistency
10. **Security Logging** (8 tests) - Infrastructure validation

**Subtotal: 19 tests**

---

## Test Coverage Goals

- **Line Coverage**: Aim for 95%+ on security-critical code
- **Branch Coverage**: 90%+ on conditional security logic
- **Edge Cases**: All bypass attempts must have explicit tests

## Test File Organization

```
openssl_encrypt/unittests/
├── test_plugin_ast_analyzer.py          # NEW - 15 tests
├── test_plugin_import_hooks.py          # NEW - 10 tests
├── test_plugin_path_security.py         # NEW - 8 tests
├── test_plugin_subprocess_blocking.py   # EXTEND - add 6 tests
├── test_plugin_capability_immutability.py # NEW - 5 tests
└── test_plugin_security.py              # EXISTING - 29 tests

openssl_encrypt_server/unittests/
├── test_jwt_refresh_tokens.py           # NEW - 15 tests
├── test_totp_rate_limiting.py           # NEW - 8 tests
├── test_rate_limiting.py                # NEW - 10 tests
├── test_proxy_auth.py                   # NEW - 10 tests
└── test_security_logger.py              # NEW - 8 tests
```

**Grand Total: 95 new tests + 29 existing = 124 total security tests**
