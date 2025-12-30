# Telemetry System Integration Tests

Comprehensive integration test suite for the telemetry system, covering client plugin, server API, and end-to-end flows.

## Test Structure

```
tests/integration/
├── test_telemetry_integration.py  # Client-side integration tests
├── test_telemetry_e2e.py          # End-to-end tests
└── requirements-test.txt          # Test dependencies

server/telemetry-server/tests/
├── test_api_integration.py        # Server API integration tests
└── requirements-test.txt          # Server test dependencies
```

## Test Coverage

### Client Integration Tests (`test_telemetry_integration.py`)
- ✅ LocalBuffer storage and retrieval
- ✅ FIFO cleanup when buffer is full
- ✅ Event marking as uploaded
- ✅ Export pending events for transparency
- ✅ APIKeyManager key generation and storage
- ✅ File permissions (0600) enforcement
- ✅ Key expiration detection
- ✅ TelemetryUploader batch uploads
- ✅ Rate limit handling
- ✅ Server error retry logic
- ✅ Complete plugin integration
- ✅ Event buffering
- ✅ Opt-out data deletion
- ✅ Complete telemetry flow with filtering

### Server Integration Tests (`test_api_integration.py`)
- ✅ Health check endpoint
- ✅ Client registration
- ✅ Invalid registration handling
- ✅ Duplicate client ID prevention
- ✅ Batch telemetry upload
- ✅ Authentication enforcement
- ✅ Invalid API key rejection
- ✅ Cascade encryption events
- ✅ Post-quantum cryptography events
- ✅ Public statistics endpoint
- ✅ Statistics with/without data
- ✅ API key refresh
- ✅ Rate limiting enforcement
- ✅ Database storage verification

### End-to-End Tests (`test_telemetry_e2e.py`)
- ✅ Complete registration and upload flow
- ✅ Server error retry
- ✅ Rate limit response handling
- ✅ Offline operation (local buffering)
- ✅ API key refresh flow
- ✅ All format versions (4-8)
- ✅ Privacy guarantees (no sensitive data)
- ✅ Cascade cipher sequence hiding
- ✅ CLI command integration

## Running Tests

### Prerequisites

```bash
# Install main dependencies
pip install -r requirements.txt

# Install test dependencies
pip install -r tests/integration/requirements-test.txt

# For server tests
cd server/telemetry-server
pip install -r requirements.txt
pip install -r tests/requirements-test.txt
```

### Run All Tests

```bash
# From project root
pytest tests/integration/ -v

# With coverage
pytest tests/integration/ --cov=openssl_encrypt.plugins.telemetry --cov-report=html

# Server tests
pytest server/telemetry-server/tests/ -v
```

### Run Specific Test Suites

```bash
# Client integration tests only
pytest tests/integration/test_telemetry_integration.py -v

# Server integration tests only
pytest server/telemetry-server/tests/test_api_integration.py -v

# End-to-end tests only
pytest tests/integration/test_telemetry_e2e.py -v
```

### Run Specific Test Classes

```bash
# Test local buffer only
pytest tests/integration/test_telemetry_integration.py::TestLocalBufferIntegration -v

# Test API key manager only
pytest tests/integration/test_telemetry_integration.py::TestAPIKeyManagerIntegration -v

# Test registration endpoint only
pytest server/telemetry-server/tests/test_api_integration.py::TestRegistrationEndpoint -v
```

### Run with Verbose Output

```bash
# Show test names and progress
pytest tests/integration/ -v

# Show print statements
pytest tests/integration/ -v -s

# Show full diff on failures
pytest tests/integration/ -vv
```

### Run with Coverage

```bash
# Generate coverage report
pytest tests/integration/ --cov=openssl_encrypt.plugins.telemetry --cov-report=term-missing

# Generate HTML coverage report
pytest tests/integration/ --cov=openssl_encrypt.plugins.telemetry --cov-report=html

# Open coverage report
open htmlcov/index.html  # macOS
xdg-open htmlcov/index.html  # Linux
```

## Test Results Interpretation

### Expected Output

```
tests/integration/test_telemetry_integration.py::TestLocalBufferIntegration::test_buffer_stores_and_retrieves_events PASSED
tests/integration/test_telemetry_integration.py::TestLocalBufferIntegration::test_buffer_fifo_cleanup PASSED
tests/integration/test_telemetry_integration.py::TestLocalBufferIntegration::test_buffer_mark_uploaded PASSED
...
tests/integration/test_telemetry_e2e.py::TestPrivacyGuarantees::test_no_sensitive_data_in_upload PASSED
tests/integration/test_telemetry_e2e.py::TestPrivacyGuarantees::test_cascade_cipher_sequence_hidden PASSED

============================== X passed in Y.YYs ==============================
```

### Coverage Goals

- **Minimum**: 80% coverage
- **Target**: 90% coverage
- **Critical paths**: 100% coverage (filtering, privacy checks)

## Troubleshooting

### Import Errors

If you get import errors:
```bash
# Ensure you're in the project root
cd /path/to/openssl_encrypt

# Install in development mode
pip install -e .

# Or add to PYTHONPATH
export PYTHONPATH="${PYTHONPATH}:$(pwd)"
```

### Database Errors

Server tests use SQLite in-memory database. If you get database errors:
```bash
# Ensure SQLAlchemy is installed
pip install sqlalchemy

# Check SQLite version
python -c "import sqlite3; print(sqlite3.sqlite_version)"
```

### Requests Mock Errors

If requests-mock doesn't work:
```bash
# Reinstall requests-mock
pip uninstall requests-mock
pip install requests-mock>=1.11.0
```

### Temporary Directory Errors

Tests use `tmp_path` fixture. If you get permission errors:
```bash
# Check /tmp permissions
ls -la /tmp

# Or set TMPDIR
export TMPDIR=/path/to/writable/tmp
```

## Test Data

### Sample Metadata (Used in Tests)

```python
metadata = {
    "format_version": 8,
    "mode": "symmetric",
    "derivation_config": {
        "salt": "base64_encoded_salt",
        "hash_config": {"sha512": {"rounds": 10000}},
        "kdf_config": {"argon2": {"time_cost": 3, "memory_cost": 65536}}
    },
    "encryption": {"algorithm": "aes-256-gcm"},
    "hashes": {}
}
```

### Expected Filtered Event

```python
{
    "timestamp": "2025-12-30T12:00:00Z",
    "operation": "encrypt",
    "mode": "symmetric",
    "format_version": 8,
    "hash_algorithms": ["sha512"],
    "kdf_algorithms": ["argon2"],
    "kdf_parameters": {"argon2": {"time_cost": 3, "memory_cost": 65536}},
    "encryption_algorithm": "aes-256-gcm",
    "success": true
}
```

## Security Tests

Critical security tests verify:

1. **No Sensitive Data Leakage**
   - Passwords NEVER in telemetry
   - Keys (public/private/symmetric) NEVER in telemetry
   - Salts NEVER in telemetry
   - Filenames NEVER in telemetry
   - Hashes NEVER in telemetry

2. **Privacy Guarantees**
   - Cascade cipher sequences hidden (only count exposed)
   - HSM slot numbers blocked
   - Client ID is random (not hardware-based)
   - No IP address logging

3. **Data Immutability**
   - TelemetryEvent is frozen (cannot be modified)

## Continuous Integration

### GitHub Actions Example

```yaml
name: Telemetry Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      - name: Install dependencies
        run: |
          pip install -r requirements.txt
          pip install -r tests/integration/requirements-test.txt
      - name: Run tests
        run: pytest tests/integration/ -v --cov
      - name: Upload coverage
        uses: codecov/codecov-action@v3
```

## Performance Benchmarks

Expected test execution times:
- Client integration: ~5-10 seconds
- Server integration: ~3-5 seconds
- End-to-end: ~10-15 seconds
- **Total**: ~20-30 seconds

## Adding New Tests

### Template for New Test

```python
def test_new_feature(tmp_path):
    """Test description."""
    # Setup
    config = TelemetryPluginConfig(
        server_url="https://test.example.com",
        buffer_path=tmp_path / "buffer.db",
    )

    plugin = OpenSSLEncryptTelemetryPlugin(config)

    # Test logic
    # ...

    # Assertions
    assert expected_behavior

    # Cleanup
    plugin.stop()
```

## Related Documentation

- Security tests: `tests/test_telemetry_security.py`
- Implementation plan: `telemetry_plan.md`
- Server README: `server/telemetry-server/README.md`
- Client plugin: `openssl_encrypt/plugins/telemetry/`
