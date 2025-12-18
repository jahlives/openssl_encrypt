# Plugin Development Guide

This guide covers how to develop secure plugins for the OpenSSL Encrypt plugin system. The plugin system implements a zero-trust architecture where plugins never access sensitive data such as passwords, keys, or plaintext content.

## Table of Contents

- [Security Architecture](#security-architecture)
- [Plugin Types](#plugin-types)
- [Development Workflow](#development-workflow)
- [Security Requirements](#security-requirements)
- [API Reference](#api-reference)
- [Example Patterns](#example-patterns)
- [Testing Guidelines](#testing-guidelines)
- [Best Practices](#best-practices)

## Security Architecture

### Zero-Trust Model

The plugin system implements a zero-trust security model with the following principles:

- **No Access to Sensitive Data**: Plugins never access passwords, encryption keys, or plaintext content
- **Capability-Based Security**: Plugins must declare required capabilities and are granted only necessary permissions
- **Sandboxed Execution**: All plugins run in a security sandbox with resource limits
- **Metadata Isolation**: Sensitive metadata is filtered before being passed to plugins
- **Secure Communication**: All plugin communication goes through secure interfaces

### Security Boundaries

```
┌─────────────────────────────────────────┐
│           Application Layer             │
├─────────────────────────────────────────┤
│           Plugin Manager                │
├─────────────────────────────────────────┤
│         Security Sandbox                │
├─────────────────────────────────────────┤
│           Plugin Code                   │
│    (No access to sensitive data)       │
└─────────────────────────────────────────┘
```

## Plugin Types

### 1. PreProcessorPlugin

Processes files before encryption. Use for:
- File format conversion
- Backup creation
- Metadata extraction
- File validation

### 2. PostProcessorPlugin

Processes results after encryption/decryption. Use for:
- Verification operations
- Cleanup tasks
- Result logging
- Statistics collection

### 3. AnalyzerPlugin

Analyzes files without modifying them. Use for:
- Metadata analysis
- File type detection
- Security scanning
- Report generation

### 4. FormatConverterPlugin

Converts between file formats. Use for:
- Text format conversion
- Data transformation
- Format standardization
- Legacy format support

### 5. MetadataHandlerPlugin

Manages file metadata. Use for:
- Custom metadata extraction
- Metadata enrichment
- Tag management
- Classification

### 6. UtilityPlugin

Provides utility functions. Use for:
- Maintenance operations
- Administrative tasks
- Helper functions
- External integrations

## Development Workflow

### 1. Plugin Structure

```python
#!/usr/bin/env python3
"""
Plugin Name

Brief description of what the plugin does.
"""

from openssl_encrypt.modules.plugin_system import (
    PreProcessorPlugin,  # or other plugin type
    PluginCapability,
    PluginResult,
    PluginSecurityContext
)

class MyPlugin(PreProcessorPlugin):
    def __init__(self):
        super().__init__("my_plugin", "My Plugin", "1.0.0")

    def get_required_capabilities(self):
        return {PluginCapability.READ_FILES, PluginCapability.WRITE_LOGS}

    def get_description(self):
        return "Description of what this plugin does"

    def process_file(self, file_path: str, context: PluginSecurityContext) -> PluginResult:
        try:
            # Plugin implementation here
            return PluginResult.success_result("Operation completed")
        except Exception as e:
            return PluginResult.error_result(f"Operation failed: {str(e)}")
```

### 2. Plugin Registration

Place your plugin file in the `openssl_encrypt/plugins/` directory. The plugin manager will automatically discover it based on:

- File location: `openssl_encrypt/plugins/**/*.py`
- Plugin class inheritance from base plugin classes
- Proper `__init__` method signature

### 3. Testing Your Plugin

```python
import unittest
from openssl_encrypt.modules.plugin_system import PluginSecurityContext, PluginCapability
from your_plugin import MyPlugin

class TestMyPlugin(unittest.TestCase):
    def setUp(self):
        self.plugin = MyPlugin()
        self.context = PluginSecurityContext(
            "test_operation",
            allowed_capabilities={PluginCapability.READ_FILES, PluginCapability.WRITE_LOGS}
        )

    def test_plugin_functionality(self):
        result = self.plugin.process_file("/path/to/test/file", self.context)
        self.assertTrue(result.success)
```

## Security Requirements

### Required Capabilities

Plugins must declare all required capabilities:

```python
def get_required_capabilities(self):
    return {
        PluginCapability.READ_FILES,      # Read file system
        PluginCapability.WRITE_LOGS,      # Write to logs
        PluginCapability.MODIFY_METADATA, # Modify context metadata
        # Add only what you need
    }
```

Available capabilities:
- `READ_FILES`: Read files from the filesystem
- `WRITE_LOGS`: Write to application logs
- `MODIFY_METADATA`: Modify plugin context metadata
- `NETWORK_ACCESS`: Make network requests (restricted)

### Forbidden Operations

Plugins MUST NOT attempt to:
- Access encryption keys or passwords
- Read plaintext content from encrypted operations
- Modify system files outside allowed directories
- Make unauthorized network requests
- Access other plugins' data
- Bypass security sandbox restrictions

### Error Handling

Always use proper error handling:

```python
def process_file(self, file_path: str, context: PluginSecurityContext) -> PluginResult:
    try:
        # Your plugin logic
        return PluginResult.success_result("Success message", optional_data)
    except FileNotFoundError:
        return PluginResult.error_result(f"File not found: {file_path}")
    except PermissionError:
        return PluginResult.error_result(f"Permission denied: {file_path}")
    except Exception as e:
        return PluginResult.error_result(f"Unexpected error: {str(e)}")
```

## API Reference

### Base Plugin Classes

#### BasePlugin

Abstract base class for all plugins.

```python
class BasePlugin(abc.ABC):
    def __init__(self, plugin_id: str, name: str, version: str)
    def get_required_capabilities(self) -> Set[PluginCapability]
    def get_description(self) -> str
    def initialize(self, config: Dict[str, Any]) -> PluginResult
    def cleanup(self) -> PluginResult
    def validate_security_context(self, context: PluginSecurityContext) -> bool
```

### PluginSecurityContext

Provides safe access to operation context.

```python
class PluginSecurityContext:
    def add_metadata(self, key: str, value: Any) -> None
    def get_metadata(self, key: str, default: Any = None) -> Any
    def has_capability(self, capability: PluginCapability) -> bool
```

**Safe metadata keys** (always accessible):
- `operation`: Current operation (encrypt/decrypt)
- `algorithm`: Encryption algorithm used
- `file_size`: File size information
- `timestamp`: Operation timestamp
- Custom keys added by plugins

**Filtered metadata** (never accessible):
- `password`: User password
- `key_data`: Encryption keys
- `plaintext_hash`: Hashes of plaintext content
- Any key containing sensitive data

### PluginResult

Standard result format for all plugin operations.

```python
class PluginResult:
    @staticmethod
    def success_result(message: str, data: Dict[str, Any] = None) -> 'PluginResult'

    @staticmethod
    def error_result(message: str, data: Dict[str, Any] = None) -> 'PluginResult'

    # Properties
    success: bool
    message: str
    data: Dict[str, Any]
    timestamp: float
```

## Example Patterns

### File Analysis Pattern

```python
def analyze_file(self, file_path: str, context: PluginSecurityContext) -> PluginResult:
    if not os.path.exists(file_path):
        return PluginResult.error_result(f"File not found: {file_path}")

    stat = os.stat(file_path)
    analysis = {
        "file_size": stat.st_size,
        "modified_time": stat.st_mtime,
        "file_extension": Path(file_path).suffix,
    }

    return PluginResult.success_result("Analysis complete", {"analysis": analysis})
```

### Safe File Processing Pattern

```python
def process_file(self, file_path: str, context: PluginSecurityContext) -> PluginResult:
    try:
        # Always validate input
        if not os.path.exists(file_path):
            return PluginResult.error_result(f"File not found: {file_path}")

        # Process safely (no access to encrypted content)
        result = self._safe_process(file_path)

        # Add metadata for other plugins
        context.add_metadata("processing_result", result)

        return PluginResult.success_result("Processing complete")

    except Exception as e:
        self.logger.error(f"Processing error: {e}")
        return PluginResult.error_result(f"Processing failed: {str(e)}")
```

### Configuration Pattern

```python
def initialize(self, config: Dict[str, Any]) -> PluginResult:
    try:
        # Validate configuration
        required_keys = ["output_directory", "max_files"]
        for key in required_keys:
            if key not in config:
                return PluginResult.error_result(f"Missing config key: {key}")

        # Store sanitized config
        self.output_dir = Path(config["output_directory"])
        self.max_files = int(config["max_files"])

        # Create directories if needed
        self.output_dir.mkdir(parents=True, exist_ok=True)

        return PluginResult.success_result("Plugin initialized")

    except Exception as e:
        return PluginResult.error_result(f"Initialization failed: {str(e)}")
```

## Testing Guidelines

### Unit Testing

Create comprehensive unit tests for your plugin:

```python
import unittest
import tempfile
import os
from pathlib import Path

class TestMyPlugin(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.plugin = MyPlugin()
        self.context = PluginSecurityContext(
            "test_operation",
            allowed_capabilities=self.plugin.get_required_capabilities()
        )

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def test_normal_operation(self):
        # Test normal successful operation
        test_file = os.path.join(self.test_dir, "test.txt")
        with open(test_file, "w") as f:
            f.write("test content")

        result = self.plugin.process_file(test_file, self.context)
        self.assertTrue(result.success)

    def test_error_handling(self):
        # Test error handling
        result = self.plugin.process_file("/nonexistent/file.txt", self.context)
        self.assertFalse(result.success)
        self.assertIn("not found", result.message)

    def test_security_validation(self):
        # Test security context validation
        invalid_context = PluginSecurityContext("test", allowed_capabilities=set())
        self.assertFalse(self.plugin.validate_security_context(invalid_context))
```

### Integration Testing

Test your plugin with the actual plugin system:

```python
def test_plugin_integration(self):
    from openssl_encrypt.modules.plugin_system import create_default_plugin_manager

    # Create plugin manager
    plugin_manager = create_default_plugin_manager()

    # Load your plugin
    plugins = plugin_manager.discover_plugins()
    my_plugin = next((p for p in plugins if p.plugin_id == "my_plugin"), None)
    self.assertIsNotNone(my_plugin)

    # Test execution
    context = PluginSecurityContext("test", my_plugin.get_required_capabilities())
    result = plugin_manager.execute_plugin("my_plugin", context)
    self.assertTrue(result.success)
```

## Best Practices

### Security Best Practices

1. **Minimal Capabilities**: Request only the capabilities you absolutely need
2. **Input Validation**: Always validate file paths and input parameters
3. **Error Handling**: Never expose sensitive information in error messages
4. **Logging Safety**: Don't log sensitive data, even in debug mode
5. **Resource Management**: Clean up temporary files and resources

### Code Quality

1. **Documentation**: Document all public methods and complex logic
2. **Type Hints**: Use type hints for better code clarity
3. **Error Messages**: Provide clear, actionable error messages
4. **Performance**: Consider performance impact, especially for large files
5. **Compatibility**: Ensure compatibility with different Python versions

### Plugin Design

1. **Single Responsibility**: Each plugin should have a clear, focused purpose
2. **Configurability**: Make plugins configurable through the initialization method
3. **Graceful Degradation**: Handle missing dependencies gracefully
4. **Version Compatibility**: Design for forward compatibility
5. **User Experience**: Provide meaningful feedback to users

### Example Directory Structure

```
openssl_encrypt/plugins/
├── examples/
│   ├── file_analyzer.py
│   ├── backup_plugin.py
│   ├── format_converter.py
│   └── audit_logger.py
├── your_organization/
│   ├── __init__.py
│   ├── custom_analyzer.py
│   └── special_formatter.py
└── PLUGIN_DEVELOPMENT.md
```

### Configuration Example

```python
# Plugin configuration in plugin manager
plugin_configs = {
    "my_plugin": {
        "output_directory": "/tmp/plugin_output",
        "max_file_size": "10MB",
        "enabled_features": ["feature1", "feature2"]
    }
}
```

### Deployment Considerations

1. **Dependencies**: Document all external dependencies
2. **Installation**: Provide clear installation instructions
3. **Permissions**: Document required file system permissions
4. **Performance**: Profile your plugin with realistic data sizes
5. **Monitoring**: Include appropriate logging for operational monitoring

## Troubleshooting

### Common Issues

1. **Capability Errors**: Ensure all required capabilities are declared
2. **Import Errors**: Check plugin path and Python module structure
3. **Permission Errors**: Verify file system permissions
4. **Memory Errors**: Monitor memory usage in sandbox environment
5. **Timeout Errors**: Optimize performance for large files

### Debugging Tips

1. Use plugin manager's debug mode
2. Add comprehensive logging to your plugin
3. Test with various file types and sizes
4. Validate security context properly
5. Use unit tests to isolate issues

### Performance Optimization

1. **File Processing**: Process files in chunks for large files
2. **Memory Management**: Clean up resources promptly
3. **Caching**: Cache expensive computations when safe
4. **Async Operations**: Use async patterns for I/O operations
5. **Resource Limits**: Respect sandbox resource limits

This completes the plugin development guide. For more examples, see the plugins in the `examples/` directory.
