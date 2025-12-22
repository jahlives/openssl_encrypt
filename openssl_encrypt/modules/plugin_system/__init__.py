#!/usr/bin/env python3
"""
OpenSSL Encrypt Plugin System

This module provides a secure, capability-based plugin architecture for
extending OpenSSL Encrypt functionality without compromising security.

Key Security Features:
- Zero-trust architecture: plugins never access sensitive data
- Capability-based security model with explicit permissions
- Sandboxed execution with resource limits
- Configuration isolation and validation
- Comprehensive audit logging

Plugin Types:
- PreProcessorPlugin: Process files before encryption
- PostProcessorPlugin: Process encrypted files after encryption
- MetadataHandlerPlugin: Work with non-sensitive metadata
- FormatConverterPlugin: Handle format conversions
- AnalyzerPlugin: Analyze encrypted files without decrypting
- UtilityPlugin: Provide helper functions
- HSMPlugin: Hardware Security Module integration for hardware-bound key derivation

Example Usage:
    # Initialize plugin system
    from openssl_encrypt.modules.plugin_system import PluginManager, PluginConfigManager

    config_manager = PluginConfigManager()
    plugin_manager = PluginManager(config_manager)

    # Add plugin directory and discover plugins
    plugin_manager.add_plugin_directory("./plugins")
    plugin_files = plugin_manager.discover_plugins()

    # Load plugins
    for plugin_file in plugin_files:
        result = plugin_manager.load_plugin(plugin_file)
        if result.success:
            print(f"Loaded plugin: {result.data['plugin_id']}")

    # Execute plugin
    from openssl_encrypt.modules.plugin_system import PluginSecurityContext, PluginCapability

    context = PluginSecurityContext("example_plugin", {PluginCapability.READ_FILES})
    context.file_paths = ["/path/to/file.txt"]

    result = plugin_manager.execute_plugin("example_plugin", context)
    if result.success:
        print("Plugin executed successfully")

Security Architecture:
    The plugin system maintains strict security boundaries:

    1. Sensitive Data Isolation:
       - Plugins NEVER receive passwords, encryption keys, or plaintext
       - All plugin operations work with encrypted files or safe metadata

    2. Capability-based Security:
       - Plugins must declare required capabilities
       - Capabilities are validated before execution
       - Fine-grained permissions (file access, network, etc.)

    3. Resource Sandboxing:
       - Memory and execution time limits
       - Restricted file system access
       - Network access controls

    4. Configuration Security:
       - Plugin configs isolated from system config
       - Input validation and sanitization
       - No sensitive data in plugin configurations
"""

__version__ = "1.3.0"
__author__ = "OpenSSL Encrypt Team"

# Standard library imports
import logging

# Core plugin system components
from .plugin_base import (
    AnalyzerPlugin,
    BasePlugin,
    FormatConverterPlugin,
    HSMPlugin,
    MetadataHandlerPlugin,
    PluginCapability,
    PluginResult,
    PluginSecurityContext,
    PluginType,
    PostProcessorPlugin,
    PreProcessorPlugin,
    UtilityPlugin,
)
from .plugin_config import (
    ConfigValidationError,
    PluginConfigManager,
    PluginConfigSchema,
    create_boolean_field,
    create_choice_field,
    create_integer_field,
    create_string_field,
)
from .plugin_manager import PluginManager, PluginRegistration
from .plugin_sandbox import (
    IsolatedPluginExecutor,
    PluginSandbox,
    ResourceMonitor,
    SandboxViolationError,
)

# Plugin system availability and status
PLUGIN_SYSTEM_AVAILABLE = True

# Export all public classes and functions
__all__ = [
    # Core base classes
    "BasePlugin",
    "PreProcessorPlugin",
    "PostProcessorPlugin",
    "MetadataHandlerPlugin",
    "FormatConverterPlugin",
    "AnalyzerPlugin",
    "UtilityPlugin",
    "HSMPlugin",
    # Enums and data structures
    "PluginCapability",
    "PluginType",
    "PluginResult",
    "PluginSecurityContext",
    "PluginRegistration",
    # Management components
    "PluginManager",
    "PluginConfigManager",
    "PluginConfigSchema",
    # Security components
    "PluginSandbox",
    "ResourceMonitor",
    "IsolatedPluginExecutor",
    # Exceptions
    "SandboxViolationError",
    "ConfigValidationError",
    # Configuration helpers
    "create_string_field",
    "create_integer_field",
    "create_boolean_field",
    "create_choice_field",
    # Status flags
    "PLUGIN_SYSTEM_AVAILABLE",
]

# Plugin system metadata and configuration
PLUGIN_SYSTEM_METADATA = {
    "version": __version__,
    "supported_capabilities": [cap.value for cap in PluginCapability],
    "supported_plugin_types": [pt.value for pt in PluginType],
    "security_features": [
        "capability_based_security",
        "resource_sandboxing",
        "configuration_isolation",
        "audit_logging",
        "zero_trust_architecture",
    ],
    "max_execution_time_default": 30.0,  # seconds
    "max_memory_default": 100,  # MB
    "supported_config_types": ["str", "int", "float", "bool", "list", "dict"],
}

# Default plugin directories (relative to OpenSSL Encrypt installation)
DEFAULT_PLUGIN_DIRECTORIES = [
    "plugins",  # Main plugins directory
    "plugins/hsm",  # HSM (Hardware Security Module) plugins
    "plugins/official",  # Official plugins
    "plugins/community",  # Community plugins
    "plugins/user",  # User-specific plugins
]

# Security configuration
SECURITY_DEFAULTS = {
    "allowed_capabilities": set(PluginCapability),
    "max_plugins": 100,  # Maximum number of loaded plugins
    "audit_log_max_entries": 1000,
    "config_file_max_size": 1024 * 10,  # 10KB
    "plugin_file_max_size": 1024 * 1024,  # 1MB
}


def create_default_plugin_manager(config_dir: str = None) -> PluginManager:
    """
    Create plugin manager with default configuration.

    Args:
        config_dir: Optional custom configuration directory

    Returns:
        Configured PluginManager instance
    """
    config_manager = PluginConfigManager(config_dir)
    plugin_manager = PluginManager(config_manager)

    # Add default plugin directories (if they exist)
    import os

    base_dir = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))

    for plugin_dir in DEFAULT_PLUGIN_DIRECTORIES:
        full_path = os.path.join(base_dir, plugin_dir)
        if os.path.exists(full_path):
            plugin_manager.add_plugin_directory(full_path)

    return plugin_manager


def is_plugin_system_available() -> bool:
    """
    Check if plugin system is available and functional.

    Returns:
        True if plugin system is available
    """
    return PLUGIN_SYSTEM_AVAILABLE


def get_plugin_system_info() -> dict:
    """
    Get information about plugin system capabilities.

    Returns:
        Dictionary with plugin system information
    """
    return PLUGIN_SYSTEM_METADATA.copy()


def validate_plugin_compatibility(plugin_file: str) -> dict:
    """
    Validate plugin file for basic compatibility.

    Args:
        plugin_file: Path to plugin file

    Returns:
        Dictionary with validation results
    """
    import ast
    import os

    result = {
        "compatible": False,
        "issues": [],
        "plugin_class_found": False,
        "required_methods": [],
        "capabilities": [],
    }

    if not os.path.exists(plugin_file):
        result["issues"].append("Plugin file does not exist")
        return result

    if os.path.getsize(plugin_file) > SECURITY_DEFAULTS["plugin_file_max_size"]:
        result["issues"].append("Plugin file too large")
        return result

    try:
        # Parse plugin file
        with open(plugin_file, "r", encoding="utf-8") as f:
            content = f.read()

        # Check for basic structure
        tree = ast.parse(content)

        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                # Check if class inherits from BasePlugin
                for base in node.bases:
                    if isinstance(base, ast.Name) and base.id in [
                        "BasePlugin",
                        "PreProcessorPlugin",
                        "PostProcessorPlugin",
                        "MetadataHandlerPlugin",
                        "FormatConverterPlugin",
                        "AnalyzerPlugin",
                        "UtilityPlugin",
                        "HSMPlugin",
                    ]:
                        result["plugin_class_found"] = True
                        break

        if result["plugin_class_found"]:
            result["compatible"] = True
        else:
            result["issues"].append("No BasePlugin subclass found")

    except Exception as e:
        result["issues"].append(f"Error parsing plugin file: {str(e)}")

    return result


# Initialize logging for plugin system
logging.getLogger(__name__).addHandler(logging.NullHandler())
