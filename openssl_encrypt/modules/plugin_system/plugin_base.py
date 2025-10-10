#!/usr/bin/env python3
"""
Plugin Base Classes for OpenSSL Encrypt

This module provides the foundational base classes for the secure plugin system.
All plugins must inherit from these classes to ensure security boundaries are
maintained and sensitive data is never exposed to third-party code.

Security Architecture:
- Zero-trust design: plugins never access passwords, keys, or plaintext
- Capability-based security model with explicit permissions
- Sandboxed execution environment with restricted operations
- Type-safe interfaces with validation and sanitization
"""

import abc
import enum
import logging
import time
from typing import Any, Dict, List, Optional, Set, Union

logger = logging.getLogger(__name__)


class PluginCapability(enum.Enum):
    """
    Security capabilities that plugins can request.
    Each capability grants specific, limited permissions.
    """

    # File system access (read-only, specific paths)
    READ_FILES = "read_files"

    # Metadata manipulation (non-sensitive only)
    MODIFY_METADATA = "modify_metadata"

    # Configuration access (plugin-specific config only)
    ACCESS_CONFIG = "access_config"

    # Logging capabilities (filtered, no sensitive data)
    WRITE_LOGS = "write_logs"

    # Network access (disabled by default for security)
    NETWORK_ACCESS = "network_access"

    # Process execution (highly restricted)
    EXECUTE_PROCESSES = "execute_processes"


class PluginType(enum.Enum):
    """
    Plugin types defining where in the pipeline plugins can hook.
    Each type has specific interfaces and security boundaries.
    """

    # Pre-processing plugins (work with input files before encryption)
    PRE_PROCESSOR = "pre_processor"

    # Post-processing plugins (work with output files after encryption)
    POST_PROCESSOR = "post_processor"

    # Metadata plugins (manipulate non-sensitive metadata)
    METADATA_HANDLER = "metadata_handler"

    # Format plugins (handle input/output format conversions)
    FORMAT_CONVERTER = "format_converter"

    # Analysis plugins (analyze encrypted files without decrypting)
    ANALYZER = "analyzer"

    # Utility plugins (provide helper functions)
    UTILITY = "utility"


class PluginSecurityContext:
    """
    Security context passed to plugins containing safe, sanitized data.
    This is the ONLY data interface plugins can access.
    """

    def __init__(self, plugin_id: str, capabilities: Set[PluginCapability]):
        self.plugin_id = plugin_id
        self.capabilities = capabilities
        self.metadata = {}  # Only non-sensitive metadata
        self.file_paths = []  # Only paths to encrypted files or safe temp files
        self.config = {}  # Plugin-specific configuration only
        self.timestamp = time.time()

    def has_capability(self, capability: PluginCapability) -> bool:
        """Check if plugin has specific capability."""
        return capability in self.capabilities

    def add_metadata(self, key: str, value: Any) -> None:
        """Add non-sensitive metadata that plugins can access."""
        if self._is_sensitive_key(key):
            logger.warning(
                f"Plugin {self.plugin_id}: Attempted to add sensitive metadata key: {key}"
            )
            return
        self.metadata[key] = value

    def get_safe_temp_path(self, suffix: str = "") -> str:
        """Generate safe temporary file path for plugin use."""
        import tempfile

        return tempfile.mktemp(suffix=suffix, prefix=f"plugin_{self.plugin_id}_")

    @staticmethod
    def _is_sensitive_key(key: str) -> bool:
        """Check if metadata key contains sensitive information."""
        sensitive_keywords = [
            "password",
            "key",
            "secret",
            "token",
            "auth",
            "credential",
            "private",
            "passphrase",
            "salt",
            "iv",
            "nonce",
            "seed",
        ]
        key_lower = key.lower()
        return any(keyword in key_lower for keyword in sensitive_keywords)


class PluginResult:
    """
    Result object returned by plugin operations.
    Provides standardized success/failure reporting and safe data return.
    """

    def __init__(
        self, success: bool = True, message: str = "", data: Optional[Dict[str, Any]] = None
    ):
        self.success = success
        self.message = message
        self.data = data or {}
        self.timestamp = time.time()

    def add_data(self, key: str, value: Any) -> None:
        """Add data to result, with security validation."""
        if PluginSecurityContext._is_sensitive_key(key):
            logger.warning(f"Plugin result: Attempted to add sensitive data key: {key}")
            return
        self.data[key] = value

    @classmethod
    def success_result(
        cls,
        message: str = "Operation completed successfully",
        data: Optional[Dict[str, Any]] = None,
    ) -> "PluginResult":
        """Create successful result."""
        return cls(success=True, message=message, data=data)

    @classmethod
    def error_result(cls, message: str, data: Optional[Dict[str, Any]] = None) -> "PluginResult":
        """Create error result."""
        return cls(success=False, message=message, data=data)


class BasePlugin(abc.ABC):
    """
    Abstract base class for all plugins in the OpenSSL Encrypt system.

    Security Design:
    - Plugins NEVER receive sensitive data (passwords, keys, plaintext)
    - All operations work with encrypted files or safe metadata only
    - Capabilities must be explicitly declared and granted
    - Execution is sandboxed with resource limits
    """

    def __init__(self, plugin_id: str, name: str, version: str):
        self.plugin_id = plugin_id
        self.name = name
        self.version = version
        self.enabled = True
        self.logger = logging.getLogger(f"plugin.{plugin_id}")

    def __getstate__(self):
        """
        Support pickling for multiprocessing.

        Logger objects cannot be pickled, so we exclude them from the state.
        The logger will be recreated when unpickling.
        """
        state = self.__dict__.copy()
        # Remove the unpicklable logger
        state.pop("logger", None)
        return state

    def __setstate__(self, state):
        """
        Support unpickling for multiprocessing.

        Recreate the logger after unpickling.
        """
        self.__dict__.update(state)
        # Recreate logger
        self.logger = logging.getLogger(f"plugin.{self.plugin_id}")

    @abc.abstractmethod
    def get_plugin_type(self) -> PluginType:
        """Return the type of this plugin."""
        pass

    @abc.abstractmethod
    def get_required_capabilities(self) -> Set[PluginCapability]:
        """Return set of capabilities this plugin requires."""
        pass

    @abc.abstractmethod
    def get_description(self) -> str:
        """Return human-readable description of plugin functionality."""
        pass

    def get_metadata(self) -> Dict[str, Any]:
        """Return plugin metadata (non-sensitive information only)."""
        return {
            "id": self.plugin_id,
            "name": self.name,
            "version": self.version,
            "type": self.get_plugin_type().value,
            "capabilities": [cap.value for cap in self.get_required_capabilities()],
            "description": self.get_description(),
            "enabled": self.enabled,
        }

    def validate_security_context(self, context: PluginSecurityContext) -> bool:
        """Validate that security context meets plugin requirements."""
        required_caps = self.get_required_capabilities()
        for cap in required_caps:
            if not context.has_capability(cap):
                self.logger.error(f"Missing required capability: {cap.value}")
                return False
        return True

    @abc.abstractmethod
    def execute(self, context: PluginSecurityContext) -> PluginResult:
        """
        Execute the plugin with given security context.
        This is the main entry point for plugin execution.
        """
        pass

    def initialize(self, config: Dict[str, Any]) -> PluginResult:
        """Initialize plugin with configuration (optional override)."""
        return PluginResult.success_result("Plugin initialized successfully")

    def cleanup(self) -> PluginResult:
        """Cleanup resources when plugin is unloaded (optional override)."""
        return PluginResult.success_result("Plugin cleaned up successfully")


class PreProcessorPlugin(BasePlugin):
    """
    Base class for pre-processing plugins.
    These plugins work with input files BEFORE encryption begins.
    """

    def get_plugin_type(self) -> PluginType:
        return PluginType.PRE_PROCESSOR

    @abc.abstractmethod
    def process_file(self, file_path: str, context: PluginSecurityContext) -> PluginResult:
        """
        Process input file before encryption.

        Args:
            file_path: Path to input file (unencrypted)
            context: Security context with capabilities and metadata

        Returns:
            PluginResult with processing status and any modifications
        """
        pass

    def execute(self, context: PluginSecurityContext) -> PluginResult:
        """Execute pre-processing for files in context."""
        if not context.file_paths:
            return PluginResult.error_result("No files provided for pre-processing")

        results = []
        for file_path in context.file_paths:
            result = self.process_file(file_path, context)
            results.append(result)
            if not result.success:
                return result  # Fail fast on first error

        return PluginResult.success_result(
            f"Pre-processed {len(results)} files successfully", {"processed_files": len(results)}
        )


class PostProcessorPlugin(BasePlugin):
    """
    Base class for post-processing plugins.
    These plugins work with output files AFTER encryption is complete.
    """

    def get_plugin_type(self) -> PluginType:
        return PluginType.POST_PROCESSOR

    @abc.abstractmethod
    def process_encrypted_file(
        self, encrypted_file_path: str, context: PluginSecurityContext
    ) -> PluginResult:
        """
        Process encrypted output file.

        Args:
            encrypted_file_path: Path to encrypted file
            context: Security context with capabilities and metadata

        Returns:
            PluginResult with processing status and any modifications
        """
        pass

    def execute(self, context: PluginSecurityContext) -> PluginResult:
        """Execute post-processing for encrypted files in context."""
        if not context.file_paths:
            return PluginResult.error_result("No encrypted files provided for post-processing")

        results = []
        for file_path in context.file_paths:
            result = self.process_encrypted_file(file_path, context)
            results.append(result)
            if not result.success:
                return result  # Fail fast on first error

        return PluginResult.success_result(
            f"Post-processed {len(results)} encrypted files successfully",
            {"processed_files": len(results)},
        )


class MetadataHandlerPlugin(BasePlugin):
    """
    Base class for metadata handling plugins.
    These plugins work ONLY with non-sensitive metadata.
    """

    def get_plugin_type(self) -> PluginType:
        return PluginType.METADATA_HANDLER

    @abc.abstractmethod
    def process_metadata(
        self, metadata: Dict[str, Any], context: PluginSecurityContext
    ) -> PluginResult:
        """
        Process non-sensitive metadata.

        Args:
            metadata: Dictionary of non-sensitive metadata
            context: Security context with capabilities

        Returns:
            PluginResult with modified metadata or processing status
        """
        pass

    def execute(self, context: PluginSecurityContext) -> PluginResult:
        """Execute metadata processing."""
        return self.process_metadata(context.metadata.copy(), context)


class FormatConverterPlugin(BasePlugin):
    """
    Base class for format conversion plugins.
    These plugins handle input/output format conversions.
    """

    def get_plugin_type(self) -> PluginType:
        return PluginType.FORMAT_CONVERTER

    @abc.abstractmethod
    def get_supported_input_formats(self) -> List[str]:
        """Return list of supported input formats (e.g., ['txt', 'doc'])."""
        pass

    @abc.abstractmethod
    def get_supported_output_formats(self) -> List[str]:
        """Return list of supported output formats (e.g., ['pdf', 'html'])."""
        pass

    @abc.abstractmethod
    def convert_format(
        self,
        input_path: str,
        output_path: str,
        input_format: str,
        output_format: str,
        context: PluginSecurityContext,
    ) -> PluginResult:
        """
        Convert file from input format to output format.

        Args:
            input_path: Path to input file
            output_path: Path for output file
            input_format: Source format
            output_format: Target format
            context: Security context

        Returns:
            PluginResult with conversion status
        """
        pass

    def execute(self, context: PluginSecurityContext) -> PluginResult:
        """Execute format conversion based on context metadata."""
        input_format = context.metadata.get("input_format")
        output_format = context.metadata.get("output_format")

        if not input_format or not output_format:
            return PluginResult.error_result("Input and output formats must be specified")

        if not context.file_paths:
            return PluginResult.error_result("No files provided for format conversion")

        input_path = context.file_paths[0]
        output_path = context.get_safe_temp_path(f".{output_format}")

        return self.convert_format(input_path, output_path, input_format, output_format, context)


class AnalyzerPlugin(BasePlugin):
    """
    Base class for file analysis plugins.
    These plugins analyze encrypted files without decrypting them.
    """

    def get_plugin_type(self) -> PluginType:
        return PluginType.ANALYZER

    @abc.abstractmethod
    def analyze_file(self, file_path: str, context: PluginSecurityContext) -> PluginResult:
        """
        Analyze encrypted file without decrypting.

        Args:
            file_path: Path to encrypted file
            context: Security context

        Returns:
            PluginResult with analysis results
        """
        pass

    def execute(self, context: PluginSecurityContext) -> PluginResult:
        """Execute analysis for files in context."""
        if not context.file_paths:
            return PluginResult.error_result("No files provided for analysis")

        analysis_results = []
        for file_path in context.file_paths:
            result = self.analyze_file(file_path, context)
            if result.success:
                analysis_results.append(result.data)
            else:
                return result  # Fail fast on analysis error

        return PluginResult.success_result(
            f"Analyzed {len(analysis_results)} files successfully",
            {"analysis_results": analysis_results},
        )


class UtilityPlugin(BasePlugin):
    """
    Base class for utility plugins.
    These plugins provide helper functions and services.
    """

    def get_plugin_type(self) -> PluginType:
        return PluginType.UTILITY

    @abc.abstractmethod
    def get_utility_functions(self) -> Dict[str, callable]:
        """
        Return dictionary of utility functions this plugin provides.

        Returns:
            Dict mapping function names to callable functions
        """
        pass

    def execute(self, context: PluginSecurityContext) -> PluginResult:
        """Execute utility function based on context."""
        function_name = context.metadata.get("function_name")
        if not function_name:
            return PluginResult.error_result("No utility function specified")

        functions = self.get_utility_functions()
        if function_name not in functions:
            return PluginResult.error_result(f"Unknown utility function: {function_name}")

        try:
            function = functions[function_name]
            function_args = context.metadata.get("function_args", {})
            result = function(**function_args)
            return PluginResult.success_result(
                f"Utility function '{function_name}' executed successfully", {"result": result}
            )
        except Exception as e:
            return PluginResult.error_result(f"Utility function failed: {str(e)}")
