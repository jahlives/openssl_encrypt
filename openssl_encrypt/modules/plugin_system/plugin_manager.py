#!/usr/bin/env python3
"""
Plugin Manager for OpenSSL Encrypt

This module manages the lifecycle of plugins including discovery, loading,
validation, and execution. It enforces security boundaries and ensures
plugins never access sensitive data.

Security Features:
- Capability-based security model
- Plugin validation and sandboxing
- Resource usage monitoring and limits
- Audit logging for all plugin operations
"""

import importlib
import importlib.util
import logging
import os
import sys
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Type

from .plugin_ast_analyzer import analyze_plugin_code
from .plugin_base import (
    BasePlugin,
    PluginCapability,
    PluginResult,
    PluginSecurityContext,
    PluginType,
)
from .plugin_config import PluginConfigManager, ensure_plugin_data_dir
from .plugin_sandbox import PluginSandbox

# Import security logger
try:
    from ..security_logger import get_security_logger

    security_logger = get_security_logger()
except ImportError:
    security_logger = None

logger = logging.getLogger(__name__)


class PluginRegistration:
    """
    Registration record for a plugin including metadata and security info.
    """

    def __init__(self, plugin: BasePlugin, file_path: str, enabled: bool = True):
        self.plugin = plugin
        self.file_path = file_path
        self.file_directory = os.path.dirname(os.path.abspath(file_path))  # Directory where plugin code is located
        self.enabled = enabled
        self.load_time = time.time()
        self.last_used = None
        self.usage_count = 0
        self.error_count = 0
        # Store capabilities as immutable frozenset to prevent runtime modification
        # This prevents plugins from escalating privileges via monkey-patching
        self.capabilities = frozenset(plugin.get_required_capabilities())

    def record_usage(self, success: bool = True):
        """Record plugin usage statistics."""
        self.usage_count += 1
        self.last_used = time.time()
        if not success:
            self.error_count += 1


class PluginManager:
    """
    Manages plugin discovery, loading, validation, and execution.

    Security Architecture:
    - All plugins run in isolated sandboxes
    - Capabilities are validated before plugin execution
    - Resource usage is monitored and limited
    - Audit trail is maintained for all operations
    """

    def __init__(
        self,
        config_manager: Optional["PluginConfigManager"] = None,
        strict_security_mode: bool = True,
    ):
        self.plugins: Dict[str, PluginRegistration] = {}
        self.plugin_directories: Set[str] = set()
        self.sandbox = PluginSandbox()
        self.config_manager = config_manager or PluginConfigManager()
        self.lock = threading.RLock()

        # Security settings
        self.max_execution_time = 30.0  # seconds
        self.max_memory_mb = 100
        self.allowed_capabilities = set(PluginCapability)
        self.audit_log = []

        # Plugin validation security settings
        self.strict_security_mode = strict_security_mode  # Default: block dangerous patterns
        self.allowed_unsafe_plugins: Set[str] = set()  # Whitelist for trusted plugins

    def add_plugin_directory(self, directory: str) -> None:
        """Add directory to scan for plugins."""
        if os.path.isdir(directory):
            self.plugin_directories.add(os.path.abspath(directory))
            logger.info(f"Added plugin directory: {directory}")
        else:
            logger.warning(f"Plugin directory does not exist: {directory}")

    def discover_plugins(self) -> List[str]:
        """
        Discover plugin files and packages in registered directories.

        Returns:
            List of plugin file paths found (includes __init__.py for packages)
        """
        discovered = []

        for directory in self.plugin_directories:
            try:
                dir_path = Path(directory)

                # Discover .py files (existing logic)
                for file_path in dir_path.glob("*.py"):
                    if not file_path.name.startswith("_"):  # Skip private files
                        discovered.append(str(file_path))
                        logger.debug(f"Discovered plugin file: {file_path}")

                # Discover packages (directories with __init__.py)
                for subdir in dir_path.iterdir():
                    if subdir.is_dir() and not subdir.name.startswith("_"):
                        init_file = subdir / "__init__.py"
                        if init_file.exists():
                            discovered.append(str(init_file))
                            logger.debug(f"Discovered plugin package: {subdir}")

            except Exception as e:
                logger.error(f"Error scanning plugin directory {directory}: {e}")

        logger.info(f"Discovered {len(discovered)} plugin files/packages")
        return discovered

    def load_plugin(self, file_path: str) -> PluginResult:
        """
        Load plugin from file path.

        Args:
            file_path: Path to plugin Python file

        Returns:
            PluginResult indicating success/failure
        """
        try:
            # Security validation
            if not self._validate_plugin_file(file_path):
                return PluginResult.error_result(
                    f"Plugin file failed security validation: {file_path}"
                )

            # Load module with proper package name to support relative imports
            # Add project root to sys.path to ensure plugins can import correctly
            # __file__ is at: .../openssl_encrypt/openssl_encrypt/modules/plugin_system/plugin_manager.py
            # We need: .../openssl_encrypt (repo root)
            # So go up 4 levels: plugin_system -> modules -> openssl_encrypt (package) -> openssl_encrypt (repo)
            project_root = os.path.dirname(
                os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            )
            original_path = sys.path.copy()
            if project_root not in sys.path:
                sys.path.insert(0, project_root)

            try:
                # Generate proper module name from file path
                # e.g., /path/to/openssl_encrypt/plugins/hsm/fido2_pepper.py
                # -> openssl_encrypt.plugins.hsm.fido2_pepper
                abs_path = os.path.abspath(file_path)
                module_name = self._file_path_to_module_name(abs_path, project_root)

                spec = importlib.util.spec_from_file_location(module_name, file_path)
                if spec is None or spec.loader is None:
                    return PluginResult.error_result(f"Could not load plugin spec: {file_path}")

                module = importlib.util.module_from_spec(spec)

                # Set up ALL parent packages recursively (for relative imports)
                # e.g., for 'openssl_encrypt.plugins.hsm.fido2_pepper', we need:
                #   - openssl_encrypt
                #   - openssl_encrypt.plugins
                #   - openssl_encrypt.plugins.hsm
                if '.' in module_name:
                    parts = module_name.split('.')
                    for i in range(1, len(parts)):
                        parent_name = '.'.join(parts[:i])
                        # Skip empty parent names or names that start with dots
                        # (can occur with paths outside project root)
                        if not parent_name or not parent_name.strip('.') or parent_name.startswith('.'):
                            continue
                        if parent_name not in sys.modules:
                            try:
                                __import__(parent_name)
                            except ImportError:
                                # Parent package might not exist as importable module, that's OK
                                logger.debug(f"Could not import parent package: {parent_name}")

                sys.modules[module_name] = module
                spec.loader.exec_module(module)
            finally:
                # Restore original sys.path
                sys.path = original_path

            # Find plugin class
            plugin_class = self._find_plugin_class(module)
            if plugin_class is None:
                return PluginResult.error_result(f"No valid plugin class found in: {file_path}")

            # Instantiate plugin
            plugin = plugin_class()

            # Validate plugin
            validation_result = self._validate_plugin(plugin)
            if not validation_result.success:
                return validation_result

            # Security check: Verify plugin config directory permissions
            # If permissions cannot be set to 0o700, skip plugin loading
            if hasattr(os, "chmod"):
                config_dir_path = ensure_plugin_data_dir(plugin.plugin_id, "")
                if config_dir_path is None:
                    error_msg = (
                        f"Plugin {plugin.plugin_id} not loaded: "
                        f"Plugin config directory has insecure permissions and cannot be secured"
                    )
                    logger.warning(error_msg)
                    return PluginResult.error_result(error_msg)

            # Register plugin
            with self.lock:
                if plugin.plugin_id in self.plugins:
                    logger.warning(f"Plugin {plugin.plugin_id} already registered, replacing")

                # Pass file_path as-is to PluginRegistration
                # For packages (__init__.py), PluginRegistration will correctly extract the package directory
                registration = PluginRegistration(plugin, file_path)
                self.plugins[plugin.plugin_id] = registration

                # Initialize plugin
                config = self.config_manager.get_plugin_config(plugin.plugin_id)
                init_result = plugin.initialize(config)
                if not init_result.success:
                    del self.plugins[plugin.plugin_id]
                    return PluginResult.error_result(
                        f"Plugin initialization failed: {init_result.message}"
                    )

            self._audit_log(f"Loaded plugin: {plugin.plugin_id} from {file_path}")
            logger.info(f"Successfully loaded plugin: {plugin.plugin_id}")

            # Security audit log
            if security_logger:
                security_logger.log_event(
                    "plugin_loaded",
                    "info",
                    {
                        "plugin_id": plugin.plugin_id,
                        "plugin_type": plugin.get_plugin_type().value,
                        "file_path": file_path,
                        "capabilities": [cap.value for cap in plugin.get_required_capabilities()],
                    },
                )

            return PluginResult.success_result(
                f"Plugin {plugin.plugin_id} loaded successfully",
                {"plugin_id": plugin.plugin_id, "type": plugin.get_plugin_type().value},
            )

        except Exception as e:
            import traceback
            error_msg = f"Error loading plugin from {file_path}: {str(e)}"
            logger.error(error_msg)
            logger.debug(f"Traceback: {traceback.format_exc()}")

            # Security audit log for failed plugin load
            if security_logger:
                security_logger.log_event(
                    "plugin_load_failed",
                    "warning",
                    {
                        "file_path": file_path,
                        "error": str(e),
                        "error_type": type(e).__name__,
                    },
                )

            return PluginResult.error_result(error_msg)

    def unload_plugin(self, plugin_id: str) -> PluginResult:
        """
        Unload plugin by ID.

        Args:
            plugin_id: ID of plugin to unload

        Returns:
            PluginResult indicating success/failure
        """
        with self.lock:
            if plugin_id not in self.plugins:
                return PluginResult.error_result(f"Plugin not found: {plugin_id}")

            registration = self.plugins[plugin_id]

            # Cleanup plugin
            try:
                cleanup_result = registration.plugin.cleanup()
                if not cleanup_result.success:
                    logger.warning(f"Plugin cleanup failed: {cleanup_result.message}")
            except Exception as e:
                logger.error(f"Error during plugin cleanup: {e}")

            del self.plugins[plugin_id]

        self._audit_log(f"Unloaded plugin: {plugin_id}")
        logger.info(f"Successfully unloaded plugin: {plugin_id}")

        return PluginResult.success_result(f"Plugin {plugin_id} unloaded successfully")

    def execute_plugin(
        self,
        plugin_id: str,
        context: PluginSecurityContext,
        use_process_isolation: bool = True,
    ) -> PluginResult:
        """
        Execute plugin with security context.

        Args:
            plugin_id: ID of plugin to execute
            context: Security context for execution
            use_process_isolation: Use process isolation (default: True)

        Returns:
            PluginResult with execution results
        """
        with self.lock:
            if plugin_id not in self.plugins:
                return PluginResult.error_result(f"Plugin not found: {plugin_id}")

            registration = self.plugins[plugin_id]

            if not registration.enabled:
                return PluginResult.error_result(f"Plugin is disabled: {plugin_id}")

        plugin = registration.plugin

        # Set plugin file directory in context if not already set
        # This allows the sandbox to determine which code directory the plugin can read from
        if not context.plugin_file_directory:
            context.plugin_file_directory = registration.file_directory
            logger.debug(f"Set plugin_file_directory for {plugin_id}: {registration.file_directory}")

        # Validate security context
        if not plugin.validate_security_context(context):
            error_msg = f"Security context validation failed for plugin: {plugin_id}"
            self._audit_log(f"SECURITY: {error_msg}")

            # Security audit log
            if security_logger:
                security_logger.log_event(
                    "security_context_validation_failed",
                    "warning",
                    {
                        "plugin_id": plugin_id,
                        "reason": "invalid_security_context",
                    },
                )

            return PluginResult.error_result(error_msg)

        # Check capabilities (use immutable capabilities from registration, not from plugin object)
        capability_check = self._check_capabilities(plugin_id, registration.capabilities, context)
        if not capability_check.success:
            self._audit_log(
                f"SECURITY: Capability check failed for plugin {plugin_id}: {capability_check.message}"
            )

            # Security audit log for capability violation
            if security_logger:
                security_logger.log_event(
                    "capability_violation",
                    "warning",
                    {
                        "plugin_id": plugin_id,
                        "error": capability_check.message,
                    },
                )

            return capability_check

        # Execute in sandbox
        start_time = time.time()
        try:
            self._audit_log(f"Executing plugin: {plugin_id}")

            result = self.sandbox.execute_plugin(
                plugin,
                context,
                max_execution_time=self.max_execution_time,
                max_memory_mb=self.max_memory_mb,
                use_process_isolation=use_process_isolation,
            )

            execution_time = time.time() - start_time

            # Record usage statistics
            registration.record_usage(result.success)

            if result.success:
                logger.info(f"Plugin {plugin_id} executed successfully in {execution_time:.2f}s")
            else:
                logger.warning(f"Plugin {plugin_id} execution failed: {result.message}")

            self._audit_log(
                f"Plugin {plugin_id} execution {'succeeded' if result.success else 'failed'} in {execution_time:.2f}s"
            )

            return result

        except Exception as e:
            execution_time = time.time() - start_time
            registration.record_usage(False)
            error_msg = f"Plugin {plugin_id} execution error: {str(e)}"
            logger.error(error_msg)
            self._audit_log(f"ERROR: {error_msg} (execution time: {execution_time:.2f}s)")
            return PluginResult.error_result(error_msg)

    def get_plugins_by_type(self, plugin_type: PluginType) -> List[PluginRegistration]:
        """Get all registered plugins of specific type."""
        with self.lock:
            return [
                registration
                for registration in self.plugins.values()
                if registration.plugin.get_plugin_type() == plugin_type and registration.enabled
            ]

    def get_plugin_info(self, plugin_id: str) -> Optional[Dict[str, Any]]:
        """Get information about specific plugin."""
        with self.lock:
            if plugin_id not in self.plugins:
                return None

            registration = self.plugins[plugin_id]
            plugin = registration.plugin

            return {
                **plugin.get_metadata(),
                "file_path": registration.file_path,
                "load_time": registration.load_time,
                "last_used": registration.last_used,
                "usage_count": registration.usage_count,
                "error_count": registration.error_count,
                "enabled": registration.enabled,
            }

    def get_plugin(self, plugin_id: str) -> Optional[Any]:
        """
        Get plugin instance by ID.

        Args:
            plugin_id: Plugin identifier

        Returns:
            Plugin instance or None if not found/disabled
        """
        with self.lock:
            if plugin_id not in self.plugins:
                return None

            registration = self.plugins[plugin_id]
            if not registration.enabled:
                return None

            # Update usage tracking
            registration.last_used = time.time()
            registration.usage_count += 1

            return registration.plugin

    def list_plugins(self) -> List[Dict[str, Any]]:
        """List all registered plugins with their information."""
        with self.lock:
            return [self.get_plugin_info(plugin_id) for plugin_id in self.plugins.keys()]

    def enable_plugin(self, plugin_id: str) -> PluginResult:
        """Enable plugin by ID."""
        with self.lock:
            if plugin_id not in self.plugins:
                return PluginResult.error_result(f"Plugin not found: {plugin_id}")

            self.plugins[plugin_id].enabled = True
            self._audit_log(f"Enabled plugin: {plugin_id}")
            return PluginResult.success_result(f"Plugin {plugin_id} enabled")

    def disable_plugin(self, plugin_id: str) -> PluginResult:
        """Disable plugin by ID."""
        with self.lock:
            if plugin_id not in self.plugins:
                return PluginResult.error_result(f"Plugin not found: {plugin_id}")

            self.plugins[plugin_id].enabled = False
            self._audit_log(f"Disabled plugin: {plugin_id}")
            return PluginResult.success_result(f"Plugin {plugin_id} disabled")

    def get_hsm_plugin(self, plugin_name: str) -> Optional[Any]:
        """
        Get HSM plugin by name.

        Args:
            plugin_name: Name of HSM plugin (e.g., 'yubikey')

        Returns:
            HSM plugin instance or None if not found
        """
        with self.lock:
            for plugin_id, registration in self.plugins.items():
                if (
                    registration.plugin.get_plugin_type() == PluginType.HSM
                    and registration.enabled
                    and plugin_name.lower() in plugin_id.lower()
                ):
                    return registration.plugin
        return None

    def execute_hsm_plugin(
        self, plugin: Any, salt: bytes, config: Optional[Dict[str, Any]] = None
    ) -> bytes:
        """
        Execute HSM plugin and return pepper.

        Args:
            plugin: HSM plugin instance
            salt: Salt to use as challenge
            config: Optional configuration (e.g., slot number)

        Returns:
            HSM pepper bytes

        Raises:
            KeyDerivationError: If HSM operation fails
        """
        try:
            from ..crypt_errors import KeyDerivationError
        except ImportError:
            # Fallback if import fails
            class KeyDerivationError(Exception):
                pass

        # Create security context
        context = PluginSecurityContext(
            plugin_id=plugin.plugin_id,
            capabilities={PluginCapability.ACCESS_CONFIG, PluginCapability.WRITE_LOGS},
        )
        context.metadata["salt"] = salt

        if config:
            context.config.update(config)

        # Execute plugin
        result = self.execute_plugin(plugin.plugin_id, context, use_process_isolation=False)

        if not result.success:
            raise KeyDerivationError(f"HSM plugin execution failed: {result.message}")

        hsm_pepper = result.data.get("hsm_pepper")
        if not hsm_pepper:
            raise KeyDerivationError("HSM plugin returned no pepper value")

        return hsm_pepper

    def get_audit_log(self) -> List[Dict[str, Any]]:
        """Get plugin audit log."""
        return self.audit_log.copy()

    def clear_audit_log(self) -> None:
        """Clear plugin audit log."""
        self.audit_log.clear()
        logger.info("Plugin audit log cleared")

    def set_strict_mode(self, enabled: bool) -> None:
        """
        Enable or disable strict security mode for plugin validation.

        In strict mode (default), plugins with dangerous patterns are blocked.
        In permissive mode, dangerous patterns generate warnings but are allowed.

        Args:
            enabled: True to enable strict mode, False for permissive mode

        Security Note:
            Disabling strict mode should only be done in controlled development
            environments. Never disable strict mode in production.
        """
        old_mode = self.strict_security_mode
        self.strict_security_mode = enabled
        logger.warning(
            f"Plugin security mode changed: {'strict' if enabled else 'permissive'} "
            f"(was: {'strict' if old_mode else 'permissive'})"
        )
        self._audit_log(f"Security mode changed to {'strict' if enabled else 'permissive'}")

    def allow_unsafe_plugin(self, plugin_id: str) -> None:
        """
        Add plugin to whitelist, allowing it to bypass dangerous pattern checks.

        This should only be used for plugins from trusted sources that have been
        manually reviewed and deemed safe despite containing dangerous patterns.

        Args:
            plugin_id: ID of plugin to whitelist

        Security Note:
            Only whitelist plugins from trusted sources after manual code review.
            Whitelisted plugins can execute arbitrary code and access system resources.
        """
        self.allowed_unsafe_plugins.add(plugin_id)
        logger.warning(f"Plugin '{plugin_id}' added to unsafe plugin whitelist")
        self._audit_log(f"Plugin whitelisted: {plugin_id}")

    def remove_unsafe_plugin_allowance(self, plugin_id: str) -> None:
        """
        Remove plugin from unsafe whitelist.

        Args:
            plugin_id: ID of plugin to remove from whitelist
        """
        if plugin_id in self.allowed_unsafe_plugins:
            self.allowed_unsafe_plugins.remove(plugin_id)
            logger.info(f"Plugin '{plugin_id}' removed from unsafe plugin whitelist")
            self._audit_log(f"Plugin whitelist removed: {plugin_id}")
        else:
            logger.warning(f"Plugin '{plugin_id}' was not in whitelist")

    def get_security_status(self) -> Dict[str, Any]:
        """
        Get current security configuration status.

        Returns:
            Dictionary with security settings and statistics
        """
        return {
            "strict_security_mode": self.strict_security_mode,
            "whitelisted_plugins": list(self.allowed_unsafe_plugins),
            "total_plugins": len(self.plugins),
            "enabled_plugins": sum(1 for r in self.plugins.values() if r.enabled),
            "max_execution_time": self.max_execution_time,
            "max_memory_mb": self.max_memory_mb,
        }

    def _validate_plugin_file(self, file_path: str) -> bool:
        """
        Validate plugin file for security issues.

        In strict security mode (default), dangerous patterns are blocked.
        Plugins can be whitelisted using allow_unsafe_plugin() method.

        Args:
            file_path: Path to plugin file to validate

        Returns:
            True if plugin passes validation, False otherwise
        """
        try:
            # Check file size (prevent huge files)
            file_size = os.path.getsize(file_path)
            if file_size > 1024 * 1024:  # 1MB limit
                logger.warning(f"Plugin file too large: {file_path} ({file_size} bytes)")
                return False

            # AST-based content validation
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()

                # Use AST-based analysis to detect dangerous patterns
                is_safe, violations = analyze_plugin_code(
                    content,
                    file_path,
                    strict_mode=self.strict_security_mode
                )

                # Log and handle any violations found
                if violations:
                    for violation in violations:
                        violation_msg = (
                            f"Line {violation.line}:{violation.col} - "
                            f"{violation.violation_type}: {violation.description}"
                        )

                        if self.strict_security_mode and violation.severity == "critical":
                            # In strict mode, block plugins with critical violations
                            logger.error(
                                f"SECURITY BLOCKED: Plugin contains security violation: {file_path}"
                            )
                            logger.error(f"  {violation_msg}")
                            logger.error(
                                "Plugin rejected in strict security mode. Security violations not allowed."
                            )

                            # Security audit log for blocked plugin
                            if security_logger:
                                security_logger.log_event(
                                    "plugin_blocked",
                                    "critical",
                                    {
                                        "file_path": file_path,
                                        "violation_type": violation.violation_type,
                                        "line": violation.line,
                                        "description": violation.description,
                                        "reason": "strict_security_mode",
                                    },
                                )
                        else:
                            # In permissive mode or for non-critical violations, only warn
                            logger.warning(
                                f"Plugin file contains security violation: {file_path}"
                            )
                            logger.warning(f"  {violation_msg}")
                            logger.warning(
                                "Security violation allowed (strict_security_mode=False). "
                                "Use with caution!"
                            )

                            # Security audit log for violation warning
                            if security_logger:
                                security_logger.log_event(
                                    "security_violation_detected",
                                    "warning",
                                    {
                                        "file_path": file_path,
                                        "violation_type": violation.violation_type,
                                        "line": violation.line,
                                        "description": violation.description,
                                        "action": "allowed_permissive_mode",
                                    },
                                )

                # In strict mode, block if not safe
                if self.strict_security_mode and not is_safe:
                    self._audit_log(f"Plugin with security violations blocked: {file_path}")
                    return False
                elif violations:
                    # In permissive mode, warn but allow
                    self._audit_log(f"Plugin with security violations allowed: {file_path}")

            return True

        except Exception as e:
            logger.error(f"Error validating plugin file {file_path}: {e}")
            return False

    def _file_path_to_module_name(self, file_path: str, project_root: str) -> str:
        """Convert file path to proper Python module name.

        Args:
            file_path: Absolute path to plugin file
            project_root: Project root directory

        Returns:
            Module name (e.g., 'openssl_encrypt.plugins.hsm.fido2_pepper')
        """
        # Remove project root from path
        rel_path = os.path.relpath(file_path, project_root)

        # Remove .py extension
        if rel_path.endswith('.py'):
            rel_path = rel_path[:-3]

        # Convert path separators to dots
        module_name = rel_path.replace(os.sep, '.')

        return module_name

    def _find_plugin_class(self, module) -> Optional[Type[BasePlugin]]:
        """Find BasePlugin subclass in module."""
        import inspect

        for name in dir(module):
            obj = getattr(module, name)
            if (
                isinstance(obj, type)
                and issubclass(obj, BasePlugin)
                and obj is not BasePlugin
                and not obj.__name__.startswith("Base")
                and not inspect.isabstract(obj)  # Skip abstract classes
            ):
                return obj
        return None

    def _validate_plugin(self, plugin: BasePlugin) -> PluginResult:
        """Validate plugin meets security requirements."""
        try:
            # Check required methods
            required_methods = [
                "execute",
                "get_plugin_type",
                "get_required_capabilities",
                "get_description",
            ]
            for method in required_methods:
                if not hasattr(plugin, method) or not callable(getattr(plugin, method)):
                    return PluginResult.error_result(f"Plugin missing required method: {method}")

            # Validate plugin ID
            if not hasattr(plugin, "plugin_id") or not plugin.plugin_id:
                return PluginResult.error_result("Plugin missing plugin_id")

            if not isinstance(plugin.plugin_id, str) or len(plugin.plugin_id) > 50:
                return PluginResult.error_result("Plugin ID must be string with max 50 characters")

            # Validate capabilities
            capabilities = plugin.get_required_capabilities()
            if not isinstance(capabilities, set):
                return PluginResult.error_result("Plugin capabilities must be a set")

            for cap in capabilities:
                if not isinstance(cap, PluginCapability):
                    return PluginResult.error_result(f"Invalid capability type: {cap}")
                if cap not in self.allowed_capabilities:
                    return PluginResult.error_result(f"Capability not allowed: {cap.value}")

            # Validate plugin type
            plugin_type = plugin.get_plugin_type()
            if not isinstance(plugin_type, PluginType):
                return PluginResult.error_result("Plugin type must be PluginType enum")

            return PluginResult.success_result("Plugin validation passed")

        except Exception as e:
            return PluginResult.error_result(f"Plugin validation error: {str(e)}")

    def _check_capabilities(
        self, plugin_id: str, required_capabilities: frozenset, context: PluginSecurityContext
    ) -> PluginResult:
        """Check if plugin has required capabilities in context.

        SECURITY: Capabilities are passed as parameter (from registration) to prevent
        plugins from escalating privileges by modifying get_required_capabilities()
        at runtime via monkey-patching.

        Args:
            plugin_id: Plugin identifier for error messages
            required_capabilities: Immutable set of required capabilities from registration
            context: Security context with granted capabilities

        Returns:
            PluginResult indicating success or capability violation
        """
        for capability in required_capabilities:
            if not context.has_capability(capability):
                return PluginResult.error_result(
                    f"Plugin {plugin_id} requires capability {capability.value} which is not granted"
                )

        return PluginResult.success_result("Capability check passed")

    def _audit_log(self, message: str) -> None:
        """Add entry to audit log."""
        entry = {
            "timestamp": time.time(),
            "message": message,
            "thread_id": threading.current_thread().ident,
        }
        self.audit_log.append(entry)

        # Limit audit log size
        if len(self.audit_log) > 1000:
            self.audit_log = self.audit_log[-500:]  # Keep last 500 entries

    def reload_plugin(self, plugin_id: str) -> PluginResult:
        """Reload plugin by ID."""
        with self.lock:
            if plugin_id not in self.plugins:
                return PluginResult.error_result(f"Plugin not found: {plugin_id}")

            file_path = self.plugins[plugin_id].file_path

            # Unload current plugin
            unload_result = self.unload_plugin(plugin_id)
            if not unload_result.success:
                return unload_result

            # Load plugin again
            return self.load_plugin(file_path)

    def shutdown(self) -> None:
        """Shutdown plugin manager and cleanup all plugins."""
        logger.info("Shutting down plugin manager")

        with self.lock:
            plugin_ids = list(self.plugins.keys())

            for plugin_id in plugin_ids:
                try:
                    self.unload_plugin(plugin_id)
                except Exception as e:
                    logger.error(f"Error unloading plugin {plugin_id} during shutdown: {e}")

        logger.info("Plugin manager shutdown complete")
