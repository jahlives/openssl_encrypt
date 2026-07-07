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
import stat
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
        self.file_directory = os.path.dirname(
            os.path.abspath(file_path)
        )  # Directory where plugin code is located
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
        signature_policy: "PluginSignaturePolicy" = None,
        trusted_keys_dir: Optional[str] = None,
        include_project_anchor: bool = True,
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
        self.builtin_plugin_root: Optional[str] = None  # Built-in plugins skip AST analysis
        self._validated_source_hashes: Dict[str, str] = {}  # TOCTOU: hash at validation time

        # Signature-gated loading (#66). Default WARN (D1): unsigned/
        # unverifiable non-built-in plugins still load, but a warning +
        # security-log event is emitted; enforce refuses them, off disables
        # the check. trusted_keys_dir defaults to the per-user store resolved
        # lazily on first use.
        from .plugin_signature import PluginSignaturePolicy

        self.signature_policy = signature_policy or PluginSignaturePolicy.WARN
        self.trusted_keys_dir = trusted_keys_dir
        # D2: the bundled project source-integrity key is a default anchor so
        # officially distributed plugins verify without manual enrollment.
        self.include_project_anchor = include_project_anchor
        self._trust_anchors_cache = None

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
                if "." in module_name:
                    parts = module_name.split(".")
                    for i in range(1, len(parts)):
                        parent_name = ".".join(parts[:i])
                        # Skip empty parent names or names that start with dots
                        # (can occur with paths outside project root)
                        if (
                            not parent_name
                            or not parent_name.strip(".")
                            or parent_name.startswith(".")
                        ):
                            continue
                        if parent_name not in sys.modules:
                            try:
                                __import__(parent_name)
                            except ImportError:
                                # Parent package might not exist as importable module, that's OK
                                logger.debug(f"Could not import parent package: {parent_name}")

                # M1 [PLUGIN-2]: re-read the source ONCE as raw bytes, verify it
                # still matches the hash pinned (over raw bytes) at validation
                # time, then execute THAT buffer via compile()+exec instead of
                # spec.loader.exec_module. exec_module does its own disk read and
                # can run a cached .pyc — so the executed bytes were not
                # provably the signed/scanned/pinned bytes. Compiling and
                # exec'ing the verified buffer binds executed == verified and
                # eliminates the .pyc-shadow vector.
                import hashlib as _hashlib

                real_path = os.path.realpath(file_path)
                with open(real_path, "rb") as _f:
                    raw_now = _f.read()

                expected_hash = self._validated_source_hashes.get(real_path)
                if expected_hash is not None:
                    current_hash = _hashlib.sha256(raw_now).hexdigest()
                    if current_hash != expected_hash:
                        return PluginResult.error_result(
                            f"Plugin file modified after validation (TOCTOU): {file_path}"
                        )
                elif not self._is_builtin_plugin(real_path):
                    # Fail CLOSED: a non-built-in with no pinned hash was never
                    # validated for THIS realpath (e.g. a symlink whose target
                    # was swapped after validation, so the pin was keyed to a
                    # different path). Refuse rather than exec unverified bytes.
                    return PluginResult.error_result(
                        f"Plugin not validated before load (no pinned hash): {file_path}"
                    )

                sys.modules[module_name] = module
                # module was built via module_from_spec, so __name__, __file__,
                # __loader__, __spec__, __package__ and (for packages) __path__
                # are already set — relative sibling imports still resolve.
                try:
                    code = compile(raw_now, real_path, "exec")
                    exec(code, module.__dict__)
                except BaseException:
                    # compile()+exec does not clean up sys.modules on failure the
                    # way importlib does; drop the half-initialized module so a
                    # later import doesn't return a broken cached object.
                    sys.modules.pop(module_name, None)
                    raise
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
            logger.debug(
                f"Set plugin_file_directory for {plugin_id}: {registration.file_directory}"
            )

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

    @staticmethod
    def _insecure_location_reason(file_path: str) -> Optional[str]:
        """Return a reason string if the plugin file or its containing
        directory can be modified by anyone other than its owner (a tampering
        window), else None.

        The check is platform-specific:

        - POSIX: the file/dir must not be group- or world-writable. A sticky
          world-writable directory (e.g. /tmp) is not flagged on its own: the
          sticky bit means only an entry's owner may rename/delete it, so the
          file's own mode governs whether it can be tampered with.
        - Windows: POSIX mode bits are meaningless there (``os.stat`` always
          reports 0o666 for files and 0o777 for directories regardless of the
          ACL), so the DACL is inspected instead - the location is insecure if
          any principal other than the owner, SYSTEM or the local
          Administrators group has write access.

        Args:
            file_path: Path to the plugin file

        Returns:
            Reason string if the location is insecure, else None.
        """
        try:
            real_file = os.path.realpath(file_path)
            targets = (real_file, os.path.dirname(real_file))
            if os.name == "nt":
                return PluginManager._windows_insecure_location_reason(targets)
            return PluginManager._posix_insecure_location_reason(targets)
        except OSError as e:
            return f"could not stat plugin path: {e}"

    @staticmethod
    def _posix_insecure_location_reason(targets) -> Optional[str]:
        """POSIX check: flag a group/world-writable file or directory."""
        writable_by_others = stat.S_IWGRP | stat.S_IWOTH
        for target in targets:
            st = os.stat(target)
            if not (st.st_mode & writable_by_others):
                continue
            is_dir = os.path.isdir(target)
            if is_dir and (st.st_mode & stat.S_ISVTX):
                # sticky directory - not a tampering window by itself
                continue
            kind = "directory" if is_dir else "file"
            return f"plugin {kind} is group/world-writable (mode {oct(st.st_mode & 0o777)})"
        return None

    @staticmethod
    def _windows_insecure_location_reason(targets) -> Optional[str]:
        """Windows check: flag a file or directory whose DACL grants write
        access to any principal other than the owner, SYSTEM or the local
        Administrators group.

        Requires pywin32. If it is unavailable the ACL cannot be inspected;
        rather than block every plugin (POSIX mode bits are meaningless on
        Windows) the check is skipped with a warning.
        """
        try:
            import ntsecuritycon
            import win32security
        except ImportError:
            logger.warning(
                "pywin32 is not available; cannot verify plugin location "
                "permissions on Windows. Install pywin32 to enable owner-only "
                "verification of plugin files."
            )
            return None

        # Rights that would let a principal tamper with the plugin file.
        write_mask = (
            ntsecuritycon.FILE_WRITE_DATA
            | ntsecuritycon.FILE_APPEND_DATA
            | ntsecuritycon.FILE_WRITE_EA
            | ntsecuritycon.FILE_WRITE_ATTRIBUTES
            | ntsecuritycon.WRITE_DAC
            | ntsecuritycon.WRITE_OWNER
            | ntsecuritycon.DELETE
            | ntsecuritycon.GENERIC_WRITE
            | ntsecuritycon.GENERIC_ALL
        )

        # SIDs whose write access is not a meaningful extra exposure:
        # CREATOR_OWNER (S-1-3-0) and OWNER_RIGHTS (S-1-3-4) are the owner by
        # definition, and an attacker who already controls SYSTEM or the local
        # Administrators group can tamper with anything regardless.
        trusted = {"S-1-3-0", "S-1-3-4"}
        for sid_type in (
            win32security.WinLocalSystemSid,
            win32security.WinBuiltinAdministratorsSid,
        ):
            try:
                trusted.add(
                    win32security.ConvertSidToStringSid(win32security.CreateWellKnownSid(sid_type))
                )
            except Exception:  # pragma: no cover - defensive
                pass

        for target in targets:
            is_dir = os.path.isdir(target)
            kind = "directory" if is_dir else "file"
            try:
                sd = win32security.GetFileSecurity(
                    target,
                    win32security.OWNER_SECURITY_INFORMATION
                    | win32security.DACL_SECURITY_INFORMATION,
                )
            except Exception as e:  # pywintypes.error is not an OSError
                # Fail closed: if we cannot read the ACL we cannot vouch for it.
                return f"could not read ACL for plugin {kind}: {e}"

            dacl = sd.GetSecurityDescriptorDacl()
            if dacl is None:
                # A NULL DACL grants everyone full access.
                return f"plugin {kind} has a NULL DACL (everyone-writable)"

            allowed = set(trusted)
            allowed.add(win32security.ConvertSidToStringSid(sd.GetSecurityDescriptorOwner()))

            for i in range(dacl.GetAceCount()):
                ace = dacl.GetAce(i)
                ace_type = ace[0][0]
                # Only ACCESS_ALLOWED ACEs grant rights; this is also the only
                # ACE type guaranteed to use the (type, flags), mask, sid shape.
                if ace_type != win32security.ACCESS_ALLOWED_ACE_TYPE:
                    continue
                mask, sid = ace[1], ace[2]
                if not (mask & write_mask):
                    continue
                sid_str = win32security.ConvertSidToStringSid(sid)
                if sid_str in allowed:
                    continue
                try:
                    name, domain, _ = win32security.LookupAccountSid(None, sid)
                    who = f"{domain}\\{name}" if domain else name
                except Exception:
                    who = sid_str
                return (
                    f"plugin {kind} grants write access to '{who}' "
                    f"({sid_str}), not just its owner"
                )
        return None

    def _default_trusted_keys_dir(self) -> str:
        """Resolve the per-user trust-anchor store directory."""
        base = os.environ.get("OPENSSL_ENCRYPT_HOME") or os.path.join(
            os.path.expanduser("~"), ".openssl_encrypt"
        )
        return os.path.join(base, "trusted_plugin_keys")

    def _load_trust_anchors(self):
        """Load (and cache) the enrolled plugin-signing trust anchors.

        Returns a list of TrustAnchor; empty if the store is absent. On a store
        that is unsafe (writable by others) the error is propagated by the
        caller's policy handling.
        """
        if self._trust_anchors_cache is not None:
            return self._trust_anchors_cache
        from .plugin_signature import TrustAnchorStore, project_trust_anchor

        anchors = []
        # D2: the bundled project key first, so distributed plugins verify
        # without enrollment. Absent on stripped installs -> simply skipped.
        if self.include_project_anchor:
            project = project_trust_anchor()
            if project is not None:
                anchors.append(project)

        directory = self.trusted_keys_dir or self._default_trusted_keys_dir()
        anchors.extend(TrustAnchorStore(directory).load_anchors())
        self._trust_anchors_cache = anchors
        return self._trust_anchors_cache

    def _check_signature_policy(self, file_path: str, plugin_bytes: bytes = None) -> bool:
        """Apply the plugin-signature policy to a (non-built-in) plugin file.

        Returns True if the plugin may proceed to load, False if it must be
        refused. WARN never refuses (only logs); ENFORCE refuses unsigned or
        unverifiable plugins; OFF is a no-op.

        ``plugin_bytes`` MUST be the exact buffer that is also AST-scanned,
        hash-pinned, and executed (M1 [PLUGIN-2]) — the caller reads the file
        once and threads the same bytes here, so the signature vouches for the
        bytes that run. If None (standalone use), the raw bytes are read here.
        """
        from .plugin_signature import (
            PluginSignaturePolicy,
            TrustAnchorError,
            signature_path_for,
            verify_plugin_signature,
        )

        if self.signature_policy == PluginSignaturePolicy.OFF:
            return True

        try:
            anchors = self._load_trust_anchors()
        except TrustAnchorError as e:
            # An unsafe anchor store means we cannot establish trust. Fail
            # closed under ENFORCE; warn otherwise.
            logger.error(f"Plugin trust-anchor store is unsafe: {e}")
            if self.signature_policy == PluginSignaturePolicy.ENFORCE:
                return False
            return True

        if plugin_bytes is None:
            try:
                with open(os.path.realpath(file_path), "rb") as f:
                    plugin_bytes = f.read()
            except OSError as e:
                logger.error(f"Could not read plugin for signature check: {file_path}: {e}")
                return self.signature_policy != PluginSignaturePolicy.ENFORCE

        verdict = verify_plugin_signature(plugin_bytes, signature_path_for(file_path), anchors)

        if verdict.verified:
            logger.info(
                f"Plugin signature verified for {file_path} "
                f"(anchor: {verdict.anchor_label}, key: {verdict.fingerprint})"
            )
            if security_logger:
                security_logger.log_event(
                    "plugin_signature_verified",
                    "info",
                    {
                        "file_path": file_path,
                        "fingerprint": verdict.fingerprint,
                        "anchor": verdict.anchor_label,
                    },
                )
            return True

        # Not verified.
        if self.signature_policy == PluginSignaturePolicy.ENFORCE:
            logger.error(
                f"SECURITY BLOCKED: unsigned/unverifiable plugin refused in enforce "
                f"mode: {file_path} ({verdict.reason})"
            )
            if security_logger:
                security_logger.log_event(
                    "plugin_blocked",
                    "critical",
                    {
                        "file_path": file_path,
                        "reason": "signature_unverified",
                        "detail": verdict.reason,
                    },
                )
            return False

        # WARN mode: allow but make it loud.
        logger.warning(
            f"Plugin {file_path} has no valid signature ({verdict.reason}). "
            f"Loading anyway (signature policy: warn). Use enforce mode to refuse."
        )
        if security_logger:
            security_logger.log_event(
                "plugin_signature_missing",
                "warning",
                {
                    "file_path": file_path,
                    "reason": verdict.reason,
                    "action": "allowed_warn_mode",
                },
            )
        return True

    def _is_builtin_plugin(self, real_path: str) -> bool:
        """True if ``real_path`` (already realpath-resolved) is under the
        trusted built-in plugin root. Built-ins skip the AST/signature gate and
        the TOCTOU hash pin (they are shipped, owner-only, and gated by the H8
        writable-location check)."""
        if not self.builtin_plugin_root:
            return False
        real_root = os.path.realpath(self.builtin_plugin_root)
        return real_path == real_root or real_path.startswith(real_root + os.sep)

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
            import hashlib as _hashlib

            # H8: refuse plugins from group/world-writable files or directories.
            # That is the window an attacker uses to drop or rewrite a plugin
            # whose module top-level code runs at import (exec_module) time,
            # before any sandbox applies. Checked before the built-in trust
            # shortcut so even shipped plugins in a tampered tree are caught.
            insecure_reason = self._insecure_location_reason(file_path)
            if insecure_reason:
                logger.error(
                    f"SECURITY BLOCKED: {insecure_reason}: {file_path}. "
                    f"Plugins must live in a directory writable only by their owner."
                )
                if security_logger:
                    security_logger.log_event(
                        "plugin_blocked",
                        "critical",
                        {
                            "file_path": file_path,
                            "reason": "insecure_location",
                            "detail": insecure_reason,
                        },
                    )
                return False

            # Built-in plugins (shipped with the package) are trusted and skip AST analysis.
            # If an attacker could modify these files, they could modify the scanner too.
            # Use realpath to resolve symlinks and prevent symlink-based bypass.
            if self._is_builtin_plugin(os.path.realpath(file_path)):
                logger.debug(f"Built-in plugin trusted, skipping AST analysis: {file_path}")
                return True

            # Check file size (prevent huge files)
            file_size = os.path.getsize(file_path)
            if file_size > 1024 * 1024:  # 1MB limit
                logger.warning(f"Plugin file too large: {file_path} ({file_size} bytes)")
                return False

            # M1 [PLUGIN-2]: read the plugin bytes ONCE (binary, from the
            # realpath) and thread the exact same buffer through signature
            # verification, the AST scan, and the hash pin — so the bytes the
            # signature vouches for are provably the bytes scanned and (via the
            # pin + compile/exec in load_plugin) executed. Previously the
            # signature read raw bytes while the AST/hash read text-mode
            # (newline-translated, utf-8 re-encoded) and exec_module read again,
            # so nothing bound signed == scanned == executed.
            real_path = os.path.realpath(file_path)
            try:
                with open(real_path, "rb") as f:
                    raw = f.read()
            except OSError as e:
                logger.error(f"Could not read plugin for validation: {file_path}: {e}")
                return False

            # Signature gate (#66) over the exact bytes.
            if not self._check_signature_policy(file_path, raw):
                return False

            # Pin sha256 of the RAW bytes for the pre-exec TOCTOU re-check.
            self._validated_source_hashes[real_path] = _hashlib.sha256(raw).hexdigest()

            # AST-based content validation over the SAME raw bytes. ast.parse
            # handles the encoding cookie/BOM identically to compile(), so the
            # scanned AST corresponds to the bytes that execute.
            is_safe, violations = analyze_plugin_code(
                raw, file_path, strict_mode=self.strict_security_mode
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
                        logger.warning(f"Plugin file contains security violation: {file_path}")
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
        if rel_path.endswith(".py"):
            rel_path = rel_path[:-3]

        # Convert path separators to dots
        module_name = rel_path.replace(os.sep, ".")

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
        self,
        plugin_id: str,
        required_capabilities: frozenset,
        context: PluginSecurityContext,
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
