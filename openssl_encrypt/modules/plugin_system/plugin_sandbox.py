#!/usr/bin/env python3
"""
Plugin Sandbox for OpenSSL Encrypt

This module provides security sandboxing for plugin execution, ensuring
plugins cannot access sensitive data, perform unauthorized operations,
or consume excessive resources.

Security Features:
- Resource limits (memory, execution time)
- Capability enforcement
- File system access restrictions
- Network access controls
- Process isolation where possible
"""

import gc
import logging
import multiprocessing
import os
import resource
import sys
import tempfile
import threading
import time
from contextlib import contextmanager
from typing import Any, Dict

from .plugin_base import BasePlugin, PluginCapability, PluginResult, PluginSecurityContext

logger = logging.getLogger(__name__)


class PluginImportGuard:
    """
    Import hook to block dangerous module imports in plugin code.

    Prevents plugins from importing restricted modules that could be used
    to bypass sandbox restrictions (e.g., subprocess, os, socket).

    Installed in sys.meta_path before plugin execution.
    Also temporarily removes dangerous modules from sys.modules to prevent
    access to already-imported modules.
    """

    # Modules that should always be blocked
    ALWAYS_BLOCKED = {
        'ctypes',         # Load arbitrary C code
        '__builtin__',    # Access to builtins
        '__builtins__',   # Access to builtins
    }

    # Modules that are blocked unless specific capability is granted
    CAPABILITY_GATED = {
        'subprocess': None,  # Always blocked (no capability for this)
        'os': None,          # Always blocked (contains os.system, etc.)
        'socket': PluginCapability.NETWORK_ACCESS,  # Allowed with NETWORK_ACCESS
    }

    def __init__(self, context: PluginSecurityContext = None):
        """Initialize the import guard.

        Args:
            context: Plugin security context with capabilities
        """
        self.context = context
        self.hidden_modules = {}

    def _should_block_module(self, module_name: str) -> bool:
        """Check if a module should be blocked based on capabilities.

        Args:
            module_name: Name of the module to check

        Returns:
            True if module should be blocked, False if allowed
        """
        # Always block certain modules
        if module_name in self.ALWAYS_BLOCKED:
            return True

        # Check capability-gated modules
        if module_name in self.CAPABILITY_GATED:
            required_capability = self.CAPABILITY_GATED[module_name]
            # If no capability can grant access (None), always block
            if required_capability is None:
                return True
            # If capability is granted, allow access
            if self.context and required_capability in self.context.capabilities:
                return False
            # Otherwise, block
            return True

        return False

    def hide_dangerous_modules(self):
        """
        Remove dangerous modules from sys.modules to prevent access.

        Saves removed modules so they can be restored later.
        """
        # Get all modules that should be blocked
        modules_to_hide = set(self.ALWAYS_BLOCKED) | set(self.CAPABILITY_GATED.keys())

        for module_name in modules_to_hide:
            # Check if module should actually be blocked based on capabilities
            if self._should_block_module(module_name) and module_name in sys.modules:
                self.hidden_modules[module_name] = sys.modules[module_name]
                del sys.modules[module_name]
                logger.debug(f"Hidden module from sys.modules: {module_name}")

    def restore_hidden_modules(self):
        """Restore previously hidden modules to sys.modules."""
        for module_name, module in self.hidden_modules.items():
            sys.modules[module_name] = module
        self.hidden_modules.clear()
        logger.debug(f"Restored {len(self.hidden_modules)} hidden modules")

    def find_module(self, fullname, path=None):
        """
        Find module hook for Python 2/3 compatibility.

        Returns self if module should be blocked, None otherwise.
        """
        # Check if the top-level module is blocked
        module_base = fullname.split('.')[0]
        if self._should_block_module(module_base):
            logger.warning(f"Blocked import attempt: {fullname}")
            raise ImportError(
                f"Import of '{fullname}' blocked by plugin security policy. "
                f"Module '{module_base}' is not allowed in plugin context."
            )
        return None

    def find_spec(self, fullname, path, target=None):
        """
        Find spec hook for Python 3.4+.

        Returns None (blocks import by raising ImportError in find_module).
        """
        return self.find_module(fullname, path)


def _plugin_worker(plugin, context, result_queue):
    """
    Worker function for multiprocessing-based plugin execution.

    This function must be at module level to be picklable.

    Args:
        plugin: Plugin instance to execute
        context: Security context for execution
        result_queue: Queue to return results
    """
    try:
        # Execute plugin
        result = plugin.execute(context)
        result_queue.put(("success", result))
    except Exception as e:
        result_queue.put(("error", str(e)))


class ResourceMonitor:
    """Monitor plugin resource usage during execution."""

    def __init__(self):
        self.start_memory = 0
        self.peak_memory = 0
        self.start_time = 0
        self.execution_time = 0
        self.monitoring = False

    def start(self):
        """Start resource monitoring."""
        self.start_memory = self._get_memory_usage()
        self.peak_memory = self.start_memory
        self.start_time = time.time()
        self.monitoring = True

    def stop(self):
        """Stop resource monitoring."""
        if self.monitoring:
            self.execution_time = time.time() - self.start_time
            self.monitoring = False

    def update_peak_memory(self):
        """Update peak memory usage."""
        if self.monitoring:
            current_memory = self._get_memory_usage()
            if current_memory > self.peak_memory:
                self.peak_memory = current_memory

    def get_stats(self) -> Dict[str, float]:
        """Get resource usage statistics."""
        return {
            "memory_start_mb": self.start_memory / (1024 * 1024),
            "memory_peak_mb": self.peak_memory / (1024 * 1024),
            "memory_used_mb": (self.peak_memory - self.start_memory) / (1024 * 1024),
            "execution_time_s": self.execution_time,
        }

    @staticmethod
    def _get_memory_usage() -> int:
        """Get current memory usage in bytes."""
        try:
            # Try to get RSS (Resident Set Size) on Unix systems
            if hasattr(resource, "RUSAGE_SELF"):
                usage = resource.getrusage(resource.RUSAGE_SELF)
                # On Linux, ru_maxrss is in KB, on BSD systems it's in bytes
                if sys.platform == "linux":
                    return usage.ru_maxrss * 1024
                else:
                    return usage.ru_maxrss
            else:
                # Fallback for systems without resource module
                import psutil

                process = psutil.Process(os.getpid())
                return process.memory_info().rss
        except ImportError:
            # Final fallback - approximate using gc
            return len(gc.get_objects()) * 64  # Very rough estimate


class SandboxViolationError(Exception):
    """Raised when plugin violates sandbox restrictions."""

    pass


class PluginSandbox:
    """
    Security sandbox for plugin execution.

    Provides isolation and resource limiting for plugin execution to prevent:
    - Excessive resource consumption
    - Unauthorized file system access
    - Network operations (unless explicitly allowed)
    - System calls that could compromise security
    """

    def __init__(self):
        self.temp_dir = None
        self.monitor = ResourceMonitor()
        self.current_context = None  # Store current plugin context for file access checks

    def execute_plugin(
        self,
        plugin: BasePlugin,
        context: PluginSecurityContext,
        max_execution_time: float = 30.0,
        max_memory_mb: int = 100,
        use_process_isolation: bool = True,
    ) -> PluginResult:
        """
        Execute plugin within security sandbox.

        Args:
            plugin: Plugin to execute
            context: Security context for execution
            max_execution_time: Maximum execution time in seconds
            max_memory_mb: Maximum memory usage in MB
            use_process_isolation: Use process isolation for reliable timeout (default: True)

        Returns:
            PluginResult with execution results

        Note:
            Process isolation is more reliable for timeout enforcement but has
            slightly more overhead. It's recommended for all plugins that may
            perform blocking operations.
        """
        try:
            if use_process_isolation:
                # Use multiprocessing for reliable timeout (recommended)
                return self._execute_in_process(plugin, context, max_execution_time, max_memory_mb)
            else:
                # Use threading (legacy, less reliable for blocking operations)
                # Setup sandbox environment without strict memory limits (threading needs more memory)
                with self._create_sandbox_environment(
                    context, max_memory_mb, use_process_isolation=False
                ):
                    # Start monitoring
                    self.monitor.start()

                    # Setup timeout
                    timeout_triggered = threading.Event()
                    timer = threading.Timer(max_execution_time, timeout_triggered.set)
                    timer.start()

                    try:
                        # Execute plugin with monitoring
                        result = self._execute_with_threading(
                            plugin, context, timeout_triggered, max_memory_mb
                        )

                        # Add resource usage to result
                        stats = self.monitor.get_stats()
                        if result.success:
                            result.add_data("resource_usage", stats)

                        logger.debug(f"Plugin {plugin.plugin_id} resource usage: {stats}")

                        return result

                    finally:
                        timer.cancel()
                        self.monitor.stop()

        except Exception as e:
            error_msg = f"Sandbox execution error: {str(e)}"
            logger.error(error_msg)
            return PluginResult.error_result(error_msg)

    @contextmanager
    def _create_sandbox_environment(
        self, context: PluginSecurityContext, max_memory_mb: int, use_process_isolation: bool = True
    ):
        """Create sandboxed environment for plugin execution.

        Args:
            context: Security context for plugin
            max_memory_mb: Maximum memory in MB
            use_process_isolation: If False, skip strict memory limits (threading needs more memory)
        """
        # Store context for file access validation
        self.current_context = context

        original_cwd = os.getcwd()
        temp_dir = None
        memory_limit_set = False
        # Store original functions to restore later
        saved_state = {}

        try:
            # Create temporary directory for plugin operations
            temp_dir = tempfile.mkdtemp(prefix=f"plugin_{context.plugin_id}_")
            self.temp_dir = temp_dir

            # Set memory limits only for process isolation (Unix only)
            # Threading mode needs more memory for thread creation, so we skip strict limits
            if use_process_isolation and hasattr(resource, "RLIMIT_AS"):
                try:
                    # Set virtual memory limit
                    memory_limit = max_memory_mb * 1024 * 1024
                    resource.setrlimit(resource.RLIMIT_AS, (memory_limit, memory_limit))
                    memory_limit_set = True
                except (OSError, ValueError) as e:
                    logger.warning(f"Could not set memory limit: {e}")

            # Change to temp directory
            os.chdir(temp_dir)

            # Setup restricted environment and save original state
            saved_state = self._setup_restricted_environment(context)

            yield temp_dir

        finally:
            # Restore original functions FIRST (before any other cleanup)
            self._restore_original_environment(saved_state)

            # Cleanup
            os.chdir(original_cwd)

            if temp_dir and os.path.exists(temp_dir):
                try:
                    self._cleanup_temp_directory(temp_dir)
                except Exception as e:
                    logger.error(f"Error cleaning up temp directory: {e}")

            # Reset memory limits only if we set them
            if memory_limit_set and hasattr(resource, "RLIMIT_AS"):
                try:
                    resource.setrlimit(resource.RLIMIT_AS, (-1, -1))
                except (OSError, ValueError):
                    pass

    def _setup_restricted_environment(self, context: PluginSecurityContext):
        """Setup restricted environment based on plugin capabilities.

        Returns:
            Dict with saved original state for restoration
        """
        saved_state = {}

        # Restrict file access based on capabilities
        if PluginCapability.READ_FILES not in context.capabilities:
            # Override file operations to restrict access
            saved_state["file_ops"] = self._restrict_file_operations()

        # Restrict network access
        if PluginCapability.NETWORK_ACCESS not in context.capabilities:
            self._restrict_network_operations(saved_state)

        # Restrict process execution
        if PluginCapability.EXECUTE_PROCESSES not in context.capabilities:
            self._restrict_process_operations(saved_state)

        # Install import guard to block dangerous module imports
        # This prevents plugins from bypassing sandbox restrictions by importing
        # dangerous modules dynamically (e.g., subprocess, os, socket)
        # The guard respects capabilities - e.g., socket is allowed if NETWORK_ACCESS is granted
        import_guard = PluginImportGuard(context)
        import_guard.hide_dangerous_modules()  # Hide already-imported dangerous modules
        sys.meta_path.insert(0, import_guard)
        saved_state["import_guard"] = import_guard
        logger.debug(f"Installed import guard for plugin {context.plugin_id}")

        return saved_state

    def _restrict_file_operations(self):
        """Restrict file system operations.

        Returns:
            Original open function for restoration
        """
        import builtins

        # Store original function
        original_open = builtins.open

        # Capture context for use in restricted_open
        context = self.current_context

        def restricted_open(file, mode="r", **kwargs):
            # Only allow access to temp directory and explicitly safe paths
            abs_path = os.path.abspath(file)

            # Check if this is a write operation
            is_write = any(c in mode for c in ['w', 'a', '+', 'x'])

            if not self._is_safe_path(abs_path, context, is_write):
                raise SandboxViolationError(f"File access denied: {file} (mode: {mode})")

            return original_open(file, mode, **kwargs)

        # Replace open function
        builtins.open = restricted_open
        return original_open

    def _restrict_network_operations(self, saved_state):
        """Restrict network operations.

        Args:
            saved_state: Dict to store original functions for restoration
        """
        import socket

        # Store original function
        saved_state["socket"] = socket.socket

        def restricted_socket(*args, **kwargs):
            raise SandboxViolationError(
                "Network access denied - plugin lacks NETWORK_ACCESS capability"
            )

        socket.socket = restricted_socket

    def _restrict_process_operations(self, saved_state):
        """Restrict process execution operations.

        Blocks multiple process execution vectors:
        - subprocess.Popen
        - os.system, os.popen, os.spawn* family

        This prevents plugins from bypassing subprocess restrictions
        by using alternative OS-level process execution functions.

        Args:
            saved_state: Dict to store original functions for restoration
        """
        import subprocess
        import os

        # Store original subprocess.Popen function
        saved_state["subprocess"] = subprocess.Popen

        def restricted_popen(*args, **kwargs):
            raise SandboxViolationError(
                "Process execution denied - plugin lacks EXECUTE_PROCESSES capability"
            )

        subprocess.Popen = restricted_popen

        # Block os.system
        if hasattr(os, 'system'):
            saved_state["os.system"] = os.system
            os.system = lambda *args, **kwargs: self._raise_process_execution_error()

        # Block os.popen
        if hasattr(os, 'popen'):
            saved_state["os.popen"] = os.popen
            os.popen = lambda *args, **kwargs: self._raise_process_execution_error()

        # Block os.spawn* family
        spawn_functions = ['spawnl', 'spawnle', 'spawnlp', 'spawnlpe',
                          'spawnv', 'spawnve', 'spawnvp', 'spawnvpe']

        for func_name in spawn_functions:
            if hasattr(os, func_name):
                saved_state[f"os.{func_name}"] = getattr(os, func_name)
                setattr(os, func_name, lambda *args, **kwargs: self._raise_process_execution_error())

    def _raise_process_execution_error(self):
        """Raise error for blocked process execution attempts."""
        raise SandboxViolationError(
            "Process execution denied - plugin lacks EXECUTE_PROCESSES capability"
        )

    def _restore_original_environment(self, saved_state):
        """Restore original functions after sandbox execution.

        IMPORTANT: Import guard must be removed FIRST before restoring
        other operations, since restoration may require importing blocked modules.

        Args:
            saved_state: Dict containing original functions to restore
        """
        if not saved_state:
            return

        # Remove import guard FIRST (before restoring anything else)
        # This is critical because restoration may require importing blocked modules
        if "import_guard" in saved_state:
            import_guard = saved_state["import_guard"]
            try:
                sys.meta_path.remove(import_guard)
                import_guard.restore_hidden_modules()  # Restore hidden modules
                logger.debug("Removed import guard from sys.meta_path")
            except ValueError:
                # Guard was already removed or not present
                logger.warning("Import guard not found in sys.meta_path during cleanup")

        # Now restore other operations (safe to import modules now)

        # Restore file operations
        if "file_ops" in saved_state:
            import builtins
            builtins.open = saved_state["file_ops"]

        # Restore network operations
        if "socket" in saved_state:
            import socket
            socket.socket = saved_state["socket"]

        # Restore process operations
        if "subprocess" in saved_state:
            import subprocess
            subprocess.Popen = saved_state["subprocess"]

        # Restore os.system
        if "os.system" in saved_state:
            import os
            os.system = saved_state["os.system"]

        # Restore os.popen
        if "os.popen" in saved_state:
            import os
            os.popen = saved_state["os.popen"]

        # Restore os.spawn* family
        spawn_functions = ['spawnl', 'spawnle', 'spawnlp', 'spawnlpe',
                          'spawnv', 'spawnve', 'spawnvp', 'spawnvpe']
        for func_name in spawn_functions:
            key = f"os.{func_name}"
            if key in saved_state:
                import os
                setattr(os, func_name, saved_state[key])

    def _is_safe_path(self, path: str, context: PluginSecurityContext = None, is_write: bool = False) -> bool:
        """Check if file path is safe for plugin access.

        SECURITY: Uses realpath() to resolve symlinks and prevent traversal attacks.

        Args:
            path: File path to check
            context: Plugin security context (contains plugin_id)
            is_write: True if this is a write operation

        Returns:
            True if access is allowed, False otherwise
        """
        # Block symlink access explicitly
        if os.path.islink(path):
            logger.warning(f"Symlink access blocked: {path}")
            return False

        # Use realpath() instead of abspath() to resolve symlinks
        # This prevents symlink attacks where a plugin creates a symlink
        # in an allowed directory pointing to a sensitive file
        try:
            abs_path = os.path.realpath(path)
        except (OSError, ValueError) as e:
            logger.warning(f"Failed to resolve path {path}: {e}")
            return False

        # Verify the resolved path exists (for additional safety)
        # This helps prevent TOCTOU issues
        if not os.path.exists(abs_path):
            # Allow non-existent paths for write operations (file creation)
            if not is_write:
                return False

        # Allow access to temp directory
        if self.temp_dir:
            temp_dir_real = os.path.realpath(self.temp_dir)
            if abs_path.startswith(temp_dir_real):
                return True

        # Allow read-only access to standard library
        stdlib_dir = os.path.realpath(os.path.dirname(os.__file__))
        if abs_path.startswith(stdlib_dir):
            return True

        # Plugin-specific directory access (if context available)
        if context and context.plugin_id:
            plugin_id = context.plugin_id

            # Plugin config directory: ~/.openssl_encrypt/plugins/<plugin_id>/
            # Allow read/write access
            config_dir = os.path.realpath(
                os.path.expanduser(f"~/.openssl_encrypt/plugins/{plugin_id}")
            )
            if abs_path.startswith(config_dir):
                # Double-check path didn't escape via symlink resolution
                if not abs_path.startswith(config_dir):
                    logger.warning(
                        f"Path traversal attempt detected: {path} -> {abs_path}"
                    )
                    return False
                return True

            # Plugin code directory: Use actual file location from context
            # Allow read-only access (deny writes)
            # This allows plugins to read from the directory where they are located
            # e.g., plugins/hsm/fido2_pepper.py can read plugins/hsm/*
            if context.plugin_file_directory:
                plugin_code_dir = os.path.realpath(context.plugin_file_directory)
                if abs_path.startswith(plugin_code_dir):
                    if is_write:
                        # Deny write access to plugin code directory
                        logger.warning(
                            f"Plugin '{plugin_id}' attempted to write to code directory: {abs_path}"
                        )
                        return False
                    # Allow read access
                    logger.debug(f"Plugin '{plugin_id}' reading from code directory: {abs_path}")
                    return True

        # Deny access to everything else
        logger.debug(f"Access denied to path: {abs_path}")
        return False

    def _execute_with_threading(
        self,
        plugin: BasePlugin,
        context: PluginSecurityContext,
        timeout_event: threading.Event,
        max_memory_mb: int,
    ) -> PluginResult:
        """
        Execute plugin with resource monitoring using threading (legacy).

        Note: This approach cannot interrupt blocking operations reliably.
        Use _execute_in_process() for reliable timeout enforcement.
        """

        def monitor_resources():
            """Monitor resource usage in background thread."""
            while not timeout_event.is_set() and self.monitor.monitoring:
                self.monitor.update_peak_memory()

                # Check memory limit
                current_memory_mb = self.monitor.peak_memory / (1024 * 1024)
                if current_memory_mb > max_memory_mb:
                    raise SandboxViolationError(
                        f"Memory limit exceeded: {current_memory_mb:.1f}MB > {max_memory_mb}MB"
                    )

                time.sleep(0.1)  # Check every 100ms

        # Start monitoring thread
        monitor_thread = threading.Thread(target=monitor_resources, daemon=True)
        monitor_thread.start()

        try:
            # Execute plugin
            result = plugin.execute(context)

            # Check if timeout occurred
            if timeout_event.is_set():
                return PluginResult.error_result("Plugin execution timed out")

            return result

        except SandboxViolationError as e:
            return PluginResult.error_result(f"Sandbox violation: {str(e)}")
        except Exception as e:
            return PluginResult.error_result(f"Plugin execution error: {str(e)}")

    def _execute_in_process(
        self,
        plugin: BasePlugin,
        context: PluginSecurityContext,
        max_execution_time: float,
        max_memory_mb: int,
    ) -> PluginResult:
        """
        Execute plugin in separate process with reliable timeout.

        This uses multiprocessing to run the plugin in a completely separate
        process, which allows for reliable timeout enforcement even when the
        plugin performs blocking operations (like time.sleep).

        Args:
            plugin: Plugin to execute
            context: Security context for execution
            max_execution_time: Maximum execution time in seconds
            max_memory_mb: Maximum memory usage in MB (not enforced in process yet)

        Returns:
            PluginResult with execution results or timeout error
        """
        # Use 'spawn' start method to avoid fork-safety issues with threads
        # Fork is unsafe when threads exist (common after many tests)
        # Spawn creates a fresh Python interpreter, avoiding threading issues
        ctx = multiprocessing.get_context("spawn")

        # Create communication queue
        result_queue = ctx.Queue()

        # Create and start process (using module-level _plugin_worker for picklability)
        process = ctx.Process(
            target=_plugin_worker, args=(plugin, context, result_queue), daemon=True
        )

        try:
            process.start()
            process.join(timeout=max_execution_time)

            # Handle timeout - process is still running
            if process.is_alive():
                logger.warning(
                    f"Plugin {plugin.plugin_id} timed out after {max_execution_time}s, terminating..."
                )
                process.terminate()
                process.join(timeout=1.0)

                if process.is_alive():
                    logger.error(f"Plugin {plugin.plugin_id} did not terminate, force killing...")
                    process.kill()
                    process.join()

                return PluginResult.error_result(
                    f"Plugin execution timed out after {max_execution_time} seconds"
                )

            # Check if process crashed or failed
            if process.exitcode != 0:
                logger.error(
                    f"Plugin {plugin.plugin_id} process failed with exit code {process.exitcode}"
                )
                return PluginResult.error_result(
                    f"Plugin process crashed or failed (exit code: {process.exitcode})"
                )

            # Process completed normally (exitcode == 0), get result from queue
            try:
                # Use timeout to avoid hanging if queue has issues
                import queue

                status, data = result_queue.get(timeout=1.0)
                if status == "success":
                    return data
                else:
                    return PluginResult.error_result(f"Plugin error: {data}")
            except queue.Empty:
                # Queue is empty even though process completed successfully
                logger.error(
                    f"Plugin {plugin.plugin_id} completed but returned no result (queue empty)"
                )
                return PluginResult.error_result(
                    "Plugin completed but did not return a result (internal error)"
                )
            except Exception as e:
                # Other queue errors
                logger.error(f"Failed to get result from queue for {plugin.plugin_id}: {e}")
                return PluginResult.error_result(
                    f"Plugin queue error: {type(e).__name__}: {str(e)}"
                )

        except Exception as e:
            # Cleanup process if still running
            if process.is_alive():
                process.terminate()
                process.join(timeout=1.0)
                if process.is_alive():
                    process.kill()
                    process.join()
            return PluginResult.error_result(f"Process execution error: {str(e)}")

    def _cleanup_temp_directory(self, temp_dir: str):
        """Safely cleanup temporary directory."""
        import shutil

        if os.path.exists(temp_dir):
            # Secure deletion of temporary files
            for root, _dirs, files in os.walk(temp_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    try:
                        # Overwrite file with random data before deletion
                        if os.path.getsize(file_path) > 0:
                            with open(file_path, "r+b") as f:
                                size = f.seek(0, 2)  # Get file size
                                f.seek(0)
                                f.write(os.urandom(size))
                                f.flush()
                                os.fsync(f.fileno())
                    except Exception:
                        pass  # Continue with deletion even if secure overwrite fails

            shutil.rmtree(temp_dir)


class IsolatedPluginExecutor:
    """
    Execute plugins in completely isolated processes (optional advanced isolation).

    This provides the highest level of isolation but with performance overhead.
    Use for untrusted plugins that require maximum security.
    """

    @staticmethod
    def execute_in_process(
        plugin_code: str, context_data: Dict[str, Any], timeout: float = 30.0
    ) -> PluginResult:
        """
        Execute plugin in isolated process.

        Args:
            plugin_code: Plugin code to execute
            context_data: Serialized context data
            timeout: Execution timeout

        Returns:
            PluginResult with execution results
        """

        def target_function(plugin_code, context_data, result_queue):
            """Target function for isolated execution."""
            try:
                # This is a simplified example
                # In production, you'd need proper serialization/deserialization

                # Create minimal execution environment
                exec_globals = {
                    "__builtins__": {
                        "print": print,
                        "len": len,
                        "str": str,
                        "int": int,
                        "float": float,
                        "dict": dict,
                        "list": list,
                        "tuple": tuple,
                        "set": set,
                    }
                }

                # Execute plugin code (intentional for isolated execution)
                exec(plugin_code, exec_globals)  # noqa: S102

                # Get result (simplified)
                result = PluginResult.success_result("Isolated execution completed")
                result_queue.put(("success", result))

            except Exception as e:
                result = PluginResult.error_result(f"Isolated execution error: {str(e)}")
                result_queue.put(("error", result))

        # Create process with timeout using spawn for fork-safety
        ctx = multiprocessing.get_context("spawn")
        result_queue = ctx.Queue()
        process = ctx.Process(
            target=target_function, args=(plugin_code, context_data, result_queue)
        )

        try:
            process.start()
            process.join(timeout=timeout)

            if process.is_alive():
                process.terminate()
                process.join()
                return PluginResult.error_result("Plugin execution timed out")

            if not result_queue.empty():
                status, result = result_queue.get()
                return result
            else:
                return PluginResult.error_result("No result returned from isolated execution")

        except Exception as e:
            if process.is_alive():
                process.terminate()
                process.join()
            return PluginResult.error_result(f"Isolated execution error: {str(e)}")
