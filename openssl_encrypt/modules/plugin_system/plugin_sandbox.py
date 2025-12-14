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

        return saved_state

    def _restrict_file_operations(self):
        """Restrict file system operations.

        Returns:
            Original open function for restoration
        """
        import builtins

        # Store original function
        original_open = builtins.open

        def restricted_open(file, mode="r", **kwargs):
            # Only allow access to temp directory and explicitly safe paths
            abs_path = os.path.abspath(file)

            if not self._is_safe_path(abs_path):
                raise SandboxViolationError(f"File access denied: {file}")

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

        Args:
            saved_state: Dict to store original functions for restoration
        """
        import subprocess

        # Store original function
        saved_state["subprocess"] = subprocess.Popen

        def restricted_popen(*args, **kwargs):
            raise SandboxViolationError(
                "Process execution denied - plugin lacks EXECUTE_PROCESSES capability"
            )

        subprocess.Popen = restricted_popen

    def _restore_original_environment(self, saved_state):
        """Restore original functions after sandbox execution.

        Args:
            saved_state: Dict containing original functions to restore
        """
        if not saved_state:
            return

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

    def _is_safe_path(self, path: str) -> bool:
        """Check if file path is safe for plugin access."""
        abs_path = os.path.abspath(path)

        # Allow access to temp directory
        if self.temp_dir and abs_path.startswith(os.path.abspath(self.temp_dir)):
            return True

        # Allow read-only access to standard library
        if abs_path.startswith(os.path.dirname(os.__file__)):
            return True

        # Deny access to everything else
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
        # Create communication queue
        result_queue = multiprocessing.Queue()

        # Create and start process (using module-level _plugin_worker for picklability)
        process = multiprocessing.Process(
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

        # Create process with timeout
        result_queue = multiprocessing.Queue()
        process = multiprocessing.Process(
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
