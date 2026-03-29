"""
Parallel Key Derivation Module for v11 Independent XOR.

This module provides parallel execution of hash algorithms and KDFs with proper
progress reporting via multiprocessing.Queue.

Implements Massey's Independent XOR composition where each algorithm processes
the same input in parallel, providing "strongest component" security guarantee.
"""

import base64
import hashlib
import multiprocessing as mp
import os
import queue
import threading
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import dataclass
from enum import Enum
from typing import Dict, Optional, Tuple

from .crypt_utils import eprint


class ProgressType(Enum):
    """Type of progress message sent from worker to main process."""

    HASH_PROGRESS = "hash_progress"  # Per-round progress for hash algorithms
    HASH_COMPLETE = "hash_complete"  # Hash algorithm finished
    KDF_START = "kdf_start"  # KDF starting
    KDF_COMPLETE = "kdf_complete"  # KDF finished
    WORKER_ERROR = "worker_error"  # Worker encountered an error


@dataclass
class ProgressMessage:
    """Message sent from worker process to main process via Queue."""

    worker_id: str  # Algorithm name (e.g., "sha256", "argon2")
    progress_type: ProgressType
    current: int = 0  # Current progress (e.g., round number)
    total: int = 0  # Total iterations
    elapsed: float = 0.0  # Time elapsed in seconds
    error: Optional[str] = None


def _normalize_bytes(data: bytes, target_length: int) -> bytes:
    """
    Normalize data to target length using HKDF (picklable version).

    This is a simplified version that doesn't use SecureBytes since we need
    it to be picklable for multiprocessing.

    Note: salt=None is intentional here. This is a deterministic normalization
    of XOR accumulator output to the target key length. Using a random salt
    would break reproducibility since both encrypt and decrypt must derive
    the same key from the same KDF outputs. Per RFC 5869, HKDF with salt=None
    uses a zero-filled salt of hash length, which is acceptable for this
    deterministic key-length normalization use case.
    """
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    if len(data) == target_length:
        return data

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=target_length,
        salt=None,
        info=b"v10_xor_normalize",
        backend=default_backend(),
    )

    return hkdf.derive(data)


def _hash_worker(
    worker_id: str,
    password_bytes: bytes,
    salt: bytes,
    algorithm: str,
    rounds: int,
    key_length: int,
    progress_queue: mp.Queue,
    report_interval: int = 1000,
    debug: bool = False,
) -> Tuple[str, bytes]:
    """
    Worker function for hash algorithm computation.

    Must be at module level for pickle compatibility.

    Args:
        worker_id: Algorithm identifier (e.g., "sha256")
        password_bytes: Initial hash bytes to process
        salt: Original salt bytes
        algorithm: Hash algorithm name
        rounds: Number of iterations
        key_length: Target output length
        progress_queue: Queue for progress updates
        report_interval: Report progress every N rounds
        debug: Enable debug output

    Returns:
        Tuple of (worker_id, result_bytes)
    """
    start_time = time.time()

    try:
        # Start with password+salt
        current = password_bytes + salt

        # Apply hash iterations
        for i in range(rounds):
            if algorithm == "sha256":
                current = hashlib.sha256(current).digest()
            elif algorithm == "sha512":
                current = hashlib.sha512(current).digest()
            elif algorithm == "sha3_256":
                current = hashlib.sha3_256(current).digest()
            elif algorithm == "sha3_512":
                current = hashlib.sha3_512(current).digest()
            elif algorithm == "blake2b":
                current = hashlib.blake2b(current).digest()
            elif algorithm == "blake3":
                import blake3

                current = blake3.blake3(current).digest()
            elif algorithm == "shake256":
                current = hashlib.shake_256(current).digest(64)
            else:
                raise ValueError(f"Unsupported hash algorithm: {algorithm}")

            # Report progress periodically
            if (i + 1) % report_interval == 0 or (i + 1) == rounds:
                progress_queue.put(
                    ProgressMessage(
                        worker_id=worker_id,
                        progress_type=ProgressType.HASH_PROGRESS,
                        current=i + 1,
                        total=rounds,
                        elapsed=time.time() - start_time,
                    )
                )

        # Normalize to key length
        result = _normalize_bytes(current, key_length)

        # Report completion
        progress_queue.put(
            ProgressMessage(
                worker_id=worker_id,
                progress_type=ProgressType.HASH_COMPLETE,
                current=rounds,
                total=rounds,
                elapsed=time.time() - start_time,
            )
        )

        return (worker_id, result)

    except Exception as e:
        # Report error
        progress_queue.put(
            ProgressMessage(
                worker_id=worker_id,
                progress_type=ProgressType.WORKER_ERROR,
                error=str(e),
            )
        )
        raise


def _kdf_worker(
    worker_id: str,
    password_bytes: bytes,
    salt: bytes,
    kdf_type: str,
    kdf_config: dict,
    key_length: int,
    progress_queue: mp.Queue,
    debug: bool = False,
) -> Tuple[str, bytes]:
    """
    Worker function for KDF computation.

    KDFs like Argon2/Scrypt don't report granular progress,
    so we only report start/complete.

    Args:
        worker_id: KDF identifier (e.g., "argon2")
        password_bytes: Initial hash bytes to process
        salt: Original salt bytes
        kdf_type: KDF type name
        kdf_config: KDF-specific configuration
        key_length: Target output length
        progress_queue: Queue for progress updates
        debug: Enable debug output

    Returns:
        Tuple of (worker_id, result_bytes)
    """
    # Report start
    progress_queue.put(
        ProgressMessage(worker_id=worker_id, progress_type=ProgressType.KDF_START, total=1)
    )

    start_time = time.time()

    try:
        if kdf_type == "argon2":
            import argon2.low_level

            # Extract Argon2 parameters
            time_cost = kdf_config.get("time_cost", 2)
            memory_cost = kdf_config.get("memory_cost", 102400)
            parallelism = kdf_config.get("parallelism", 8)
            argon2_type_str = kdf_config.get("type", "id")

            # Map type string to Argon2 Type enum
            if argon2_type_str == "i":
                argon2_type = argon2.low_level.Type.I
            elif argon2_type_str == "d":
                argon2_type = argon2.low_level.Type.D
            else:  # "id" or default
                argon2_type = argon2.low_level.Type.ID

            # Run Argon2
            result = argon2.low_level.hash_secret_raw(
                secret=password_bytes,
                salt=salt,
                time_cost=time_cost,
                memory_cost=memory_cost,
                parallelism=parallelism,
                hash_len=key_length,
                type=argon2_type,
            )

        elif kdf_type == "scrypt":
            # Extract Scrypt parameters
            n = kdf_config.get("n", 32768)
            r = kdf_config.get("r", 8)
            p = kdf_config.get("p", 1)

            # Run Scrypt
            result = hashlib.scrypt(
                password=password_bytes,
                salt=salt,
                n=n,
                r=r,
                p=p,
                maxmem=2 * (128 * n * r * p),
                dklen=key_length,
            )

        elif kdf_type == "balloon":
            # Import balloon hash (local import to avoid issues)
            import importlib.util

            # Find the balloon_hash module
            spec = importlib.util.find_spec("openssl_encrypt.modules.balloon_hash")
            if spec is None:
                raise ValueError("Balloon hash module not found")

            balloon_module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(balloon_module)
            balloon_hash = balloon_module.balloon_hash

            # Extract Balloon parameters
            space_cost = kdf_config.get("space_cost", 16)
            time_cost = kdf_config.get("time_cost", 20)
            delta = kdf_config.get("delta", 4)

            # Run Balloon
            result = balloon_hash(
                password=password_bytes,
                salt=salt,
                space_cost=space_cost,
                time_cost=time_cost,
                delta=delta,
                hash_len=key_length,
            )

        elif kdf_type == "hkdf":
            from cryptography.hazmat.backends import default_backend
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.kdf.hkdf import HKDF

            # Extract HKDF parameters
            info = kdf_config.get("info", b"independent-xor-hkdf")

            # Run HKDF
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=key_length,
                salt=salt,
                info=info if isinstance(info, bytes) else info.encode(),
                backend=default_backend(),
            )

            result = hkdf.derive(password_bytes)

        elif kdf_type == "randomx":
            from .randomx import randomx_kdf

            rounds = kdf_config.get("rounds", 1)
            mode = kdf_config.get("mode", "light")
            height = kdf_config.get("height", 1)
            hash_len = kdf_config.get("hash_len", key_length)

            result = password_bytes
            for i in range(rounds):
                if i == 0:
                    round_salt = salt
                else:
                    round_salt = result[:32] if len(result) >= 32 else result
                result = randomx_kdf(
                    password=result,
                    salt=round_salt,
                    rounds=1,
                    mode=mode,
                    height=height,
                    hash_len=hash_len,
                )

        else:
            raise ValueError(f"Unsupported KDF type: {kdf_type}")

        # Report completion
        progress_queue.put(
            ProgressMessage(
                worker_id=worker_id,
                progress_type=ProgressType.KDF_COMPLETE,
                current=1,
                total=1,
                elapsed=time.time() - start_time,
            )
        )

        return (worker_id, result)

    except Exception as e:
        # Report error
        progress_queue.put(
            ProgressMessage(
                worker_id=worker_id,
                progress_type=ProgressType.WORKER_ERROR,
                error=str(e),
            )
        )
        raise


class ParallelProgressAggregator:
    """
    Aggregates progress from multiple parallel workers and displays unified progress.

    Runs in a separate thread in the main process, reading from the progress queue.
    """

    def __init__(
        self,
        progress_queue: mp.Queue,
        total_workers: int,
        quiet: bool = False,
        progress_enabled: bool = True,
    ):
        self.queue = progress_queue
        self.total_workers = total_workers
        self.quiet = quiet
        self.progress_enabled = progress_enabled

        # Track per-worker progress
        self.worker_progress: Dict[str, Tuple[int, int]] = {}  # worker_id -> (current, total)
        self.completed_workers: set = set()
        self.completed_times: Dict[str, float] = {}  # worker_id -> elapsed time
        self.stop_event = threading.Event()
        self.last_update_time = time.time()

    def _display_aggregated_progress(self):
        """Display combined progress from all workers."""
        if self.quiet or not self.progress_enabled:
            return

        # Calculate overall progress
        total_progress = 0
        total_work = 0
        active_workers = []

        for worker_id, (current, total) in self.worker_progress.items():
            if worker_id not in self.completed_workers:
                total_progress += current
                total_work += total
                active_workers.append(worker_id.upper())

        if total_work > 0:
            percent = (total_progress / total_work) * 100
        else:
            percent = 100.0

        completed = len(self.completed_workers)

        # Build progress bar
        bar_length = 30
        filled = int(bar_length * percent / 100)
        bar = "█" * filled + " " * (bar_length - filled)

        # Show which workers are active (max 3 to avoid clutter)
        if active_workers:
            active_str = ", ".join(active_workers[:3])
            if len(active_workers) > 3:
                active_str += f"... (+{len(active_workers) - 3})"
            active_display = f" Active: {active_str}"
        else:
            active_display = ""

        eprint(
            f"\rParallel KDF: [{bar}] {percent:.1f}% "
            f"({completed}/{self.total_workers} complete){active_display}",
            end="",
            flush=True,
        )

    def _handle_message(self, msg: ProgressMessage):
        """Process a progress message from a worker."""
        if msg.progress_type == ProgressType.HASH_PROGRESS:
            # Update worker progress
            self.worker_progress[msg.worker_id] = (msg.current, msg.total)

        elif msg.progress_type == ProgressType.HASH_COMPLETE:
            # Mark worker as completed
            self.completed_workers.add(msg.worker_id)
            self.completed_times[msg.worker_id] = msg.elapsed

        elif msg.progress_type == ProgressType.KDF_START:
            # Initialize KDF progress (won't update until complete)
            self.worker_progress[msg.worker_id] = (0, msg.total)

        elif msg.progress_type == ProgressType.KDF_COMPLETE:
            # Mark KDF as completed
            self.completed_workers.add(msg.worker_id)
            self.completed_times[msg.worker_id] = msg.elapsed

        elif msg.progress_type == ProgressType.WORKER_ERROR:
            # Don't update display for errors - let exception propagate
            pass

    def run(self):
        """Main aggregator loop - runs in thread."""
        while not self.stop_event.is_set():
            try:
                # Check for messages with timeout
                msg = self.queue.get(timeout=0.1)
                self._handle_message(msg)

                # Update display (throttle to avoid flicker)
                current_time = time.time()
                if current_time - self.last_update_time >= 0.1:  # Update every 100ms
                    self._display_aggregated_progress()
                    self.last_update_time = current_time

            except queue.Empty:
                # No messages - still update display for active workers
                if time.time() - self.last_update_time >= 0.5:  # Update every 500ms
                    self._display_aggregated_progress()
                    self.last_update_time = time.time()
                continue

        # Final display update before exiting
        if not self.quiet and self.progress_enabled:
            eprint(f"\r{' ' * 100}\r", end="", flush=True)


def generate_key_independent_xor_parallel(
    password: bytes,
    salt: bytes,
    hash_config: dict,
    quiet: bool = False,
    algorithm: str = "aes-256-gcm",
    progress: bool = False,
    debug: bool = False,
    pqc_keypair: tuple = None,
    hsm_pepper: bytes = None,
    format_version: int = 11,
    max_workers: int = None,
) -> tuple:
    """
    Generate encryption key using Independent XOR composition with parallel processing.

    Based on Massey's work: K = H1(x) ⊕ H2(x) ⊕ ... ⊕ Hn(x)

    Each algorithm receives the SAME input and runs in parallel via multiprocessing.
    Progress is aggregated and displayed via Queue-based communication.

    Args:
        password: User password (bytes)
        salt: Random salt (bytes)
        hash_config: Configuration dict for enabled algorithms
        quiet: Suppress output messages
        algorithm: Encryption algorithm (determines key length)
        progress: Show progress indicators
        debug: Enable debug logging
        pqc_keypair: Post-quantum keypair (if applicable)
        hsm_pepper: HSM pepper (if applicable)
        format_version: Metadata format version (11 for 1.4)
        max_workers: Maximum number of parallel workers (default: CPU count)

    Returns:
        Tuple of (key, salt, iv)

    Raises:
        ValueError: If no algorithms are enabled
    """
    # Import here to avoid circular imports
    from . import crypt_core
    from .secure_memory import SecureBytes, secure_memzero

    if debug:
        eprint(f"DEBUG: Parallel KDF starting with format_version={format_version}")

    # Determine required key length based on algorithm
    if algorithm == "fernet":
        key_length = 32
    elif algorithm in [
        "aes-256-gcm",
        "chacha20-poly1305",
        "xchacha20-poly1305",
        "aes-gcm-siv",
        "cascade",
    ]:
        key_length = 32
    elif algorithm == "aes-siv":
        key_length = 64
    elif algorithm == "threefish-512":
        key_length = 64
    elif algorithm == "threefish-1024":
        key_length = 128
    else:
        key_length = 32

    # Ensure password and salt are bytes
    if isinstance(password, str):
        password = password.encode("utf-8")
    if isinstance(salt, str):
        salt = salt.encode("utf-8")

    # Apply HSM pepper if provided
    if hsm_pepper:
        if debug:
            eprint("DEBUG: Mixing HSM pepper into password")
        password = SecureBytes(password + hsm_pepper)

    # Compute initial hash (must be done in main process)
    initial_hash = hashlib.sha256(bytes(password) + salt).digest()

    # Build task list
    tasks = []

    # Hash algorithm tasks
    hash_algorithms = [
        "sha256",
        "sha512",
        "sha3_256",
        "sha3_512",
        "blake2b",
        "blake3",
        "shake256",
    ]

    for algo in hash_algorithms:
        rounds = crypt_core.get_hash_rounds(hash_config, algo)
        if rounds > 0:
            tasks.append({"type": "hash", "worker_id": algo, "algorithm": algo, "rounds": rounds})

    # KDF tasks
    if hash_config and "derivation_config" in hash_config:
        kdf_config_section = hash_config["derivation_config"].get("kdf_config", {})
    else:
        kdf_config_section = hash_config if hash_config else {}

    for kdf_type in ["argon2", "scrypt", "balloon", "hkdf", "randomx"]:
        if kdf_config_section.get(kdf_type, {}).get("enabled", False):
            tasks.append(
                {
                    "type": "kdf",
                    "worker_id": kdf_type,
                    "kdf_type": kdf_type,
                    "kdf_config": kdf_config_section[kdf_type],
                }
            )

    if not tasks:
        raise ValueError("No algorithms enabled for key derivation")

    if debug:
        eprint(f"DEBUG: {len(tasks)} tasks to execute in parallel")

    # Create progress queue (using Manager for cross-process sharing)
    ctx = mp.get_context("spawn")
    manager = ctx.Manager()
    progress_queue = manager.Queue()

    # Start progress aggregator thread
    aggregator = ParallelProgressAggregator(progress_queue, len(tasks), quiet, progress)
    aggregator_thread = threading.Thread(target=aggregator.run, daemon=True)
    aggregator_thread.start()

    # Execute tasks in parallel
    results = {}
    max_workers = max_workers or min(len(tasks), mp.cpu_count())

    try:
        with ProcessPoolExecutor(max_workers=max_workers, mp_context=ctx) as executor:
            futures = {}

            for task in tasks:
                if task["type"] == "hash":
                    future = executor.submit(
                        _hash_worker,
                        task["worker_id"],
                        initial_hash,
                        salt,
                        task["algorithm"],
                        task["rounds"],
                        key_length,
                        progress_queue,
                        1000,  # report_interval
                        debug,
                    )
                else:  # KDF
                    future = executor.submit(
                        _kdf_worker,
                        task["worker_id"],
                        initial_hash,
                        salt,
                        task["kdf_type"],
                        task["kdf_config"],
                        key_length,
                        progress_queue,
                        debug,
                    )
                futures[future] = task["worker_id"]

            # Collect results as they complete
            for future in as_completed(futures):
                worker_id = futures[future]
                try:
                    name, result_bytes = future.result()
                    results[name] = result_bytes
                except Exception as e:
                    if debug:
                        eprint(f"DEBUG: Worker {worker_id} failed: {e}")
                    raise

    finally:
        # Stop aggregator
        aggregator.stop_event.set()
        aggregator_thread.join(timeout=1.0)

        # Clear progress line
        if progress and not quiet:
            eprint(f"\r{' ' * 100}\r", end="", flush=True)

    # Convert results to SecureBytes and XOR
    xor_components = []

    try:
        # Add initial hash component (first XOR component)
        initial_normalized = crypt_core.normalize_to_key_length_secure(initial_hash, key_length)
        xor_components.append(initial_normalized)

        if debug:
            eprint(f"DEBUG: Initial component: {bytes(initial_normalized).hex()[:32]}")

        # Add parallel results in deterministic order (task submission order)
        for task in tasks:
            worker_id = task["worker_id"]
            if worker_id in results:
                result_bytes = results[worker_id]
                xor_components.append(SecureBytes(result_bytes))
                if debug:
                    eprint(f"DEBUG: {worker_id} component: {result_bytes.hex()[:32]}")

        if debug:
            eprint(f"DEBUG: Collected {len(xor_components)} components, performing XOR")

        # XOR all components together
        final_key = crypt_core.xor_bytes_secure(xor_components)

        if not quiet:
            # Calculate rough time savings estimate
            parallel_time = (
                max(aggregator.completed_times.values()) if aggregator.completed_times else 0
            )
            sequential_estimate = (
                sum(aggregator.completed_times.values()) if aggregator.completed_times else 0
            )

            eprint(
                f"✅ Combined {len(xor_components)} independent components using XOR (Massey) "
                f"[{parallel_time:.1f}s parallel, ~{sequential_estimate:.1f}s sequential estimate]"
            )

        # Generate IV
        iv = os.urandom(16)

        # Apply algorithm-specific key formatting
        final_key_bytes = bytes(final_key)

        if algorithm == "fernet":
            final_key_bytes = base64.urlsafe_b64encode(final_key_bytes)
        elif algorithm in [
            "aes-256-gcm",
            "aes-gcm",
            "aes-gcm-siv",
            "chacha20-poly1305",
            "xchacha20-poly1305",
            "ml-kem-512-hybrid",
            "ml-kem-768-hybrid",
            "ml-kem-1024-hybrid",
            "ml-kem-512-chacha20",
            "ml-kem-768-chacha20",
            "ml-kem-1024-chacha20",
            "hqc-128-hybrid",
            "hqc-192-hybrid",
            "hqc-256-hybrid",
            "mayo-1-hybrid",
            "mayo-3-hybrid",
            "mayo-5-hybrid",
            "cross-128-hybrid",
            "cross-192-hybrid",
            "cross-256-hybrid",
        ]:
            final_key_bytes = hashlib.sha256(final_key_bytes).digest()
        elif algorithm == "aes-siv":
            final_key_bytes = hashlib.sha512(final_key_bytes).digest()
        elif algorithm in ["threefish-512", "threefish-1024"]:
            from cryptography.hazmat.backends import default_backend
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.kdf.hkdf import HKDF

            if algorithm == "threefish-512":
                hkdf = HKDF(
                    algorithm=hashes.SHA256(),
                    length=64,
                    salt=salt,
                    info=b"threefish-512-key-expansion",
                    backend=default_backend(),
                )
                final_key_bytes = hkdf.derive(final_key_bytes)
            else:  # threefish-1024
                hkdf = HKDF(
                    algorithm=hashes.SHA256(),
                    length=128,
                    salt=salt,
                    info=b"threefish-1024-key-expansion",
                    backend=default_backend(),
                )
                final_key_bytes = hkdf.derive(final_key_bytes)
        elif algorithm == "cascade":
            pass  # Cascade uses raw key
        else:
            # Default: base64 encode
            final_key_bytes = base64.b64encode(hashlib.sha256(final_key_bytes).digest())

        return final_key_bytes, salt, iv

    finally:
        # CRITICAL: Zero all intermediate components
        for component in xor_components:
            try:
                secure_memzero(component)
            except Exception:
                pass
        if "final_key" in locals():
            try:
                secure_memzero(final_key)
            except Exception:
                pass
        if "initial_hash" in locals():
            try:
                secure_memzero(bytearray(initial_hash))
            except Exception:
                pass
        # Zero results dict
        for result_bytes in results.values():
            try:
                secure_memzero(bytearray(result_bytes))
            except Exception:
                pass
