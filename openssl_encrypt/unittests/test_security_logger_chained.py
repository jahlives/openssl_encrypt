#!/usr/bin/env python3
"""
Integration tests for chained mode in SecurityAuditLogger.

Verifies that:
  * Chain mode is opt-in (env var or constructor arg) and default-off.
  * Chain fields are added to every event in chained mode and absent otherwise.
  * Concurrent writes produce a chain that the offline verifier accepts.
  * Legacy unchained logs are archived on first chained init.
  * clear_logs() refuses without break_glass=True in chained mode.
  * Restarting the logger reuses the persisted seed and resumes the chain.
"""

import json
import os
import shutil
import tempfile
import threading
import unittest
from pathlib import Path


def _reset_singleton():
    """Drop the SecurityAuditLogger singleton between tests."""
    from openssl_encrypt.modules import security_logger as sl

    sl.SecurityAuditLogger._instance = None
    sl._security_logger = None


class _ChainEnv:
    """Context manager that clears chain-related env vars during a test."""

    _VARS = (
        "OPENSSL_ENCRYPT_AUDIT_CHAIN",
        "OPENSSL_ENCRYPT_AUDIT_SEED_FILE",
        "OPENSSL_ENCRYPT_DISABLE_AUDIT_LOG",
    )

    def __init__(self, **overrides):
        self.overrides = overrides
        self.saved = {}

    def __enter__(self):
        for var in self._VARS:
            self.saved[var] = os.environ.pop(var, None)
        for var, value in self.overrides.items():
            os.environ[var] = value
        return self

    def __exit__(self, *args):
        for var in self._VARS:
            os.environ.pop(var, None)
        for var, value in self.saved.items():
            if value is not None:
                os.environ[var] = value


class _BaseChainedLoggerTest(unittest.TestCase):
    def setUp(self):
        _reset_singleton()
        self.dir = tempfile.mkdtemp()

    def tearDown(self):
        _reset_singleton()
        shutil.rmtree(self.dir, ignore_errors=True)

    def _read_log_lines(self, path=None):
        path = Path(path or (Path(self.dir) / "security-audit.log"))
        if not path.exists():
            return []
        with open(path, "r", encoding="utf-8") as f:
            return [json.loads(line) for line in f if line.strip()]


class TestChainOptIn(_BaseChainedLoggerTest):
    def test_chain_disabled_by_default(self):
        from openssl_encrypt.modules.security_logger import SecurityAuditLogger

        with _ChainEnv():
            logger = SecurityAuditLogger(log_dir=self.dir, enabled=True)
            self.assertFalse(getattr(logger, "chain_enabled", False))
            logger.log_event("evt", "info", {"k": "v"})
            events = self._read_log_lines()
            self.assertEqual(len(events), 1)
            self.assertNotIn("seq", events[0])
            self.assertNotIn("mac", events[0])

    def test_chain_enabled_via_env_var(self):
        from openssl_encrypt.modules.security_logger import SecurityAuditLogger

        with _ChainEnv(OPENSSL_ENCRYPT_AUDIT_CHAIN="1"):
            logger = SecurityAuditLogger(log_dir=self.dir, enabled=True)
            self.assertTrue(logger.chain_enabled)
            logger.log_event("evt", "info", {"k": "v"})
            events = self._read_log_lines()
            self.assertEqual(events[0]["seq"], 0)
            self.assertIn("mac", events[0])
            self.assertIn("prev_hash", events[0])

    def test_chain_enabled_via_constructor_arg(self):
        from openssl_encrypt.modules.security_logger import SecurityAuditLogger

        with _ChainEnv():
            logger = SecurityAuditLogger(log_dir=self.dir, enabled=True, chain_enabled=True)
            self.assertTrue(logger.chain_enabled)
            logger.log_event("evt", "info", {"k": "v"})
            events = self._read_log_lines()
            self.assertEqual(events[0]["seq"], 0)


class TestChainedWriteShape(_BaseChainedLoggerTest):
    def test_existing_call_sites_unaffected_by_chain(self):
        """log_event signature unchanged; chain fields are additive."""
        from openssl_encrypt.modules.security_logger import SecurityAuditLogger

        with _ChainEnv(OPENSSL_ENCRYPT_AUDIT_CHAIN="1"):
            logger = SecurityAuditLogger(log_dir=self.dir, enabled=True)
            logger.log_event(
                "encryption_started",
                "info",
                {"algorithm": "aes-256-gcm", "file_count": 1, "password": "secret"},
            )
            events = self._read_log_lines()
            evt = events[0]
            # Existing fields preserved.
            self.assertEqual(evt["event_type"], "encryption_started")
            self.assertEqual(evt["severity"], "info")
            self.assertEqual(evt["details"]["algorithm"], "aes-256-gcm")
            # Sensitive redaction still works.
            self.assertEqual(evt["details"]["password"], "***REDACTED***")
            # Chain fields added.
            self.assertEqual(evt["seq"], 0)
            self.assertIn("mac", evt)

    def test_seq_increments_across_calls(self):
        from openssl_encrypt.modules.security_logger import SecurityAuditLogger

        with _ChainEnv(OPENSSL_ENCRYPT_AUDIT_CHAIN="1"):
            logger = SecurityAuditLogger(log_dir=self.dir, enabled=True)
            for i in range(5):
                logger.log_event(f"e{i}", "info")
            events = self._read_log_lines()
            self.assertEqual([e["seq"] for e in events], [0, 1, 2, 3, 4])

    def test_chain_verifies_against_offline_verifier(self):
        from openssl_encrypt.modules.audit_verifier import verify_chain
        from openssl_encrypt.modules.security_logger import SecurityAuditLogger

        with _ChainEnv(OPENSSL_ENCRYPT_AUDIT_CHAIN="1"):
            logger = SecurityAuditLogger(log_dir=self.dir, enabled=True)
            for i in range(20):
                logger.log_event(f"e{i}", "info", {"i": i})

            seed = logger._read_seed()
            log_path = Path(self.dir) / "security-audit.log"
            report = verify_chain(log_path, seed=seed)
            self.assertTrue(report.intact, msg=str(report.failures))
            self.assertEqual(report.records_verified, 20)


class TestSeedPersistence(_BaseChainedLoggerTest):
    def test_seed_file_is_owner_only_perms(self):
        from openssl_encrypt.modules.security_logger import SecurityAuditLogger

        with _ChainEnv(OPENSSL_ENCRYPT_AUDIT_CHAIN="1"):
            logger = SecurityAuditLogger(log_dir=self.dir, enabled=True)
            logger.log_event("e", "info")

            seed_file = Path(self.dir) / "audit-seed.bin"
            self.assertTrue(seed_file.exists())
            mode = seed_file.stat().st_mode & 0o777
            self.assertEqual(mode, 0o600, oct(mode))

    def test_seed_persisted_across_logger_instances(self):
        from openssl_encrypt.modules.security_logger import SecurityAuditLogger

        with _ChainEnv(OPENSSL_ENCRYPT_AUDIT_CHAIN="1"):
            logger1 = SecurityAuditLogger(log_dir=self.dir, enabled=True)
            logger1.log_event("e1", "info")
            seed1 = bytes(logger1._read_seed())

            _reset_singleton()

            logger2 = SecurityAuditLogger(log_dir=self.dir, enabled=True)
            logger2.log_event("e2", "info")
            seed2 = bytes(logger2._read_seed())

            self.assertEqual(seed1, seed2)
            events = self._read_log_lines()
            # Second instance must continue at seq=1 (chain not reset).
            self.assertEqual([e["seq"] for e in events], [0, 1])

    def test_state_file_is_owner_only_perms(self):
        from openssl_encrypt.modules.security_logger import SecurityAuditLogger

        with _ChainEnv(OPENSSL_ENCRYPT_AUDIT_CHAIN="1"):
            logger = SecurityAuditLogger(log_dir=self.dir, enabled=True)
            logger.log_event("e", "info")
            state_file = Path(self.dir) / "audit-state.json"
            self.assertTrue(state_file.exists())
            mode = state_file.stat().st_mode & 0o777
            self.assertEqual(mode, 0o600, oct(mode))


class TestLegacyMigration(_BaseChainedLoggerTest):
    def test_legacy_log_archived_on_first_chained_init(self):
        from openssl_encrypt.modules.security_logger import SecurityAuditLogger

        # Pre-create a non-chained log.
        log_path = Path(self.dir) / "security-audit.log"
        with open(log_path, "w", encoding="utf-8") as f:
            f.write(json.dumps({"event_type": "old", "severity": "info"}) + "\n")

        with _ChainEnv(OPENSSL_ENCRYPT_AUDIT_CHAIN="1"):
            logger = SecurityAuditLogger(log_dir=self.dir, enabled=True)
            logger.log_event("new", "info")

            # Old log should be archived.
            legacy = Path(self.dir) / "security-audit.log.legacy"
            self.assertTrue(legacy.exists(), "legacy log not archived")
            with open(legacy, "r", encoding="utf-8") as f:
                self.assertIn("old", f.read())

            # New log should start fresh chained at seq=0.
            events = self._read_log_lines()
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0]["event_type"], "new")
            self.assertEqual(events[0]["seq"], 0)

    def test_already_chained_log_not_archived(self):
        from openssl_encrypt.modules.audit_chain import ChainState
        from openssl_encrypt.modules.security_logger import SecurityAuditLogger

        # Pre-write an already-chained record. Use a known seed so the
        # logger reuses it instead of archiving and starting fresh.
        seed = b"\x42" * 32
        seed_path = Path(self.dir) / "audit-seed.bin"
        os.makedirs(self.dir, mode=0o700, exist_ok=True)
        fd = os.open(str(seed_path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.write(fd, seed)
        os.close(fd)

        state = ChainState.initial(seed=seed)
        record = state.append_record({"event_type": "pre", "severity": "info"})
        log_path = Path(self.dir) / "security-audit.log"
        with open(log_path, "w", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")
        state.save_atomic(Path(self.dir) / "audit-state.json")

        with _ChainEnv(OPENSSL_ENCRYPT_AUDIT_CHAIN="1"):
            logger = SecurityAuditLogger(log_dir=self.dir, enabled=True)
            logger.log_event("new", "info")

            # No .legacy archive should appear.
            self.assertFalse((Path(self.dir) / "security-audit.log.legacy").exists())
            events = self._read_log_lines()
            self.assertEqual([e["seq"] for e in events], [0, 1])


class TestClearLogsBreakGlass(_BaseChainedLoggerTest):
    def test_clear_logs_refused_without_break_glass(self):
        from openssl_encrypt.modules.security_logger import SecurityAuditLogger

        with _ChainEnv(OPENSSL_ENCRYPT_AUDIT_CHAIN="1"):
            logger = SecurityAuditLogger(log_dir=self.dir, enabled=True)
            logger.log_event("e", "info")
            with self.assertRaises(PermissionError):
                logger.clear_logs()

    def test_clear_logs_with_break_glass_resets_chain(self):
        from openssl_encrypt.modules.security_logger import SecurityAuditLogger

        with _ChainEnv(OPENSSL_ENCRYPT_AUDIT_CHAIN="1"):
            logger = SecurityAuditLogger(log_dir=self.dir, enabled=True)
            logger.log_event("e1", "info")
            logger.log_event("e2", "info")

            self.assertTrue(logger.clear_logs(break_glass=True))

            log_path = Path(self.dir) / "security-audit.log"
            self.assertFalse(log_path.exists())

            # Subsequent event starts a fresh chain at seq=0.
            logger.log_event("e3", "info")
            events = self._read_log_lines()
            self.assertEqual([e["seq"] for e in events], [0])

    def test_clear_logs_unchanged_in_non_chained_mode(self):
        from openssl_encrypt.modules.security_logger import SecurityAuditLogger

        with _ChainEnv():
            logger = SecurityAuditLogger(log_dir=self.dir, enabled=True)
            logger.log_event("e", "info")
            self.assertTrue(logger.clear_logs())
            self.assertFalse((Path(self.dir) / "security-audit.log").exists())


class TestConcurrentWrites(_BaseChainedLoggerTest):
    def test_concurrent_writes_intact_chain(self):
        from openssl_encrypt.modules.audit_verifier import verify_chain
        from openssl_encrypt.modules.security_logger import SecurityAuditLogger

        with _ChainEnv(OPENSSL_ENCRYPT_AUDIT_CHAIN="1"):
            logger = SecurityAuditLogger(log_dir=self.dir, enabled=True)

            num_threads = 8
            events_per_thread = 50

            def worker(tid):
                for i in range(events_per_thread):
                    logger.log_event(f"t{tid}_e{i}", "info", {"tid": tid, "i": i})

            threads = [threading.Thread(target=worker, args=(t,)) for t in range(num_threads)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

            seed = logger._read_seed()
            report = verify_chain(Path(self.dir) / "security-audit.log", seed=seed)
            self.assertTrue(report.intact, msg=str(report.failures[:5]))
            self.assertEqual(report.records_verified, num_threads * events_per_thread)


class TestSeedFileOverride(_BaseChainedLoggerTest):
    def test_seed_file_path_override_via_env(self):
        from openssl_encrypt.modules.security_logger import SecurityAuditLogger

        custom_seed_file = Path(self.dir) / "custom-seed.bin"
        with _ChainEnv(
            OPENSSL_ENCRYPT_AUDIT_CHAIN="1",
            OPENSSL_ENCRYPT_AUDIT_SEED_FILE=str(custom_seed_file),
        ):
            logger = SecurityAuditLogger(log_dir=self.dir, enabled=True)
            logger.log_event("e", "info")
            self.assertTrue(custom_seed_file.exists())
            self.assertFalse((Path(self.dir) / "audit-seed.bin").exists())


if __name__ == "__main__":
    unittest.main()
