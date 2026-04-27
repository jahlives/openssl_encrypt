#!/usr/bin/env python3
"""
Tests for the offline audit-chain verifier.

The verifier walks a list of log files (oldest → newest, supporting rotation)
and asserts:
  * sequence numbers form a contiguous run starting at the expected first seq;
  * each record's prev_hash equals BLAKE2b-256 of the prior record's canonical
    encoding;
  * each record's HMAC verifies under the seq-indexed forward-secure key
    derived from the seed;
  * if the optional ``ChainState`` is supplied, the most recent seq matches
    (catches tail-truncation between anchors).
"""

import json
import shutil
import tempfile
import unittest
from pathlib import Path


def _write_records(path: Path, records):
    with open(path, "w", encoding="utf-8") as f:
        for rec in records:
            f.write(json.dumps(rec) + "\n")


class _ChainHarness(unittest.TestCase):
    """Helpers for emitting a synthetic intact chain into a temp directory."""

    def setUp(self):
        from openssl_encrypt.modules.audit_chain import ChainState

        self.dir = Path(tempfile.mkdtemp())
        self.seed = b"\x01" * 32
        self.state = ChainState.initial(seed=self.seed)
        self.records = []

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def _emit(self, n):
        for i in range(n):
            self.records.append(
                self.state.append_record({"event_type": f"e{i}", "severity": "info"})
            )

    def _flush(self, path):
        _write_records(path, self.records)


class TestVerifierHappyPath(_ChainHarness):
    def test_intact_chain_verifies_clean(self):
        from openssl_encrypt.modules.audit_verifier import verify_chain

        self._emit(10)
        log = self.dir / "security-audit.log"
        self._flush(log)

        report = verify_chain(log, seed=self.seed)
        self.assertTrue(report.intact, msg=str(report.failures))
        self.assertEqual(report.records_verified, 10)
        self.assertEqual(report.first_seq, 0)
        self.assertEqual(report.last_seq, 9)
        self.assertEqual(report.failures, [])

    def test_empty_log_returns_intact_zero_records(self):
        from openssl_encrypt.modules.audit_verifier import verify_chain

        log = self.dir / "security-audit.log"
        log.write_text("", encoding="utf-8")

        report = verify_chain(log, seed=self.seed)
        self.assertTrue(report.intact)
        self.assertEqual(report.records_verified, 0)

    def test_chain_spans_rotated_log_files(self):
        """Verifier accepts an ordered list of files; chain crosses boundary."""
        from openssl_encrypt.modules.audit_verifier import verify_chain

        self._emit(20)
        rotated = self.dir / "security-audit.log.1"
        current = self.dir / "security-audit.log"
        _write_records(rotated, self.records[:12])
        _write_records(current, self.records[12:])

        report = verify_chain([rotated, current], seed=self.seed)
        self.assertTrue(report.intact, msg=str(report.failures))
        self.assertEqual(report.records_verified, 20)
        self.assertEqual(report.last_seq, 19)


class TestVerifierTamperDetection(_ChainHarness):
    def test_modified_record_detected_at_correct_seq(self):
        from openssl_encrypt.modules.audit_verifier import verify_chain

        self._emit(10)
        # Tamper with record at seq=5.
        self.records[5]["event_type"] = "tampered"
        log = self.dir / "security-audit.log"
        self._flush(log)

        report = verify_chain(log, seed=self.seed)
        self.assertFalse(report.intact)
        self.assertTrue(report.failures)
        self.assertEqual(report.failures[0].seq, 5)
        self.assertEqual(report.failures[0].reason, "mac_mismatch")

    def test_modified_mac_detected_via_prev_hash(self):
        """Swapping just the MAC must break the next record's prev_hash."""
        from openssl_encrypt.modules.audit_verifier import verify_chain

        self._emit(10)
        bad_mac = "hmac-sha256:" + "f" * 64
        self.records[3]["mac"] = bad_mac
        log = self.dir / "security-audit.log"
        self._flush(log)

        report = verify_chain(log, seed=self.seed)
        self.assertFalse(report.intact)
        self.assertEqual(report.failures[0].seq, 3)
        # Either mac_mismatch (caught directly) or prev_hash_mismatch on seq=4.
        self.assertIn(report.failures[0].reason, {"mac_mismatch", "prev_hash_mismatch"})

    def test_deleted_record_detected_as_gap(self):
        from openssl_encrypt.modules.audit_verifier import verify_chain

        self._emit(10)
        del self.records[4]
        log = self.dir / "security-audit.log"
        self._flush(log)

        report = verify_chain(log, seed=self.seed)
        self.assertFalse(report.intact)
        # First failure is at the gap (the record that was supposed to be seq=4).
        self.assertEqual(report.failures[0].seq, 4)
        self.assertIn(report.failures[0].reason, {"seq_gap", "prev_hash_mismatch"})

    def test_reordered_records_detected(self):
        from openssl_encrypt.modules.audit_verifier import verify_chain

        self._emit(10)
        self.records[3], self.records[4] = self.records[4], self.records[3]
        log = self.dir / "security-audit.log"
        self._flush(log)

        report = verify_chain(log, seed=self.seed)
        self.assertFalse(report.intact)
        self.assertEqual(report.failures[0].seq, 3)

    def test_wrong_seed_fails_all_macs(self):
        from openssl_encrypt.modules.audit_verifier import verify_chain

        self._emit(5)
        log = self.dir / "security-audit.log"
        self._flush(log)

        report = verify_chain(log, seed=b"\x99" * 32)
        self.assertFalse(report.intact)
        self.assertEqual(report.failures[0].seq, 0)
        self.assertEqual(report.failures[0].reason, "mac_mismatch")


class TestVerifierTailTruncation(_ChainHarness):
    def test_truncated_tail_detected_via_state_file(self):
        """If state says current_seq=10 but log only has 7 records, flag it."""
        from openssl_encrypt.modules.audit_verifier import verify_chain

        self._emit(10)
        log = self.dir / "security-audit.log"
        # Persist state *before* truncating the log on disk.
        state_snapshot = self.state
        # Simulate truncation: only flush first 7 records.
        truncated_records = self.records[:7]
        with open(log, "w", encoding="utf-8") as f:
            for rec in truncated_records:
                f.write(json.dumps(rec) + "\n")

        report = verify_chain(log, seed=self.seed, state=state_snapshot)
        self.assertFalse(report.intact)
        # Should report tail_truncated, identifying the missing window.
        truncation_failures = [f for f in report.failures if f.reason == "tail_truncated"]
        self.assertTrue(truncation_failures, msg=str(report.failures))
        # The expected next seq from state is 10; last seen seq is 6.
        self.assertEqual(truncation_failures[0].seq, 7)

    def test_state_matches_log_tail_no_failure(self):
        from openssl_encrypt.modules.audit_verifier import verify_chain

        self._emit(10)
        log = self.dir / "security-audit.log"
        self._flush(log)

        report = verify_chain(log, seed=self.seed, state=self.state)
        self.assertTrue(report.intact, msg=str(report.failures))


class TestVerifierStructuralErrors(_ChainHarness):
    def test_invalid_json_line_reported(self):
        from openssl_encrypt.modules.audit_verifier import verify_chain

        self._emit(3)
        log = self.dir / "security-audit.log"
        with open(log, "w", encoding="utf-8") as f:
            f.write(json.dumps(self.records[0]) + "\n")
            f.write("this is not json\n")
            f.write(json.dumps(self.records[1]) + "\n")

        report = verify_chain(log, seed=self.seed)
        self.assertFalse(report.intact)
        self.assertEqual(report.failures[0].reason, "decode_error")

    def test_missing_chain_fields_reported(self):
        from openssl_encrypt.modules.audit_verifier import verify_chain

        self._emit(3)
        # Strip required chain fields from one record.
        del self.records[1]["mac"]
        log = self.dir / "security-audit.log"
        self._flush(log)

        report = verify_chain(log, seed=self.seed)
        self.assertFalse(report.intact)
        self.assertEqual(report.failures[0].reason, "missing_field")
        self.assertEqual(report.failures[0].seq, 1)


class _ChainEnv:
    """Minimal env helper duplicated here to keep this test file self-contained."""

    _VARS = (
        "OPENSSL_ENCRYPT_AUDIT_CHAIN",
        "OPENSSL_ENCRYPT_AUDIT_SEED_FILE",
        "OPENSSL_ENCRYPT_AUDIT_ANCHOR_INTERVAL",
        "OPENSSL_ENCRYPT_DISABLE_AUDIT_LOG",
    )

    def __init__(self, **overrides):
        self.overrides = overrides
        self.saved = {}

    def __enter__(self):
        import os

        for var in self._VARS:
            self.saved[var] = os.environ.pop(var, None)
        for var, value in self.overrides.items():
            os.environ[var] = value
        return self

    def __exit__(self, *args):
        import os

        for var in self._VARS:
            os.environ.pop(var, None)
        for var, value in self.saved.items():
            if value is not None:
                os.environ[var] = value


def _reset_security_logger_singleton():
    from openssl_encrypt.modules import security_logger as sl

    sl.SecurityAuditLogger._instance = None
    sl._security_logger = None


class TestVerifierWithAnchors(unittest.TestCase):
    """End-to-end: chained logger with anchors → offline verifier accepts."""

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        _reset_security_logger_singleton()

    def tearDown(self):
        _reset_security_logger_singleton()
        shutil.rmtree(self.dir, ignore_errors=True)

    def _emit(self, count, anchor_interval=4):
        from openssl_encrypt.modules.security_logger import SecurityAuditLogger

        with _ChainEnv(
            OPENSSL_ENCRYPT_AUDIT_CHAIN="1",
            OPENSSL_ENCRYPT_AUDIT_ANCHOR_INTERVAL=str(anchor_interval),
        ):
            logger = SecurityAuditLogger(log_dir=str(self.dir), enabled=True)
            for i in range(count):
                logger.log_event(f"e{i}", "info", {"i": i})
            seed = logger._read_seed()
            pubkey = logger._anchor_pubkey
        return seed, pubkey

    def test_intact_chain_with_anchors_verifies(self):
        from openssl_encrypt.modules.audit_verifier import verify_chain

        seed, _ = self._emit(12, anchor_interval=4)
        report = verify_chain(self.dir / "security-audit.log", seed=seed)
        self.assertTrue(report.intact, msg=str(report.failures))

    def test_tampered_anchor_root_detected(self):
        from openssl_encrypt.modules.audit_verifier import verify_chain

        seed, _ = self._emit(8, anchor_interval=4)
        log_path = self.dir / "security-audit.log"
        lines = log_path.read_text(encoding="utf-8").splitlines()
        # Anchor record sits at seq=4 (index 4 in the line list).
        anchor = json.loads(lines[4])
        self.assertEqual(anchor["event_type"], "audit.anchor")
        anchor["details"]["merkle_root"] = "blake2b-256:" + "0" * 64
        # Recompute MAC so the chain itself is still intact — only the
        # *anchor* is tampered, isolating the failure to anchor verification.
        from openssl_encrypt.modules.audit_chain import (
            compute_record_mac,
            derive_initial_key,
            evolve_key,
        )

        key = derive_initial_key(seed)
        for _ in range(4):  # advance to K_4
            key = evolve_key(key)
        without_mac = {k: v for k, v in anchor.items() if k != "mac"}
        anchor["mac"] = compute_record_mac(without_mac, key)
        lines[4] = json.dumps(anchor)
        # Records after the anchor link via prev_hash to its content; we
        # also need to refresh those. Simpler: truncate to just the
        # tampered window so the verifier hits the anchor before any
        # downstream prev_hash mismatch.
        log_path.write_text("\n".join(lines[:5]) + "\n", encoding="utf-8")

        report = verify_chain(log_path, seed=seed)
        self.assertFalse(report.intact)
        self.assertEqual(report.failures[0].reason, "anchor_invalid")
        self.assertEqual(report.failures[0].seq, 4)

    def test_anchor_pubkey_pin_succeeds(self):
        from openssl_encrypt.modules.audit_verifier import verify_chain

        seed, pubkey = self._emit(8, anchor_interval=4)
        report = verify_chain(
            self.dir / "security-audit.log",
            seed=seed,
            anchor_pubkey=pubkey,
        )
        self.assertTrue(report.intact, msg=str(report.failures))

    def test_anchor_pubkey_pin_fails_with_wrong_pubkey(self):
        from openssl_encrypt.modules.audit_anchor import AnchorSigner
        from openssl_encrypt.modules.audit_verifier import verify_chain

        seed, _ = self._emit(8, anchor_interval=4)
        wrong_pubkey, _ = AnchorSigner().generate_keypair()
        report = verify_chain(
            self.dir / "security-audit.log",
            seed=seed,
            anchor_pubkey=wrong_pubkey,
        )
        self.assertFalse(report.intact)
        # First anchor sits at seq=4; pin mismatch reported there.
        anchor_failures = [f for f in report.failures if f.reason == "anchor_pubkey_mismatch"]
        self.assertTrue(anchor_failures, msg=str(report.failures))
        self.assertEqual(anchor_failures[0].seq, 4)


if __name__ == "__main__":
    unittest.main()
