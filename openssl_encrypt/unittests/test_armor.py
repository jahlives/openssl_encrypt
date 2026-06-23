#!/usr/bin/env python3
"""
Unit tests for the ASCII-armor transport codec (openssl_encrypt.modules.armor).

ASCII armor wraps the binary encrypted-file output in a PEM-style Base64
envelope so ciphertext survives email, chat, YAML and copy-paste. The codec
is a pure transport wrapper: it MUST be byte-exact reversible
(``dearmor(armor(x)) == x`` for every byte string ``x``) and MUST detect
paste truncation/corruption via an OpenPGP-style CRC-24 checksum.

Test classes:
- TestArmorRoundTrip:   byte-exact reversibility across many inputs
- TestArmorFormat:      envelope structure (markers, line width, CRC line)
- TestArmorDetection:   is_armored() content detection
- TestDearmorRobustness: tolerant parsing (CRLF, whitespace, headers)
- TestDearmorRejection: adversarial / corrupted input is rejected
- TestArmorFileHelpers: file-level convenience helpers
"""

import os
import shutil
import tempfile
import unittest

from openssl_encrypt.modules.armor import (
    ARMOR_BEGIN,
    ARMOR_END,
    LINE_WIDTH,
    ArmorError,
    armor,
    armor_file,
    dearmor,
    dearmor_file,
    is_armored,
    is_armored_file,
)


class TestArmorRoundTrip(unittest.TestCase):
    """armor()/dearmor() must be byte-exact reversible for all inputs."""

    def _roundtrip(self, data: bytes) -> None:
        wrapped = armor(data)
        self.assertIsInstance(wrapped, bytes)
        self.assertEqual(dearmor(wrapped), data)

    def test_roundtrip_empty(self):
        self._roundtrip(b"")

    def test_roundtrip_single_byte(self):
        self._roundtrip(b"\x00")
        self._roundtrip(b"\xff")

    def test_roundtrip_small_text(self):
        self._roundtrip(b"Hello, world!")

    def test_roundtrip_all_byte_values(self):
        self._roundtrip(bytes(range(256)))

    def test_roundtrip_large_random(self):
        self._roundtrip(os.urandom(100_003))  # non-multiple-of-3 length

    def test_roundtrip_native_file_format(self):
        """The native output is ``b64(metadata):b64(data)`` with a colon."""
        self._roundtrip(b"eyJmb3JtYXQiOjEwfQ==:3q2+7w==")

    def test_roundtrip_lengths_around_line_boundary(self):
        for n in range(0, 200):
            self._roundtrip(os.urandom(n))


class TestArmorFormat(unittest.TestCase):
    """The armored envelope structure."""

    def setUp(self):
        self.data = os.urandom(500)
        self.wrapped = armor(self.data)

    def test_starts_with_begin_marker(self):
        self.assertTrue(self.wrapped.startswith(ARMOR_BEGIN))

    def test_contains_end_marker(self):
        self.assertIn(ARMOR_END, self.wrapped)
        self.assertTrue(self.wrapped.rstrip(b"\n").endswith(ARMOR_END))

    def test_body_line_width(self):
        """Base64 body lines must not exceed LINE_WIDTH characters."""
        lines = self.wrapped.split(b"\n")
        body = [
            ln
            for ln in lines
            if ln and ln not in (ARMOR_BEGIN, ARMOR_END) and not ln.startswith(b"=")
        ]
        for ln in body:
            self.assertLessEqual(len(ln), LINE_WIDTH)

    def test_has_crc_line(self):
        """A CRC-24 line ``=XXXX`` (1 + 4 base64 chars) precedes END."""
        lines = self.wrapped.rstrip(b"\n").split(b"\n")
        # CRC line is the last line before the END marker.
        self.assertEqual(lines[-1], ARMOR_END)
        crc_line = lines[-2]
        self.assertTrue(crc_line.startswith(b"="))
        self.assertEqual(len(crc_line), 5)

    def test_armor_is_deterministic(self):
        self.assertEqual(armor(self.data), armor(self.data))

    def test_output_is_ascii(self):
        self.wrapped.decode("ascii")  # must not raise


class TestArmorDetection(unittest.TestCase):
    """is_armored() content detection."""

    def test_detects_armored(self):
        self.assertTrue(is_armored(armor(b"payload")))

    def test_detects_armored_with_leading_whitespace(self):
        self.assertTrue(is_armored(b"\n\n  " + armor(b"payload")))

    def test_rejects_binary(self):
        self.assertFalse(is_armored(os.urandom(64)))

    def test_rejects_native_format(self):
        self.assertFalse(is_armored(b"eyJmb3JtYXQiOjEwfQ==:3q2+7w=="))

    def test_rejects_empty(self):
        self.assertFalse(is_armored(b""))


class TestDearmorRobustness(unittest.TestCase):
    """dearmor() must tolerate benign transport mangling."""

    def setUp(self):
        self.data = os.urandom(300)
        self.wrapped = armor(self.data)

    def test_tolerates_crlf_line_endings(self):
        crlf = self.wrapped.replace(b"\n", b"\r\n")
        self.assertEqual(dearmor(crlf), self.data)

    def test_tolerates_surrounding_whitespace(self):
        padded = b"\n\n\t" + self.wrapped + b"\n  \n"
        self.assertEqual(dearmor(padded), self.data)

    def test_tolerates_optional_headers(self):
        """Forward-compat: header lines + blank line after BEGIN are skipped."""
        injected = self.wrapped.replace(
            ARMOR_BEGIN + b"\n",
            ARMOR_BEGIN + b"\nVersion: openssl-encrypt 9.9\nComment: hi\n\n",
            1,
        )
        self.assertEqual(dearmor(injected), self.data)

    def test_accepts_str_input(self):
        """dearmor() should accept text (str) as well as bytes."""
        self.assertEqual(dearmor(self.wrapped.decode("ascii")), self.data)


class TestDearmorRejection(unittest.TestCase):
    """Adversarial / corrupted input must raise ArmorError, never silently pass."""

    def setUp(self):
        self.data = os.urandom(300)
        self.wrapped = armor(self.data)

    def test_missing_begin_marker(self):
        with self.assertRaises(ArmorError):
            dearmor(self.wrapped.replace(ARMOR_BEGIN, b"-----BEGIN NONSENSE-----"))

    def test_missing_end_marker(self):
        with self.assertRaises(ArmorError):
            dearmor(self.wrapped.replace(b"\n" + ARMOR_END, b""))

    def test_truncated_body_detected_by_crc(self):
        """Dropping a body line corrupts the payload; CRC must catch it."""
        lines = self.wrapped.split(b"\n")
        # Remove a middle body line (index 1 is the first body line).
        del lines[1]
        with self.assertRaises(ArmorError):
            dearmor(b"\n".join(lines))

    def test_flipped_base64_char_detected(self):
        b = bytearray(self.wrapped)
        # Flip a character on the first body line (after BEGIN + newline).
        pos = len(ARMOR_BEGIN) + 1
        b[pos] = b"A"[0] if b[pos] != b"A"[0] else b"B"[0]
        with self.assertRaises(ArmorError):
            dearmor(bytes(b))

    def test_non_base64_garbage_in_body(self):
        injected = self.wrapped.replace(
            ARMOR_BEGIN + b"\n", ARMOR_BEGIN + b"\n!!!! not b64 !!!!\n", 1
        )
        with self.assertRaises(ArmorError):
            dearmor(injected)

    def test_plain_binary_rejected(self):
        with self.assertRaises(ArmorError):
            dearmor(os.urandom(64))


class TestArmorFileHelpers(unittest.TestCase):
    """File-level convenience helpers used by the CLI wiring."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _write(self, name, data):
        p = os.path.join(self.tmp, name)
        with open(p, "wb") as f:
            f.write(data)
        return p

    def test_armor_file_in_place_roundtrip(self):
        data = os.urandom(2048)
        p = self._write("blob.enc", data)
        armor_file(p)
        with open(p, "rb") as f:
            on_disk = f.read()
        self.assertTrue(is_armored(on_disk))
        self.assertEqual(dearmor(on_disk), data)

    def test_is_armored_file(self):
        binp = self._write("bin", os.urandom(128))
        armp = self._write("arm", armor(os.urandom(128)))
        self.assertFalse(is_armored_file(binp))
        self.assertTrue(is_armored_file(armp))

    def test_dearmor_file_returns_bytes(self):
        data = os.urandom(777)
        p = self._write("arm.enc", armor(data))
        self.assertEqual(dearmor_file(p), data)


if __name__ == "__main__":
    unittest.main()
