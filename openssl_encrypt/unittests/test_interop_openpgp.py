#!/usr/bin/env python3
"""
Tests for read-only OpenPGP symmetric (`gpg -c`) decryption (feature #5, phase 2).

Functional coverage uses REAL fixtures produced by GnuPG 2.2.40 (committed under
testfiles/openpgp/), exercising multiple ciphers, compression algorithms, S2K
hashes, ASCII armor, and a 200 KB file (partial-length packets). Negative tests
cover wrong passphrase, MDC tamper, the unauthenticated SED packet (refused),
and non-OpenPGP input.
"""

import hashlib
import os
import random
import sys
import unittest

from openssl_encrypt.modules.interop.openpgp import (
    OpenPGPError,
    OpenPGPFormatError,
    OpenPGPIntegrityError,
    OpenPGPWrongPassphrase,
    decrypt,
    is_openpgp_file,
)

_PW = "correct horse battery"
_DIR = os.path.join(os.path.dirname(__file__), "testfiles", "openpgp")
_SMALL = b"hello openpgp symmetric world"
_BIG_SHA256 = "7b28964e0d878c2ca373f816ec9bf18864cb058901416419ac25a56864f35cd8"


def _load(name):
    with open(os.path.join(_DIR, name), "rb") as f:
        return f.read()


class TestOpenPGPReferenceVectors(unittest.TestCase):
    """Decrypt real GnuPG `gpg -c` output across ciphers / options."""

    def _check_small(self, name):
        self.assertEqual(decrypt(_load(name), passphrase=_PW), _SMALL)

    def test_default(self):
        self._check_small("v_default.gpg")  # AES-256 + compression + MDC

    def test_aes256(self):
        self._check_small("v_aes256.gpg")

    def test_aes128(self):
        self._check_small("v_aes128.gpg")

    def test_cast5(self):
        self._check_small("v_cast5.gpg")

    def test_3des(self):
        self._check_small("v_3des.gpg")

    def test_zlib_compression(self):
        self._check_small("v_zlib.gpg")

    def test_sha512_s2k(self):
        self._check_small("v_sha512.gpg")

    def test_ascii_armored(self):
        self.assertTrue(is_openpgp_file(_load("v_armored.asc")))
        self._check_small("v_armored.asc")

    def test_large_partial_lengths(self):
        pt = decrypt(_load("v_big.gpg"), passphrase=_PW)
        self.assertEqual(hashlib.sha256(pt).hexdigest(), _BIG_SHA256)


class TestOpenPGPRejection(unittest.TestCase):
    def test_wrong_passphrase(self):
        with self.assertRaises(OpenPGPWrongPassphrase):
            decrypt(_load("v_aes256.gpg"), passphrase="not the passphrase")

    def test_tampered_ciphertext(self):
        """Tamper must be reported AS tamper, not as a malformed message.

        This asserted only OpenPGPError, so a change that downgraded an
        integrity failure to a format error would have kept every test
        green -- and "this file is malformed" tells the user something
        materially different from "this file was modified". The byte flipped
        lands inside the MDC's SHA-1, past the CFB prefix the quick-check
        reads, so it is the MDC that fires.
        """
        data = bytearray(_load("v_aes256.gpg"))
        data[-8] ^= 0x01
        with self.assertRaises(OpenPGPIntegrityError):
            decrypt(bytes(data), passphrase=_PW)

    def test_sed_packet_refused(self):
        # A bare Symmetrically Encrypted Data packet (tag 9, no integrity).
        sed = bytes([0xA4, 0x01, 0x00])  # old-format tag 9, 1-byte body
        with self.assertRaises(OpenPGPFormatError):
            decrypt(sed, passphrase=_PW)

    def test_not_openpgp(self):
        """Deterministic inputs only.

        This used to assert `is_openpgp_file(os.urandom(64))` is False, which
        fails about one run in fifty (measured 1.97% over 200k draws): the
        detector accepts any first byte with bit 7 set whose packet tag is 3,
        which random data hits at 1/64 for the old packet format plus 1/256
        for the new one. A test that fails 2% of the time makes the
        baseline-vs-after comparison unreliable, so the randomness is gone
        (gitlab#196).
        """
        self.assertFalse(is_openpgp_file(b""))
        # Bit 7 clear -- not a packet tag byte at all.
        self.assertFalse(is_openpgp_file(b"\x00" + os.urandom(63)))
        self.assertFalse(is_openpgp_file(b"not an openpgp message"))
        # Bit 7 set, but a tag the detector must reject, in both formats.
        for ctb in (0x84, 0x88, 0xA4, 0xC1, 0xC9, 0xD2):
            self.assertFalse(
                is_openpgp_file(bytes([ctb]) + os.urandom(63)),
                f"control byte {ctb:#04x} was taken for an SKESK packet",
            )
        with self.assertRaises(OpenPGPError):
            decrypt(b"\x00" + os.urandom(63), passphrase=_PW)

    def test_malformed_input_always_raises_an_openpgp_error(self):
        """The module's documented taxonomy must hold for hostile input.

        decrypt() promises OpenPGPFormatError for a malformed message, but
        the packet reader indexed length fields and the S2K specifier
        without bounds checks, so a truncated or crafted packet escaped as a
        raw IndexError or struct.error. Callers catching OpenPGPError to
        report "not a valid OpenPGP file" got an unhandled traceback, on
        input that is untrusted by definition (gitlab#196).

        The corpus SPLICES the fixture's intact SEIPD packet behind each
        crafted SKESK. Without that, every blob died at the "no
        integrity-protected packet found" check, which sits above the SKESK
        parse -- so an earlier version of this test reached neither
        _s2k_derive nor three of the five length guards while appearing to
        cover them. Verified by tracing executed lines, not by reading it.
        """
        rng = random.Random(20260808)
        real = _load("v_aes256.gpg")
        seipd = real[15:]  # the tag-18 packet; the SKESK is real[:15]

        corpus = []
        # Truncated SKESK bodies, spliced in front of a valid SEIPD so the
        # parse gets far enough to reach the S2K specifier.
        for length in range(0, 14):
            corpus.append(bytes([0x8C, length]) + real[2 : 2 + length] + seipd)
        # Every S2K type against every truncation of its specifier.
        for s2k_type in (0, 1, 3, 9):
            for length in range(0, 12):
                body = bytes([4, 9, s2k_type]) + bytes(rng.getrandbits(8) for _ in range(length))
                corpus.append(bytes([0x8C, len(body)]) + body + seipd)
        # Every packet-length encoding, truncated at the length field.
        corpus.extend(
            [
                b"\x8d\x00",  # old format, 2-byte length
                b"\x8e\x00\x00\x00",  # old format, 4-byte length
                b"\xc3\xc0",  # new format, two-octet length
                b"\xc3\xff\x00\x00\x00",  # new format, five-octet length
                b"\xc3\xe1",  # new format, partial body length
            ]
        )
        # Random bodies behind a valid SKESK control byte.
        for _ in range(200):
            corpus.append(
                bytes([0x8C]) + bytes(rng.getrandbits(8) for _ in range(rng.randrange(64)))
            )
        # Every truncation of a real message, and the real one itself.
        corpus.extend(real[:n] for n in range(0, len(real) + 1))

        for blob in corpus:
            try:
                result = decrypt(blob, passphrase=_PW)
            except OpenPGPError:
                continue
            except Exception as exc:  # noqa: BLE001 - that is the point
                self.fail(
                    f"{type(exc).__name__} escaped the OpenPGP error taxonomy for "
                    f"{blob[:12].hex()}... ({len(blob)} bytes): {exc}"
                )
            else:
                # Only the untruncated fixture may decrypt; anything else
                # returning means a crafted blob was ACCEPTED.
                if blob != real:
                    self.fail(
                        f"crafted input was accepted and returned {len(result)} bytes: "
                        f"{blob[:12].hex()}... ({len(blob)} bytes)"
                    )

    def test_the_corpus_reaches_the_code_it_is_meant_to_cover(self):
        """A corpus that never runs the guarded code proves nothing.

        The first version of the test above passed while reaching neither
        _s2k_derive nor three of the five length guards -- every blob died
        earlier, at the missing-SEIPD check. This asserts the coverage
        directly instead of trusting that the inputs look adversarial.
        """
        from openssl_encrypt.modules.interop import openpgp as module

        executed = set()
        module_file = module.__file__

        def tracer(frame, event, arg):
            if event == "line" and frame.f_code.co_filename == module_file:
                executed.add(frame.f_lineno)
            return tracer

        source = open(module_file, encoding="utf-8").read().splitlines()
        need_sites = {
            i + 1
            for i, line in enumerate(source)
            if "_need(data" in line and not line.lstrip().startswith("def ")
        }
        s2k_guard = {i + 1 for i, line in enumerate(source) if "truncated S2K specifier" in line}

        previous = sys.gettrace()
        sys.settrace(tracer)
        try:
            self.test_malformed_input_always_raises_an_openpgp_error()
        finally:
            sys.settrace(previous)

        missed = sorted(need_sites - executed)
        self.assertFalse(
            missed,
            f"the corpus never executes the bounds check(s) at line(s) {missed}; "
            "it is not covering what it claims to",
        )
        self.assertTrue(
            s2k_guard & executed,
            "the corpus never reaches the S2K truncation guard",
        )

    def test_the_detector_is_a_one_byte_heuristic(self):
        """Pinned so the flakiness above is not "fixed" in the wrong place.

        Accepting a random buffer that happens to start with a tag-3 byte is
        intended: is_openpgp_file only decides whether to ATTEMPT a parse,
        and decrypt() is what actually rejects the input. A one-byte check
        cannot distinguish further, so the test was the thing to fix, not
        the heuristic.
        """
        for ctb in (0x8C, 0xC3):  # old-format tag 3, new-format tag 3
            self.assertTrue(
                is_openpgp_file(bytes([ctb]) + os.urandom(63)),
                f"control byte {ctb:#04x} is a valid SKESK tag and must be attempted",
            )
        with self.assertRaises(OpenPGPError):
            decrypt(b"\x8c" + os.urandom(63), passphrase=_PW)

    def test_no_seipd(self):
        # SKESK alone (no encrypted data) must fail closed, not hang/guess.
        skesk_only = _extract_first_packet(_load("v_aes256.gpg"))
        with self.assertRaises(OpenPGPFormatError):
            decrypt(skesk_only, passphrase=_PW)


def _extract_first_packet(data):
    """Return just the first packet (the SKESK) from a message."""
    from openssl_encrypt.modules.interop.openpgp import _read_packet

    _tag, _body, off = _read_packet(data, 0)
    return data[:off]


class TestOpenPGPDetection(unittest.TestCase):
    def test_detect_binary_skesk(self):
        self.assertTrue(is_openpgp_file(_load("v_aes256.gpg")))

    def test_detect_armored(self):
        self.assertTrue(is_openpgp_file(_load("v_armored.asc")))

    def test_reject_age_file(self):
        self.assertFalse(is_openpgp_file(b"age-encryption.org/v1\n-> X25519 ..."))


if __name__ == "__main__":
    unittest.main()
