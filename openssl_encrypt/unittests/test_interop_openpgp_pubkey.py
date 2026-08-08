#!/usr/bin/env python3
"""
Tests for read-only OpenPGP PUBLIC-KEY decryption (feature #5, phase 3).

Functional coverage uses REAL GnuPG 2.2.40 keypairs + public-key-encrypted
messages (committed under testfiles/openpgp_pubkey/): RSA-3072, Curve25519
(cv25519 ECDH), and NIST P-256/384/521 ECDH. Negative tests cover a wrong key
passphrase and a non-matching key.
"""

import os
import random
import unittest

from openssl_encrypt.modules.interop.openpgp import (
    OpenPGPError,
    OpenPGPWrongPassphrase,
    _read_packet,
)
from openssl_encrypt.modules.interop.openpgp_pubkey import (
    OpenPGPNoMatchingKey,
    decrypt,
    parse_secret_keys,
)

_PW = "keypw"
_DIR = os.path.join(os.path.dirname(__file__), "testfiles", "openpgp_pubkey")
_EXPECT = b"public-key openpgp interop test message"
_CURVES = ["rsa", "cv25519", "nistp256", "nistp384", "nistp521"]


def _read(name):
    with open(os.path.join(_DIR, name), "rb") as f:
        return f.read()


class TestOpenPGPPublicKeyVectors(unittest.TestCase):
    """Decrypt real GnuPG public-key messages across RSA + ECDH curves."""

    def _roundtrip(self, name):
        keys = parse_secret_keys(_read(f"sec_{name}.asc"), _PW)
        pt = decrypt(_read(f"msg_{name}.gpg"), secret_keys=keys)
        self.assertEqual(pt, _EXPECT)

    def test_rsa3072(self):
        self._roundtrip("rsa")

    def test_curve25519(self):
        self._roundtrip("cv25519")

    def test_nistp256(self):
        self._roundtrip("nistp256")

    def test_nistp384(self):
        self._roundtrip("nistp384")

    def test_nistp521(self):
        self._roundtrip("nistp521")


class TestOpenPGPPublicKeyRejection(unittest.TestCase):
    def test_wrong_key_passphrase(self):
        with self.assertRaises(OpenPGPWrongPassphrase):
            parse_secret_keys(_read("sec_rsa.asc"), "not the key passphrase")

    def test_non_matching_key(self):
        # Decrypt a cv25519 message with only the RSA key loaded.
        rsa_keys = parse_secret_keys(_read("sec_rsa.asc"), _PW)
        with self.assertRaises(OpenPGPNoMatchingKey):
            decrypt(_read("msg_cv25519.gpg"), secret_keys=rsa_keys)


class TestPublicKeyMalformedInput(unittest.TestCase):
    """The taxonomy must hold on the public-key path too (gitlab#196).

    This side matters at least as much as the symmetric one: a public-key
    message is authored by anyone holding the recipient's PUBLIC key, so
    reaching this parser with hostile input needs no shared secret. It had
    the same unchecked reads and, unlike the symmetric path, no wrapper at
    all -- a truncated packet came out as a raw IndexError traceback.
    """

    def test_malformed_input_always_raises_an_openpgp_error(self):
        for fixture in ("rsa", "cv25519"):
            with self.subTest(fixture=fixture):
                self._assert_taxonomy_holds(fixture)

    def _assert_taxonomy_holds(self, fixture):
        """Both key types, because the raw reads differ per algorithm.

        The ECDH path has its own field reads (the wrapped-key length after
        the ephemeral-point MPI), which the RSA fixture never touches -- an
        RSA-only corpus passed even with the taxonomy wrapper removed.
        """
        keys = parse_secret_keys(_read(f"sec_{fixture}.asc"), _PW)
        real = _read(f"msg_{fixture}.gpg")
        rng = random.Random(20260808)

        corpus = [real[:n] for n in range(0, len(real))]
        corpus.extend(
            [
                b"",
                b"\xc1",  # new-format PKESK, no length
                b"\xc1\xc0",  # two-octet length, truncated
                b"\xc1\xff\x00\x00\x00",  # five-octet length, truncated
                b"\x85\x00\x00",  # old-format PKESK, 2-byte length
                b"\xa8\x00",  # compressed packet, empty body
            ]
        )
        for _ in range(200):
            corpus.append(
                bytes([0xC1]) + bytes(rng.getrandbits(8) for _ in range(rng.randrange(80)))
            )
        # WELL-FORMED packets with short/garbage bodies. The random blobs
        # above are almost always rejected by the shared packet reader
        # ("truncated body") and never reach the PKESK parse at all, so on
        # their own they prove nothing about this module -- verified by
        # narrowing the wrapper and watching the test still pass. A declared
        # length that matches the body is what gets past the reader.
        # The key id has to be the REAL one, or decrypt() skips the packet as
        # "not for us" long before any of this module's own field reads run;
        # and a VALID SEIPD packet has to follow, because the
        # missing-integrity-packet check fires before the session key is
        # unwrapped. Both are taken from the fixture rather than hardcoded --
        # without either, a crafted PKESK is rejected upstream and the field
        # reads it targets are never executed.
        key_id, algo, seipd_raw, offset = None, None, None, 0
        while offset < len(real):
            tag, body, next_offset = _read_packet(real, offset)
            if tag == 1 and key_id is None:
                key_id, algo = body[1:9], body[9]
            elif tag == 18:
                seipd_raw = real[offset:next_offset]
            offset = next_offset
        self.assertIsNotNone(key_id, "no PKESK packet in the fixture")
        self.assertIsNotNone(seipd_raw, "no SEIPD packet in the fixture")

        for length in range(0, 48):
            body = bytes([3]) + key_id + bytes([algo])
            body += bytes(rng.getrandbits(8) for _ in range(length))
            corpus.append(bytes([0xC1, len(body)]) + body)
            corpus.append(bytes([0xC1, len(body)]) + body + seipd_raw)

        # CRAFTED session keys, not random ones. Random bytes almost never
        # form a valid MPI header, so they are rejected by the MPI reader
        # and never reach the field reads that follow it -- a random-only
        # corpus passed with those bounds checks deleted. These are the
        # shapes that do reach them: a well-formed MPI followed by nothing,
        # or by a length octet with no wrapped key behind it.
        for esk in (
            b"\x00\x08\x01",
            b"\x00\x40" + b"\x02" * 8,
            b"\x00\x08\x01\x20",
            b"\x00\x08\x01\x08" + b"\x03" * 4,
        ):
            body = bytes([3]) + key_id + bytes([algo]) + esk
            corpus.append(bytes([0xC1, len(body)]) + body)
            corpus.append(bytes([0xC1, len(body)]) + body + seipd_raw)

        for blob in corpus:
            try:
                decrypt(blob, secret_keys=keys)
            except OpenPGPError:
                continue
            except Exception as exc:  # noqa: BLE001 - that is the point
                self.fail(
                    f"{type(exc).__name__} escaped the OpenPGP error taxonomy for "
                    f"{blob[:12].hex()}... ({len(blob)} bytes): {exc}"
                )
            else:
                self.fail(f"crafted input was accepted: {blob[:12].hex()}... ({len(blob)} bytes)")


if __name__ == "__main__":
    unittest.main()
