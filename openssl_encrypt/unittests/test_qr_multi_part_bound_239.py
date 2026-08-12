#!/usr/bin/env python3
"""Multi-QR import must bound the untrusted `total` field (gitlab#239, scan F24,
CWE-789).

`_parse_multi_qr_data` took `total` verbatim from an attacker-supplied QR JSON
and drove `set(range(1, total + 1))`; a payload declaring total=10**12 allocated
~10^12 ints and hung `keystore-cli import-qr` until OOM. `part`/`total` are now
validated as ints in 1..99 (the same cap the creation path enforces) before any
range materialization.
"""

import base64
import json
import unittest

from openssl_encrypt.modules.portable_media.qr_distribution import (
    _MAX_QR_PARTS,
    QRKeyDistribution,
    QRKeyError,
)


def _part(part, total):
    d = {
        "header": "ossl_encrypt_key_multi",
        "part": part,
        "total": total,
        "key_name": "k",
        "overall_checksum": "abcd",
        "data": base64.b64encode(b"x").decode("ascii"),
    }
    return base64.b64encode(json.dumps(d).encode("utf-8")).decode("ascii")


class TestMultiQrTotalBounded(unittest.TestCase):
    def setUp(self):
        self.qr = QRKeyDistribution()

    def test_absurd_total_is_rejected_before_allocation(self):
        # total=10**12 must be refused, not turned into set(range(1, 10**12+1)).
        with self.assertRaises(QRKeyError):
            self.qr._parse_multi_qr_data([_part(1, 10**12)])

    def test_total_just_over_cap_is_rejected(self):
        with self.assertRaises(QRKeyError):
            self.qr._parse_multi_qr_data([_part(1, _MAX_QR_PARTS + 1)])

    def test_non_int_total_is_rejected(self):
        with self.assertRaises(QRKeyError):
            self.qr._parse_multi_qr_data([_part(1, "1000000000000")])

    def test_part_greater_than_total_is_rejected(self):
        with self.assertRaises(QRKeyError):
            self.qr._parse_multi_qr_data([_part(5, 2)])

    def test_in_range_total_passes_the_range_guard(self):
        # total=2 is within the cap; the parse then fails for a DIFFERENT reason
        # (only 1 of 2 parts present), not the range guard.
        with self.assertRaises(QRKeyError) as ctx:
            self.qr._parse_multi_qr_data([_part(1, 2)])
        self.assertNotIn("out of range", str(ctx.exception))


class TestSingleQrDecompressionBounded(unittest.TestCase):
    """gitlab#239 review: the compressed single-QR path must bound the zlib
    expansion so a crafted highly-compressible payload cannot OOM."""

    def setUp(self):
        self.qr = QRKeyDistribution()

    def test_decompression_bomb_is_rejected(self):
        import zlib

        bomb = zlib.compress(b"\x00" * (50 * 1024 * 1024))  # 50 MiB -> tiny
        payload = {
            "header": self.qr.MAGIC_HEADER,
            "metadata": {"name": "k", "compressed": True, "size": 50 * 1024 * 1024},
            "key": base64.b64encode(bomb).decode("ascii"),
            "checksum": base64.b64encode(b"\x00" * 4).decode("ascii"),
        }
        qr_data = base64.b64encode(json.dumps(payload).encode("utf-8")).decode("ascii")
        with self.assertRaises(QRKeyError):
            self.qr._parse_single_qr_data(qr_data)


if __name__ == "__main__":
    unittest.main()
