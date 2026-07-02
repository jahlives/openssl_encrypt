"""Regression test for the streaming metadata-separator scan bound (#72 / IO-2).

StreamingDecryptor.decrypt_file located the `metadata:payload` colon by reading
the file in blocks into an unbounded buffer. A crafted file whose first ':' is
gigabytes in (or absent) forced the whole file into memory before failing -- a
pre-authentication OOM DoS, despite the method's "memory stays bounded" promise.

The on-disk format is `base64(metadata) + b":" + payload` and base64 never
contains ':', so the separator sits at exactly len(metadata_b64). The scan is now
bounded to that, so a far/absent colon is rejected quickly as "no metadata
separator" instead of being scanned into memory.
"""

import os
import tempfile
import unittest

from openssl_encrypt.modules.crypt_errors import DecryptionError
from openssl_encrypt.modules.streaming import StreamingDecryptor


class TestStreamingColonScanBound(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self._tmp.cleanup()

    def test_far_colon_is_not_scanned_into_memory(self):
        metadata_b64 = b"YWJjZA=="  # 8 bytes -> a real separator would be at offset 8
        path = os.path.join(self._tmp.name, "evil.bin")
        with open(path, "wb") as f:
            f.write(b"A" * (512 * 1024))  # 512 KiB with no colon
            f.write(b":")  # the first colon, far beyond len(metadata_b64)
            f.write(b"XXXXXXXX")

        dec = StreamingDecryptor(
            key=b"\x00" * 32,
            algorithm="aes-gcm",
            nonce_prefix=b"\x00" * 8,
            chunk_size=65536,
        )
        # With the bound, the scan stops well before the far colon and reports the
        # missing separator. Without it, the scan reaches the far colon and fails
        # later with a different (header/magic) error instead.
        with self.assertRaisesRegex(DecryptionError, "no metadata separator"):
            dec.decrypt_file(
                input_file=path,
                output_file=None,
                metadata_b64=metadata_b64,
                expected_chunk_count=1,
                quiet=True,
            )


if __name__ == "__main__":
    unittest.main()
