#!/usr/bin/env python3
"""FLAC stego decode must bound the untrusted total_samples field (gitlab#240,
scan F14, CWE-789).

The 36-bit STREAMINFO total_samples drove np.random.randint(size=(total_samples,
channels)); the only guard re-estimated when total_samples > 100_000_000, so a
~50-byte file could declare ~100M samples and allocate ~800 MB (stereo int32)
plus a flatten() copy. total_samples is now bounded by what the audio payload
could actually contain.
"""

import unittest

from openssl_encrypt.plugins.steganography.formats.flac import FLACSteganography


class TestFlacTotalSamplesBounded(unittest.TestCase):
    def setUp(self):
        self.flac = FLACSteganography()

    def test_absurd_total_samples_bounded_by_file_size(self):
        # A ~50-byte file cannot hold 100M samples; the decode must not allocate
        # a 100M-row array. (No STEG marker -> the synthetic fallback path.)
        flac_data = b"fLaC" + b"\x00" * 50
        info = {
            "total_samples": 100_000_000,
            "channels": 2,
            "bits_per_sample": 16,
            "audio_offset": 4,
        }
        samples = self.flac._decode_flac_samples(flac_data, info)
        # Bounded to the re-estimate clamp (<= ~1M rows), not 100M.
        self.assertLessEqual(samples.shape[0], 1_000_000)

    def test_max_36bit_total_samples_bounded(self):
        flac_data = b"fLaC" + b"\x00" * 20
        info = {
            "total_samples": (1 << 36) - 1,  # max the field can hold
            "channels": 2,
            "bits_per_sample": 16,
            "audio_offset": 4,
        }
        samples = self.flac._decode_flac_samples(flac_data, info)
        self.assertLessEqual(samples.shape[0], 1_000_000)

    def test_in_range_total_samples_is_honored(self):
        # A file whose declared samples fit its payload keeps that count.
        n = 500
        flac_data = b"fLaC" + b"\x00" * (n * 2 * 2)  # n samples * 2ch * 2 bytes
        info = {"total_samples": n, "channels": 2, "bits_per_sample": 16, "audio_offset": 4}
        samples = self.flac._decode_flac_samples(flac_data, info)
        self.assertEqual(samples.shape[0], n)


if __name__ == "__main__":
    unittest.main()
