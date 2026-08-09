#!/usr/bin/env python3
"""Template KDF-downgrade protection (gitlab#169 part 2), 1.5.x.

The template *management* subsystem (self-asserted score / list ranking, part 1)
does not exist on 1.5.x. But the `encrypt --template <file>` path
(get_template_config -> load_template_file) does, and a template file dropped
into the template directory could apply weak key derivation (e.g.
pbkdf2_iterations: 1). Applying a file template now warns loudly, and the
template directory has its group/other write bits stripped so another local
user cannot plant a template.
"""

import io
import os
import tempfile
import unittest
from contextlib import redirect_stderr

from openssl_encrypt.modules.crypt_cli import _warn_if_weak_template_kdf
from openssl_encrypt.modules.file_permissions import harden_directory_permissions


class TestWeakTemplateKdfWarns(unittest.TestCase):
    def _stderr_of(self, hash_config):
        buf = io.StringIO()
        with redirect_stderr(buf):
            _warn_if_weak_template_kdf(hash_config, "some-template")
        return buf.getvalue()

    def test_weak_config_warns(self):
        self.assertIn("WARNING", self._stderr_of({"pbkdf2_iterations": 1}))

    def test_strong_argon2_does_not_warn(self):
        self.assertEqual(self._stderr_of({"argon2": {"enabled": True, "memory_cost": 131072}}), "")

    def test_strong_pbkdf2_alone_does_not_warn(self):
        self.assertEqual(self._stderr_of({"pbkdf2_iterations": 600000}), "")

    def test_pbkdf2_below_the_floor_warns(self):
        # 200k clears the old 100k threshold but not the 600k OWASP floor.
        self.assertIn("WARNING", self._stderr_of({"pbkdf2_iterations": 200000}))

    def test_enabled_but_trivial_balloon_still_warns(self):
        out = self._stderr_of(
            {"balloon": {"enabled": True, "space_cost": 1}, "pbkdf2_iterations": 1}
        )
        self.assertIn("WARNING", out)

    def test_strong_balloon_does_not_warn(self):
        self.assertEqual(self._stderr_of({"balloon": {"enabled": True, "space_cost": 131072}}), "")

    def test_hostile_shapes_do_not_raise(self):
        self._stderr_of({"argon2": "nope", "pbkdf2_iterations": True})
        self._stderr_of("not-a-dict")


class TestHardenDirectoryPermissions(unittest.TestCase):
    def test_strips_group_other_write_preserving_read(self):
        with tempfile.TemporaryDirectory() as d:
            os.chmod(d, 0o775)
            harden_directory_permissions(d)
            mode = os.stat(d).st_mode & 0o777
            self.assertEqual(mode & 0o022, 0)  # no group/other write
            self.assertTrue(mode & 0o040)  # group read preserved (multi-user read)

    def test_never_raises_on_a_missing_path(self):
        harden_directory_permissions("/nonexistent/does/not/exist")


if __name__ == "__main__":
    unittest.main()
