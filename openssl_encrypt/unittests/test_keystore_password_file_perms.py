"""Regression test for keystore password-file permission warning (#101 / KDF-9).

get_keystore_password read a --keystore-password-file with no permission check.
It now warns (advisory) if the file is accessible to group/others.
"""

import os
import stat
import sys
import tempfile
import unittest
from io import StringIO
from types import SimpleNamespace
from unittest import mock

from openssl_encrypt.modules.keystore_utils import get_keystore_password


@unittest.skipIf(sys.platform == "win32", "POSIX permission semantics")
class TestKeystorePasswordFilePerms(unittest.TestCase):
    def _read_with_perms(self, mode):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "pw.txt")
            with open(path, "w") as f:
                f.write("s3cret")
            os.chmod(path, mode)
            args = SimpleNamespace(keystore_password_file=path, quiet=False)
            err = StringIO()
            with mock.patch("sys.stderr", err):
                pw = get_keystore_password(args)
            return pw, err.getvalue()

    def test_group_readable_file_warns(self):
        pw, err = self._read_with_perms(0o644)
        self.assertEqual(pw, "s3cret")
        self.assertIn("accessible to group/others", err)

    def test_owner_only_file_no_warning(self):
        pw, err = self._read_with_perms(0o600)
        self.assertEqual(pw, "s3cret")
        self.assertNotIn("accessible to group/others", err)


if __name__ == "__main__":
    unittest.main()
