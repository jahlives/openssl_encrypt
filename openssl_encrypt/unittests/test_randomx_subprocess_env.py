"""Regression tests for GitLab #88 [CLI-5]: subprocess env hygiene.

The RandomX/pyrx import probes spawned children with a full copy of the
parent environment (including password env vars such as
``OPENSSL_ENCRYPT_PASSWORD``), resolved ``python3`` through PATH, and
exported every ``sys.path`` entry — including relative ones — as
PYTHONPATH. The children must instead get a scrubbed minimal
environment, an absolute interpreter path, and only absolute PYTHONPATH
entries.
"""

import os
import sys
import unittest
from unittest import mock

from openssl_encrypt.modules.randomx import (
    _get_python_executable,
    _get_subprocess_env,
    _test_pyrx_import,
    _test_randomx_import,
)


class TestSubprocessEnvScrubbed(unittest.TestCase):
    """The probe environment must not leak secrets or invite hijacking."""

    def test_password_env_vars_not_propagated(self) -> None:
        secrets_env = {
            "OPENSSL_ENCRYPT_PASSWORD": "hunter2",
            "OPENSSL_ENCRYPT_REKEY_PASSWORD": "hunter3",
            "AWS_SECRET_ACCESS_KEY": "AKIA-not-for-children",
            "SOME_RANDOM_TOKEN": "t0k3n",
        }
        with mock.patch.dict(os.environ, secrets_env):
            env = _get_subprocess_env()

        for key in secrets_env:
            self.assertNotIn(key, env, f"{key} leaked into probe subprocess env")

    def test_pythonpath_contains_only_absolute_entries(self) -> None:
        fake_path = ["", ".", os.path.join("relative", "dir"), sys.path[0] or "/tmp"]
        with mock.patch.object(sys, "path", fake_path):
            env = _get_subprocess_env()

        for entry in env.get("PYTHONPATH", "").split(os.pathsep):
            if entry:
                self.assertTrue(
                    os.path.isabs(entry),
                    f"relative PYTHONPATH entry {entry!r} would let a child "
                    "import attacker-controlled modules from the CWD",
                )

    def test_interpreter_is_absolute_or_none(self) -> None:
        exe = _get_python_executable()
        self.assertTrue(
            exe is None or os.path.isabs(exe),
            f"interpreter {exe!r} must be an absolute path, not resolved "
            "by the shell through PATH at exec time",
        )

    def test_probes_still_return_bool(self) -> None:
        self.assertIsInstance(_test_randomx_import(), bool)
        self.assertIsInstance(_test_pyrx_import(), bool)

    def test_probes_survive_missing_interpreter(self) -> None:
        """If no interpreter can be resolved, the probes must fail closed."""
        with mock.patch(
            "openssl_encrypt.modules.randomx._get_python_executable", return_value=None
        ):
            self.assertFalse(_test_randomx_import())
            self.assertFalse(_test_pyrx_import())


if __name__ == "__main__":
    unittest.main()
