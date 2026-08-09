#!/usr/bin/env python3
"""PepperConfig.get_default_config_path() must exist (gitlab#221).

crypt_cli.py and crypt_core.py error paths call
``PepperConfig.get_default_config_path()`` to point the user at the config file,
but the classmethod did not exist -- only the module-level
``_get_default_config_path`` -- so any path that reached those call sites raised
``AttributeError`` instead of the intended "Configure at: ..." message.
"""

import unittest
from pathlib import Path


class TestPepperConfigDefaultPath(unittest.TestCase):
    def test_accessor_exists_and_matches_the_module_helper(self):
        from openssl_encrypt.plugins.pepper.config import (
            PepperConfig,
            _get_default_config_path,
        )

        path = PepperConfig.get_default_config_path()
        self.assertIsInstance(path, Path)
        self.assertEqual(path, _get_default_config_path())

    def test_callers_reference_an_attribute_that_exists(self):
        # The error paths in crypt_cli / crypt_core interpolate the accessor;
        # guard that the attribute is present so the AttributeError cannot return.
        from openssl_encrypt.plugins.pepper.config import PepperConfig

        self.assertTrue(hasattr(PepperConfig, "get_default_config_path"))
        self.assertTrue(callable(PepperConfig.get_default_config_path))


if __name__ == "__main__":
    unittest.main()
