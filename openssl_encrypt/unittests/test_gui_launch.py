#!/usr/bin/env python3
"""
`--gui` must reach the current GUI, by either entry point (gitlab#197).

Two defects sat on top of each other:

  * `python -m openssl_encrypt --gui` never saw the flag. `__main__.py`
    imported `main` from `modules.crypt_cli`, bypassing `cli.py` where
    `--gui` is handled, so argparse rejected the run with "the following
    arguments are required: action". The console script
    (`openssl-encrypt`, declared as `openssl_encrypt.cli:main`) worked.
    Two doors into one program, behaving differently.

  * `--gui` launched `crypt_gui.py`, the tkinter GUI. The current GUI is
    the Flutter desktop app under `desktop_gui/`, which had no entry point
    from the Python side at all. Fixing only the routing would have routed
    the flag to the wrong program more reliably.

The launcher runs an external binary, so these tests also pin the things
that keep that safe: no shell, an explicit resolution order, and a refusal
rather than a fallback when nothing is found — silently starting a
different program than the one asked for is how this issue arose.
"""

import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from openssl_encrypt import cli


class TestBothEntryPointsAgree(unittest.TestCase):
    """The regression the issue opens with."""

    def test_main_module_delegates_to_the_same_entry_point(self):
        """`python -m openssl_encrypt` must go through cli.main.

        Asserted on the source rather than by running it: importing
        __main__ executes it. The import is what was wrong -- it named
        modules.crypt_cli, which knows nothing about --gui.
        """
        import openssl_encrypt

        main_module = os.path.join(os.path.dirname(openssl_encrypt.__file__), "__main__.py")
        with open(main_module, encoding="utf-8") as handle:
            source = handle.read()

        self.assertIn(
            "from .cli import main",
            source,
            "python -m openssl_encrypt does not route through cli.main, so --gui "
            "(handled only there) is invisible to it",
        )
        self.assertNotIn(
            "from .modules.crypt_cli import main",
            source,
            "still importing the CLI directly; the two entry points will diverge again",
        )

    def test_the_console_script_target_still_exists(self):
        """setup.py points the console script at cli:main."""
        self.assertTrue(callable(cli.main))


class TestGuiResolution(unittest.TestCase):
    """Which program `--gui` starts, and in what order it looks."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def _executable(self, name="openssl_encrypt"):
        path = os.path.join(self.tmp, name)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("#!/bin/sh\nexit 0\n")
        os.chmod(path, os.stat(path).st_mode | stat.S_IXUSR)
        return path

    def test_the_override_environment_variable_wins(self):
        """An explicit answer for packagers and unusual installs."""
        target = self._executable("my-gui")
        with mock.patch.dict(os.environ, {"OPENSSL_ENCRYPT_GUI": target}, clear=False):
            self.assertEqual(cli._resolve_gui_command()[0], target)

    def test_an_override_that_is_not_executable_is_refused(self):
        """Naming something unrunnable must not fall through to another GUI.

        Falling back would start a different program than the user asked
        for -- the exact defect this issue is about.
        """
        plain = os.path.join(self.tmp, "not-executable")
        with open(plain, "w", encoding="utf-8") as handle:
            handle.write("data")
        with mock.patch.dict(os.environ, {"OPENSSL_ENCRYPT_GUI": plain}, clear=False):
            with self.assertRaises(cli.GuiNotAvailable):
                cli._resolve_gui_command()

    def test_a_built_bundle_in_the_tree_is_found(self):
        bundle = os.path.join(self.tmp, "desktop_gui", "build", "linux", "x64", "release", "bundle")
        os.makedirs(bundle)
        target = os.path.join(bundle, "openssl_encrypt")
        with open(target, "w", encoding="utf-8") as handle:
            handle.write("#!/bin/sh\nexit 0\n")
        os.chmod(target, os.stat(target).st_mode | stat.S_IXUSR)

        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("OPENSSL_ENCRYPT_GUI", None)
            with mock.patch.object(cli, "_repository_root", return_value=self.tmp):
                with mock.patch.object(cli, "_flatpak_app_installed", return_value=False):
                    with mock.patch.object(shutil, "which", return_value=None):
                        self.assertEqual(cli._resolve_gui_command()[0], target)

    def test_release_is_preferred_over_debug(self):
        for flavour in ("debug", "release"):
            bundle = os.path.join(
                self.tmp, "desktop_gui", "build", "linux", "x64", flavour, "bundle"
            )
            os.makedirs(bundle)
            target = os.path.join(bundle, "openssl_encrypt")
            with open(target, "w", encoding="utf-8") as handle:
                handle.write("#!/bin/sh\nexit 0\n")
            os.chmod(target, os.stat(target).st_mode | stat.S_IXUSR)

        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("OPENSSL_ENCRYPT_GUI", None)
            with mock.patch.object(cli, "_repository_root", return_value=self.tmp):
                with mock.patch.object(cli, "_flatpak_app_installed", return_value=False):
                    with mock.patch.object(shutil, "which", return_value=None):
                        self.assertIn("release", cli._resolve_gui_command()[0])

    def test_nothing_found_raises_rather_than_starting_the_legacy_gui(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("OPENSSL_ENCRYPT_GUI", None)
            with mock.patch.object(cli, "_repository_root", return_value=self.tmp):
                with mock.patch.object(cli, "_flatpak_app_installed", return_value=False):
                    with mock.patch.object(shutil, "which", return_value=None):
                        with self.assertRaises(cli.GuiNotAvailable) as caught:
                            cli._resolve_gui_command()
        message = str(caught.exception)
        self.assertIn("flutter", message.lower(), "the message does not say how to get a GUI")


class TestGuiLaunchIsNotAShell(unittest.TestCase):
    """The launcher runs an external program; keep that boring."""

    def test_the_subprocess_call_uses_an_argv_list_and_no_shell(self):
        recorded = {}

        def fake_run(argv, **kwargs):
            recorded["argv"] = argv
            recorded["kwargs"] = kwargs

            class Result:
                returncode = 0

            return Result()

        with mock.patch.object(cli, "_resolve_gui_command", return_value=["/opt/gui/app"]):
            with mock.patch.object(subprocess, "run", side_effect=fake_run):
                cli._launch_gui()

        self.assertIsInstance(recorded["argv"], list)
        self.assertEqual(recorded["argv"], ["/opt/gui/app"])
        self.assertNotIn("shell", recorded["kwargs"])

    def test_flutter_run_is_never_invoked_implicitly(self):
        """`flutter run` compiles and runs code from the working tree.

        Suggesting it in a message is fine; doing it because someone typed
        --gui is not.
        """
        import inspect

        source = inspect.getsource(cli)
        launcher = source[source.index("def _resolve_gui_command") :]
        launcher = launcher[: launcher.index("\ndef ", 1)]
        self.assertNotIn(
            '"flutter", "run"',
            launcher,
            "the resolver would run the Flutter toolchain implicitly",
        )


class TestLegacyGuiStaysReachable(unittest.TestCase):
    def test_the_legacy_flag_exists_and_names_tkinter(self):
        import inspect

        source = inspect.getsource(cli)
        self.assertIn("--gui-legacy", source)
        self.assertIn("crypt_gui", source, "the legacy GUI is no longer reachable at all")


if __name__ == "__main__":
    unittest.main()
