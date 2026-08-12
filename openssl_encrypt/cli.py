#!/usr/bin/env python3
"""
Main CLI entry point for openssl_encrypt.

This module is what both entry points run: the ``openssl-encrypt`` console
script (declared in setup.py as ``openssl_encrypt.cli:main``) and
``python -m openssl_encrypt`` (via ``__main__.py``). They used to differ --
``__main__.py`` imported the CLI directly and so never saw ``--gui`` -- and
keeping them on one path is the point of this module (gitlab#197).

``--gui`` launches the desktop application, which is now a separate project
(``openssl_encrypt_gui``) installed alongside this CLI rather than built from
this repository; ``_resolve_gui_command`` locates that install. The tkinter GUI
in ``crypt_gui.py`` is legacy and stays reachable under ``--gui-legacy``.
"""

import os
import shutil

# Used only to start the desktop GUI: a resolved absolute path, an argv
# list, and never a shell.
import subprocess  # nosec B404
import sys

from .modules.crypt_utils import eprint

# The Flatpak application id, as published in the metainfo.
FLATPAK_APP_ID = "com.opensslencrypt.OpenSSLEncrypt"

# The launcher name of the INSTALLED desktop GUI on PATH. The GUI is now a
# separate application (its own project, openssl_encrypt_gui) and is no longer
# built from this repository, so --gui resolves an installed GUI rather than a
# bundle under desktop_gui/. The name is deliberately distinct from the CLI's
# own ``openssl-encrypt`` so the two can sit on PATH together.
GUI_EXECUTABLE = "openssl-encrypt-gui"

# Known fixed locations a packaged GUI install drops its launcher, checked
# before a PATH lookup. The first is where the Flatpak's GUI module installs
# the bundle, so a CLI running inside the Flatpak launches the co-installed GUI
# directly instead of shelling out to a nested ``flatpak run``.
GUI_INSTALL_PATHS = (
    "/app/bin/openssl-encrypt-gui/openssl_encrypt",
    "/usr/lib/openssl-encrypt-gui/openssl-encrypt-gui",
    "/usr/local/lib/openssl-encrypt-gui/openssl-encrypt-gui",
)

# Explicit override. A packager or an unusual install needs a supported
# answer that does not depend on this module guessing correctly.
GUI_OVERRIDE_ENV = "OPENSSL_ENCRYPT_GUI"


class GuiNotAvailable(RuntimeError):
    """No desktop GUI could be found to launch."""


def _is_executable(path):
    return bool(path) and os.path.isfile(path) and os.access(path, os.X_OK)


def _flatpak_app_installed():
    """Whether the Flatpak app is installed, per flatpak itself."""
    flatpak = shutil.which("flatpak")
    if not flatpak:
        return False
    try:
        # Fixed argv, binary resolved by shutil.which, no shell.
        result = subprocess.run(  # nosec B603
            [flatpak, "info", FLATPAK_APP_ID],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return result.returncode == 0


def _resolve_gui_command():
    """The argv that starts the INSTALLED desktop GUI, most specific first.

    The GUI is a separate application now, so this resolves an install rather
    than a build in this tree. Order: the ``OPENSSL_ENCRYPT_GUI`` override, a
    known fixed install location (including the in-Flatpak bundle), the
    installed Flatpak app, then the launcher on PATH.

    Raises:
        GuiNotAvailable: If none of them is present. Deliberately an error
            rather than a fall back to the legacy tkinter GUI: starting a
            different program from the one the user asked for is precisely
            the defect gitlab#197 is about.
    """
    override = os.environ.get(GUI_OVERRIDE_ENV)
    if override:
        if not _is_executable(override):
            raise GuiNotAvailable(
                f"{GUI_OVERRIDE_ENV} is set to {override!r}, which is not an "
                f"executable file. Point it at the desktop application, or unset "
                f"it to search the usual places."
            )
        return [override]

    for candidate in GUI_INSTALL_PATHS:
        if _is_executable(candidate):
            return [candidate]

    if _flatpak_app_installed():
        return [shutil.which("flatpak"), "run", FLATPAK_APP_ID]

    on_path = shutil.which(GUI_EXECUTABLE)
    if on_path:
        return [on_path]

    raise GuiNotAvailable(
        "The desktop GUI is a separate application and was not found. It now "
        "lives in its own project (openssl_encrypt_gui) and is no longer built "
        f"from this repository. Install the Flatpak ({FLATPAK_APP_ID}), install "
        f"the {GUI_EXECUTABLE} package so its launcher is on PATH, or set "
        f"{GUI_OVERRIDE_ENV} to the GUI executable.\n"
        "  The legacy tkinter interface is still available as --gui-legacy."
    )


def _launch_gui():
    """Start the desktop GUI and return its exit status.

    The Flutter toolchain is never invoked from here even when it is
    present: `flutter run` compiles and executes code from the working
    tree, which is not something a --gui flag should do on the user's
    behalf. It is named in the not-found message instead.
    """
    command = _resolve_gui_command()
    try:
        # command[0] is an absolute path this module resolved; argv list, no shell.
        result = subprocess.run(command)  # nosec B603
    except OSError as error:
        raise GuiNotAvailable(f"Could not start {command[0]!r}: {error}") from error
    return result.returncode


def _print_help():
    eprint("usage: openssl-encrypt [--gui] | [--gui-legacy] | [command] [options...]")
    eprint("")
    eprint("Encrypt or decrypt files with password protection")
    eprint("")
    eprint("Available commands:")
    eprint("  encrypt              Encrypt files with password protection")
    eprint("  decrypt              Decrypt previously encrypted files")
    eprint("  shred                Securely delete files")
    eprint("  generate-password    Generate cryptographically secure passwords")
    eprint("  list-algorithms      List available cryptographic algorithms")
    eprint("  security-info        Display security information and algorithms")
    eprint("  check-argon2         Verify Argon2 implementation")
    eprint("  check-pqc           Check post-quantum cryptography support")
    eprint("  version             Show version information")
    eprint("")
    eprint("Steganography:")
    eprint("  Use --stego-hide with encrypt command to hide encrypted data in images")
    eprint("  Use --stego-extract with decrypt command to extract data from images")
    eprint("")
    eprint("Global options:")
    eprint("  --gui               Launch the desktop application")
    eprint("  --gui-legacy        Launch the legacy tkinter interface")
    eprint("  -h, --help          Show this help message")
    eprint("")
    eprint("For detailed help on a command: openssl-encrypt <command> --help")


def main():
    """Main entry point for the openssl-encrypt command."""
    if len(sys.argv) > 1 and sys.argv[1] == "--gui":
        try:
            sys.exit(_launch_gui())
        except GuiNotAvailable as error:
            eprint(f"Error: {error}")
            sys.exit(1)

    if len(sys.argv) > 1 and sys.argv[1] == "--gui-legacy":
        # The tkinter interface. Kept because it is self-contained and needs
        # no build step, which makes it useful where the Flutter app cannot
        # run; it is not the current GUI.
        from .crypt_gui import main as gui_main

        gui_main()
        return

    if len(sys.argv) == 2 and sys.argv[1] in ("--help", "-h"):
        _print_help()
        return

    from .modules.crypt_cli import main as cli_main

    cli_main()


if __name__ == "__main__":
    main()
