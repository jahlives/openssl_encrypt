#!/usr/bin/env python3
"""
Main CLI entry point for openssl_encrypt.

This module is what both entry points run: the ``openssl-encrypt`` console
script (declared in setup.py as ``openssl_encrypt.cli:main``) and
``python -m openssl_encrypt`` (via ``__main__.py``). They used to differ --
``__main__.py`` imported the CLI directly and so never saw ``--gui`` -- and
keeping them on one path is the point of this module (gitlab#197).

``--gui`` launches the Flutter desktop application under ``desktop_gui/``.
The tkinter GUI in ``crypt_gui.py`` is legacy and stays reachable under
``--gui-legacy``.
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

# The executable Flutter produces for the Linux desktop bundle.
BUNDLE_EXECUTABLE = "openssl_encrypt"

# Build flavours, most preferred first: a release build is what a user
# means by "the app"; a debug build is a developer's, and is only a
# fallback so a working tree without a release build still launches.
BUNDLE_FLAVOURS = ("release", "debug")

# Explicit override. A packager or an unusual install needs a supported
# answer that does not depend on this module guessing correctly.
GUI_OVERRIDE_ENV = "OPENSSL_ENCRYPT_GUI"


class GuiNotAvailable(RuntimeError):
    """No desktop GUI could be found to launch."""


def _repository_root():
    """The source tree this package lives in, if it is one."""
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


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
    """The argv that starts the desktop GUI, most specific source first.

    Order: the ``OPENSSL_ENCRYPT_GUI`` override, the installed Flatpak app,
    a built bundle in this source tree, then a binary on PATH.

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

    if _flatpak_app_installed():
        return [shutil.which("flatpak"), "run", FLATPAK_APP_ID]

    root = _repository_root()
    for flavour in BUNDLE_FLAVOURS:
        candidate = os.path.join(
            root, "desktop_gui", "build", "linux", "x64", flavour, "bundle", BUNDLE_EXECUTABLE
        )
        if _is_executable(candidate):
            return [candidate]

    on_path = shutil.which(BUNDLE_EXECUTABLE)
    if on_path:
        return [on_path]

    raise GuiNotAvailable(
        "The desktop application was not found. Build it with "
        "`cd desktop_gui && flutter build linux`, run it from source with "
        "`cd desktop_gui && flutter run -d linux`, install the Flatpak "
        f"({FLATPAK_APP_ID}), or set {GUI_OVERRIDE_ENV} to its path.\n"
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
