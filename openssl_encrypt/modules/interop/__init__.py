#!/usr/bin/env python3
"""
Interoperability: read-only decryption of foreign encrypted file formats.

Feature #5. This package lets ``openssl-encrypt decrypt --from <fmt>`` decrypt
files produced by other ecosystems (currently ``age``; OpenPGP lands in later
phases), easing migration without depending on those ecosystems' tools.

Each foreign parser treats its input as UNTRUSTED: sizes are bounded, integrity
is mandatory (no unauthenticated plaintext is ever returned), and unsupported
constructions fail closed with a clear error rather than guessing.
"""

SUPPORTED_FOREIGN_FORMATS = ("age", "pgp")


def decrypt_foreign_cli(args) -> int:
    """CLI handler for ``decrypt --from <fmt>`` (read-only foreign decryption).

    Returns a process exit code (0 success, 1 failure).
    """
    import getpass
    import os
    import sys

    from ..crypt_utils import eprint

    fmt = getattr(args, "from_format", None)

    try:
        with open(args.input, "rb") as f:
            data = f.read()
    except OSError as exc:
        eprint(f"Error: cannot read input file: {exc}")
        return 1

    if fmt == "age":
        from . import age as _age

        identities = []
        try:
            for path in getattr(args, "age_identity", None) or []:
                identities.extend(_age.parse_identities_file(path))
        except _age.AgeError as exc:
            eprint(f"Error: {exc}")
            return 1

        passphrase = getattr(args, "password", None) or os.environ.get("OPENSSL_ENCRYPT_PASSWORD")
        # An age file is unlocked by EITHER an X25519 identity OR a passphrase
        # (scrypt). If neither was supplied, prompt — the common `age -p` case.
        if not identities and passphrase is None:
            passphrase = getpass.getpass("Passphrase for age file: ")

        try:
            plaintext = _age.decrypt(data, identities=identities, passphrase=passphrase)
        except _age.NoMatchingIdentityError:
            eprint(
                "Error: no matching age identity or passphrase for this file "
                "(supply --age-identity FILE and/or the passphrase via --password)."
            )
            return 1
        except _age.AgeError as exc:
            eprint(f"Error: age decryption failed: {exc}")
            return 1

    elif fmt == "pgp":
        from . import openpgp as _pgp

        key_files = getattr(args, "pgp_key", None) or []
        passphrase = getattr(args, "password", None) or os.environ.get("OPENSSL_ENCRYPT_PASSWORD")

        if key_files:
            # Public-key message: unlock the secret key(s) with the passphrase.
            from . import openpgp_pubkey as _pgpk

            if passphrase is None:
                passphrase = getpass.getpass("Passphrase for OpenPGP secret key: ")
            try:
                secret_keys = []
                for path in key_files:
                    with open(path, "rb") as kf:
                        secret_keys.extend(_pgpk.parse_secret_keys(kf.read(), passphrase))
                plaintext = _pgpk.decrypt(data, secret_keys=secret_keys)
            except _pgpk.OpenPGPNoMatchingKey:
                eprint("Error: none of the supplied OpenPGP keys match this message.")
                return 1
            except _pgp.OpenPGPWrongPassphrase:
                eprint("Error: wrong passphrase (could not unlock the OpenPGP secret key).")
                return 1
            except _pgp.OpenPGPError as exc:
                eprint(f"Error: OpenPGP decryption failed: {exc}")
                return 1
            except OSError as exc:
                eprint(f"Error: cannot read OpenPGP key file: {exc}")
                return 1
        else:
            # Passphrase-based (gpg -c) message.
            if passphrase is None:
                passphrase = getpass.getpass("Passphrase for OpenPGP file: ")
            try:
                plaintext = _pgp.decrypt(data, passphrase=passphrase)
            except _pgp.OpenPGPWrongPassphrase:
                eprint("Error: wrong passphrase for this OpenPGP file.")
                return 1
            except _pgp.OpenPGPError as exc:
                eprint(f"Error: OpenPGP decryption failed: {exc}")
                return 1

    else:
        eprint(f"Error: unsupported foreign format: {fmt}")
        return 1

    output = getattr(args, "output", None)
    if output:
        with open(output, "wb") as f:
            f.write(plaintext)
        if not getattr(args, "quiet", False):
            eprint(f"✅ Decrypted {fmt} file → {output}")
    else:
        sys.stdout.buffer.write(plaintext)
        sys.stdout.buffer.flush()

    if getattr(args, "shred", False):
        from ..crypt_utils import secure_shred_file

        secure_shred_file(
            args.input, getattr(args, "shred_passes", 3), getattr(args, "quiet", False)
        )

    return 0
