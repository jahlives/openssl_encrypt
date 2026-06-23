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

SUPPORTED_FOREIGN_FORMATS = ("age",)
