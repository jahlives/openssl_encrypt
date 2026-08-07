#!/usr/bin/env python3
"""
`version.py.template` must stay valid Python.

`setup.py` does not parse or validate the template: it reads it, substitutes
``${VERSION}``/``${GIT_COMMIT}`` and writes the result straight to
`openssl_encrypt/version.py`, which the package then imports. So a syntax
error in the template is not a packaging warning -- it is an ImportError in
the installed package, and nothing in the build catches it first.

The realistic way to introduce one is the changelog workflow: every release
appends prose to a VERSION_HISTORY entry, each entry is one long
double-quoted string, and prose about this codebase naturally wants to quote
things like a file mode or a flag. A single unescaped double quote ends the
string early and the rest of the sentence becomes a syntax error. That is
exactly how it happened while landing gitlab#148.
"""

import ast
import os
import unittest

TEMPLATE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "version.py.template"
)

# The substitutions setup.py makes, with values shaped like the real ones.
PLACEHOLDERS = {"${VERSION}": "9.9.9", "${GIT_COMMIT}": "0123456789abcdef"}


def _rendered():
    with open(TEMPLATE, "r", encoding="utf-8") as handle:
        content = handle.read()
    for placeholder, value in PLACEHOLDERS.items():
        content = content.replace(placeholder, value)
    return content


class TestVersionTemplateIsValidPython(unittest.TestCase):
    def test_the_rendered_template_parses(self):
        try:
            ast.parse(_rendered())
        except SyntaxError as error:
            self.fail(
                f"version.py.template does not parse after substitution "
                f"(line {error.lineno}): {error.msg}. setup.py writes this file "
                f"verbatim to version.py, so this breaks importing the package. "
                f"The usual cause is an unescaped double quote in a VERSION_HISTORY "
                f"entry -- each entry is one double-quoted string."
            )

    def test_every_placeholder_is_substituted(self):
        """A leftover ${...} would be a NameError or a silent wrong value."""
        self.assertNotIn("${", _rendered(), "an unsubstituted placeholder remains")

    def test_version_history_is_a_mapping_of_strings(self):
        rendered = _rendered()
        namespace = {}
        exec(compile(rendered, TEMPLATE, "exec"), namespace)  # nosec B102 - our own template

        history = namespace.get("VERSION_HISTORY")
        self.assertIsInstance(history, dict, "VERSION_HISTORY is not a dict")
        self.assertTrue(history, "VERSION_HISTORY is empty")
        for version, description in history.items():
            self.assertIsInstance(version, str, f"key {version!r} is not a string")
            self.assertIsInstance(description, str, f"value for {version!r} is not a string")
            self.assertTrue(description.strip(), f"{version} has an empty description")


if __name__ == "__main__":
    unittest.main()
