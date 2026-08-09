#!/usr/bin/env python3
"""
Every GUI service parameter must have a caller (gitlab#198).

The argv lint (`test_gui_argv_matches_cli.py`) reads the argv `cli_service`
BUILDS and checks it against the real argparse tree: it catches a flag the
GUI sends that the CLI cannot accept. This is the mirror image — service
surface the GUI declares and **never sends at all**, because no widget
passes it.

Both are "the plumbing exists, one end is missing", and both hide behind a
green test run. This one exists because the audit of 2026-08-08 found
CHANGELOG entries describing Encrypt-tab controls that do not exist: the
service half of gitlab#153 landed, the widget half did not, and nothing
noticed for months. (That specific finding is on the 1.4.x line; this line
has its own set, including the HSM and force-password controls.)

What counts as wired: a named argument `name:` appearing in any Dart file
other than `cli_service.dart`. That is deliberately generous — it does not
check that the value is meaningful, only that some widget passes it — so a
finding here is a real gap rather than a style opinion.

Entries in KNOWN_UNWIRED are gaps that are accepted for now, each naming the
issue that tracks it. As with the argv lint's KNOWN_BROKEN, a stale entry is
an error: an exemption that outlives its gap stops the check protecting that
surface.
"""

import os
import re
import unittest

GUI_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "desktop_gui",
    "lib",
)
SERVICE = os.path.join(GUI_DIR, "cli_service.dart")

_COMMENT_RE = re.compile(r"//[^\n]*|/\*.*?\*/", re.S)
# A named parameter inside the `{...}` block of a declaration.
_PARAM_RE = re.compile(r"(?:^|,)\s*(?:required\s+)?[\w<>,?\s]+?\s+(\w+)\s*(?:=[^,]*)?(?=,|\s*$)")

# Accepted gaps. Format: (method, parameter, why / issue).
#
# Pruned 2026-08-09: the caller scan had never recursed into lib/tabs/,
# lib/widgets/ or lib/screens/, so most entries here described wiring that
# in fact existed. What remains is verified against the recursive scan.
KNOWN_UNWIRED = [
    # gitlab#193: the pepper CLI surface does not exist yet, so the GUI
    # cannot usefully drive this.
    ("configurePepperDeadman", None, "gitlab#193: pepper CLI not implemented yet"),
    # gitlab#198: cascade validation is only ever invoked in its advisory
    # form; a strict-mode control is part of the cascade-diversity UI.
    ("validateCascade", "strict", "gitlab#198: cascade strict mode has no control"),
]


def _sources():
    service = _COMMENT_RE.sub("", open(SERVICE, encoding="utf-8").read())
    callers = []
    # Recurse: the widgets live in lib/tabs/, lib/widgets/ and lib/screens/,
    # not only at the top of lib/. A non-recursive scan here once reported
    # already-wired Encrypt-tab parameters as gaps and kept the registry
    # lying in both directions (gitlab#198 follow-up, 2026-08-09).
    for root, _dirs, names in sorted(os.walk(GUI_DIR)):
        for name in sorted(names):
            if name.endswith(".dart") and name != "cli_service.dart":
                with open(os.path.join(root, name), encoding="utf-8") as handle:
                    callers.append(_COMMENT_RE.sub("", handle.read()))
    return service, "\n".join(callers)


def _parameter_list(text, open_paren):
    """The balanced contents of the parameter list starting at open_paren."""
    depth, index = 0, open_paren
    while index < len(text):
        if text[index] == "(":
            depth += 1
        elif text[index] == ")":
            depth -= 1
            if depth == 0:
                return text[open_paren + 1 : index]
        index += 1
    raise AssertionError("unbalanced parameter list; the extractor is broken, not the GUI")


def _declared():
    """Yield (method, [named parameters]) for every public static method."""
    service, _ = _sources()
    for match in re.finditer(r"static\s+[\w<>,?\s]+?\s+(\w+)\(", service):
        name = match.group(1)
        # `Function` is a function-typed FIELD declaration (the test seam
        # `commandRunnerOverride`), not a callable service method — its
        # parameter names are part of a type, so "wiring" them is meaningless.
        if name.startswith("_") or name == "Function":
            continue
        params = _parameter_list(service, match.end() - 1)
        if "{" not in params or "}" not in params:
            continue
        block = params[params.index("{") + 1 : params.rindex("}")]
        yield name, _PARAM_RE.findall(block)


def _unwired():
    """(method, parameter) pairs that no widget passes."""
    _, callers = _sources()
    found = []
    for method, params in _declared():
        for param in params:
            if not re.search(rf"\b{re.escape(param)}\s*:", callers):
                found.append((method, param))
    return found


def _exempt(method, param):
    for known_method, known_param, _why in KNOWN_UNWIRED:
        if known_method == method and known_param in (None, param):
            return True
    return False


class TestGuiServiceHasCallers(unittest.TestCase):
    def test_the_extractor_sees_the_service(self):
        """A regression here would empty the check silently.

        The argv lint learned this the hard way: its extractor once stopped
        seeing encrypt/decrypt/shred and the suite stayed green.
        """
        declared = list(_declared())
        self.assertGreater(len(declared), 10, "the extractor found almost no methods")
        names = {name for name, _ in declared}
        for expected in ("encryptTextWithProgress", "decryptTextWithProgress", "encryptText"):
            self.assertIn(expected, names, f"{expected} is not being read")

    def test_every_declared_parameter_has_a_caller(self):
        problems = [
            f"  {method}(): {param}" for method, param in _unwired() if not _exempt(method, param)
        ]
        self.assertFalse(
            problems,
            "cli_service declares parameters no widget passes, so the CLI "
            "surface behind them is unreachable from the GUI:\n"
            + "\n".join(problems)
            + "\n\nWire a control, or record it in KNOWN_UNWIRED with the issue "
            "that tracks it. A parameter with no caller is a feature the "
            "changelog can claim and a user cannot find.",
        )

    def test_no_stale_known_unwired_entries(self):
        """An exemption that outlives its gap stops the check protecting it."""
        unwired = set(_unwired())
        methods_with_gaps = {method for method, _ in unwired}
        stale = []
        for method, param, why in KNOWN_UNWIRED:
            if param is None:
                if method not in methods_with_gaps:
                    stale.append(f"  {method}(): every parameter is wired now ({why})")
            elif (method, param) not in unwired:
                stale.append(f"  {method}(): {param} is wired now ({why})")

        self.assertFalse(
            stale,
            "KNOWN_UNWIRED entries that are no longer unwired:\n"
            + "\n".join(stale)
            + "\n\nDelete them.",
        )

    def test_known_unwired_entries_name_an_issue(self):
        for method, _param, why in KNOWN_UNWIRED:
            self.assertRegex(
                why,
                r"gitlab#\d+",
                f"the exemption for {method} does not name a tracking issue",
            )


if __name__ == "__main__":
    unittest.main()
