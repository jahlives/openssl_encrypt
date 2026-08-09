#!/usr/bin/env python3
"""
Lint: every argv the desktop GUI EXECUTES must parse against the real CLI
parser (gitlab#186 / github#103).

"Executes" is deliberate: the preview builders that render a copy-pasteable
command line for the user are not covered (gitlab#191).

The GUI has repeatedly emitted CLI surface that does not exist, each time
failing at argparse with exit 2 and each time swallowed into an empty
result, so the feature simply never worked: gitlab#164 (`identity import
--data/--alias`), gitlab#183 (`identity list --json`), gitlab#185
(`identity delete --contact`), gitlab#187 (`generate-password --json`).
Writing the widget does not verify the feature; only driving the real CLI
does, and pytest never exercises the GUI.

This reads `desktop_gui/lib/cli_service.dart`, extracts each call site's
command path and flag literals, and checks them against the parser
`build_subparser()` returns -- the same object the CLI uses, not a
reconstruction of it.

WHAT THIS DOES NOT COVER, so nobody mistakes a pass for proof:
  * flag ARITY -- a value-carrying option sent as a bare boolean fails at
    runtime with "expected one argument" and looks fine here -- a declared
    option string passes even when used with the wrong arity (gitlab#190);
  * Dart-interpolated literals ('--$template'), counted and reported as
    unverified rather than guessed at;
  * argv assembled outside the enclosing method, or by a helper;
  * a relocated global flag whose dest a subparser re-declares, which
    parses but is silently dropped (gitlab#171/#176).

Call sites that fail today live in KNOWN_BROKEN, each naming its tracking
issue, so the lint passes now but fails on anything new. Companion tests
assert every entry is still genuinely broken and names an issue, so an
exemption cannot outlive the bug it describes.
"""

import argparse
import bisect
import os
import re
import unittest

from openssl_encrypt.modules.crypt_cli import TRULY_GLOBAL_FLAGS
from openssl_encrypt.modules.crypt_cli_subparser import REGISTRY_AVAILABLE, build_subparser

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CLI_SERVICE = os.path.join(REPO_ROOT, "desktop_gui", "lib", "cli_service.dart")

# Exact, not a lower bound: the first version of this lint silently stopped
# seeing encrypt/decrypt/shred when its extractor regressed, and a loose ">"
# assertion had the headroom to hide it.
#
# 21 methods that run the CLI, plus the 2 preview builders that construct an
# argv and show it to the user (gitlab#191). Widening the anchor to those two
# immediately found --pbkdf2-iterations in the encrypt preview, a flag 1.5
# removed, which would have failed at argparse if the user pasted it.
# +1 (23): telemetryOptOut -> `telemetry opt-out --force` (gitlab#165).
EXPECTED_CALL_SITES = 23

# Commands whose loss would gut the lint. Asserted present by name so an
# extractor change cannot quietly drop the KDF/cascade flag surface.
# This line's GUI predates the Shred, Rekey and Password Generator
# screens, so its command set is smaller than 1.4.x's by design.
REQUIRED_COMMANDS = {"encrypt", "decrypt", "identity"}

# Interpolated literals cannot be resolved statically. Pinned exactly, so
# new unverifiable surface has to be acknowledged rather than absorbed.
EXPECTED_INTERPOLATED = {
    ("encryptTextWithProgress", "--$template"),
    ("encryptTextWithProgress", "--cascade=$cascadePreset"),
}

# (dart_method, offending_token, issue). The token is either a "--flag" or a
# bare command-path element. Each entry must name a real tracked bug -- this
# is a list of known defects, not a place to silence the lint.
KNOWN_BROKEN = [
    # The pepper and integrity controls are kept deliberately: the CLI
    # surface for them is planned (gitlab#193, gitlab#194). Until it lands
    # these calls fail at argparse, so they are declared here rather than
    # silently tolerated -- and the stale-entry test will demand these
    # entries be deleted the day the subcommands appear.
    ("configurePepperDeadman", "pepper", "gitlab#193: pepper CLI not implemented yet"),
    ("listPeppers", "pepper", "gitlab#193: pepper CLI not implemented yet"),
    ("setupPepperTotp", "pepper", "gitlab#193: pepper CLI not implemented yet"),
    ("verifyPepperTotp", "pepper", "gitlab#193: pepper CLI not implemented yet"),
    ("testPepperConnection", "pepper", "gitlab#193: pepper CLI not implemented yet"),
    ("testIntegrityConnection", "integrity", "gitlab#194: integrity CLI not implemented yet"),
    ("verifyFileIntegrity", "integrity", "gitlab#194: integrity CLI not implemented yet"),
    ("getIntegrityStats", "integrity", "gitlab#194: integrity CLI not implemented yet"),
]

# A Dart method declaration at exactly two-space (class body) indentation.
# The type must be a known type or a capitalised identifier followed by
# whitespace then `name(`, which excludes statements such as
# `throw Exception(`, `print(`, `return await _runCLICommand(` and the
# parameter line `Function(String)? onProgress,`.
_DECL_RE = re.compile(
    r"^  (?:static\s+)?"
    r"(?:Future<.*?>|void|bool|int|String|double|List<.*?>|Map<.*?>|[A-Z]\w*)\??\s+(\w+)\(",
    re.M,
)
# Dart string literals, both quote styles.
_LITERAL_RE = re.compile(r"'([^'\n]*)'|\"([^\"\n]*)\"")
# Comments are stripped before literals are read: a comment quoting a flag
# name (cli_service.dart does exactly that for --dice-sep) is documentation,
# not argv, and reading it produces a phantom finding.
_COMMENT_RE = re.compile(r"//[^\n]*|/\*.*?\*/", re.S)
# The argv list itself, and every later append to it.
_ARGV_INIT_RE = re.compile(r"\bargs\s*=\s*(?:<String>)?\[")
# Some call sites pass the list inline: _runCLICommand(['list-recovery', ...]).
_ARGV_INLINE_RE = re.compile(r"_runCLICommand\w*\(\s*(?:<String>)?\[")
_ARGV_ADD_RE = re.compile(r"\bargs\.add(?:All)?\(([^;]*?)\)\s*;", re.S)
# Any other mutation of the argv list -- insert, +=, cascade, a helper --
# would silently drop flags, so it is a hard error rather than a gap.
_ARGV_UNHANDLED_RE = re.compile(
    r"\bargs\s*\+=|\bargs\s*\.\.|"
    r"\bargs\.(?:insert|insertAll|remove|removeAt|removeLast|removeWhere|"
    r"replaceRange|setAll|setRange|fillRange|clear|sort|shuffle)\s*\("
)
# The runner methods themselves are not call sites.
_RUNNERS = re.compile(r"^_runCLICommand")
# Methods that BUILD an argv without running it: the command preview the GUI
# renders as a copy-pasteable line for the user. Same defect surface as a
# call site -- the GUI can hand out a command that fails at argparse if
# pasted -- and they construct `args` exactly the same way, so the extractor
# reads them unchanged; only the anchor had to widen (gitlab#191).
_PREVIEW_BUILDERS = ("previewEncryptCommand", "previewDecryptCommand")


def _subcommands(parser):
    """The subcommand choices of a parser, or {} if it has none."""
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            return action.choices
    return {}


def _resolve(parser, path):
    """Walk a command path; return the parser it lands on, or None."""
    node = parser
    for part in path:
        choices = _subcommands(node)
        if part not in choices:
            return None
        node = choices[part]
    return node


def _raw_literals(text):
    """String literals in an already comment-stripped fragment."""
    for match in _LITERAL_RE.finditer(text):
        yield match.group(1) if match.group(1) is not None else match.group(2)


def _argv_literals(body):
    """Literals that actually become argv in this method.

    Reads the `args = [...]` / `args = <String>[...]` initialiser plus every
    `args.add(...)` / `args.addAll([...])`, so unrelated string literals --
    log messages, error text, another subprocess\'s arguments -- cannot be
    mistaken for the command or its flags.
    """
    body = _COMMENT_RE.sub("", body)
    unhandled = _ARGV_UNHANDLED_RE.search(body)
    if unhandled:
        raise AssertionError(
            f"argv is mutated in a form this lint cannot read: "
            f"{unhandled.group(0)!r}. Teach _argv_literals about it rather "
            f"than letting those flags go unchecked."
        )
    literals = []

    for pattern in (_ARGV_INIT_RE, _ARGV_INLINE_RE):
        for match in pattern.finditer(body):
            depth, index, quote = 0, match.end() - 1, None
            while index < len(body):
                char = body[index]
                if quote:
                    # Brackets inside a string literal are text, not
                    # structure ('[input-file]' appears in this file).
                    if char == quote and body[index - 1] != "\\":
                        quote = None
                elif char in "'\"":
                    quote = char
                elif char == "[":
                    depth += 1
                elif char == "]":
                    depth -= 1
                    if depth == 0:
                        break
                index += 1
            if depth != 0:
                raise AssertionError(
                    f"unbalanced argv list starting at offset {match.start()}; "
                    "the extractor would silently truncate or over-capture"
                )
            literals.extend(_raw_literals(body[match.end() : index]))

    for match in _ARGV_ADD_RE.finditer(body):
        literals.extend(_raw_literals(match.group(1)))

    return literals


def _split_top_level(text):
    """Split a Dart list body on its top-level commas.

    Elements, not literals: `'-a', algorithm` is a flag followed by a
    VARIABLE, and reading only string literals makes that value invisible --
    which is precisely why the flag-existence check could not see gitlab#190.
    """
    elements, depth, quote, start = [], 0, None, 0
    for index, char in enumerate(text):
        if quote:
            if char == quote and text[index - 1] != "\\":
                quote = None
        elif char in "'\"":
            quote = char
        elif char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
        elif char == "," and depth == 0:
            elements.append(text[start:index].strip())
            start = index + 1
    tail = text[start:].strip()
    if tail:
        elements.append(tail)
    return [e for e in elements if e]


def _argv_elements(body):
    """Ordered argv ELEMENTS, each as its raw source text.

    Parallel to _argv_literals, which drops everything that is not a quoted
    string. Arity checking needs to know that something follows a flag even
    when that something is a variable.
    """
    body = _COMMENT_RE.sub("", body)
    elements = []

    # The list initialiser and any inline list: the bracket is at the end of
    # the match, so the scan starts there. Searching FORWARD for the next
    # "[" instead would wander into unrelated code -- an earlier version did
    # exactly that and read `data[key]` from a helper further down as argv.
    for pattern in (_ARGV_INIT_RE, _ARGV_INLINE_RE):
        for match in pattern.finditer(body):
            depth, index, quote = 0, match.end() - 1, None
            while index < len(body):
                char = body[index]
                if quote:
                    if char == quote and body[index - 1] != "\\":
                        quote = None
                elif char in "'\"":
                    quote = char
                elif char == "[":
                    depth += 1
                elif char == "]":
                    depth -= 1
                    if depth == 0:
                        break
                index += 1
            elements.extend(_split_top_level(body[match.end() : index]))

    # args.add(x) / args.addAll([...]): the captured group IS the argument
    # text, so no searching is needed.
    for match in _ARGV_ADD_RE.finditer(body):
        argument = match.group(1).strip()
        if argument.startswith("["):
            argument = argument[1:]
            if argument.endswith("]"):
                argument = argument[:-1]
        elements.extend(_split_top_level(argument))

    return elements


def _quoted(element):
    """The string a quoted element holds, or None if it is an expression."""
    match = re.fullmatch(r"'([^'\n]*)'|\"([^\"\n]*)\"", element.strip())
    if not match:
        return None
    return match.group(1) if match.group(1) is not None else match.group(2)


def _cli_calling_methods():
    """Names of every GUI method that shells out to the CLI.

    The authoritative denominator: a method in here that _call_sites cannot
    read is a coverage hole, not something to skip quietly.
    """
    return {name for name, _body in _method_bodies().items()}


def _method_bodies():
    """Map each CLI-calling method name to its source body."""
    with open(CLI_SERVICE, "r", encoding="utf-8") as handle:
        source = handle.read()

    declarations = [(m.start(), m.group(1)) for m in _DECL_RE.finditer(source)]
    starts = [start for start, _ in declarations]
    bodies = {}

    for match in re.finditer(r"_runCLICommand\w*\(", source):
        index = bisect.bisect_right(starts, match.start())
        if index == 0:
            raise AssertionError(
                f"call at offset {match.start()} has no enclosing method "
                "declaration; the extractor is broken, not the GUI"
            )
        start, name = declarations[index - 1]
        if _RUNNERS.match(name):
            continue  # the runner definitions, not call sites
        end = starts[index] if index < len(starts) else len(source)
        bodies[name] = source[start:end]

    for position, (start, name) in enumerate(declarations):
        if name not in _PREVIEW_BUILDERS or name in bodies:
            continue
        end = starts[position + 1] if position + 1 < len(starts) else len(source)
        bodies[name] = source[start:end]

    missing = [name for name in _PREVIEW_BUILDERS if name not in bodies]
    if missing:
        raise AssertionError(
            f"preview builder(s) {missing} not found in cli_service.dart. "
            "If they were renamed, update _PREVIEW_BUILDERS -- losing them "
            "silently is how this surface went unchecked in the first place."
        )

    return bodies


def _call_sites():
    """Yield (method, path, flags, unresolved, unverified) per GUI call site.

    Anchored on the calls themselves: each `_runCLICommand*(` is mapped back
    to its enclosing declaration rather than trusting a regex to carve the
    file into methods. An unmappable call is a hard error, so an extractor
    regression cannot silently shrink coverage.
    """
    bodies = _method_bodies()
    parser = build_subparser()
    top = _subcommands(parser)

    for name, body in bodies.items():
        argv = _argv_literals(body)
        if not argv:
            continue

        # The command path is the leading run of bare literals in the argv
        # list itself. Anchored on that list rather than on "the first
        # literals in the method": several methods run an unrelated helper
        # first (one shells out to `install -m 600`), and scanning the whole
        # body would read that as the command.
        path, unresolved = [], None
        for literal in argv:
            if literal.startswith("-"):
                break
            if not path:
                if literal in top:
                    path.append(literal)
                    continue
                break
            node = _resolve(parser, path)
            choices = _subcommands(node) if node is not None else {}
            if not choices:
                break
            if literal in choices:
                path.append(literal)
            else:
                unresolved = literal
                break

        if not path:
            continue

        flags, unverified = [], []
        for literal in argv:
            if not literal.startswith("-") or literal == "-":
                continue
            if "$" in literal:
                unverified.append(literal)
            else:
                flags.append(literal)

        yield name, path, flags, unresolved, unverified, _argv_elements(body)


class TestGuiArgvMatchesCli(unittest.TestCase):
    """The GUI may only emit CLI surface that exists."""

    @classmethod
    def setUpClass(cls):
        if not os.path.isdir(os.path.join(REPO_ROOT, "desktop_gui")):
            # The unittests package ships inside the wheel; desktop_gui does
            # not. Skip rather than error on an installed tree.
            raise unittest.SkipTest("desktop_gui/ not present (installed package)")
        cls.parser = build_subparser()
        # Only the flags preprocess_global_args actually relocates are usable
        # after a subcommand. The top-level parser also declares --yes,
        # --identity-store and --keyring-remove, which it does NOT relocate,
        # so treating every top-level option as global would bless argv that
        # exits 2 at runtime.
        # list-available-algorithms is only registered when the algorithm
        # registry imports; without it a call site stops resolving and the
        # count assertion would misdiagnose an environment problem as a GUI
        # change.
        if not REGISTRY_AVAILABLE:
            raise unittest.SkipTest("algorithm registry unavailable; site count would differ")
        cls.global_flags = set(TRULY_GLOBAL_FLAGS)
        cls.sites = list(_call_sites())

    def _valid_flags(self, path):
        node = _resolve(self.parser, path)
        if node is None:
            return None
        return {opt for a in node._actions for opt in a.option_strings} | self.global_flags

    def _zero_argument_options(self, path):
        """Option strings on this command that consume NO value.

        store_true/store_false/count/help/version all have nargs == 0.
        Passing them a value does not error on the flag itself -- argparse
        takes the value as a POSITIONAL, and most of these subcommands
        declare none, so the whole command dies with "unrecognized
        arguments" and the flag looks innocent (gitlab#190).
        """
        node = _resolve(self.parser, path)
        if node is None:
            return set()
        options = set()
        for action in node._actions:
            if action.nargs == 0:
                options.update(action.option_strings)
        return options

    def _known_tokens(self, method):
        return {token for name, token, _ in KNOWN_BROKEN if name == method}

    def test_the_lint_sees_every_call_site(self):
        self.assertTrue(os.path.isfile(CLI_SERVICE), CLI_SERVICE)
        self.assertEqual(
            len(self.sites),
            EXPECTED_CALL_SITES,
            "the set of GUI call sites changed; update EXPECTED_CALL_SITES "
            "deliberately, after checking the new ones are covered",
        )
        seen = {path[0] for _n, path, _f, _u, _v, _a in self.sites}
        for command in REQUIRED_COMMANDS:
            self.assertIn(command, seen, f"the lint no longer sees `{command}`")

    def test_every_cli_calling_method_is_covered(self):
        """No method may call the CLI without its argv being read.

        The count above only catches sites disappearing. This catches the
        forward case: a NEW method that builds its argv in a shape the
        extractor does not recognise would otherwise ship unlinted -- with
        exactly the unverified CLI surface this lint exists to catch.
        """
        covered = {name for name, *_ in self.sites}
        missing = sorted(_cli_calling_methods() - covered)
        self.assertFalse(
            missing,
            "these GUI methods call the CLI but their argv could not be read:\n"
            + "\n".join(f"  {name}()" for name in missing)
            + "\n\nTeach _argv_literals about the construction they use; do "
            "not leave them unchecked.",
        )

    def test_every_command_the_gui_names_exists(self):
        problems = []
        for name, path, _flags, unresolved, _unverified, _argv in self.sites:
            if unresolved is None or unresolved in self._known_tokens(name):
                continue
            problems.append(f"  {name}(): `{' '.join(path)}` has no subcommand {unresolved!r}")

        self.assertFalse(
            problems,
            "The GUI names CLI commands that do not exist:\n"
            + "\n".join(problems)
            + "\n\nAdd the command to the CLI, or stop calling it. Do not add "
            "it to KNOWN_BROKEN without a tracking issue.",
        )

    def test_every_flag_the_gui_sends_is_declared(self):
        problems = []
        for name, path, flags, unresolved, _unverified, _argv in self.sites:
            known = self._known_tokens(name)
            # A path token that is itself known-broken means the whole
            # command does not exist, so there is no parser these flags
            # could be checked against; the stale test re-enables checking
            # the moment the command appears. Any OTHER unresolved path
            # still gets its flags checked against the deepest prefix that
            # does resolve, so a broken command cannot exempt them.
            if unresolved is not None and unresolved in known:
                continue
            # path is built only from literals already confirmed to be
            # subcommands, so it always resolves.
            valid = self._valid_flags(path)
            where = " ".join(path)
            if unresolved is not None:
                where += f" (unknown subcommand {unresolved!r})"
            for flag in flags:
                if flag in valid or flag in known:
                    continue
                problems.append(f"  {name}(): `{where}` <- {flag}")

        self.assertFalse(
            problems,
            "The GUI sends flags the CLI does not declare:\n"
            + "\n".join(problems)
            + "\n\nEvery one of these fails at argparse with exit 2, and the "
            "GUI swallows it. Declare the flag on that subcommand, or stop "
            "sending it.",
        )

    def test_no_flag_is_given_a_value_it_cannot_take(self):
        """A declared flag is not necessarily a CORRECT flag.

        gitlab#190 survived the existence check above because the GUI sent
        `-a <algorithm>` and `-a` does exist -- as the short form of
        `--armor`, a store_true. argparse set armor=True and left the
        algorithm as an unrecognised positional, so the command exited 2
        while every flag in it was "declared". Checking existence without
        checking arity is exactly the shape of bug this lint was built to
        catch, so it checks both.
        """
        problems = []
        for name, path, _flags, unresolved, _unverified, argv in self.sites:
            known = self._known_tokens(name)
            if unresolved is not None and unresolved in known:
                continue
            zero_arg = self._zero_argument_options(path)
            for index, element in enumerate(argv):
                flag = _quoted(element)
                if flag is None or flag not in zero_arg or flag in known:
                    continue
                if index + 1 >= len(argv):
                    continue
                following = argv[index + 1]
                # A following FLAG is fine; anything else -- a literal value
                # or a variable -- is the value this option cannot take. The
                # variable case is the one that matters: gitlab#190 was
                # `'-a', algorithm`, and a literal-only reader saw nothing
                # after the flag at all.
                value = _quoted(following)
                if value is not None and value.startswith("-") and value != "-":
                    continue
                shown = following if value is None else repr(value)
                problems.append(
                    f"  {name}(): `{' '.join(path)}` <- {flag} {shown} " f"({flag} takes no value)"
                )

        self.assertFalse(
            problems,
            "The GUI passes a value to a flag that accepts none:\n"
            + "\n".join(problems)
            + "\n\nargparse assigns the value to a positional instead, and "
            "these subcommands declare none, so the command exits 2 with "
            "'unrecognized arguments' while the flag itself looks fine.",
        )

    def test_no_stale_known_broken_entries(self):
        """Every entry must still be broken.

        Without this the registry becomes a graveyard of exemptions that
        outlive the bugs they describe, and the lint silently stops
        protecting the call sites it lists.
        """
        sites = {rec[0]: rec for rec in self.sites}
        stale = []

        for method, token, issue in KNOWN_BROKEN:
            if method not in sites:
                stale.append(f"  {method}(): no such call site any more ({issue})")
                continue
            _name, path, flags, unresolved, _unverified, _argv = sites[method]
            if token.startswith("--"):
                if unresolved is not None and unresolved in self._known_tokens(method):
                    continue  # the command is broken; no parser to judge against
                valid = self._valid_flags(path)
                if valid is not None and token in valid:
                    stale.append(f"  {method}(): {token} is declared now ({issue})")
                elif token not in flags:
                    stale.append(f"  {method}(): no longer sends {token} ({issue})")
            elif unresolved != token:
                stale.append(f"  {method}(): `{token}` resolves now ({issue})")

        self.assertFalse(
            stale,
            "KNOWN_BROKEN entries that are no longer broken:\n"
            + "\n".join(stale)
            + "\n\nDelete them: an exemption that outlives its bug stops the "
            "lint protecting that call site.",
        )

    def test_known_broken_entries_name_an_issue(self):
        for method, token, issue in KNOWN_BROKEN:
            self.assertRegex(
                issue,
                r"(gitlab|github)#\d+",
                f"{method}/{token} must name a tracking issue, not just a reason",
            )

    def test_interpolated_flags_stay_visible(self):
        """Interpolated literals cannot be checked; the gap must stay visible.

        '--$template' is the --quick/--standard/--paranoid selector: real
        surface this lint does not verify, which must not be mistaken for
        surface it verified.
        """
        unverified = {
            (name, literal)
            for name, _p, _f, _u, interpolated, _a in self.sites
            for literal in interpolated
        }
        self.assertEqual(
            unverified,
            EXPECTED_INTERPOLATED,
            "the set of unverifiable interpolated flags changed; pin it "
            "deliberately -- a loose bound is how coverage silently shrinks",
        )


if __name__ == "__main__":
    unittest.main()
