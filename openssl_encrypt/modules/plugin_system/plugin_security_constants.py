#!/usr/bin/env python3
"""
Shared security constants for the plugin sandbox system.

Both the AST analyzer (static analysis) and the import guard (runtime)
reference this single source of truth to ensure blocked module lists
stay in sync.
"""

# Modules that must be blocked in both the AST analyzer and the runtime
# import guard to prevent sandbox escape.
BLOCKED_MODULES = frozenset({
    "subprocess",
    "ctypes",
    "multiprocessing",
    "importlib",
    "__builtin__",
    "__builtins__",
    "sys",
    "shutil",
    "pickle",
    "shelve",
    "commands",
    "pty",
    "fcntl",
    "pwd",
    "grp",
    "signal",
    "resource",
    "pipes",
    "popen2",
    "platform",
    "os",       # os.system, os.popen, etc. — always blocked
    "pathlib",  # Path.read_text() etc. bypass sandbox file restrictions
    "io",       # io.open() bypasses sandbox restricted_open
})
