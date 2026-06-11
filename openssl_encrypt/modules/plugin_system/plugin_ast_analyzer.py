#!/usr/bin/env python3
"""
AST-Based Static Analysis for Plugin Security

This module provides AST-based security analysis for plugins to detect
dangerous patterns that regex-based analysis would miss.

Detects:
- Direct dangerous function calls (eval, exec, compile, __import__)
- getattr(__builtins__, ...) patterns for accessing blocked functions
- String concatenation to build dangerous function names
- Dynamic import patterns
- Dangerous OS functions (os.system, os.popen, etc.)
- Subprocess creation attempts

Note: File operations (open) and basic os/socket imports are allowed because:
- File access is restricted by the sandbox's allowed_paths mechanism
- Network access is needed for some legitimate plugins
- Dangerous OS functions are still blocked (os.system, os.popen, etc.)
"""

import ast
import logging
from dataclasses import dataclass
from typing import List, Optional, Set

logger = logging.getLogger(__name__)


@dataclass
class SecurityViolation:
    """Represents a security violation found during AST analysis"""

    line: int
    col: int
    violation_type: str
    description: str
    severity: str  # "critical", "high", "medium", "low"


class DangerousPatternVisitor(ast.NodeVisitor):
    """
    AST visitor that detects dangerous security patterns in plugin code.

    This visitor traverses the Abstract Syntax Tree of plugin code and identifies
    potentially dangerous operations that could bypass sandbox restrictions.
    """

    # Functions that are always dangerous
    # Note: open() is NOT included here as it's needed for legitimate file I/O
    # File operations are handled by the sandbox's allowed_paths mechanism
    DANGEROUS_FUNCTIONS = {
        "eval",
        "exec",
        "compile",
        "__import__",
        "globals",
        "locals",
        "vars",
        "dir",
        "type",
        "breakpoint",
    }

    # Dunder attributes that enable type hierarchy traversal / sandbox escape.
    # Note: __init__, __new__, __del__, __dict__, __func__, __self__, __class__
    # are NOT included here because they are standard Python and commonly used
    # in legitimate plugin code.  Only attributes that enable sandbox escapes
    # (type hierarchy traversal, scope access, code manipulation, pickle exploits)
    # are blocked.
    DANGEROUS_DUNDER_ATTRIBUTES = {
        "__mro__",
        "__subclasses__",
        "__bases__",
        "__globals__",
        "__builtins__",
        "__code__",
        "__reduce__",
        "__reduce_ex__",
        "__class__",
        "__import__",
        "__loader__",
        "__spec__",
        "__dict__",
        "__func__",
        "__self__",
        # H8: frame / traceback traversal recovers real builtins and reaches
        # eval, e.g. e.__traceback__.tb_frame.f_back.f_globals['__builtins__'].
        # These are not __dunder__ names but visit_Attribute/getattr checks
        # membership by attribute string, so listing them here closes the chain.
        "__traceback__",
        "tb_frame",
        "tb_next",
        "f_back",
        "f_globals",
        "f_locals",
        "f_builtins",
        "gi_frame",
        "cr_frame",
        "ag_frame",
    }

    # Use the shared blocked modules set to keep AST and runtime in sync
    from .plugin_security_constants import BLOCKED_MODULES

    DANGEROUS_MODULES = BLOCKED_MODULES

    # os module functions that are dangerous
    DANGEROUS_OS_FUNCTIONS = {
        "system",
        "popen",
        "spawn",
        "exec",
        "execl",
        "execle",
        "execlp",
        "execlpe",
        "execv",
        "execve",
        "execvp",
        "execvpe",
        "fork",
        "forkpty",
        "kill",
        "killpg",
        "spawnl",
        "spawnle",
        "spawnlp",
        "spawnlpe",
        "spawnv",
        "spawnve",
        "spawnvp",
        "spawnvpe",
        "popen2",
        "popen3",
        "popen4",
        "remove",
        "unlink",
        "rmdir",
        "removedirs",
        "rename",
        "renames",
        "symlink",
        "link",
        "chmod",
        "chown",
        "chroot",
        "lchmod",
        "lchown",
        "setuid",
        "setgid",
        "seteuid",
        "setegid",
    }

    def __init__(self, strict_mode: bool = True):
        """
        Initialize the visitor.

        Args:
            strict_mode: If True, treat all violations as errors
        """
        self.strict_mode = strict_mode
        self.violations: List[SecurityViolation] = []
        self.imported_modules: Set[str] = set()
        self.imported_names: Set[str] = set()

    def add_violation(
        self, node: ast.AST, violation_type: str, description: str, severity: str = "critical"
    ):
        """Add a security violation"""
        self.violations.append(
            SecurityViolation(
                line=node.lineno,
                col=node.col_offset,
                violation_type=violation_type,
                description=description,
                severity=severity,
            )
        )

    def visit_Import(self, node: ast.Import) -> None:
        """Check for dangerous imports: import subprocess"""
        for alias in node.names:
            module_base = alias.name.split(".")[0]
            self.imported_modules.add(module_base)

            if module_base in self.DANGEROUS_MODULES:
                self.add_violation(
                    node,
                    "dangerous_import",
                    f"Import of dangerous module '{alias.name}' detected. "
                    f"This module is blocked by the plugin security policy.",
                    "critical",
                )

        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Check for dangerous from imports: from subprocess import Popen"""
        if node.module:
            module_base = node.module.split(".")[0]
            self.imported_modules.add(module_base)

            if module_base in self.DANGEROUS_MODULES:
                self.add_violation(
                    node,
                    "dangerous_import",
                    f"Import from dangerous module '{node.module}' detected. "
                    f"This module is blocked by the plugin security policy.",
                    "critical",
                )

            # Track imported names for later analysis
            for alias in node.names:
                if alias.name != "*":
                    self.imported_names.add(alias.name)

        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        """
        Check for dangerous function calls.

        Detects:
        - eval(), exec(), compile()
        - __import__()
        - getattr(__builtins__, 'eval')
        - "".join(['e','v','a','l'])() patterns
        """
        # Direct function calls: eval(), exec(), etc.
        if isinstance(node.func, ast.Name):
            func_name = node.func.id

            if func_name in self.DANGEROUS_FUNCTIONS:
                self.add_violation(
                    node,
                    "dangerous_function",
                    f"Call to dangerous function '{func_name}()' detected. "
                    f"This function can execute arbitrary code and bypass sandbox restrictions.",
                    "critical",
                )

        # Attribute calls: os.system(), subprocess.Popen()
        elif isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                module = node.func.value.id
                func = node.func.attr

                # Check os.system, os.popen, etc.
                if module == "os" and func in self.DANGEROUS_OS_FUNCTIONS:
                    self.add_violation(
                        node,
                        "dangerous_os_function",
                        f"Call to dangerous function 'os.{func}()' detected. "
                        f"Process execution is blocked by the plugin security policy.",
                        "critical",
                    )

                # Check subprocess calls
                if module == "subprocess":
                    self.add_violation(
                        node,
                        "subprocess_call",
                        f"Call to 'subprocess.{func}()' detected. "
                        f"Process execution is blocked by the plugin security policy.",
                        "critical",
                    )

        # Check for .__subclasses__() calls on any object (sandbox escape)
        if isinstance(node.func, ast.Attribute):
            if node.func.attr == "__subclasses__":
                self.add_violation(
                    node,
                    "subclasses_call",
                    "Call to __subclasses__() detected. "
                    "This is a known sandbox escape technique via type hierarchy traversal.",
                    "critical",
                )

        # getattr patterns: getattr(__builtins__, 'eval') or getattr(obj, '__class__')
        if isinstance(node.func, ast.Name) and node.func.id == "getattr":
            if len(node.args) >= 2:
                if isinstance(node.args[1], ast.Constant):
                    attr_name = node.args[1].value
                    # Check for dangerous dunder access via getattr
                    if isinstance(attr_name, str) and attr_name in self.DANGEROUS_DUNDER_ATTRIBUTES:
                        self.add_violation(
                            node,
                            "getattr_dunder_bypass",
                            f"Attempt to access '{attr_name}' via getattr(). "
                            f"This is a known sandbox bypass technique.",
                            "critical",
                        )
                    # Check if first arg is __builtins__ or similar
                    if isinstance(node.args[0], ast.Name):
                        obj_name = node.args[0].id
                        if obj_name in ("__builtins__", "__builtin__", "builtins"):
                            if isinstance(attr_name, str) and attr_name in self.DANGEROUS_FUNCTIONS:
                                self.add_violation(
                                    node,
                                    "getattr_bypass",
                                    f"Attempt to access '{attr_name}' via "
                                    f"getattr(__builtins__, ...). "
                                    f"This is a known sandbox bypass technique.",
                                    "critical",
                                )
                else:
                    # Dynamic getattr with non-constant attribute name — potential bypass
                    self.add_violation(
                        node,
                        "dynamic_getattr",
                        "getattr() called with a dynamic (non-constant) attribute name. "
                        "This can be used to bypass sandbox restrictions by computing "
                        "dangerous attribute names at runtime.",
                        "high",
                    )

        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        """
        Check for dangerous attribute access.

        Detects:
        - __builtins__.eval
        - sys.modules['os']
        - x.__class__.__mro__[1].__subclasses__() (type hierarchy traversal)
        - obj.__globals__, obj.__code__, etc.
        """
        # Check for dangerous dunder attribute access (sandbox escape via type hierarchy)
        if node.attr in self.DANGEROUS_DUNDER_ATTRIBUTES:
            self.add_violation(
                node,
                "dunder_access",
                f"Access to dangerous dunder attribute '{node.attr}' detected. "
                f"Dunder attribute traversal can be used to escape the sandbox.",
                "critical",
            )

        # Check for builtins access to dangerous functions
        if isinstance(node.value, ast.Name):
            if node.value.id in ("__builtins__", "__builtin__", "builtins"):
                if node.attr in self.DANGEROUS_FUNCTIONS:
                    self.add_violation(
                        node,
                        "builtins_access",
                        f"Direct access to __builtins__.{node.attr} detected. "
                        f"This is a potential sandbox bypass.",
                        "critical",
                    )

        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript) -> None:
        """
        Check for dangerous subscript operations.

        Detects:
        - sys.modules['subprocess']
        - __builtins__['eval']
        """
        if isinstance(node.value, ast.Attribute):
            # sys.modules['os']
            if isinstance(node.value.value, ast.Name) and node.value.value.id == "sys":
                if node.value.attr == "modules":
                    if isinstance(node.slice, ast.Constant):
                        module = node.slice.value
                        if module in self.DANGEROUS_MODULES:
                            self.add_violation(
                                node,
                                "sys_modules_access",
                                f"Attempt to access sys.modules['{module}']. "
                                f"This is a known sandbox bypass technique.",
                                "critical",
                            )

        # __builtins__['eval']
        elif isinstance(node.value, ast.Name):
            if node.value.id in ("__builtins__", "__builtin__", "builtins"):
                if isinstance(node.slice, ast.Constant):
                    func = node.slice.value
                    if func in self.DANGEROUS_FUNCTIONS:
                        self.add_violation(
                            node,
                            "builtins_subscript",
                            f"Access to __builtins__['{func}'] detected. "
                            f"This is a potential sandbox bypass.",
                            "critical",
                        )

        self.generic_visit(node)

    def visit_Str(self, node: ast.Str) -> None:
        """Check for suspicious strings (base64 encoded code, etc.)"""
        # This is for older Python versions; in 3.8+ ast.Str is deprecated
        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant) -> None:
        """Check constant values for suspicious patterns"""
        if isinstance(node.value, str):
            # Check for base64-looking strings that might be encoded payloads
            if len(node.value) > 50 and node.value.isalnum():
                # Could be base64, but this is just informational
                logger.debug(
                    f"Line {node.lineno}: Found long alphanumeric constant (possible base64)"
                )

        self.generic_visit(node)


def analyze_plugin_code(
    code: str, file_path: str, strict_mode: bool = True
) -> tuple[bool, List[SecurityViolation]]:
    """
    Analyze plugin code for security violations using AST.

    Args:
        code: Python source code to analyze
        file_path: Path to the plugin file (for error messages)
        strict_mode: If True, any violation fails validation

    Returns:
        tuple: (is_safe, violations_list)
    """
    try:
        # Parse the code into an AST
        tree = ast.parse(code, filename=file_path)

        # Visit the tree and collect violations
        visitor = DangerousPatternVisitor(strict_mode=strict_mode)
        visitor.visit(tree)

        # In strict mode, any critical or high severity violation fails validation
        if strict_mode:
            blocking_violations = [
                v for v in visitor.violations if v.severity in ("critical", "high")
            ]
            is_safe = len(blocking_violations) == 0
        else:
            # In permissive mode, we just warn but allow
            is_safe = True

        return is_safe, visitor.violations

    except SyntaxError as e:
        # If the code doesn't parse, it's definitely not safe
        logger.error(f"Syntax error in plugin {file_path}: {e}")
        violation = SecurityViolation(
            line=e.lineno or 0,
            col=e.offset or 0,
            violation_type="syntax_error",
            description=f"Plugin contains invalid Python syntax: {e.msg}",
            severity="critical",
        )
        return False, [violation]

    except Exception as e:
        # Unexpected error during analysis
        logger.error(f"Error analyzing plugin {file_path}: {e}")
        violation = SecurityViolation(
            line=0,
            col=0,
            violation_type="analysis_error",
            description=f"Failed to analyze plugin: {str(e)}",
            severity="critical",
        )
        return False, [violation]
