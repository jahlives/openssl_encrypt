#!/usr/bin/env python3
"""
Unit tests for AST-based plugin static analysis.

Tests the DangerousPatternVisitor and analyze_plugin_code function
to ensure dangerous patterns are detected and bypass attempts blocked.
"""

import pytest
from openssl_encrypt.modules.plugin_system.plugin_ast_analyzer import (
    analyze_plugin_code,
    DangerousPatternVisitor,
    SecurityViolation
)


class TestDirectFunctionCalls:
    """Tests for detecting direct dangerous function calls"""

    def test_direct_eval_call_detected(self):
        """eval() call should be detected"""
        code = '''
def plugin_function():
    result = eval("1 + 1")
    return result
'''
        is_safe, violations = analyze_plugin_code(code, "test.py", strict_mode=True)

        assert not is_safe
        assert len(violations) == 1
        assert violations[0].violation_type == "dangerous_function"
        assert "eval" in violations[0].description
        assert violations[0].line == 3

    def test_direct_exec_call_detected(self):
        """exec() call should be detected"""
        code = '''
def plugin_function():
    exec("import os")
    return True
'''
        is_safe, violations = analyze_plugin_code(code, "test.py", strict_mode=True)

        assert not is_safe
        assert len(violations) == 1
        assert violations[0].violation_type == "dangerous_function"
        assert "exec" in violations[0].description

    def test_compile_call_detected(self):
        """compile() call should be detected"""
        code = '''
def plugin_function():
    code_obj = compile("print('hello')", "string", "exec")
    return code_obj
'''
        is_safe, violations = analyze_plugin_code(code, "test.py", strict_mode=True)

        assert not is_safe
        assert len(violations) == 1
        assert violations[0].violation_type == "dangerous_function"
        assert "compile" in violations[0].description

    def test_dunder_import_detected(self):
        """__import__() call should be detected"""
        code = '''
def plugin_function():
    os_module = __import__("os")
    return os_module
'''
        is_safe, violations = analyze_plugin_code(code, "test.py", strict_mode=True)

        assert not is_safe
        assert len(violations) == 1
        assert violations[0].violation_type == "dangerous_function"
        assert "__import__" in violations[0].description


class TestBypassAttempts:
    """Tests for detecting common sandbox bypass techniques"""

    def test_getattr_builtins_bypass_detected(self):
        """getattr(__builtins__, 'eval') should be detected"""
        code = '''
def plugin_function():
    eval_func = getattr(__builtins__, "eval")
    return eval_func("1 + 1")
'''
        is_safe, violations = analyze_plugin_code(code, "test.py", strict_mode=True)

        assert not is_safe
        # Should detect both getattr bypass and eval usage
        assert len(violations) >= 1
        violation_types = [v.violation_type for v in violations]
        assert "getattr_bypass" in violation_types

    def test_builtins_subscript_access_detected(self):
        """__builtins__['exec'] should be detected"""
        code = '''
def plugin_function():
    exec_func = __builtins__["exec"]
    return exec_func
'''
        is_safe, violations = analyze_plugin_code(code, "test.py", strict_mode=True)

        assert not is_safe
        assert len(violations) >= 1
        violation_types = [v.violation_type for v in violations]
        assert "builtins_subscript" in violation_types

    def test_sys_modules_access_detected(self):
        """sys.modules['subprocess'] should be detected"""
        code = '''
import sys

def plugin_function():
    subprocess = sys.modules["subprocess"]
    return subprocess
'''
        is_safe, violations = analyze_plugin_code(code, "test.py", strict_mode=True)

        assert not is_safe
        # Should detect sys.modules access
        violation_types = [v.violation_type for v in violations]
        assert "sys_modules_access" in violation_types

    def test_builtins_attribute_access_detected(self):
        """Direct __builtins__.eval access should be detected"""
        code = '''
def plugin_function():
    return __builtins__.eval
'''
        is_safe, violations = analyze_plugin_code(code, "test.py", strict_mode=True)

        assert not is_safe
        violation_types = [v.violation_type for v in violations]
        assert "builtins_access" in violation_types


class TestDangerousOSFunctions:
    """Tests for detecting dangerous os module functions"""

    def test_os_system_call_detected(self):
        """os.system() call should be detected"""
        code = '''
import os

def plugin_function():
    os.system("ls")
    return True
'''
        is_safe, violations = analyze_plugin_code(code, "test.py", strict_mode=True)

        assert not is_safe
        # Should detect os.system() call (os import is now allowed)
        assert len(violations) >= 1
        violation_types = [v.violation_type for v in violations]
        assert "dangerous_os_function" in violation_types

    def test_os_popen_call_detected(self):
        """os.popen() call should be detected"""
        code = '''
import os

def plugin_function():
    result = os.popen("cat /etc/passwd")
    return result.read()
'''
        is_safe, violations = analyze_plugin_code(code, "test.py", strict_mode=True)

        assert not is_safe
        violation_types = [v.violation_type for v in violations]
        assert "dangerous_os_function" in violation_types

    def test_os_spawn_variants_detected(self):
        """os.spawn* family should be detected"""
        code = '''
import os

def plugin_function():
    os.spawnl(os.P_WAIT, "/bin/ls", "ls")
    os.spawnv(os.P_NOWAIT, "/bin/sh", [])
    return True
'''
        is_safe, violations = analyze_plugin_code(code, "test.py", strict_mode=True)

        assert not is_safe
        # Multiple spawn calls should be detected
        dangerous_os_violations = [v for v in violations if v.violation_type == "dangerous_os_function"]
        assert len(dangerous_os_violations) >= 2


class TestDangerousImports:
    """Tests for detecting dangerous module imports"""

    def test_subprocess_import_detected(self):
        """import subprocess should be detected"""
        code = '''
import subprocess

def plugin_function():
    return True
'''
        is_safe, violations = analyze_plugin_code(code, "test.py", strict_mode=True)

        assert not is_safe
        assert len(violations) == 1
        assert violations[0].violation_type == "dangerous_import"
        assert "subprocess" in violations[0].description

    def test_from_import_detected(self):
        """from subprocess import Popen should be detected"""
        code = '''
from subprocess import Popen

def plugin_function():
    return True
'''
        is_safe, violations = analyze_plugin_code(code, "test.py", strict_mode=True)

        assert not is_safe
        assert violations[0].violation_type == "dangerous_import"
        assert "subprocess" in violations[0].description

    def test_all_dangerous_modules_detected(self):
        """All dangerous modules should be detected"""
        # Note: 'os' and 'socket' are now allowed (file/network access controlled by sandbox)
        dangerous_modules = [
            'subprocess', 'ctypes', 'multiprocessing',
            'importlib', 'sys', 'shutil'
        ]

        for module in dangerous_modules:
            code = f'import {module}\n\ndef test(): pass'

            is_safe, violations = analyze_plugin_code(code, "test.py", strict_mode=True)

            assert not is_safe, f"Module '{module}' was not detected as dangerous"
            assert violations[0].violation_type == "dangerous_import"
            assert module in violations[0].description

    def test_subprocess_call_detected(self):
        """subprocess.Popen() call should be detected"""
        code = '''
import subprocess

def plugin_function():
    subprocess.Popen(["ls", "-la"])
    return True
'''
        is_safe, violations = analyze_plugin_code(code, "test.py", strict_mode=True)

        assert not is_safe
        violation_types = [v.violation_type for v in violations]
        assert "dangerous_import" in violation_types
        assert "subprocess_call" in violation_types


class TestSafeCode:
    """Tests that safe code passes analysis"""

    def test_safe_code_passes_analysis(self):
        """Safe plugin code should pass without violations"""
        code = '''
import json
import datetime
import hashlib

def plugin_function(data):
    """Safe plugin that uses allowed modules"""
    timestamp = datetime.datetime.now().isoformat()
    hash_obj = hashlib.sha256(data.encode())

    result = {
        "timestamp": timestamp,
        "hash": hash_obj.hexdigest(),
        "data": json.dumps(data)
    }

    return result
'''
        is_safe, violations = analyze_plugin_code(code, "test.py", strict_mode=True)

        assert is_safe
        assert len(violations) == 0

    def test_safe_imports_allowed(self):
        """Common safe imports should be allowed"""
        safe_imports = [
            'json', 'datetime', 'hashlib', 'base64', 'uuid',
            'collections', 'itertools', 'functools', 'typing',
            'os', 'socket'  # Now allowed (file/network access controlled by sandbox)
        ]

        for module in safe_imports:
            code = f'''
import {module}

def plugin_function():
    return True
'''
            is_safe, violations = analyze_plugin_code(code, "test.py", strict_mode=True)

            assert is_safe, f"Safe module '{module}' was incorrectly flagged as dangerous"
            assert len(violations) == 0

    def test_file_operations_allowed(self):
        """File operations (open) should be allowed - sandbox controls access"""
        code = '''
import os
import json

def plugin_function(config_dir):
    # Safe file operations - sandbox controls allowed paths
    config_file = os.path.join(config_dir, "config.json")

    with open(config_file, "r") as f:
        config = json.load(f)

    with open(config_file, "w") as f:
        json.dump(config, f)

    return config
'''
        is_safe, violations = analyze_plugin_code(code, "test.py", strict_mode=True)

        assert is_safe, "File operations should be allowed"
        assert len(violations) == 0


class TestSyntaxErrors:
    """Tests for handling invalid Python syntax"""

    def test_syntax_error_handled(self):
        """Invalid Python syntax should be caught"""
        code = '''
def plugin_function(
    # Missing closing parenthesis
    return True
'''
        is_safe, violations = analyze_plugin_code(code, "test.py", strict_mode=True)

        assert not is_safe
        assert len(violations) == 1
        assert violations[0].violation_type == "syntax_error"
        assert "syntax" in violations[0].description.lower()

    def test_incomplete_code_handled(self):
        """Incomplete code should be rejected"""
        code = '''
def plugin_function():
    if True:
'''
        is_safe, violations = analyze_plugin_code(code, "test.py", strict_mode=True)

        assert not is_safe
        assert violations[0].violation_type == "syntax_error"


class TestViolationDetails:
    """Tests for violation metadata"""

    def test_violation_includes_line_and_column(self):
        """Violations should include line and column numbers"""
        code = '''
def plugin_function():
    x = 1
    y = 2
    result = eval("x + y")
    return result
'''
        is_safe, violations = analyze_plugin_code(code, "test.py", strict_mode=True)

        assert len(violations) == 1
        assert violations[0].line == 5  # eval is on line 5
        assert violations[0].col >= 0

    def test_violation_includes_description(self):
        """Violations should have clear descriptions"""
        code = '''
def test():
    exec("code")
'''
        is_safe, violations = analyze_plugin_code(code, "test.py", strict_mode=True)

        assert len(violations) == 1
        assert len(violations[0].description) > 0
        assert "exec" in violations[0].description.lower()

    def test_violation_has_severity(self):
        """Violations should have severity levels"""
        code = '''
def test():
    eval("1 + 1")
'''
        is_safe, violations = analyze_plugin_code(code, "test.py", strict_mode=True)

        assert len(violations) == 1
        assert violations[0].severity == "critical"


class TestStrictVsPermissiveMode:
    """Tests for strict vs permissive mode behavior"""

    def test_strict_mode_blocks_critical_violations(self):
        """Strict mode should block code with critical violations"""
        code = '''
def test():
    eval("1 + 1")
'''
        is_safe, violations = analyze_plugin_code(code, "test.py", strict_mode=True)

        assert not is_safe
        assert len(violations) == 1

    def test_permissive_mode_allows_with_warnings(self):
        """Permissive mode should allow code but return violations"""
        code = '''
def test():
    eval("1 + 1")
'''
        is_safe, violations = analyze_plugin_code(code, "test.py", strict_mode=False)

        # In permissive mode, is_safe is True but violations are still returned
        assert is_safe
        assert len(violations) == 1  # Violations still detected


class TestMultipleViolations:
    """Tests for code with multiple security issues"""

    def test_multiple_violations_all_detected(self):
        """Code with multiple violations should detect all"""
        code = '''
import subprocess
import socket

def test():
    eval("1 + 1")
    exec("code")
    os.system("ls")
'''
        is_safe, violations = analyze_plugin_code(code, "test.py", strict_mode=True)

        assert not is_safe
        # Should detect: import subprocess, import socket, eval, exec, os.system (if os imported)
        assert len(violations) >= 4

    def test_complex_bypass_attempts_detected(self):
        """Complex code with multiple bypass attempts"""
        code = '''
import sys

def test():
    # Multiple bypass techniques
    e = getattr(__builtins__, "eval")
    x = __builtins__["exec"]
    s = sys.modules["subprocess"]

    # Direct dangerous calls
    compile("code", "file", "exec")
    __import__("socket")
'''
        is_safe, violations = analyze_plugin_code(code, "test.py", strict_mode=True)

        assert not is_safe
        assert len(violations) >= 5  # Many violations should be detected


class TestEdgeCases:
    """Tests for edge cases and corner scenarios"""

    def test_empty_file(self):
        """Empty file should be safe"""
        code = ''

        is_safe, violations = analyze_plugin_code(code, "test.py", strict_mode=True)

        assert is_safe
        assert len(violations) == 0

    def test_only_comments(self):
        """File with only comments should be safe"""
        code = '''
# This is a comment
# Another comment
'''
        is_safe, violations = analyze_plugin_code(code, "test.py", strict_mode=True)

        assert is_safe
        assert len(violations) == 0

    def test_docstring_only(self):
        """File with only docstring should be safe"""
        code = '''
"""
This is a module docstring.
It describes the module.
"""
'''
        is_safe, violations = analyze_plugin_code(code, "test.py", strict_mode=True)

        assert is_safe
        assert len(violations) == 0

    def test_dangerous_pattern_in_string_literal(self):
        """Dangerous patterns in string literals are not calls"""
        code = '''
def test():
    message = "Use eval() for evaluation"
    doc = "The exec() function is dangerous"
    return message + doc
'''
        # String literals containing "eval(" or "exec(" should not trigger violations
        # Only actual function calls should be detected
        is_safe, violations = analyze_plugin_code(code, "test.py", strict_mode=True)

        assert is_safe
        assert len(violations) == 0

    def test_dangerous_pattern_in_comment(self):
        """Dangerous patterns in comments should be ignored"""
        code = '''
def test():
    # Don't use eval() in production
    # exec() is also dangerous
    return True
'''
        is_safe, violations = analyze_plugin_code(code, "test.py", strict_mode=True)

        assert is_safe
        assert len(violations) == 0
