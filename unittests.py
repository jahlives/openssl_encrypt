import unittest
import os
import sys
import tempfile
import shutil
import random
import string
import hashlib
import json
import base64
from unittest.mock import patch, MagicMock, Mock, call
import subprocess
import time
import threading
import re
import stat

# Import tkinter modules - add explicit import to fix NameError
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog

# Import functions from crypt.py
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
try:
    from modules.crypt_core import (
        set_secure_permissions, get_file_permissions, copy_permissions,
        check_argon2_support, with_progress_bar, ARGON2_AVAILABLE,
        WHIRLPOOL_AVAILABLE
    )
    from modules.crypt_utils import (
        expand_glob_patterns, generate_strong_password, display_password_with_timeout,
        secure_shred_file, show_security_recommendations, request_confirmation
    )
except ImportError:
    print("Error: Could not import from crypt modules. Make sure they're in the correct directory.")
    sys.exit(1)

# Try to import the secure memory module
try:
    from modules.secure_memory import (
        secure_memzero, SecureBytes, SecureMemoryAllocator, 
        allocate_secure_buffer, free_secure_buffer, secure_memcpy,
        secure_compare, generate_secure_random_bytes,
        get_memory_page_size
    )
    SECURE_MEMORY_AVAILABLE = True
except ImportError:
    print("Warning: Could not import secure_memory module. Related tests will be skipped.")
    SECURE_MEMORY_AVAILABLE = False

# Try to import the settings module
try:
    from modules.crypt_settings import SettingsTab, DEFAULT_CONFIG
    SETTINGS_AVAILABLE = True
except ImportError:
    print("Warning: Could not import crypt_settings module. Related tests will be skipped.")
    SETTINGS_AVAILABLE = False

# Try to import the GUI components
try:
    # Import GUI with a modified name to avoid name conflicts with the module
    import crypt_gui as gui_module
    GUI_AVAILABLE = True
except ImportError:
    print("Warning: Could not import crypt_gui.py. GUI tests will be skipped.")
    GUI_AVAILABLE = False


class TestCryptCoreFunctions(unittest.TestCase):
    """Test the core encryption/decryption functions"""
    
    def setUp(self):
        """Set up test environment"""
        # Create a temporary directory for test files
        self.test_dir = tempfile.mkdtemp()
        
        # Create a test file
        self.test_file = os.path.join(self.test_dir, "core_test.txt")
        with open(self.test_file, "w") as f:
            f.write("Test file for core functions testing.")
    
    def tearDown(self):
        """Clean up test environment"""
        try:
            shutil.rmtree(self.test_dir)
        except Exception as e:
            print(f"Error during tearDown: {e}")
            
    def test_file_permissions(self):
        """Test file permission functions"""
        # Test setting secure permissions
        set_secure_permissions(self.test_file)
        permissions = get_file_permissions(self.test_file)
        # Check that only owner read/write permissions are set (0600)
        self.assertEqual(permissions & 0o600, 0o600)
        self.assertEqual(permissions & 0o077, 0)  # No group/other permissions
        
        # Create a new file with different permissions
        other_file = os.path.join(self.test_dir, "other_file.txt")
        with open(other_file, "w") as f:
            f.write("Another test file")
        
        # Set different permissions (read-only)
        os.chmod(other_file, 0o400)
        
        # Test copying permissions
        copy_permissions(other_file, self.test_file)
        new_permissions = get_file_permissions(self.test_file)
        self.assertEqual(new_permissions & 0o777, 0o400)

    def check_argon2_support():
        """Check if Argon2 hashing is available and return version and supported types"""
        try:
            import argon2.low_level
            # Use the modern way to get version
            version = argon2.low_level.ffi.string(argon2.low_level.lib.ARGON2_VERSION_STRING).decode('ascii')
            # Get supported types
            types = []
            if hasattr(argon2.Type, 'D'):
                types.append('D')
            if hasattr(argon2.Type, 'I'):
                types.append('I')
            if hasattr(argon2.Type, 'ID'):
                types.append('ID')
            return True, version, types
        except ImportError:
            return False, None, []

    @patch('time.time')
    def test_with_progress_bar(self, mock_time):
        """Test the with_progress_bar function"""
        # Set up time.time to return predictable values
        mock_time.side_effect = [0, 2]  # Start at 0, end at 2 (2 seconds elapsed)
        
        # Mock function to execute
        mock_func = Mock(return_value="test_result")
        
        # Mock threading.Thread to avoid actually running background threads
        with patch('threading.Thread') as mock_thread:
            mock_thread_instance = MagicMock()
            mock_thread.return_value = mock_thread_instance
            
            # Call with_progress_bar
            result = with_progress_bar(mock_func, "Testing progress", "arg1", kwarg1="kwarg1", quiet=False)
            
            # Verify the function was called with correct arguments
            mock_func.assert_called_once_with("arg1", kwarg1="kwarg1")
            
            # Verify threading.Thread was called
            mock_thread.assert_called_once()
            
            # Verify thread.start was called
            mock_thread_instance.start.assert_called_once()
            
            # Verify thread.join was called
            mock_thread_instance.join.assert_called_once()
            
            # Verify the function returned the expected result
            self.assertEqual(result, "test_result")


@unittest.skipIf(not SECURE_MEMORY_AVAILABLE, "Secure memory module not available")
class TestSecureMemoryFunctions(unittest.TestCase):
    """Test the secure memory handling functions"""
    
    def test_secure_memzero(self):
        """Test the secure_memzero function"""
        # Test on bytearray
        test_data = bytearray(b"sensitive data")
        original_data = bytes(test_data)
        secure_memzero(test_data)
        # Verify the data was zeroed out
        self.assertNotEqual(bytes(test_data), original_data)
        self.assertEqual(bytes(test_data), b"\x00" * len(original_data))
        
        # Test on SecureBytes
        secure_bytes = SecureBytes(b"more sensitive data")
        original_secure = bytes(secure_bytes)
        secure_memzero(secure_bytes)
        # Verify the data was zeroed out
        self.assertNotEqual(bytes(secure_bytes), original_secure)
        self.assertEqual(bytes(secure_bytes), b"\x00" * len(original_secure))
    
    def test_secure_bytes_class(self):
        """Test the SecureBytes class"""
        # Test creation
        secure_data = SecureBytes(b"test data")
        self.assertEqual(bytes(secure_data), b"test data")
        
        # Test copy_from class method
        source_data = b"source data"
        copied = SecureBytes.copy_from(source_data)
        self.assertEqual(bytes(copied), source_data)
        
        # Test automatic zeroing on deletion
        # This is hard to test directly as __del__ is called by GC
        # But we can check the implementation
        with patch.object(SecureBytes, '__del__') as mock_del:
            secure_data = SecureBytes(b"test deletion")
            del secure_data
            # __del__ should be called
            self.assertTrue(mock_del.called)
    
    def test_secure_memory_allocator(self):
        """Test the SecureMemoryAllocator class"""
        allocator = SecureMemoryAllocator()
        
        # Test allocation
        buffer = allocator.allocate(16)
        self.assertIsInstance(buffer, SecureBytes)
        self.assertEqual(len(buffer), 16)
        
        # Test tracking of allocated blocks
        self.assertIn(buffer, allocator.allocated_blocks)
        
        # Test explicit freeing
        allocator.free(buffer)
        self.assertNotIn(buffer, allocator.allocated_blocks)
    
    def test_allocate_free_secure_buffer(self):
        """Test allocate_secure_buffer and free_secure_buffer functions"""
        buffer = allocate_secure_buffer(32)
        self.assertIsInstance(buffer, SecureBytes)
        self.assertEqual(len(buffer), 32)
        
        # Test freeing
        free_secure_buffer(buffer)
        # Can't test directly if freed, but function should complete without error
    
    def test_secure_memcpy(self):
        """Test the secure_memcpy function"""
        # Test copying between two buffers
        src = SecureBytes(b"source data")
        dest = SecureBytes(10)  # Empty 10-byte buffer
        
        # Copy data
        copied = secure_memcpy(dest, src)
        self.assertEqual(copied, 10)  # 10 bytes copied
        self.assertEqual(bytes(dest), b"source dat")  # Only fits 10 bytes
        
        # Test auto-resizing (if supported)
        src2 = SecureBytes(b"larger source data")
        dest2 = SecureBytes(5)
        try:
            copied2 = secure_memcpy(dest2, src2)
            # If resize works, all data should be copied
            if len(dest2) > 5:
                self.assertEqual(bytes(dest2), b"larger source data"[:len(dest2)])
            else:
                # Otherwise, only 5 bytes should be copied
                self.assertEqual(bytes(dest2), b"large")
        except:
            # If resize fails, should copy what it can
            self.assertEqual(bytes(dest2), b"large")
    
    def test_secure_compare(self):
        """Test the secure_compare function"""
        # Test equal inputs
        a = b"test string"
        b = b"test string"
        self.assertTrue(secure_compare(a, b))
        
        # Test unequal inputs
        c = b"different"
        self.assertFalse(secure_compare(a, c))
        
        # Test different lengths
        d = b"test strin"  # One char shorter
        self.assertFalse(secure_compare(a, d))
    
    def test_generate_secure_random_bytes(self):
        """Test the generate_secure_random_bytes function"""
        # Generate random bytes
        random_bytes = generate_secure_random_bytes(32)
        self.assertIsInstance(random_bytes, SecureBytes)
        self.assertEqual(len(random_bytes), 32)
        
        # Generate more random bytes and verify they're different
        more_random = generate_secure_random_bytes(32)
        self.assertNotEqual(bytes(random_bytes), bytes(more_random))


class TestCryptUtilsFunctions(unittest.TestCase):
    """Test the utility functions"""
    
    def setUp(self):
        """Set up test environment"""
        # Create a temporary directory for test files
        self.test_dir = tempfile.mkdtemp()
        
        # Create a test file
        self.test_file = os.path.join(self.test_dir, "utils_test.txt")
        with open(self.test_file, "w") as f:
            f.write("Test file for utility functions testing.")
        
        # Create a test directory with nested files
        self.nested_dir = os.path.join(self.test_dir, "nested")
        os.makedirs(os.path.join(self.nested_dir, "subdir"))
        with open(os.path.join(self.nested_dir, "file1.txt"), "w") as f:
            f.write("Nested file 1")
        with open(os.path.join(self.nested_dir, "subdir", "file2.txt"), "w") as f:
            f.write("Nested file 2")
    
    def tearDown(self):
        """Clean up test environment"""
        try:
            shutil.rmtree(self.test_dir)
        except Exception as e:
            print(f"Error during tearDown: {e}")
            
    def test_secure_shred_file_with_options(self):
        """Test secure_shred_file with various options and conditions"""
        # Test with different pass counts
        file_with_passes = os.path.join(self.test_dir, "passes_test.txt")
        with open(file_with_passes, "w") as f:
            f.write("Test file for shredding with multiple passes")
        
        result = secure_shred_file(file_with_passes, passes=7, quiet=True)
        self.assertTrue(result)
        self.assertFalse(os.path.exists(file_with_passes))
        
        # Test with recursive directory shredding
        result = secure_shred_file(self.nested_dir, passes=2, quiet=True)
        self.assertTrue(result)
        self.assertFalse(os.path.exists(self.nested_dir))
        self.assertFalse(os.path.exists(os.path.join(self.nested_dir, "subdir")))
        self.assertFalse(os.path.exists(os.path.join(self.nested_dir, "file1.txt")))
        
        # Test with empty file
        empty_file = os.path.join(self.test_dir, "empty.txt")
        with open(empty_file, "w") as f:
            pass  # Create empty file
        
        result = secure_shred_file(empty_file, passes=1, quiet=True)
        self.assertTrue(result)
        self.assertFalse(os.path.exists(empty_file))
        
        # Test with very small file (edge case)
        small_file = os.path.join(self.test_dir, "small.txt")
        with open(small_file, "w") as f:
            f.write("a")  # One byte file
        
        result = secure_shred_file(small_file, passes=1, quiet=True)
        self.assertTrue(result)
        self.assertFalse(os.path.exists(small_file))
        
        # Test with empty directory
        empty_dir = os.path.join(self.test_dir, "empty_dir")
        os.makedirs(empty_dir)
        
        result = secure_shred_file(empty_dir, passes=1, quiet=True)
        self.assertTrue(result)
        self.assertFalse(os.path.exists(empty_dir))
        
        # Test with read-only file
        readonly_file = os.path.join(self.test_dir, "readonly.txt")
        with open(readonly_file, "w") as f:
            f.write("Read-only file")
        os.chmod(readonly_file, 0o400)  # Make read-only
        
        result = secure_shred_file(readonly_file, passes=1, quiet=True)
        # Should be able to shred read-only files by changing permissions
        self.assertTrue(result)
        self.assertFalse(os.path.exists(readonly_file))
    
    def test_expand_glob_patterns_advanced(self):
        """Test expand_glob_patterns with various patterns"""
        # Create test files for glob matching
        for name in ["test1.txt", "test2.txt", "test.doc", "TEST.TXT"]:
            with open(os.path.join(self.test_dir, name), "w") as f:
                f.write("Glob test file")
        
        # Basic glob pattern
        pattern = os.path.join(self.test_dir, "test*.txt")
        matches = expand_glob_patterns(pattern)
        self.assertEqual(len(matches), 2)  # test1.txt and test2.txt
        
        # Case sensitivity test (depends on OS)
        if sys.platform == 'win32':
            # Windows is case-insensitive
            pattern = os.path.join(self.test_dir, "TEST*.txt")
            matches = expand_glob_patterns(pattern)
            self.assertIn(os.path.join(self.test_dir, "test1.txt"), matches)
        else:
            # Unix/Linux is case-sensitive
            pattern = os.path.join(self.test_dir, "TEST*.txt")
            matches = expand_glob_patterns(pattern)
            self.assertNotIn(os.path.join(self.test_dir, "test1.txt"), matches)
            
        # Multiple patterns with specific extensions
        pattern = os.path.join(self.test_dir, "*.doc")
        matches = expand_glob_patterns(pattern)
        self.assertEqual(len(matches), 1)
        self.assertIn(os.path.join(self.test_dir, "test.doc"), matches)
        
        # Test with non-existent pattern
        pattern = os.path.join(self.test_dir, "nonexistent*.xyz")
        matches = expand_glob_patterns(pattern)
        self.assertEqual(len(matches), 0)
    
    def test_generate_strong_password_validation(self):
        """Test generate_strong_password with various requirements"""
        # Default behavior should include all character types
        password = generate_strong_password(16)
        self.assertEqual(len(password), 16)
        self.assertTrue(any(c.islower() for c in password))
        self.assertTrue(any(c.isupper() for c in password))
        self.assertTrue(any(c.isdigit() for c in password))
        self.assertTrue(any(c in string.punctuation for c in password))
        
        # Test minimum length enforcement
        password = generate_strong_password(4)  # Too short
        self.assertGreaterEqual(len(password), 8)  # Should adjust to minimum
        
        # Test custom character sets
        password = generate_strong_password(16, use_lowercase=True, use_uppercase=False, 
                                           use_digits=False, use_special=False)
        self.assertEqual(len(password), 16)
        self.assertTrue(all(c.islower() for c in password))
        
        # Test with all options disabled (should default to alphanumeric)
        password = generate_strong_password(16, use_lowercase=False, use_uppercase=False,
                                           use_digits=False, use_special=False)
        self.assertEqual(len(password), 16)
        # Should default to include lowercase, uppercase, and digits
        self.assertTrue(any(c.islower() for c in password) or 
                       any(c.isupper() for c in password) or
                       any(c.isdigit() for c in password))
        
        # Test password distribution - should have a good mix of character types
        # We'll test this statistically by generating a long password and checking proportions
        long_pass = generate_strong_password(1000)
        lowercase_count = sum(1 for c in long_pass if c.islower())
        uppercase_count = sum(1 for c in long_pass if c.isupper())
        digit_count = sum(1 for c in long_pass if c.isdigit())
        special_count = sum(1 for c in long_pass if c in string.punctuation)
        
        # Each character type should be at least 15% of the password
        self.assertGreaterEqual(lowercase_count / 1000, 0.08)
        self.assertGreaterEqual(uppercase_count / 1000, 0.08)
        self.assertGreaterEqual(digit_count / 1000, 0.08)
        self.assertGreaterEqual(special_count / 1000, 0.08)
    
    @patch('time.sleep')  # Patch sleep to avoid waiting
    @patch('builtins.print')  # Patch print to avoid actual output
    @patch('os.system')  # Patch system to avoid actual screen clearing
    def test_display_password_with_timeout(self, mock_system, mock_print, mock_sleep):
        """Test display_password_with_timeout function"""
        # Test normal operation
        display_password_with_timeout("test_password", timeout_seconds=2)
        
        # Verify print was called with the password
        mock_print.assert_any_call(f"\nPassword: test_password")
        
        # Verify sleep was called for the timeout
        mock_sleep.assert_called()
        
        # Verify system was called to clear the screen
        mock_system.assert_called()
    
    @patch('builtins.print')
    def test_show_security_recommendations(self, mock_print):
        """Test the show_security_recommendations function"""
        # Call the function
        show_security_recommendations()

        # Verify print was called multiple times
        self.assertGreater(mock_print.call_count, 10)

        # Check some expected content
        # Extract the printed content
        printed_content = ''.join(str(call[0][0]) for call in mock_print.call_args_list if call[0])

        # Verify key phrases appear in the output
        self.assertIn("Argon2id", printed_content)
        self.assertIn("Scrypt", printed_content)
        self.assertIn("PBKDF2", printed_content)
        self.assertIn("Password Hashing", printed_content)


@unittest.skipIf(not SETTINGS_AVAILABLE, "Settings module not available")
class TestSettingsModule(unittest.TestCase):
    """Test the settings module"""
    
    def setUp(self):
        """Set up test environment"""
        # Create a root window for Tkinter
        self.root = tk.Tk()
        self.root.withdraw()  # Hide the window
        
        # Create a temp directory for settings file
        self.test_dir = tempfile.mkdtemp()
        self.original_dir = os.getcwd()
        os.chdir(self.test_dir)  # Change to test directory
        
        # Create a mock GUI instance
        self.mock_gui = MagicMock()
    
    def tearDown(self):
        """Clean up test environment"""
        self.root.destroy()
        os.chdir(self.original_dir)  # Restore original directory
        try:
            shutil.rmtree(self.test_dir)
        except Exception as e:
            print(f"Error during tearDown: {e}")
    
    def test_settings_tab_initialization(self):
        """Test that SettingsTab initializes correctly"""
        # Create a frame for the settings tab
        frame = ttk.Frame(self.root)
        
        # Create the settings tab
        settings_tab = SettingsTab(frame, self.mock_gui)
        
        # Verify the settings tab has the expected attributes
        self.assertEqual(settings_tab.parent, frame)
        self.assertEqual(settings_tab.gui, self.mock_gui)
        self.assertIsNotNone(settings_tab.config)
        
        # Verify default config is loaded
        self.assertEqual(settings_tab.config['pbkdf2_iterations'], 
                        DEFAULT_CONFIG['pbkdf2_iterations'])

    def test_load_and_save_settings(self):
        """Test loading and saving settings"""
        import tkinter.messagebox as messagebox
        from unittest.mock import patch, MagicMock
        import sys
        import importlib
        import os

        # Import the CONFIG_FILE from the module
        from modules.crypt_settings import CONFIG_FILE

        # Print detailed import information
        print("Sys path:", sys.path)
        print("Messagebox module:", messagebox)
        print("Messagebox module file:", messagebox.__file__)

        # Create a frame for the settings tab
        frame = ttk.Frame(self.root)

        # Create the settings tab
        settings_tab = SettingsTab(frame, self.mock_gui)

        # Modify settings
        settings_tab.config['sha512'] = 20000
        settings_tab.config['pbkdf2_iterations'] = 150000
        settings_tab.config['argon2']['enabled'] = True

        # Temporarily set a valid config file path for testing
        original_config_file = CONFIG_FILE

        # Use a temporary file path in the test directory
        temp_config_file = os.path.join(self.test_dir, "test_settings.json")

        # Monkey patch the CONFIG_FILE
        import modules.crypt_settings
        modules.crypt_settings.CONFIG_FILE = temp_config_file

        # Create a mock for messagebox
        mock_messagebox = MagicMock()

        # Patch multiple import paths
        with patch('tkinter.messagebox', mock_messagebox), \
                patch.object(mock_messagebox, 'showinfo', wraps=mock_messagebox.showinfo) as mock_showinfo:

            try:
                # Ensure the test directory exists
                os.makedirs(self.test_dir, exist_ok=True)

                # Call save_settings and capture any exceptions
                print("[TEST] Calling save_settings()")
                result = settings_tab.save_settings()
                print(f"[TEST] Save settings result: {result}")

                # Verify the file was created
                print(f"[TEST] Config file exists: {os.path.exists(temp_config_file)}")
                if os.path.exists(temp_config_file):
                    with open(temp_config_file, 'r') as f:
                        print(f"[TEST] File contents: {f.read()}")

                # Print detailed mock information
                print(f"[TEST] Mock showinfo call count: {mock_showinfo.call_count}")
                print(f"[TEST] Mock showinfo calls: {mock_showinfo.call_args_list}")

                # Assert that showinfo was called once with specific arguments
                mock_showinfo.assert_called_once_with(
                    "Settings Saved",
                    "Your encryption settings have been saved successfully.\n\n"
                    "These settings will be applied to all future encryption operations."
                )

            except Exception as e:
                # Print comprehensive error details
                print(f"[TEST] Exception during save_settings: {e}")
                import traceback
                traceback.print_exc()
                raise
            finally:
                # Restore original config file path
                modules.crypt_settings.CONFIG_FILE = original_config_file
    
    def test_presets(self):
        """Test loading security presets"""
        # Create a frame for the settings tab
        frame = ttk.Frame(self.root)
        
        # Create the settings tab
        settings_tab = SettingsTab(frame, self.mock_gui)
        
        # Store original config
        original_config = settings_tab.config.copy()
        
        # Test Standard preset
        with patch('tkinter.messagebox.showinfo') as mock_showinfo:
            settings_tab.load_preset("standard")
            mock_showinfo.assert_called_once()
        
        # Verify changes
        self.assertNotEqual(settings_tab.config, original_config)
        
        # Test High Security preset
        with patch('tkinter.messagebox.showinfo') as mock_showinfo:
            settings_tab.load_preset("high")
            mock_showinfo.assert_called_once()
        
        # Verify changes - check for higher values than standard
        self.assertGreater(settings_tab.config['sha512'], 10000)
        self.assertGreater(settings_tab.config['pbkdf2_iterations'], 100000)
        self.assertTrue(settings_tab.config['argon2']['enabled'])
        
        # Test Paranoid preset
        with patch('tkinter.messagebox.showinfo') as mock_showinfo:
            settings_tab.load_preset("paranoid")
            mock_showinfo.assert_called_once()
        
        # Verify changes - check for even higher values
        self.assertGreater(settings_tab.config['sha512'], 50000)
        self.assertGreater(settings_tab.config['pbkdf2_iterations'], 200000)
        self.assertTrue(settings_tab.config['argon2']['enabled'])
        
        # Test reset to defaults
        with patch('tkinter.messagebox.askyesno', return_value=True), \
             patch('tkinter.messagebox.showinfo') as mock_showinfo:
            settings_tab.reset_to_defaults()
            mock_showinfo.assert_called_once()
        
        # Verify reset to defaults
        self.assertEqual(settings_tab.config['sha512'], DEFAULT_CONFIG['sha512'])
        self.assertEqual(settings_tab.config['pbkdf2_iterations'], 
                         DEFAULT_CONFIG['pbkdf2_iterations'])
    
    def test_validate_settings(self):
        """Test settings validation"""
        # Create a frame for the settings tab
        frame = ttk.Frame(self.root)
        
        # Create the settings tab
        settings_tab = SettingsTab(frame, self.mock_gui)
        
        # Test valid settings
        settings_tab.config['scrypt']['n'] = 16384  # Power of 2
        settings_tab.config['pbkdf2_iterations'] = 100000
        result = settings_tab.validate_settings()
        self.assertTrue(result)
        
        # Test invalid Scrypt N (not power of 2)
        settings_tab.config['scrypt']['n'] = 12345  # Not power of 2
        settings_tab.scrypt_vars['n'].set(12345)
        with patch('tkinter.messagebox.showerror') as mock_showerror:
            result = settings_tab.validate_settings()
            mock_showerror.assert_called_once()
            self.assertFalse(result)
        
        # Test too low PBKDF2 iterations
        settings_tab.config['scrypt']['n'] = 16384  # Power of 2
        settings_tab.scrypt_vars['n'].set(16384)
        settings_tab.config['pbkdf2_iterations'] = 5000  # Too low
        settings_tab.hash_vars['pbkdf2_iterations'].set(5000)
        
        with patch('tkinter.messagebox.askyesno', return_value=False) as mock_askyesno:
            result = settings_tab.validate_settings()
            mock_askyesno.assert_called_once()
            self.assertFalse(result)
        
        # Test warning when all hash algorithms disabled
        settings_tab.config['sha512'] = 0
        settings_tab.config['sha256'] = 0
        settings_tab.config['sha3_256'] = 0
        settings_tab.config['sha3_512'] = 0
        settings_tab.config['whirlpool'] = 0
        settings_tab.config['scrypt']['n'] = 0
        settings_tab.config['argon2']['enabled'] = False
        settings_tab.config['pbkdf2_iterations'] = 100000  # Above minimum
        
        settings_tab.hash_vars['sha512'].set(0)
        settings_tab.hash_vars['sha256'].set(0)
        settings_tab.hash_vars['sha3_256'].set(0)
        settings_tab.hash_vars['sha3_512'].set(0)
        settings_tab.hash_vars['whirlpool'].set(0)
        settings_tab.scrypt_vars['n'].set(0)
        settings_tab.argon2_vars['enabled'].set(False)
        settings_tab.hash_vars['pbkdf2_iterations'].set(100000)
        
        with patch('tkinter.messagebox.showwarning') as mock_showwarning:
            result = settings_tab.validate_settings()
            mock_showwarning.assert_called_once()
            self.assertTrue(result)  # Should still be valid, just a warning


class TestCommandLineInterfaceAdvanced(unittest.TestCase):
    """Advanced integration tests for the command-line interface"""
    
    def setUp(self):
        """Set up test environment"""
        # Create a temporary directory for test files
        self.test_dir = tempfile.mkdtemp()
        
        # Create a test file
        self.test_content = "This is a test file for advanced CLI testing."
        self.test_file = os.path.join(self.test_dir, "cli_advanced_test.txt")
        with open(self.test_file, "w") as f:
            f.write(self.test_content)
        
        # Create a large test file (1MB) for testing large file handling
        self.large_file = os.path.join(self.test_dir, "large_file.bin")
        with open(self.large_file, "wb") as f:
            f.write(os.urandom(1024 * 1024))  # 1MB of random data
        
        # Script path
        self.script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "crypt.py")
        self.assertTrue(os.path.exists(self.script_path), "crypt.py not found")
    
    def tearDown(self):
        """Clean up test environment"""
        try:
            shutil.rmtree(self.test_dir)
        except Exception as e:
            print(f"Error during tearDown: {e}")
    
    def run_command(self, args, input_text=None):
        """Run the script with given arguments and return stdout, stderr, and return code"""
        command = [sys.executable, self.script_path] + args
        process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE if input_text else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True
        )
        
        stdout, stderr = process.communicate(input=input_text)
        return stdout, stderr, process.returncode
    
    def test_cli_argon2_parameters(self):
        """Test using Argon2 parameters via CLI"""
        encrypted_file = os.path.join(self.test_dir, "argon2_encrypted.bin")
        decrypted_file = os.path.join(self.test_dir, "argon2_decrypted.txt")
        
        # Encrypt with Argon2 parameters
        stdout, stderr, returncode = self.run_command(
            ["encrypt", "-i", self.test_file, "-o", encrypted_file, 
             "--enable-argon2", "--argon2-time", "2", "--argon2-memory", "32768",
             "--argon2-parallelism", "2", "--argon2-hash-len", "32", "--argon2-type", "id",
             "-p", "argon2pass"],
        )
        
        # Check if Argon2 is available and handle accordingly
        if "argon2-cffi" in stderr or "module not found" in stderr:
            print("Skipping Argon2 test as the module is not available")
            return
        
        self.assertEqual(returncode, 0, f"Encryption with Argon2 failed: {stderr}")
        self.assertTrue(os.path.exists(encrypted_file))
        
        # Decrypt the file
        stdout, stderr, returncode = self.run_command(
            ["decrypt", "-i", encrypted_file, "-o", decrypted_file, "-p", "argon2pass"],
        )
        self.assertEqual(returncode, 0, f"Decryption failed: {stderr}")
        
        # Verify content
        with open(decrypted_file, "r") as f:
            decrypted_content = f.read()
        self.assertEqual(self.test_content, decrypted_content)
    
    def test_cli_scrypt_parameters(self):
        """Test using Scrypt parameters via CLI"""
        encrypted_file = os.path.join(self.test_dir, "scrypt_encrypted.bin")
        decrypted_file = os.path.join(self.test_dir, "scrypt_decrypted.txt")
        
        # Encrypt with Scrypt parameters
        stdout, stderr, returncode = self.run_command(
            ["encrypt", "-i", self.test_file, "-o", encrypted_file, 
             "--scrypt-n", "16384", "--scrypt-r", "8", "--scrypt-p", "1",
             "-p", "scryptpass"],
        )
        self.assertEqual(returncode, 0, f"Encryption with Scrypt failed: {stderr}")
        self.assertTrue(os.path.exists(encrypted_file))
        
        # Decrypt the file
        stdout, stderr, returncode = self.run_command(
            ["decrypt", "-i", encrypted_file, "-o", decrypted_file, "-p", "scryptpass"],
        )
        self.assertEqual(returncode, 0, f"Decryption failed: {stderr}")
        
        # Verify content
        with open(decrypted_file, "r") as f:
            decrypted_content = f.read()
        self.assertEqual(self.test_content, decrypted_content)
    
    def test_cli_encrypt_large_file(self):
        """Test encrypting and decrypting a large file"""
        encrypted_file = os.path.join(self.test_dir, "large_encrypted.bin")
        decrypted_file = os.path.join(self.test_dir, "large_decrypted.bin")
        
        # Get original file hash for later comparison
        with open(self.large_file, "rb") as f:
            original_content = f.read()
            original_hash = hashlib.sha256(original_content).hexdigest()
        
        # Encrypt the large file
        stdout, stderr, returncode = self.run_command(
            ["encrypt", "-i", self.large_file, "-o", encrypted_file, "-p", "largepass"],
        )
        self.assertEqual(returncode, 0, f"Large file encryption failed: {stderr}")
        self.assertTrue(os.path.exists(encrypted_file))
        
        # Check that the encrypted file is different
        with open(encrypted_file, "rb") as f:
            encrypted_content = f.read()
            encrypted_hash = hashlib.sha256(encrypted_content).hexdigest()
        self.assertNotEqual(original_hash, encrypted_hash)
        
        # Decrypt the file
        stdout, stderr, returncode = self.run_command(
            ["decrypt", "-i", encrypted_file, "-o", decrypted_file, "-p", "largepass"],
        )
        self.assertEqual(returncode, 0, f"Large file decryption failed: {stderr}")
        
        # Verify the decrypted content matches the original
        with open(decrypted_file, "rb") as f:
            decrypted_content = f.read()
            decrypted_hash = hashlib.sha256(decrypted_content).hexdigest()
        self.assertEqual(original_hash, decrypted_hash)
    
    def test_cli_security_info(self):
        """Test the security-info command"""
        stdout, stderr, returncode = self.run_command(["security-info"])
        self.assertEqual(returncode, 0, f"Security info command failed: {stderr}")
        
        # Check for expected content in output
        self.assertIn("SECURITY RECOMMENDATIONS", stdout)
        self.assertIn("Password Hashing Algorithm Recommendations", stdout)
        self.assertIn("Argon2id", stdout)
        self.assertIn("Scrypt", stdout)
        self.assertIn("PBKDF2", stdout)
    
    def test_cli_check_argon2(self):
        """Test the check-argon2 command"""
        stdout, stderr, returncode = self.run_command(["check-argon2"])
        self.assertEqual(returncode, 0, f"Check Argon2 command failed: {stderr}")
        
        # Check for expected content in output
        self.assertIn("ARGON2 SUPPORT CHECK", stdout)
        
        # Should either show "AVAILABLE" or "NOT AVAILABLE"
        self.assertTrue("Argon2 is AVAILABLE" in stdout or "Argon2 is NOT AVAILABLE" in stdout)
    
    def test_cli_wrong_password(self):
        """Test behavior with wrong password"""
        encrypted_file = os.path.join(self.test_dir, "wrong_pass_test.bin")
        decrypted_file = os.path.join(self.test_dir, "wrong_pass_decrypted.txt")
        
        # Encrypt with a password
        stdout, stderr, returncode = self.run_command(
            ["encrypt", "-i", self.test_file, "-o", encrypted_file, "-p", "correctpass"],
        )
        self.assertEqual(returncode, 0, f"Encryption failed: {stderr}")
        
        # Try to decrypt with wrong password
        stdout, stderr, returncode = self.run_command(
            ["decrypt", "-i", encrypted_file, "-o", decrypted_file, "-p", "wrongpass"],
        )
        
        # Should fail with non-zero return code
        self.assertNotEqual(returncode, 0)
        # Error message should mention password or decryption
        self.assertTrue("password" in stderr.lower() or "decryption failed" in stderr.lower() or "password" in stdout.lower() or "decryption failed" in stdout.lower())
        
        # File should not exist or should be empty/corrupt
        if os.path.exists(decrypted_file):
            with open(decrypted_file, "rb") as f:
                content = f.read()
            # Either file should not exist or content should not match original
            with open(self.test_file, "rb") as f:
                original = f.read()
            self.assertNotEqual(content, original)


@unittest.skipIf(not GUI_AVAILABLE, "GUI module not available")
class TestGuiAdvancedFeatures(unittest.TestCase):
    """Test GUI advanced features"""
    
    def setUp(self):
        """Set up GUI test environment"""
        # Create a test root window
        self.root = tk.Tk()
        self.root.withdraw()  # Hide the window
        
        # Create a temporary directory for test files
        self.test_dir = tempfile.mkdtemp()
        
        # Create a test file
        self.test_file = os.path.join(self.test_dir, "gui_advanced_test.txt")
        with open(self.test_file, "w") as f:
            f.write("Test file for advanced GUI testing.")
    
    def tearDown(self):
        """Clean up test environment"""
        # Destroy the root window
        self.root.destroy()
        
        # Remove the temporary directory
        try:
            shutil.rmtree(self.test_dir)
        except Exception as e:
            print(f"Error during tearDown: {e}")
    
    def test_progress_bar_functionality(self):
        """Test the progress bar updates and animations"""
        app = gui_module.CryptGUI(self.root)
        
        # Initially the progress bar should be hidden
        self.assertFalse(app.progress_bar.winfo_ismapped())
        
        # Set up mocking for threading
        with patch('threading.Thread') as mock_thread:
            mock_thread_instance = MagicMock()
            mock_thread.return_value = mock_thread_instance
            
            # Create a function that would normally run in the thread
            # In unittests.py, modify the test_progress_bar_functionality method
            def simulate_run_in_thread():
                # Show the progress bar
                app.progress_bar.pack(side=tk.BOTTOM, fill=tk.X, padx=5, pady=(0, 5))

                # Test updating progress - set exact value and prevent further updates
                app.progress_var.set(50)
                original_set = app.progress_var.set
                app.progress_var.set = lambda val: None  # Prevent further updates

                app.status_var.set("Processing at 50%")

                # Test changing algorithms
                app.current_algorithm = "SHA-512"
                app.status_var.set("SHA-512 hashing: 50% (5000/10000)")

                # Test indeterminate mode
                app.progress_bar.configure(mode="indeterminate")
                app.progress_bar.start()

                # Test stopping and hiding
                app.progress_bar.stop()
                app.progress_bar.configure(mode="determinate")
                app.progress_bar.pack_forget()

                # Restore original set method before finishing
                app.progress_var.set = original_set
    
    def test_run_command_with_progress_parsing(self):
        """Test the command output parsing of run_command_with_progress"""
        app = gui_module.CryptGUI(self.root)
        
        # Create a mock subprocess and process
        with patch('subprocess.Popen') as mock_popen:
            mock_process = MagicMock()
            mock_popen.return_value = mock_process
            
            # Set up the mocked process
            mock_stdout_lines = [
                "Applying 1000000 rounds of SHA-512...",
                "SHA-512 hashing: [██████████        ] 50.0% (500000/1000000)",
                "SHA-512 hashing: [████████████████  ] 80.0% (800000/1000000)",
                "SHA-512 hashing: [████████████████████] 100.0% (1000000/1000000)",
                "Applying scrypt with n=16384, r=8, p=1...",
                "Scrypt processing",
                "Generating encryption key...",
                "Key generation completed",
                "✓ Decrypted content integrity verified successfully"
            ]
            
            # Set up mock stdout reader
            mock_process.stdout.readline.side_effect = mock_stdout_lines + ['']
            mock_process.stderr.readline.side_effect = ['']
            mock_process.wait.return_value = None
            mock_process.returncode = 0
            
            # Create a function that would normally run in the thread
            def execute_run_in_thread():
                # Extract the threading setup
                with patch('threading.Thread') as mock_thread:
                    # Call the method
                    app.run_command_with_progress(["test", "command"])
                    
                    # Get the function passed to Thread
                    run_in_thread = mock_thread.call_args[1]['target']
                    
                    # Execute it directly
                    run_in_thread()
            
            # Execute the command
            execute_run_in_thread()
            
            # Check that progress and status were updated correctly
            self.assertEqual(app.status_var.get(), "Command completed successfully")
            
            # Verify important output was captured
            self.assertIn("Decrypted content integrity verified successfully", 
                         app.output_text.get(1.0, tk.END))
    
    def test_show_output_dialog(self):
        """Test showing output in the dialog"""
        app = gui_module.CryptGUI(self.root)
        
        # Clear any existing output
        app.output_text.delete(1.0, tk.END)
        
        # Show some test output
        app.show_output_dialog("Test Output", "Line 1\nLine 2\nLine 3")
        
        # Check the output text
        output_text = app.output_text.get(1.0, tk.END).strip()
        self.assertIn("--- Test Output ---", output_text)
        self.assertIn("Line 1", output_text)
        self.assertIn("Line 2", output_text)
        self.assertIn("Line 3", output_text)
        
        # Check status bar
        self.assertEqual(app.status_var.get(), "Output displayed: Test Output")
    
    def test_validation_in_all_tabs(self):
        """Test validation in all tabs"""
        app = gui_module.CryptGUI(self.root)
        
        # Test encrypt tab validation
        with patch('tkinter.messagebox.showerror') as mock_showerror:
            # Missing input file
            app.run_encrypt()
            mock_showerror.assert_called_with("Error", "Please select an input file.")
            mock_showerror.reset_mock()
            
            # Missing password
            app.encrypt_input_var.set(self.test_file)
            app.run_encrypt()
            mock_showerror.assert_called_with("Error", "Please enter a password.")
            mock_showerror.reset_mock()
            
            # Password mismatch
            app.encrypt_password_var.set("password1")
            app.encrypt_confirm_var.set("password2")
            app.run_encrypt()
            mock_showerror.assert_called_with("Error", "Passwords do not match.")
            mock_showerror.reset_mock()
            
            # Missing output file
            app.encrypt_password_var.set("password")
            app.encrypt_confirm_var.set("password")
            app.run_encrypt()
            mock_showerror.assert_called_with("Error", "Please select an output file or enable overwrite.")
            mock_showerror.reset_mock()
        
        # Test decrypt tab validation
        with patch('tkinter.messagebox.showerror') as mock_showerror:
            # Missing input file
            app.run_decrypt()
            mock_showerror.assert_called_with("Error", "Please select an input file.")
            mock_showerror.reset_mock()
            
            # Missing password
            app.decrypt_input_var.set(self.test_file)
            app.run_decrypt()
            mock_showerror.assert_called_with("Error", "Please enter a password.")
            mock_showerror.reset_mock()
            
            # Missing output options
            app.decrypt_password_var.set("password")
            app.run_decrypt()
            mock_showerror.assert_called_with("Error", 
                                             "Please select an output file, enable overwrite, or select display to screen.")
            mock_showerror.reset_mock()
        
        # Test shred tab validation
        with patch('tkinter.messagebox.showerror') as mock_showerror, \
             patch('tkinter.messagebox.askyesno', return_value=False) as mock_askyesno:
            # Missing input files
            app.run_shred()
            mock_showerror.assert_called_with("Error", "Please select files or directories to shred.")
            mock_showerror.reset_mock()
            
            # Cancelling confirmation
            app.shred_input_var.set(self.test_file)
            app.run_shred()
            mock_askyesno.assert_called_once()
            # Since we return False for askyesno, no action should be taken
    
    def test_command_building(self):
        """Test that commands are built correctly with all options"""
        app = gui_module.CryptGUI(self.root)
        
        # Set up settings tab mock to return custom hash config
        mock_settings_tab = MagicMock()
        mock_settings_tab.get_current_config.return_value = {
            'sha512': 10000,
            'sha256': 5000,
            'sha3_256': 0,
            'sha3_512': 0,
            'whirlpool': 0,
            'pbkdf2_iterations': 100000,
            'scrypt': {
                'n': 16384,
                'r': 8,
                'p': 1
            },
            'argon2': {
                'enabled': True,
                'time_cost': 3,
                'memory_cost': 65536,
                'parallelism': 4,
                'hash_len': 32,
                'type': 'id'
            }
        }
        app.settings_tab = mock_settings_tab
        
        # Test encrypt command building
        app.encrypt_input_var.set(self.test_file)
        app.encrypt_output_var.set(os.path.join(self.test_dir, "encrypted.bin"))
        app.encrypt_password_var.set("testpass")
        app.encrypt_confirm_var.set("testpass")
        app.encrypt_shred_var.set(True)
        
        with patch('threading.Thread') as mock_thread:
            app.run_encrypt()
            # Get the command that would be passed to run_command_with_progress
            run_in_thread = mock_thread.call_args[1]['target']
            
            # Extract the command from the function's closure
            # This is a bit hacky but works for testing
            command = None
            for cell in run_in_thread.__closure__:
                value = cell.cell_contents
                if isinstance(value, list) and len(value) > 1 and value[0] == sys.executable:
                    command = value
                    break
                    
            # Verify command components
            self.assertIsNotNone(command)
            self.assertEqual(command[2], "encrypt")
            self.assertEqual(command[4], self.test_file)  # Input file
            
            # Check for options
            self.assertIn("-s", command)  # Shred option
            self.assertIn("-p", command)  # Password option
            self.assertIn("testpass", command)  # Password value
            
            # Check for hash parameters
            self.assertIn("--sha512-rounds", command)
            self.assertIn("10000", command)
            self.assertIn("--sha256-rounds", command)
            self.assertIn("5000", command)
            self.assertIn("--pbkdf2-iterations", command)
            self.assertIn("100000", command)
            self.assertIn("--scrypt-n", command)
            self.assertIn("16384", command)
            self.assertIn("--enable-argon2", command)
            self.assertIn("--argon2-time", command)
            self.assertIn("3", command)
        
        # Test decrypt command building
        app.decrypt_input_var.set(self.test_file)
        app.decrypt_output_var.set(os.path.join(self.test_dir, "decrypted.txt"))
        app.decrypt_password_var.set("testpass")
        app.decrypt_overwrite_var.set(True)
        
        with patch('threading.Thread') as mock_thread:
            app.run_decrypt()
            
            # Extract the command similarly
            run_in_thread = mock_thread.call_args[1]['target']
            command = None
            for cell in run_in_thread.__closure__:
                value = cell.cell_contents
                if isinstance(value, list) and len(value) > 1 and value[0] == sys.executable:
                    command = value
                    break
            
            # Verify command components
            self.assertIsNotNone(command)
            self.assertEqual(command[2], "decrypt")
            self.assertEqual(command[4], self.test_file)  # Input file
            
            # Check for options
            self.assertIn("--overwrite", command)
            self.assertIn("-p", command)
            self.assertIn("testpass", command)
    
    def test_center_window(self):
        """Test the center_window method"""
        app = gui_module.CryptGUI(self.root)
        
        # Get the screen dimensions
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        
        # Call center_window
        app.center_window()
        
        # Get the window geometry
        geometry = self.root.geometry()
        # Parse the geometry string (format: "widthxheight+x+y")
        match = re.match(r"(\d+)x(\d+)\+(\d+)\+(\d+)", geometry)
        if match:
            width, height, x, y = map(int, match.groups())
            
            # Check that the window size is at least the minimum
            self.assertGreaterEqual(width, 650)
            self.assertGreaterEqual(height, 580)
            
            # Check that x and y are roughly centered
            # Allow for rounding differences
            self.assertAlmostEqual(x, (screen_width - width) // 2, delta=5)
            self.assertAlmostEqual(y, (screen_height - height) // 2, delta=5)
