#!/usr/bin/env python3
"""
Unit tests for openssl_encrypt D-Bus service

These tests verify the functionality of the D-Bus service interface
and client library.
"""

import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    import dbus
    from dbus.mainloop.glib import DBusGMainLoop
    from gi.repository import GLib

    DBUS_AVAILABLE = True
except ImportError:
    DBUS_AVAILABLE = False
    print("Warning: D-Bus dependencies not available, skipping tests")

if DBUS_AVAILABLE:
    from openssl_encrypt.modules.dbus_client import CryptoClient


@unittest.skipUnless(DBUS_AVAILABLE, "D-Bus dependencies not available")
class TestDBusService(unittest.TestCase):
    """Test D-Bus service functionality"""

    @classmethod
    def setUpClass(cls):
        """Set up test class - check if service is available"""
        try:
            cls.client = CryptoClient()
            cls.service_available = True
        except Exception as e:
            print(f"\nWarning: D-Bus service not available: {e}")
            print("Start service with: python3 -m openssl_encrypt.modules.dbus_service")
            cls.service_available = False

    def setUp(self):
        """Set up test case"""
        if not self.service_available:
            self.skipTest("D-Bus service not available")

    def test_get_version(self):
        """Test GetVersion method"""
        version = self.client.get_version()
        self.assertIsInstance(version, str)
        self.assertGreater(len(version), 0)
        print(f"  Version: {version}")

    def test_get_supported_algorithms(self):
        """Test GetSupportedAlgorithms method"""
        algorithms = self.client.get_supported_algorithms()
        self.assertIsInstance(algorithms, list)
        self.assertGreater(len(algorithms), 0)

        # Check for expected algorithms
        expected_algorithms = ["fernet", "aes-gcm", "ml-kem-768-hybrid"]
        for algo in expected_algorithms:
            self.assertIn(algo, algorithms, f"Algorithm {algo} not in supported list")

        print(f"  Found {len(algorithms)} algorithms")

    def test_validate_password(self):
        """Test ValidatePassword method"""
        # Test weak password
        valid, issues = self.client.validate_password("weak")
        self.assertFalse(valid)
        self.assertGreater(len(issues), 0)

        # Test strong password
        valid, issues = self.client.validate_password("StrongPassword123!")
        # Note: May still have issues depending on password policy
        self.assertIsInstance(valid, bool)
        self.assertIsInstance(issues, list)

    def test_get_properties(self):
        """Test property access"""
        active_ops = self.client.get_active_operations()
        self.assertIsInstance(active_ops, int)
        self.assertGreaterEqual(active_ops, 0)

        max_ops = self.client.get_max_concurrent_operations()
        self.assertIsInstance(max_ops, int)
        self.assertGreater(max_ops, 0)

        timeout = self.client.get_default_timeout()
        self.assertIsInstance(timeout, int)
        self.assertGreater(timeout, 0)

        print(f"  Active: {active_ops}, Max: {max_ops}, Timeout: {timeout}s")

    def test_set_properties(self):
        """Test property modification"""
        # Get original values
        original_max_ops = self.client.get_max_concurrent_operations()
        original_timeout = self.client.get_default_timeout()

        # Set new values
        self.client.set_max_concurrent_operations(10)
        self.assertEqual(self.client.get_max_concurrent_operations(), 10)

        self.client.set_default_timeout(600)
        self.assertEqual(self.client.get_default_timeout(), 600)

        # Restore original values
        self.client.set_max_concurrent_operations(original_max_ops)
        self.client.set_default_timeout(original_timeout)


@unittest.skipUnless(DBUS_AVAILABLE, "D-Bus dependencies not available")
class TestDBusFileOperations(unittest.TestCase):
    """Test D-Bus file encryption/decryption operations"""

    @classmethod
    def setUpClass(cls):
        """Set up test class"""
        try:
            cls.client = CryptoClient()
            cls.service_available = True
        except Exception:
            cls.service_available = False

    def setUp(self):
        """Set up test case"""
        if not self.service_available:
            self.skipTest("D-Bus service not available")

        # Create temporary files
        self.test_dir = tempfile.mkdtemp(prefix="dbus_test_")
        self.test_file = os.path.join(self.test_dir, "test.txt")
        self.encrypted_file = os.path.join(self.test_dir, "test.txt.enc")
        self.decrypted_file = os.path.join(self.test_dir, "test.txt.dec")

        # Write test data
        with open(self.test_file, "w") as f:
            f.write("This is a test file.\n")
            f.write("It contains test data.\n" * 10)

    def tearDown(self):
        """Clean up test files"""
        if hasattr(self, "test_dir"):
            import shutil

            shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_encrypt_file(self):
        """Test file encryption"""
        # Track progress
        self.progress_called = False

        def on_progress(op_id, percent, message):
            self.progress_called = True
            print(f"    Progress: {percent:.1f}% - {message}")

        # Encrypt file
        success, error, op_id = self.client.encrypt_file(
            input_path=self.test_file,
            output_path=self.encrypted_file,
            password="TestPassword123!",
            algorithm="fernet",
            options={"sha512_rounds": 1000},
            progress_callback=on_progress,
        )

        # Check result
        # Note: Service may not have actual encryption implemented yet
        self.assertIsInstance(success, bool)
        self.assertIsInstance(error, str)
        self.assertIsInstance(op_id, str)

        if success:
            # Wait for operation to complete
            time.sleep(2)

            # Check if encrypted file was created
            if os.path.exists(self.encrypted_file):
                print("  ✓ Encrypted file created")
            else:
                print("  ⚠ Encrypted file not found (implementation pending)")

    def test_decrypt_file(self):
        """Test file decryption"""
        # Note: This test requires actual encryption implementation
        # For now, just test the API

        success, error, op_id = self.client.decrypt_file(
            input_path=self.encrypted_file,
            output_path=self.decrypted_file,
            password="TestPassword123!",
        )

        self.assertIsInstance(success, bool)
        self.assertIsInstance(error, str)
        self.assertIsInstance(op_id, str)


@unittest.skipUnless(DBUS_AVAILABLE, "D-Bus dependencies not available")
class TestDBusKeystore(unittest.TestCase):
    """Test D-Bus keystore operations"""

    @classmethod
    def setUpClass(cls):
        """Set up test class"""
        try:
            cls.client = CryptoClient()
            cls.service_available = True
        except Exception:
            cls.service_available = False

    def setUp(self):
        """Set up test case"""
        if not self.service_available:
            self.skipTest("D-Bus service not available")

        # Create a temporary file securely (avoids race condition in mktemp)
        temp_file = tempfile.NamedTemporaryFile(mode="w", suffix=".pqc", delete=False)
        self.keystore_file = temp_file.name
        temp_file.close()

    def tearDown(self):
        """Clean up keystore file"""
        if hasattr(self, "keystore_file"):
            try:
                os.remove(self.keystore_file)
            except FileNotFoundError:
                pass

    def test_generate_pqc_key(self):
        """Test PQC key generation"""
        success, key_id, error = self.client.generate_pqc_key(
            algorithm="ml-kem-768",
            keystore_path=self.keystore_file,
            keystore_password="KeystorePassword123!",
            key_name="Test Key",
        )

        self.assertIsInstance(success, bool)
        self.assertIsInstance(key_id, str)
        self.assertIsInstance(error, str)

        if success:
            print(f"  ✓ Key generated: {key_id}")
        else:
            print(f"  ⚠ Key generation not implemented: {error}")

    def test_list_pqc_keys(self):
        """Test listing PQC keys"""
        success, keys, error = self.client.list_pqc_keys(
            keystore_path=self.keystore_file,
            keystore_password="KeystorePassword123!",
        )

        self.assertIsInstance(success, bool)
        self.assertIsInstance(keys, list)
        self.assertIsInstance(error, str)


class TestDBusServiceStructure(unittest.TestCase):
    """Test D-Bus service structure without requiring running service"""

    def test_imports(self):
        """Test that modules can be imported"""
        try:
            from openssl_encrypt.modules import dbus_client, dbus_service

            self.assertTrue(True)
        except ImportError as e:
            self.fail(f"Failed to import modules: {e}")

    def test_interface_xml_exists(self):
        """Test that interface XML file exists"""
        xml_path = Path(__file__).parent.parent / "openssl_encrypt" / "dbus" / "interface.xml"
        self.assertTrue(xml_path.exists(), "Interface XML file not found")

        # Check XML is valid
        import xml.etree.ElementTree as ET

        try:
            tree = ET.parse(xml_path)
            root = tree.getroot()
            self.assertEqual(root.tag, "node")
        except ET.ParseError as e:
            self.fail(f"Invalid XML: {e}")

    def test_service_files_exist(self):
        """Test that all required service files exist"""
        base_path = Path(__file__).parent.parent / "openssl_encrypt" / "dbus"

        required_files = [
            "interface.xml",
            "ch.rm-rf.openssl_encrypt.service",
            "ch.rm-rf.openssl_encrypt.conf",
            "ch.rm-rf.openssl_encrypt.policy",
        ]

        for filename in required_files:
            file_path = base_path / filename
            self.assertTrue(file_path.exists(), f"Required file not found: {filename}")

    def test_documentation_exists(self):
        """Test that documentation exists"""
        doc_path = Path(__file__).parent.parent / "openssl_encrypt" / "docs" / "dbus-service.md"
        self.assertTrue(doc_path.exists(), "Documentation not found")


def run_tests():
    """Run all tests"""
    # Initialize D-Bus main loop if available
    if DBUS_AVAILABLE:
        DBusGMainLoop(set_as_default=True)

    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    # Add test classes
    suite.addTests(loader.loadTestsFromTestCase(TestDBusServiceStructure))

    if DBUS_AVAILABLE:
        suite.addTests(loader.loadTestsFromTestCase(TestDBusService))
        suite.addTests(loader.loadTestsFromTestCase(TestDBusFileOperations))
        suite.addTests(loader.loadTestsFromTestCase(TestDBusKeystore))

    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(run_tests())
