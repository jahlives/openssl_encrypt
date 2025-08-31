#!/usr/bin/env python3
"""
Basic USB Drive Encryption Test

This test verifies the basic functionality of USB drive creation and verification
without requiring actual USB devices.
"""

import json
import os
import sys
import tempfile
from pathlib import Path

# Add the parent directory to Python path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

def test_usb_creation():
    """Test basic USB drive creation without actual hardware"""
    print("Testing USB drive creation...")
    
    try:
        from usb_creator import USBDriveCreator, USBSecurityProfile
        
        # Create temporary directory to simulate USB drive
        with tempfile.TemporaryDirectory() as temp_dir:
            usb_path = Path(temp_dir) / "test_usb"
            usb_path.mkdir()
            
            # Test USB creation
            creator = USBDriveCreator(USBSecurityProfile.STANDARD)
            
            # Create minimal portable USB
            result = creator.create_portable_usb(
                usb_path=usb_path,
                password="test_usb_password_123",
                include_logs=True
            )
            
            print(f"✅ USB creation result: {result['success']}")
            print(f"   Portable root: {result['portable_root']}")
            print(f"   Security profile: {result['security_profile']}")
            print(f"   Workspace created: {result['workspace']['created']}")
            print(f"   Autorun files: {len(result['autorun']['files_created'])}")
            print(f"   Integrity files: {result['integrity']['files_verified']}")
            
            # Verify the directory structure was created
            portable_root = usb_path / creator.PORTABLE_DIR
            assert portable_root.exists(), "Portable root directory not created"
            assert (portable_root / "config").exists(), "Config directory not created"
            assert (portable_root / "data").exists(), "Data directory not created"
            assert (portable_root / "logs").exists(), "Logs directory not created"
            
            # Check autorun files
            assert (usb_path / "autorun.inf").exists(), "Windows autorun.inf not created"
            assert (usb_path / "autorun.sh").exists(), "Linux autorun.sh not created"
            assert (usb_path / ".autorun").exists(), "macOS .autorun not created"
            
            # Check configuration file
            config_file = portable_root / "config" / "portable.conf"
            assert config_file.exists(), "Config file not created"
            
            with open(config_file, 'r') as f:
                config = json.load(f)
            
            assert config['portable_mode'] == True, "Portable mode not enabled"
            assert config['security_profile'] == "standard", "Security profile incorrect"
            assert config['network_disabled'] == True, "Network not disabled"
            
            print("✅ Directory structure validation passed")
            
            return True
    
    except ImportError as e:
        print(f"⚠️  USB dependencies not available: {e}")
        return False
    except Exception as e:
        print(f"❌ USB creation test failed: {e}")
        return False


def test_usb_verification():
    """Test USB drive verification"""
    print("\nTesting USB drive verification...")
    
    try:
        from usb_creator import USBDriveCreator, USBSecurityProfile
        
        # Create temporary directory to simulate USB drive
        with tempfile.TemporaryDirectory() as temp_dir:
            usb_path = Path(temp_dir) / "test_usb"
            usb_path.mkdir()
            
            creator = USBDriveCreator(USBSecurityProfile.HIGH_SECURITY)
            password = "verification_test_password_456"
            
            # Create USB drive
            creation_result = creator.create_portable_usb(
                usb_path=usb_path,
                password=password
            )
            
            assert creation_result['success'], "USB creation failed"
            
            # Verify integrity
            verification_result = creator.verify_usb_integrity(usb_path, password)
            
            print(f"✅ Verification result: {verification_result['integrity_ok']}")
            print(f"   Files verified: {verification_result['verified_files']}")
            print(f"   Files failed: {verification_result['failed_files']}")
            print(f"   Files missing: {verification_result['missing_files']}")
            
            assert verification_result['integrity_ok'], "Integrity check failed"
            assert verification_result['failed_files'] == 0, "Some files failed verification"
            assert verification_result['missing_files'] == 0, "Some files are missing"
            
            print("✅ Integrity verification passed")
            
            return True
    
    except Exception as e:
        print(f"❌ USB verification test failed: {e}")
        return False


def test_usb_security_profiles():
    """Test different security profiles"""
    print("\nTesting security profiles...")
    
    try:
        from usb_creator import USBDriveCreator, USBSecurityProfile
        
        profiles = [
            USBSecurityProfile.STANDARD,
            USBSecurityProfile.HIGH_SECURITY, 
            USBSecurityProfile.PARANOID
        ]
        
        for profile in profiles:
            with tempfile.TemporaryDirectory() as temp_dir:
                usb_path = Path(temp_dir) / "test_usb"
                usb_path.mkdir()
                
                creator = USBDriveCreator(profile)
                result = creator.create_portable_usb(
                    usb_path=usb_path,
                    password=f"test_password_for_{profile.value}"
                )
                
                assert result['success'], f"Failed to create USB with {profile.value} profile"
                assert result['security_profile'] == profile.value, f"Security profile mismatch for {profile.value}"
                
                print(f"✅ Security profile {profile.value} working")
        
        return True
    
    except Exception as e:
        print(f"❌ Security profiles test failed: {e}")
        return False


def test_error_handling():
    """Test error handling scenarios"""
    print("\nTesting error handling...")
    
    try:
        from usb_creator import USBDriveCreator, USBCreationError
        
        creator = USBDriveCreator()
        
        # Test with non-existent path
        try:
            result = creator.create_portable_usb(
                usb_path="/non/existent/path",
                password="test_password"
            )
            print("❌ Should have failed with non-existent path")
            return False
        except USBCreationError:
            print("✅ Non-existent path correctly rejected")
        
        # Test verification with wrong password
        with tempfile.TemporaryDirectory() as temp_dir:
            usb_path = Path(temp_dir) / "test_usb"
            usb_path.mkdir()
            
            # Create USB with one password
            creator.create_portable_usb(usb_path, "correct_password")
            
            # Try to verify with wrong password
            try:
                creator.verify_usb_integrity(usb_path, "wrong_password")
                print("❌ Should have failed with wrong password")
                return False
            except USBCreationError:
                print("✅ Wrong password correctly rejected")
        
        return True
    
    except Exception as e:
        print(f"❌ Error handling test failed: {e}")
        return False


def main():
    """Run basic USB functionality tests"""
    print("🔒 USB Drive Encryption - Basic Tests")
    print("=" * 50)
    
    tests = [
        test_usb_creation,
        test_usb_verification,
        test_usb_security_profiles,
        test_error_handling
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        if test():
            passed += 1
    
    print("\n" + "=" * 50)
    print(f"Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All basic USB tests passed!")
        return 0
    else:
        print("⚠️  Some tests failed")
        return 1


if __name__ == "__main__":
    sys.exit(main())