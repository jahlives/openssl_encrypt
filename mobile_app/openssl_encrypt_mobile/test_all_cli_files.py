#!/usr/bin/env python3

"""
Comprehensive CLI File Compatibility Test
Tests mobile backend against ALL non-post-quantum CLI test files with password '1234'
"""

import os
import base64
import json
from mobile_crypto_core import MobileCryptoCore

def is_post_quantum_algorithm(algorithm):
    """Check if an algorithm is post-quantum"""
    pq_keywords = [
        'kyber', 'ml-kem', 'mayo', 'cross', 'hqc', 
        'hybrid', 'pqc', 'post-quantum'
    ]
    return any(keyword in algorithm.lower() for keyword in pq_keywords)

def extract_algorithm_from_filename(filename):
    """Extract algorithm name from test filename"""
    # Remove test prefix and .txt suffix
    name = filename.replace('test1_', '').replace('.txt', '')
    
    # Handle special cases
    if 'fernet_balloon' in name:
        return 'fernet'  # Fernet with Balloon KDF
    elif '-' in name and not name.startswith('aes-') and not name.startswith('chacha') and not name.startswith('xchacha'):
        # This might be a hybrid algorithm like 'kyber512-aes-gcm'
        parts = name.split('-')
        if is_post_quantum_algorithm(parts[0]):
            return 'post-quantum'
    
    return name

def test_cli_file(mobile, filepath, filename):
    """Test a single CLI file"""
    try:
        with open(filepath, 'rb') as f:
            cli_data = f.read()
        
        # Parse CLI format (base64_metadata:encrypted_data)
        parts = cli_data.split(b':', 1)
        if len(parts) != 2:
            return {"success": False, "error": "Invalid file format - missing metadata separator"}
        
        try:
            metadata = json.loads(base64.urlsafe_b64decode(parts[0]).decode())
        except Exception as e:
            return {"success": False, "error": f"Failed to parse metadata: {e}"}
        
        encrypted_data_b64 = parts[1].decode()
        
        # Get algorithm from metadata (handle different format versions)
        if metadata.get("format_version") == 3:
            # v3 format: algorithm is directly in metadata
            algorithm = metadata.get("algorithm", "unknown")
        else:
            # v4/v5 format: algorithm is in encryption section
            algorithm = metadata.get("encryption", {}).get("algorithm", "unknown")
        
        # Test decryption
        result = mobile.decrypt_data(encrypted_data_b64, metadata, '1234')
        
        if result['success']:
            decrypted_text = result['decrypted_data'].decode()
            # Most CLI test files contain "Hello World" but handle variations
            expected_texts = ['Hello World', 'Hello World\n', 'Test content', 'test content']
            success = any(decrypted_text.strip() == expected.strip() for expected in expected_texts)
            
            return {
                "success": True,
                "algorithm": algorithm,
                "decrypted": decrypted_text.strip(),
                "content_match": success
            }
        else:
            return {
                "success": False, 
                "algorithm": algorithm,
                "error": result['error']
            }
            
    except Exception as e:
        return {"success": False, "error": f"Exception: {e}"}

def main():
    print("=" * 80)
    print("COMPREHENSIVE CLI FILE COMPATIBILITY TEST")
    print("Testing mobile backend against ALL non-post-quantum CLI test files")
    print("Password: '1234'")
    print("=" * 80)
    
    mobile = MobileCryptoCore()
    
    # Find all test directories
    base_test_dir = "../../openssl_encrypt/unittests/testfiles"
    test_versions = []
    
    for item in os.listdir(base_test_dir):
        item_path = os.path.join(base_test_dir, item)
        if os.path.isdir(item_path) and (item.startswith('v') or item.isdigit()):
            test_versions.append(item)
    
    test_versions.sort()
    print(f"Found test versions: {test_versions}")
    
    total_files = 0
    successful_files = 0
    failed_files = 0
    post_quantum_skipped = 0
    
    results_by_algorithm = {}
    
    # Test each version directory
    for version in test_versions:
        version_dir = os.path.join(base_test_dir, version)
        if not os.path.isdir(version_dir):
            continue
            
        print(f"\n--- Testing {version} ---")
        
        test_files = [f for f in os.listdir(version_dir) if f.endswith('.txt')]
        test_files.sort()
        
        version_success = 0
        version_total = 0
        
        for filename in test_files:
            filepath = os.path.join(version_dir, filename)
            
            # Extract algorithm for filtering
            file_algorithm = extract_algorithm_from_filename(filename)
            
            # Skip post-quantum algorithms
            if file_algorithm == 'post-quantum' or is_post_quantum_algorithm(file_algorithm):
                post_quantum_skipped += 1
                continue
            
            total_files += 1
            version_total += 1
            
            print(f"  Testing {filename}...", end=" ")
            
            result = test_cli_file(mobile, filepath, filename)
            
            if result["success"]:
                algorithm = result["algorithm"]
                content_ok = result.get("content_match", True)
                
                if content_ok:
                    successful_files += 1
                    version_success += 1
                    status = "✅ SUCCESS"
                else:
                    status = f"⚠️  DECRYPT OK (content: '{result['decrypted']}')"
                
                # Track by algorithm
                if algorithm not in results_by_algorithm:
                    results_by_algorithm[algorithm] = {"success": 0, "total": 0, "files": []}
                results_by_algorithm[algorithm]["success"] += 1 if content_ok else 0
                results_by_algorithm[algorithm]["total"] += 1
                results_by_algorithm[algorithm]["files"].append((filename, True, result.get("decrypted", "")))
                
            else:
                failed_files += 1
                algorithm = result.get("algorithm", "unknown")
                status = f"❌ FAILED: {result['error']}"
                
                # Track by algorithm
                if algorithm not in results_by_algorithm:
                    results_by_algorithm[algorithm] = {"success": 0, "total": 0, "files": []}
                results_by_algorithm[algorithm]["total"] += 1
                results_by_algorithm[algorithm]["files"].append((filename, False, result.get("error", "")))
            
            print(status)
        
        if version_total > 0:
            print(f"  {version} summary: {version_success}/{version_total} successful ({version_success/version_total*100:.1f}%)")
    
    # Final summary
    print("\n" + "=" * 80)
    print("FINAL RESULTS SUMMARY")
    print("=" * 80)
    
    print(f"Total files tested: {total_files}")
    print(f"Successful: {successful_files}")
    print(f"Failed: {failed_files}")
    print(f"Post-quantum skipped: {post_quantum_skipped}")
    print(f"Success rate: {successful_files/total_files*100:.1f}%")
    
    print("\n--- Results by Algorithm ---")
    print(f"{'Algorithm':<25} {'Success/Total':<15} {'Rate':<8} {'Status'}")
    print("-" * 70)
    
    algorithm_names = sorted(results_by_algorithm.keys())
    perfect_algorithms = 0
    
    for algorithm in algorithm_names:
        stats = results_by_algorithm[algorithm]
        success_rate = stats["success"] / stats["total"] * 100 if stats["total"] > 0 else 0
        
        if success_rate == 100:
            status = "✅ PERFECT"
            perfect_algorithms += 1
        elif success_rate >= 80:
            status = "⚠️  MOSTLY OK"
        else:
            status = "❌ NEEDS WORK"
        
        print(f"{algorithm:<25} {stats['success']}/{stats['total']:<14} {success_rate:6.1f}% {status}")
    
    print("-" * 70)
    print(f"Perfect algorithms: {perfect_algorithms}/{len(algorithm_names)}")
    
    if failed_files > 0:
        print(f"\n--- Failed Files Details ---")
        for algorithm in algorithm_names:
            failed_files_for_algo = [f for f in results_by_algorithm[algorithm]["files"] if not f[1]]
            if failed_files_for_algo:
                print(f"\n{algorithm}:")
                for filename, success, error in failed_files_for_algo:
                    print(f"  ❌ {filename}: {error}")
    
    print("\n" + "=" * 80)
    if successful_files == total_files:
        print("🎉 ALL NON-POST-QUANTUM CLI FILES WORKING PERFECTLY! 🎉")
    else:
        print(f"📝 {failed_files} files still need attention")
    print("=" * 80)

if __name__ == "__main__":
    main()