#!/usr/bin/env python3
"""
Debug CLI File Format
Analyze the exact format and metadata structure of CLI test files
"""

import base64
import json

def analyze_cli_file():
    """Analyze the CLI test file format and metadata"""
    print("🔍 Analyzing CLI Test File")
    print("=" * 50)
    
    cli_file = "cli_test_file.txt"
    
    try:
        with open(cli_file, 'r') as f:
            raw_content = f.read().strip()
        
        print(f"Raw content length: {len(raw_content)}")
        print(f"First 100 chars: {raw_content[:100]}")
        
        if ':' in raw_content:
            try:
                metadata_b64, data_b64 = raw_content.split(':', 1)
                print(f"✅ Split successful")
                print(f"   Metadata B64 length: {len(metadata_b64)}")
                print(f"   Data B64 length: {len(data_b64)}")
                
                # Decode metadata
                metadata_json = base64.b64decode(metadata_b64).decode('utf-8')
                metadata = json.loads(metadata_json)
                
                print(f"\n📋 CLI Metadata Structure:")
                print(json.dumps(metadata, indent=2))
                
                # Check specific fields
                if "derivation_config" in metadata:
                    derivation = metadata["derivation_config"]
                    print(f"\n🔑 Derivation Config:")
                    print(f"   Salt: {derivation.get('salt', 'MISSING')}")
                    
                    if "hash_config" in derivation:
                        hash_config = derivation["hash_config"]
                        print(f"   Hash config keys: {list(hash_config.keys())}")
                        
                        # Check for data contamination
                        contaminated_fields = []
                        for key, value in hash_config.items():
                            if not isinstance(value, (int, dict)):
                                contaminated_fields.append(f"{key}: {type(value)} = {value}")
                        
                        if contaminated_fields:
                            print(f"   ⚠️ Contaminated fields: {contaminated_fields}")
                        else:
                            print(f"   ✅ Clean hash config")
                            
                        # Show hash config structure
                        for algo, config in hash_config.items():
                            if isinstance(config, dict):
                                print(f"     {algo}: {config}")
                            else:
                                print(f"     {algo}: {config} ({type(config)})")
                    
                    if "kdf_config" in derivation:
                        kdf_config = derivation["kdf_config"]
                        print(f"   KDF config keys: {list(kdf_config.keys())}")
                        for kdf, config in kdf_config.items():
                            print(f"     {kdf}: {config}")
                
                return metadata
                    
            except Exception as e:
                print(f"❌ Failed to parse CLI format: {e}")
                return None
        else:
            print("❌ No ':' separator found - unexpected format")
            return None
            
    except Exception as e:
        print(f"❌ Failed to read CLI file: {e}")
        return None

if __name__ == "__main__":
    analyze_cli_file()