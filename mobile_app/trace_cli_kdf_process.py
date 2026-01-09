#!/usr/bin/env python3
"""
Phase 1: Trace CLI KDF Process
Monkey-patch CLI KDF functions to capture exact intermediate values
"""

import sys
import base64
import json
sys.path.insert(0, '../openssl_encrypt')

def trace_cli_kdf_functions():
    """Monkey-patch CLI KDF functions to trace their execution"""
    print("🔍 Phase 1: Tracing CLI KDF Process")
    print("=" * 50)
    
    try:
        # Import CLI modules
        from openssl_encrypt.modules import crypt_core
        from cryptography.fernet import Fernet
        
        # Storage for captured data
        kdf_trace = {
            "calls": [],
            "argon2_calls": [],
            "pbkdf2_calls": [],
            "final_key": None
        }
        
        # Patch Fernet key capture
        original_fernet_init = Fernet.__init__
        def capture_fernet_key(self, key):
            kdf_trace["final_key"] = key
            print(f"🎯 Final Fernet key captured: {key}")
            return original_fernet_init(self, key)
        Fernet.__init__ = capture_fernet_key
        
        # Try to find and patch KDF-related functions
        kdf_functions_to_patch = [
            'multi_kdf_derive',
            'derive_key', 
            'apply_kdf',
            'kdf_derive',
        ]
        
        patched_functions = []
        
        for func_name in kdf_functions_to_patch:
            if hasattr(crypt_core, func_name):
                original_func = getattr(crypt_core, func_name)
                
                def make_tracer(name, orig_func):
                    def traced_func(*args, **kwargs):
                        print(f"🔍 CLI {name} called:")
                        print(f"   Args: {[type(a).__name__ for a in args]}")
                        print(f"   Kwargs: {list(kwargs.keys())}")
                        
                        result = orig_func(*args, **kwargs)
                        
                        print(f"   Result type: {type(result).__name__}")
                        if hasattr(result, '__len__'):
                            print(f"   Result length: {len(result)}")
                        if hasattr(result, 'hex'):
                            print(f"   Result hex: {result.hex()[:32]}...")
                            
                        kdf_trace["calls"].append({
                            "function": name,
                            "args_types": [type(a).__name__ for a in args],
                            "result_hex": result.hex() if hasattr(result, 'hex') else str(result)[:50]
                        })
                        
                        return result
                    return traced_func
                
                setattr(crypt_core, func_name, make_tracer(func_name, original_func))
                patched_functions.append(func_name)
        
        print(f"✅ Patched functions: {patched_functions}")
        
        # Try to patch Argon2 if available
        try:
            import argon2.low_level
            original_hash_secret_raw = argon2.low_level.hash_secret_raw
            
            def traced_argon2(*args, **kwargs):
                print(f"🔍 Argon2 hash_secret_raw called:")
                print(f"   Secret length: {len(args[0]) if args else 'N/A'}")
                print(f"   Salt length: {len(args[1]) if len(args) > 1 else 'N/A'}")
                print(f"   Kwargs: {kwargs}")
                
                result = original_hash_secret_raw(*args, **kwargs)
                print(f"   Argon2 result: {result.hex()[:32]}...")
                
                kdf_trace["argon2_calls"].append({
                    "input_len": len(args[0]) if args else 0,
                    "salt_len": len(args[1]) if len(args) > 1 else 0,
                    "kwargs": kwargs,
                    "result_hex": result.hex()
                })
                
                return result
                
            argon2.low_level.hash_secret_raw = traced_argon2
            print("✅ Argon2 tracing enabled")
            
        except Exception as e:
            print(f"⚠️ Argon2 tracing failed: {e}")
        
        # Try to patch PBKDF2
        try:
            from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
            original_pbkdf2_derive = PBKDF2HMAC.derive
            
            def traced_pbkdf2_derive(self, key_material):
                print(f"🔍 PBKDF2 derive called:")
                print(f"   Key material length: {len(key_material)}")
                print(f"   Algorithm: {self._algorithm}")
                print(f"   Length: {self._length}")
                print(f"   Salt length: {len(self._salt)}")
                print(f"   Iterations: {self._iterations}")
                
                result = original_pbkdf2_derive(self, key_material)
                print(f"   PBKDF2 result: {result.hex()[:32]}...")
                
                kdf_trace["pbkdf2_calls"].append({
                    "input_len": len(key_material),
                    "algorithm": str(self._algorithm),
                    "salt_len": len(self._salt),
                    "iterations": self._iterations,
                    "result_hex": result.hex()
                })
                
                return result
                
            PBKDF2HMAC.derive = traced_pbkdf2_derive
            print("✅ PBKDF2 tracing enabled")
            
        except Exception as e:
            print(f"⚠️ PBKDF2 tracing failed: {e}")
        
        return kdf_trace
        
    except Exception as e:
        print(f"❌ Failed to enable KDF tracing: {e}")
        import traceback
        traceback.print_exc()
        return None

def run_traced_cli_decrypt():
    """Run CLI decrypt with full tracing enabled"""
    print(f"\n🧪 Running Traced CLI Decrypt")
    print("=" * 40)
    
    # Enable tracing
    kdf_trace = trace_cli_kdf_functions()
    if not kdf_trace:
        print("❌ Tracing setup failed")
        return None
    
    # Run CLI decrypt
    try:
        from openssl_encrypt.modules.crypt_core import decrypt_file
        
        test_file = "/home/work/private/git/openssl_encrypt/openssl_encrypt/unittests/testfiles/v5/test1_fernet.txt"
        output_file = "/tmp/traced_cli_output.txt"
        password = b"1234"
        
        print(f"🔑 Decrypting with CLI...")
        print(f"   File: {test_file}")
        print(f"   Password: {password}")
        
        result = decrypt_file(test_file, output_file, password, quiet=True)
        
        print(f"🎯 CLI decrypt result: {result}")
        
        if result:
            with open(output_file, 'r') as f:
                content = f.read()
            print(f"📄 Decrypted content: '{content.strip()}'")
        
        print(f"\n📊 KDF Trace Summary:")
        print(f"   General KDF calls: {len(kdf_trace['calls'])}")
        print(f"   Argon2 calls: {len(kdf_trace['argon2_calls'])}")
        print(f"   PBKDF2 calls: {len(kdf_trace['pbkdf2_calls'])}")
        print(f"   Final key: {kdf_trace['final_key']}")
        
        return kdf_trace
        
    except Exception as e:
        print(f"❌ Traced CLI decrypt failed: {e}")
        import traceback
        traceback.print_exc()
        return None

def analyze_kdf_trace(kdf_trace):
    """Analyze the captured KDF trace data"""
    if not kdf_trace:
        return
        
    print(f"\n🔍 Phase 1 Analysis: KDF Trace Details")
    print("=" * 50)
    
    # Analyze Argon2 calls
    if kdf_trace["argon2_calls"]:
        print(f"📋 Argon2 Calls ({len(kdf_trace['argon2_calls'])}):")
        for i, call in enumerate(kdf_trace["argon2_calls"]):
            print(f"   Call {i+1}:")
            print(f"      Input: {call['input_len']} bytes")
            print(f"      Salt: {call['salt_len']} bytes")
            print(f"      Params: {call['kwargs']}")
            print(f"      Result: {call['result_hex'][:32]}...")
    
    # Analyze PBKDF2 calls
    if kdf_trace["pbkdf2_calls"]:
        print(f"📋 PBKDF2 Calls ({len(kdf_trace['pbkdf2_calls'])}):")
        for i, call in enumerate(kdf_trace["pbkdf2_calls"]):
            print(f"   Call {i+1}:")
            print(f"      Input: {call['input_len']} bytes")
            print(f"      Algorithm: {call['algorithm']}")
            print(f"      Salt: {call['salt_len']} bytes")  
            print(f"      Iterations: {call['iterations']}")
            print(f"      Result: {call['result_hex'][:32]}...")
    
    # Analyze call sequence
    if kdf_trace["calls"]:
        print(f"📋 KDF Call Sequence:")
        for i, call in enumerate(kdf_trace["calls"]):
            print(f"   {i+1}. {call['function']} -> {call['result_hex'][:20]}...")
    
    # Key information
    if kdf_trace["final_key"]:
        try:
            key_raw = base64.urlsafe_b64decode(kdf_trace["final_key"])
            print(f"📋 Final Key Analysis:")
            print(f"   Base64: {kdf_trace['final_key']}")
            print(f"   Raw hex: {key_raw.hex()}")
            print(f"   Length: {len(key_raw)} bytes")
        except Exception as e:
            print(f"   Key decode failed: {e}")

if __name__ == "__main__":
    print("🎯 Phase 1: CLI KDF Process Tracing")
    print("=" * 60)
    
    # Run the trace
    trace_data = run_traced_cli_decrypt()
    
    # Analyze results
    analyze_kdf_trace(trace_data)
    
    if trace_data and (trace_data["argon2_calls"] or trace_data["pbkdf2_calls"]):
        print(f"\n✅ Phase 1 SUCCESS: Captured CLI KDF process details!")
    else:
        print(f"\n⚠️ Phase 1 PARTIAL: Some KDF details captured, need deeper investigation")