#!/usr/bin/env python3

import sys
sys.path.append('.')
from mobile_crypto_core import MobileCryptoCore
import base64

class DebugCore(MobileCryptoCore):
    def decrypt_data(self, encrypted_data_b64, metadata, password):
        try:
            print('🔍 Starting decrypt_data debug...')
            
            # Decode encrypted data
            encrypted_data = base64.b64decode(encrypted_data_b64.encode())
            print(f'✅ Decoded encrypted data, length: {len(encrypted_data)}')
            
            # Check metadata structure
            print(f'📋 Metadata keys: {list(metadata.keys())}')
            format_version = metadata.get('format_version')
            print(f'📋 Format version: {format_version}')
            
            if format_version == 5 and 'derivation_config' in metadata:
                print('📋 Processing CLI format version 5')
                derivation_config = metadata['derivation_config']
                
                # Get salt
                salt = base64.b64decode(derivation_config['salt'].encode())
                print(f'✅ Got salt, length: {len(salt)}')
                
                # Extract hash config  
                cli_hash_config = derivation_config.get('hash_config', {})
                hash_config = {}
                for algo, config in cli_hash_config.items():
                    if isinstance(config, dict) and 'rounds' in config:
                        hash_config[algo] = config['rounds']
                    else:
                        hash_config[algo] = config if isinstance(config, int) else 0
                
                # Add missing algorithms
                for algo in self.default_hash_config:
                    if algo not in hash_config:
                        hash_config[algo] = 0
                        
                print('✅ Hash config processed')
                
                # Extract KDF config
                cli_kdf_config = derivation_config.get('kdf_config', {})
                kdf_config = self.default_kdf_config.copy()
                
                for kdf in kdf_config:
                    kdf_config[kdf]['enabled'] = False
                
                for kdf_name, kdf_params in cli_kdf_config.items():
                    if kdf_name in kdf_config:
                        kdf_config[kdf_name]['enabled'] = True
                        for param, value in kdf_params.items():
                            if param != 'enabled':
                                kdf_config[kdf_name][param] = value
                
                print('✅ KDF config processed')
                
                # Derive key
                print('🔑 Deriving key...')
                key = self._derive_key(password, salt, hash_config, kdf_config)
                print(f'✅ Key derived, length: {len(key)}')
                
                # Create Fernet key
                import hashlib
                key_hash = hashlib.sha256(key).digest()
                fernet_key = base64.urlsafe_b64encode(key_hash)
                print('✅ Fernet key created')
                
                # Decrypt
                from cryptography.fernet import Fernet
                f = Fernet(fernet_key)
                decrypted_data = f.decrypt(encrypted_data)
                print(f'✅ Decryption successful, length: {len(decrypted_data)}')
                
                return {'success': True, 'decrypted_data': decrypted_data}
            else:
                print('❌ Unsupported metadata format')
                return {'success': False, 'error': 'Unsupported format'}
                
        except Exception as e:
            print(f'❌ Exception: {e}')
            import traceback
            traceback.print_exc()
            return {'success': False, 'error': str(e)}

def main():
    # Test with debug core
    core = DebugCore()
    result = core.encrypt_data('test'.encode(), '1234')
    print('Encrypt result keys:', list(result.keys()) if result else 'None')
    
    if result and result['success']:
        print('\nTesting decrypt...')
        debug_result = core.decrypt_data(result['encrypted_data'], result['metadata'], '1234')
        print(f'🎯 Final debug result: {debug_result}')
    else:
        print('Encrypt failed:', result)

if __name__ == '__main__':
    main()