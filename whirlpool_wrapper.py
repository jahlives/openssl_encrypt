"""
Wrapper module for importing Whirlpool hash library.
"""

import sys
import os
import importlib.util
from importlib.machinery import ExtensionFileLoader

def find_and_load_whirlpool():
    """Find and load the Whirlpool module."""
    # First try standard import
    try:
        import whirlpool
        return whirlpool
    except ImportError:
        pass
    
    # Then try pywhirlpool
    try:
        import pywhirlpool
        return pywhirlpool
    except ImportError:
        pass
    
    # Try to find whirlpool-py311.so
    user_site = os.path.expanduser("~/.local/lib/python{}.{}/site-packages".format(
        sys.version_info.major, sys.version_info.minor))
    
    # Look for the module with different possible extensions
    possible_names = [
        "whirlpool-py311.cpython-{}{}-x86_64-linux-gnu.so".format(
            sys.version_info.major, sys.version_info.minor),
        "whirlpool_py311.cpython-{}{}-x86_64-linux-gnu.so".format(
            sys.version_info.major, sys.version_info.minor),
        "whirlpool.cpython-{}{}-x86_64-linux-gnu.so".format(
            sys.version_info.major, sys.version_info.minor),
    ]
    
    whirlpool_path = None
    for name in possible_names:
        path = os.path.join(user_site, name)
        if os.path.exists(path):
            whirlpool_path = path
            break
    
    if whirlpool_path:
        # Create the module name by removing the extension 
        # and replacing hyphens with underscores
        module_name = os.path.splitext(os.path.basename(whirlpool_path))[0]
        module_name = module_name.split('.')[0]  # Remove .cpython part if present
        module_name = module_name.replace('-', '_')
        
        try:
            # Load the extension module directly
            loader = ExtensionFileLoader(module_name, whirlpool_path)
            spec = importlib.util.spec_from_file_location(module_name, whirlpool_path, loader=loader)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            
            # Make sure the module has the required functions
            if hasattr(module, 'new'):
                return module
        except Exception as e:
            print(f"Error loading Whirlpool extension: {e}")
    
    # If we couldn't load from the extension file, look for the .so directly
    # and try to manually create a compatible interface
    so_path = None
    for root, dirs, files in os.walk(user_site):
        for file in files:
            if "whirlpool" in file.lower() and file.endswith(".so"):
                so_path = os.path.join(root, file)
                break
        if so_path:
            break
    
    if so_path:
        # Try to load it directly
        try:
            loader = ExtensionFileLoader("whirlpool_wrapper", so_path)
            spec = importlib.util.spec_from_file_location("whirlpool_wrapper", so_path, loader=loader)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            
            # Create a wrapper with the standard interface if needed
            class WhirlpoolWrapper:
                @staticmethod
                def new(data=None):
                    return Whirlpool(data)
                
                @staticmethod
                def whirlpool(data):
                    return Whirlpool(data)
            
            class Whirlpool:
                def __init__(self, data=None):
                    self.obj = module.Whirlpool() if hasattr(module, "Whirlpool") else None
                    if data and self.obj:
                        self.obj.update(data)
                
                def update(self, data):
                    if self.obj:
                        self.obj.update(data)
                    return self
                
                def digest(self):
                    if self.obj:
                        return self.obj.digest()
                    return b''
                
                def hexdigest(self):
                    if self.obj:
                        return self.obj.hexdigest()
                    return ''
            
            return WhirlpoolWrapper
        except Exception as e:
            print(f"Error creating Whirlpool wrapper: {e}")
    
    # If all else fails, return None
    return None

# Export the main whirlpool module
whirlpool = find_and_load_whirlpool()