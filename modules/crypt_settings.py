#!/usr/bin/env python3
"""
Enhanced GUI for the encryption tool with settings tab.
This version adds a settings tab to configure hash parameters.
"""

import os
import sys
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog
import subprocess
import threading
import random
import string
import time
import json

# Default configuration
DEFAULT_CONFIG = {
    # Hash iterations
    'sha512': 10000,
    'sha256': 0,
    'sha3_256': 0,
    'sha3_512': 0,
    'whirlpool': 0,
    # Scrypt parameters
    'scrypt': {
        'n': 16384,  # CPU/memory cost factor (must be power of 2)
        'r': 8,      # Block size
        'p': 1       # Parallelization factor
    },
    # Argon2 parameters
    'argon2': {
        'enabled': False,
        'time_cost': 3,
        'memory_cost': 65536,  # 64 MB
        'parallelism': 4,
        'hash_len': 32,
        'type': 'id'  # id, i, or d
    },
    # PBKDF2 parameters
    'pbkdf2_iterations': 100000
}

CONFIG_FILE = "crypt_settings.json"

# Settings class for the settings tab
class SettingsTab:
    def __init__(self, parent, gui_instance):
        """Initialize the settings tab"""
        self.parent = parent
        self.gui = gui_instance
        self.config = DEFAULT_CONFIG.copy()
        
        # Load existing settings if they exist
        self.load_settings()
        
        # Setup the tab
        self.setup_tab()
        
    def setup_tab(self):
        """Set up the settings tab UI"""
        # Create a frame with scrollbar for many settings
        main_frame = ttk.Frame(self.parent)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Add a canvas with scrollbar for scrolling if needed
        canvas = tk.Canvas(main_frame)
        scrollbar = ttk.Scrollbar(main_frame, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(
                scrollregion=canvas.bbox("all")
            )
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Settings header
        ttk.Label(scrollable_frame, text="Hash Algorithm Settings", 
                 font=("TkDefaultFont", 12, "bold")).pack(pady=(10, 5), padx=10, anchor=tk.W)
        ttk.Separator(scrollable_frame, orient='horizontal').pack(fill=tk.X, padx=10, pady=5)
        
        # Iterative hash settings
        hash_frame = ttk.LabelFrame(scrollable_frame, text="Iterative Hash Algorithms")
        hash_frame.pack(fill=tk.X, expand=True, padx=10, pady=5)
        
        # Create variables for iterative hashes
        self.hash_vars = {}
        
        # SHA-512
        row = 0
        ttk.Label(hash_frame, text="SHA-512 rounds:").grid(row=row, column=0, sticky=tk.W, padx=5, pady=5)
        self.hash_vars['sha512'] = tk.IntVar(value=self.config['sha512'])
        ttk.Entry(hash_frame, textvariable=self.hash_vars['sha512'], width=10).grid(
            row=row, column=1, sticky=tk.W, padx=5, pady=5)
        ttk.Label(hash_frame, text="(0 to disable)").grid(row=row, column=2, sticky=tk.W, padx=5, pady=5)
        
        # SHA-256
        row += 1
        ttk.Label(hash_frame, text="SHA-256 rounds:").grid(row=row, column=0, sticky=tk.W, padx=5, pady=5)
        self.hash_vars['sha256'] = tk.IntVar(value=self.config['sha256'])
        ttk.Entry(hash_frame, textvariable=self.hash_vars['sha256'], width=10).grid(
            row=row, column=1, sticky=tk.W, padx=5, pady=5)
        ttk.Label(hash_frame, text="(0 to disable)").grid(row=row, column=2, sticky=tk.W, padx=5, pady=5)
        
        # SHA3-256
        row += 1
        ttk.Label(hash_frame, text="SHA3-256 rounds:").grid(row=row, column=0, sticky=tk.W, padx=5, pady=5)
        self.hash_vars['sha3_256'] = tk.IntVar(value=self.config['sha3_256'])
        ttk.Entry(hash_frame, textvariable=self.hash_vars['sha3_256'], width=10).grid(
            row=row, column=1, sticky=tk.W, padx=5, pady=5)
        ttk.Label(hash_frame, text="(0 to disable)").grid(row=row, column=2, sticky=tk.W, padx=5, pady=5)
        
        # SHA3-512
        row += 1
        ttk.Label(hash_frame, text="SHA3-512 rounds:").grid(row=row, column=0, sticky=tk.W, padx=5, pady=5)
        self.hash_vars['sha3_512'] = tk.IntVar(value=self.config['sha3_512'])
        ttk.Entry(hash_frame, textvariable=self.hash_vars['sha3_512'], width=10).grid(
            row=row, column=1, sticky=tk.W, padx=5, pady=5)
        ttk.Label(hash_frame, text="(0 to disable)").grid(row=row, column=2, sticky=tk.W, padx=5, pady=5)
        
        # Whirlpool
        row += 1
        ttk.Label(hash_frame, text="Whirlpool rounds:").grid(row=row, column=0, sticky=tk.W, padx=5, pady=5)
        self.hash_vars['whirlpool'] = tk.IntVar(value=self.config['whirlpool'])
        ttk.Entry(hash_frame, textvariable=self.hash_vars['whirlpool'], width=10).grid(
            row=row, column=1, sticky=tk.W, padx=5, pady=5)
        ttk.Label(hash_frame, text="(0 to disable)").grid(row=row, column=2, sticky=tk.W, padx=5, pady=5)
        
        # PBKDF2 settings
        row += 1
        ttk.Label(hash_frame, text="PBKDF2 iterations:").grid(row=row, column=0, sticky=tk.W, padx=5, pady=5)
        self.hash_vars['pbkdf2_iterations'] = tk.IntVar(value=self.config['pbkdf2_iterations'])
        ttk.Entry(hash_frame, textvariable=self.hash_vars['pbkdf2_iterations'], width=10).grid(
            row=row, column=1, sticky=tk.W, padx=5, pady=5)
        ttk.Label(hash_frame, text="(min 10000 recommended)").grid(row=row, column=2, sticky=tk.W, padx=5, pady=5)
        
        # Scrypt settings
        scrypt_frame = ttk.LabelFrame(scrollable_frame, text="Scrypt Settings (Memory-Hard Function)")
        scrypt_frame.pack(fill=tk.X, expand=True, padx=10, pady=5)
        
        self.scrypt_vars = {}
        
        # CPU/Memory cost factor (N)
        row = 0
        ttk.Label(scrypt_frame, text="CPU/Memory cost (N):").grid(row=row, column=0, sticky=tk.W, padx=5, pady=5)
        self.scrypt_vars['n'] = tk.IntVar(value=self.config['scrypt']['n'])
        n_values = [0, 1024, 2048, 4096, 8192, 16384, 32768, 65536, 131072, 262144, 524288, 1048576]
        n_combo = ttk.Combobox(scrypt_frame, textvariable=self.scrypt_vars['n'], values=n_values, width=10)
        n_combo.grid(row=row, column=1, sticky=tk.W, padx=5, pady=5)
        ttk.Label(scrypt_frame, text="(0 to disable, must be power of 2)").grid(
            row=row, column=2, sticky=tk.W, padx=5, pady=5)
        
        # Block size (r)
        row += 1
        ttk.Label(scrypt_frame, text="Block size (r):").grid(row=row, column=0, sticky=tk.W, padx=5, pady=5)
        self.scrypt_vars['r'] = tk.IntVar(value=self.config['scrypt']['r'])
        r_values = [4, 8, 16, 32]
        r_combo = ttk.Combobox(scrypt_frame, textvariable=self.scrypt_vars['r'], values=r_values, width=10)
        r_combo.grid(row=row, column=1, sticky=tk.W, padx=5, pady=5)
        ttk.Label(scrypt_frame, text="(8 is standard)").grid(row=row, column=2, sticky=tk.W, padx=5, pady=5)
        
        # Parallelization (p)
        row += 1
        ttk.Label(scrypt_frame, text="Parallelization (p):").grid(row=row, column=0, sticky=tk.W, padx=5, pady=5)
        self.scrypt_vars['p'] = tk.IntVar(value=self.config['scrypt']['p'])
        p_values = [1, 2, 4, 8]
        p_combo = ttk.Combobox(scrypt_frame, textvariable=self.scrypt_vars['p'], values=p_values, width=10)
        p_combo.grid(row=row, column=1, sticky=tk.W, padx=5, pady=5)
        ttk.Label(scrypt_frame, text="(1 is standard)").grid(row=row, column=2, sticky=tk.W, padx=5, pady=5)
        
        # Argon2 settings
        argon2_frame = ttk.LabelFrame(scrollable_frame, text="Argon2 Settings (Memory-Hard Function)")
        argon2_frame.pack(fill=tk.X, expand=True, padx=10, pady=5)
        
        self.argon2_vars = {}
        
        # Enable Argon2
        row = 0
        self.argon2_vars['enabled'] = tk.BooleanVar(value=self.config['argon2']['enabled'])
        ttk.Checkbutton(argon2_frame, text="Enable Argon2", variable=self.argon2_vars['enabled']).grid(
            row=row, column=0, columnspan=3, sticky=tk.W, padx=5, pady=5)
        
        # Argon2 variant
        row += 1
        ttk.Label(argon2_frame, text="Variant:").grid(row=row, column=0, sticky=tk.W, padx=5, pady=5)
        self.argon2_vars['type'] = tk.StringVar(value=self.config['argon2']['type'])
        variant_values = ['id', 'i', 'd']
        variant_combo = ttk.Combobox(argon2_frame, textvariable=self.argon2_vars['type'], 
                                    values=variant_values, width=10)
        variant_combo.grid(row=row, column=1, sticky=tk.W, padx=5, pady=5)
        ttk.Label(argon2_frame, text="(id is recommended for most uses)").grid(
            row=row, column=2, sticky=tk.W, padx=5, pady=5)
        
        # Time cost
        row += 1
        ttk.Label(argon2_frame, text="Time cost:").grid(row=row, column=0, sticky=tk.W, padx=5, pady=5)
        self.argon2_vars['time_cost'] = tk.IntVar(value=self.config['argon2']['time_cost'])
        time_values = [1, 2, 3, 4, 6, 8, 10, 12, 16]
        time_combo = ttk.Combobox(argon2_frame, textvariable=self.argon2_vars['time_cost'], 
                                 values=time_values, width=10)
        time_combo.grid(row=row, column=1, sticky=tk.W, padx=5, pady=5)
        ttk.Label(argon2_frame, text="(higher is slower but more secure)").grid(
            row=row, column=2, sticky=tk.W, padx=5, pady=5)
        
        # Memory cost
        row += 1
        ttk.Label(argon2_frame, text="Memory cost (KB):").grid(row=row, column=0, sticky=tk.W, padx=5, pady=5)
        self.argon2_vars['memory_cost'] = tk.IntVar(value=self.config['argon2']['memory_cost'])
        memory_values = [8192, 16384, 32768, 65536, 131072, 262144, 524288, 1048576]
        memory_combo = ttk.Combobox(argon2_frame, textvariable=self.argon2_vars['memory_cost'], 
                                   values=memory_values, width=10)
        memory_combo.grid(row=row, column=1, sticky=tk.W, padx=5, pady=5)
        ttk.Label(argon2_frame, text="(65536 = 64MB, higher is more secure)").grid(
            row=row, column=2, sticky=tk.W, padx=5, pady=5)
        
        # Parallelism
        row += 1
        ttk.Label(argon2_frame, text="Parallelism:").grid(row=row, column=0, sticky=tk.W, padx=5, pady=5)
        self.argon2_vars['parallelism'] = tk.IntVar(value=self.config['argon2']['parallelism'])
        parallel_values = [1, 2, 4, 8, 16]
        parallel_combo = ttk.Combobox(argon2_frame, textvariable=self.argon2_vars['parallelism'], 
                                     values=parallel_values, width=10)
        parallel_combo.grid(row=row, column=1, sticky=tk.W, padx=5, pady=5)
        ttk.Label(argon2_frame, text="(should match number of CPU cores)").grid(
            row=row, column=2, sticky=tk.W, padx=5, pady=5)
        
        # Hash length
        row += 1
        ttk.Label(argon2_frame, text="Hash length:").grid(row=row, column=0, sticky=tk.W, padx=5, pady=5)
        self.argon2_vars['hash_len'] = tk.IntVar(value=self.config['argon2']['hash_len'])
        hash_len_values = [16, 24, 32, 48, 64]
        hash_len_combo = ttk.Combobox(argon2_frame, textvariable=self.argon2_vars['hash_len'], 
                                     values=hash_len_values, width=10)
        hash_len_combo.grid(row=row, column=1, sticky=tk.W, padx=5, pady=5)
        ttk.Label(argon2_frame, text="(32 is standard)").grid(row=row, column=2, sticky=tk.W, padx=5, pady=5)
        
        # Presets section
        presets_frame = ttk.LabelFrame(scrollable_frame, text="Security Presets")
        presets_frame.pack(fill=tk.X, expand=True, padx=10, pady=5)
        
        # Preset buttons
        preset_row = ttk.Frame(presets_frame)
        preset_row.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(preset_row, text="Standard", 
                  command=lambda: self.load_preset("standard")).pack(side=tk.LEFT, padx=5)
        ttk.Button(preset_row, text="High Security", 
                  command=lambda: self.load_preset("high")).pack(side=tk.LEFT, padx=5)
        ttk.Button(preset_row, text="Paranoid", 
                  command=lambda: self.load_preset("paranoid")).pack(side=tk.LEFT, padx=5)
        ttk.Button(preset_row, text="Legacy", 
                  command=lambda: self.load_preset("legacy")).pack(side=tk.LEFT, padx=5)
        
        # Action buttons
        button_frame = ttk.Frame(scrollable_frame)
        button_frame.pack(fill=tk.X, padx=10, pady=20)
        
        ttk.Button(button_frame, text="Save Settings", 
                  command=self.save_settings).pack(side=tk.LEFT, padx=5, pady=5)
        ttk.Button(button_frame, text="Reset to Defaults", 
                  command=self.reset_to_defaults).pack(side=tk.LEFT, padx=5, pady=5)
        ttk.Button(button_frame, text="Test Settings", 
                  command=self.test_settings).pack(side=tk.LEFT, padx=5, pady=5)
        
        # Information section
        info_frame = ttk.LabelFrame(scrollable_frame, text="Information")
        info_frame.pack(fill=tk.X, expand=True, padx=10, pady=5)
        
        info_text = ("These settings control how your passwords are processed during encryption.\n"
                    "Higher values provide better security but slower performance.\n\n"
                    "For most users, the Standard preset is recommended.\n"
                    "For sensitive data, consider the High Security preset.\n"
                    "The Paranoid preset is extremely secure but may be slow on older hardware.")
        
        ttk.Label(info_frame, text=info_text, wraplength=550, justify=tk.LEFT).pack(padx=10, pady=10)
        
    def load_preset(self, preset_name):
        """Load a predefined security preset"""
        if preset_name == "standard":
            # Standard preset - good balance of security and performance
            preset = {
                'sha512': 10000,
                'sha256': 0,
                'sha3_256': 0,
                'sha3_512': 0,
                'whirlpool': 0,
                'scrypt': {
                    'n': 16384,
                    'r': 8,
                    'p': 1
                },
                'argon2': {
                    'enabled': False,
                    'time_cost': 3,
                    'memory_cost': 65536,
                    'parallelism': 4,
                    'hash_len': 32,
                    'type': 'id'
                },
                'pbkdf2_iterations': 100000
            }
        elif preset_name == "high":
            # High security preset - stronger but slower
            preset = {
                'sha512': 50000,
                'sha256': 0,
                'sha3_512': 5000,
                'sha3_256': 0,
                'whirlpool': 0,
                'scrypt': {
                    'n': 65536,
                    'r': 8,
                    'p': 2
                },
                'argon2': {
                    'enabled': True,
                    'time_cost': 4,
                    'memory_cost': 131072,
                    'parallelism': 4,
                    'hash_len': 32,
                    'type': 'id'
                },
                'pbkdf2_iterations': 200000
            }
        elif preset_name == "paranoid":
            # Paranoid preset - extremely secure but very slow
            preset = {
                'sha512': 100000,
                'sha256': 10000,
                'sha3_512': 10000,
                'sha3_256': 10000,
                'whirlpool': 5000,
                'scrypt': {
                    'n': 262144,
                    'r': 8,
                    'p': 4
                },
                'argon2': {
                    'enabled': True,
                    'time_cost': 8,
                    'memory_cost': 262144,
                    'parallelism': 8,
                    'hash_len': 64,
                    'type': 'id'
                },
                'pbkdf2_iterations': 500000
            }
        elif preset_name == "legacy":
            # Legacy preset - simple SHA-512 for compatibility
            preset = {
                'sha512': 1000,
                'sha256': 0,
                'sha3_256': 0,
                'sha3_512': 0,
                'whirlpool': 0,
                'scrypt': {
                    'n': 0,
                    'r': 8,
                    'p': 1
                },
                'argon2': {
                    'enabled': False,
                    'time_cost': 3,
                    'memory_cost': 65536,
                    'parallelism': 4,
                    'hash_len': 32,
                    'type': 'id'
                },
                'pbkdf2_iterations': 10000
            }
        else:
            # Default to standard
            return
            
        # Update the config
        self.config = preset
        
        # Update UI variables
        self.update_ui_from_config()
        
        messagebox.showinfo("Preset Loaded", f"The {preset_name} security preset has been loaded.\n\n"
                           "Remember to click 'Save Settings' to apply these changes.")
    
    def update_ui_from_config(self):
        """Update UI variables from current configuration"""
        # Update hash variables
        for key in self.hash_vars:
            if key in self.config:
                self.hash_vars[key].set(self.config[key])
        
        # Update Scrypt variables
        for key in self.scrypt_vars:
            if key in self.config['scrypt']:
                self.scrypt_vars[key].set(self.config['scrypt'][key])
        
        # Update Argon2 variables
        for key in self.argon2_vars:
            if key in self.config['argon2']:
                self.argon2_vars[key].set(self.config['argon2'][key])
    
    def update_config_from_ui(self):
        """Update configuration from UI variables"""
        # Update hash settings
        for key in self.hash_vars:
            if key in self.config:
                self.config[key] = self.hash_vars[key].get()
        
        # Update Scrypt settings
        for key in self.scrypt_vars:
            if key in self.config['scrypt']:
                self.config['scrypt'][key] = self.scrypt_vars[key].get()
        
        # Update Argon2 settings
        for key in self.argon2_vars:
            if key in self.config['argon2']:
                self.config['argon2'][key] = self.argon2_vars[key].get()
    
    def validate_settings(self):
        """Validate user settings for sanity"""
        # Check that N value for Scrypt is a power of 2
        n_value = self.scrypt_vars['n'].get()
        if n_value > 0 and (n_value & (n_value - 1)) != 0:
            messagebox.showerror("Invalid Setting", 
                               "Scrypt N value must be a power of 2 (1024, 2048, 4096, etc.)")
            return False
            
        # Ensure PBKDF2 iterations is at least 10000 for security
        pbkdf2_iterations = self.hash_vars['pbkdf2_iterations'].get()
        if pbkdf2_iterations < 10000:
            if messagebox.askyesno("Security Warning", 
                                 "PBKDF2 iterations is set below the recommended minimum of 10,000.\n\n"
                                 "This reduces the security of your encryption.\n\n"
                                 "Do you want to continue anyway?"):
                # User chose to ignore warning
                pass
            else:
                return False
                
        # Check if at least one hashing algorithm is enabled
        all_disabled = (
            self.hash_vars['sha512'].get() == 0 and
            self.hash_vars['sha256'].get() == 0 and
            self.hash_vars['sha3_256'].get() == 0 and
            self.hash_vars['sha3_512'].get() == 0 and
            self.hash_vars['whirlpool'].get() == 0 and
            self.scrypt_vars['n'].get() == 0 and
            (not self.argon2_vars['enabled'].get())
        )
        
        if all_disabled:
            messagebox.showwarning("Security Warning", 
                                 "You have disabled all hash algorithms except for base PBKDF2.\n\n"
                                 "While this will work, it's recommended to enable at least one "
                                 "additional algorithm for better security.")
        
        return True
    
    def save_settings(self):
        """Save settings to configuration file"""
        # Update config from UI
        self.update_config_from_ui()
        
        # Validate before saving
        if not self.validate_settings():
            return
            
        try:
            # Save to file
            with open(CONFIG_FILE, 'w') as f:
                json.dump(self.config, f, indent=4)
                
            messagebox.showinfo("Settings Saved", 
                              "Your encryption settings have been saved successfully.\n\n"
                              "These settings will be applied to all future encryption operations.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save settings: {str(e)}")
    
    def load_settings(self):
        """Load settings from configuration file"""
        try:
            if os.path.exists(CONFIG_FILE):
                with open(CONFIG_FILE, 'r') as f:
                    loaded_config = json.load(f)
                    
                # Merge with default config to ensure all keys exist
                self.merge_config(loaded_config)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load settings: {str(e)}\n\nDefault settings will be used.")
            # Reset to defaults on error
            self.config = DEFAULT_CONFIG.copy()
    
    def merge_config(self, loaded_config):
        """Merge loaded config with default config to ensure all keys exist"""
        # Update top-level keys
        for key in self.config:
            if key in loaded_config:
                if isinstance(self.config[key], dict) and isinstance(loaded_config[key], dict):
                    # For nested dictionaries like scrypt and argon2
                    for subkey in self.config[key]:
                        if subkey in loaded_config[key]:
                            self.config[key][subkey] = loaded_config[key][subkey]
                else:
                    # For simple values
                    self.config[key] = loaded_config[key]
    
    def reset_to_defaults(self):
        """Reset settings to default values"""
        if messagebox.askyesno("Reset Settings", 
                             "Are you sure you want to reset all settings to their defaults?"):
            self.config = DEFAULT_CONFIG.copy()
            self.update_ui_from_config()
            messagebox.showinfo("Settings Reset", 
                              "All settings have been reset to their default values.\n\n"
                              "Click 'Save Settings' to apply these changes.")
    
    def test_settings(self):
        """Test current settings on a small sample to estimate performance"""
        # Update config from UI
        self.update_config_from_ui()
        
        # Show a simple estimate
        message = (
            "Based on your current settings, here's a rough performance estimate:\n\n"
            "SHA-512: {sha512} rounds\n"
            "SHA-256: {sha256} rounds\n"
            "SHA3-512: {sha3_512} rounds\n"
            "SHA3-256: {sha3_256} rounds\n"
            "Whirlpool: {whirlpool} rounds\n"
            "Scrypt: {scrypt_enabled} (N={scrypt_n}, r={scrypt_r}, p={scrypt_p})\n"
            "Argon2: {argon2_enabled} (t={argon2_t}, m={argon2_m}KB, p={argon2_p})\n"
            "PBKDF2: {pbkdf2} iterations\n\n"
        ).format(
            sha512=self.config['sha512'],
            sha256=self.config['sha256'],
            sha3_512=self.config['sha3_512'],
            sha3_256=self.config['sha3_256'],
            whirlpool=self.config['whirlpool'],
            scrypt_enabled="Enabled" if self.config['scrypt']['n'] > 0 else "Disabled",
            scrypt_n=self.config['scrypt']['n'],
            scrypt_r=self.config['scrypt']['r'],
            scrypt_p=self.config['scrypt']['p'],
            argon2_enabled="Enabled" if self.config['argon2']['enabled'] else "Disabled",
            argon2_t=self.config['argon2']['time_cost'],
            argon2_m=self.config['argon2']['memory_cost'],
            argon2_p=self.config['argon2']['parallelism'],
            pbkdf2=self.config['pbkdf2_iterations']
        )
        
        # Estimate performance
        performance_level = self.estimate_performance_level()
        
        if performance_level == "light":
            message += "Performance Impact: Light ✓\nEncryption and decryption should be fast."
        elif performance_level == "moderate":
            message += "Performance Impact: Moderate ⚠️\nEncryption and decryption may take a few seconds."
        elif performance_level == "heavy":
            message += "Performance Impact: Heavy ⚠️⚠️\nEncryption and decryption may take 10+ seconds."
        else:  # intensive
            message += "Performance Impact: Intensive ⚠️⚠️⚠️\nEncryption and decryption may take 30+ seconds or more."
            
        messagebox.showinfo("Settings Performance Estimate", message)
    
    def estimate_performance_level(self):
        """Estimate the performance impact of current settings"""
        # Calculate a rough score based on the settings
        score = 0
        
        # Score iterative hashes
        score += self.config['sha512'] / 10000
        score += self.config['sha256'] / 10000
        score += self.config['sha3_256'] / 10000
        score += self.config['sha3_512'] / 10000
        score += self.config['whirlpool'] / 5000
        
        # Score PBKDF2
        score += self.config['pbkdf2_iterations'] / 50000
        
        # Score Scrypt (higher impact)
        if self.config['scrypt']['n'] > 0:
            # Logarithmic scale since Scrypt impact grows quickly with N
            score += (2 * (self.config['scrypt']['n'] / 8192)) * (self.config['scrypt']['r'] / 8) * self.config['scrypt']['p']
        
        # Score Argon2 (higher impact)
        if self.config['argon2']['enabled']:
            score += (2 * (self.config['argon2']['memory_cost'] / 65536)) * \
                    (self.config['argon2']['time_cost'] / 3) * \
                    (self.config['argon2']['parallelism'] / 4)
        
        # Determine performance level
        if score < 5:
            return "light"
        elif score < 15:
            return "moderate"
        elif score < 30:
            return "heavy"
        else:
            return "intensive"
            
    def get_current_config(self):
        """Return the current configuration (used by other components)"""
        self.update_config_from_ui()
        return self.config
