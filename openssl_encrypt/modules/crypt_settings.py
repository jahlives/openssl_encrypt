#!/usr/bin/env python3
"""
Enhanced GUI for the encryption tool with settings tab.
This version adds a settings tab to configure hash parameters.
"""

import os
import sys
import tkinter as tk
from tkinter import ttk, filedialog, simpledialog, messagebox
import subprocess
import threading
import random
import string
import time
import json

CONFIG_FILE = os.path.join(os.path.expanduser("~"), ".crypt_settings.json")

# Default configuration
DEFAULT_CONFIG = {
    # Hash iterations
    'sha512': 10000,
    'sha256': 0,
    'sha3_256': 10000,  # Enable SHA3-256 by default with 10000 iterations
    'sha3_512': 0,
    'blake2b': 0,       # BLAKE2b hash function with default of 0 iterations
    'shake256': 0,      # SHAKE-256 hash function with default of 0 iterations
    'whirlpool': 0,
    # Scrypt parameters
    'scrypt': {
        'enabled': False,
        'rounds': 100,
        'n': 16384,  # CPU/memory cost factor (must be power of 2)
        'r': 8,      # Block size
        'p': 1       # Parallelization factor
    },
    # Argon2 parameters
    'argon2': {
        'enabled': False,
        'rounds': 100,
        'time_cost': 3,
        'memory_cost': 65536,  # 64 MB
        'parallelism': 4,
        'hash_len': 32,
        'type': 'id'  # id, i, or d
    },
    # Balloon parameters
    'balloon': {
        'enabled': False,
        'rounds': 1,           # Number of chained KDF rounds
        'space_cost': 16,      # Memory usage factor
        'time_cost': 20,       # Number of internal rounds
        'delta': 4,            # Number of random blocks
        'parallel_cost': 4     # Number of concurrent instances for balloon_m
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

        # SHA3-256 - Enhanced with tooltip/help text
        row += 1
        ttk.Label(hash_frame, text="SHA3-256 rounds:").grid(row=row, column=0, sticky=tk.W, padx=5, pady=5)
        self.hash_vars['sha3_256'] = tk.IntVar(value=self.config['sha3_256'])
        ttk.Entry(hash_frame, textvariable=self.hash_vars['sha3_256'], width=10).grid(
            row=row, column=1, sticky=tk.W, padx=5, pady=5)
        sha3_256_help = ttk.Label(hash_frame, text="(Recommended: 10000+)", foreground="blue")
        sha3_256_help.grid(row=row, column=2, sticky=tk.W, padx=5, pady=5)

        # Add tooltip functionality for SHA3-256
        self.create_tooltip(sha3_256_help,
                            "SHA3-256 is a modern, NIST-standardized hash function with improved security "
                            "compared to SHA-2. It's resistant to length extension attacks and recommended "
                            "for new implementations.")

        # SHA3-512
        row += 1
        ttk.Label(hash_frame, text="SHA3-512 rounds:").grid(row=row, column=0, sticky=tk.W, padx=5, pady=5)
        self.hash_vars['sha3_512'] = tk.IntVar(value=self.config['sha3_512'])
        ttk.Entry(hash_frame, textvariable=self.hash_vars['sha3_512'], width=10).grid(
            row=row, column=1, sticky=tk.W, padx=5, pady=5)
        ttk.Label(hash_frame, text="(0 to disable)").grid(row=row, column=2, sticky=tk.W, padx=5, pady=5)

        # BLAKE2b - Modern cryptographic hash function
        row += 1
        ttk.Label(hash_frame, text="BLAKE2b rounds:").grid(row=row, column=0, sticky=tk.W, padx=5, pady=5)
        self.hash_vars['blake2b'] = tk.IntVar(value=self.config['blake2b'])
        ttk.Entry(hash_frame, textvariable=self.hash_vars['blake2b'], width=10).grid(
            row=row, column=1, sticky=tk.W, padx=5, pady=5)
        blake2b_help = ttk.Label(hash_frame, text="(Modern, high-performance hash)", foreground="blue")
        blake2b_help.grid(row=row, column=2, sticky=tk.W, padx=5, pady=5)
        
        # Add tooltip for BLAKE2b
        self.create_tooltip(blake2b_help,
                           "BLAKE2b is a cryptographic hash function faster than MD5, SHA-1, SHA-2, and SHA-3, "
                           "yet is at least as secure as the latest standard SHA-3. It's widely used in modern "
                           "cryptographic applications and provides 512-bit output.")

        # SHAKE-256 - Extendable-output function (XOF)
        row += 1
        ttk.Label(hash_frame, text="SHAKE-256 rounds:").grid(row=row, column=0, sticky=tk.W, padx=5, pady=5)
        self.hash_vars['shake256'] = tk.IntVar(value=self.config['shake256'])
        ttk.Entry(hash_frame, textvariable=self.hash_vars['shake256'], width=10).grid(
            row=row, column=1, sticky=tk.W, padx=5, pady=5)
        shake256_help = ttk.Label(hash_frame, text="(SHA-3 family extendable-output function)", foreground="blue")
        shake256_help.grid(row=row, column=2, sticky=tk.W, padx=5, pady=5)
        
        # Add tooltip for SHAKE-256
        self.create_tooltip(shake256_help,
                           "SHAKE-256 is an extendable-output function (XOF) from the SHA-3 family. "
                           "It can generate outputs of any desired length, making it highly versatile. "
                           "In this implementation, it produces 64 bytes (512 bits) of output for "
                           "consistency with other hash functions.")

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
        
        # Enable Scrypt
        row = 0
        self.scrypt_vars['enabled'] = tk.BooleanVar(value=self.config['scrypt']['enabled'])
        scrypt_enable = ttk.Checkbutton(scrypt_frame, text="Enable Scrypt", variable=self.scrypt_vars['enabled'])
        scrypt_enable.grid(row=row, column=0, columnspan=3, sticky=tk.W, padx=5, pady=5)
        
        # Add tooltip for Scrypt
        self.create_tooltip(scrypt_enable,
                          "Scrypt is a memory-hard key derivation function designed to be resistant to "
                          "hardware attacks. It requires significant memory resources, making it "
                          "particularly effective against GPU-based attacks.")

        # CPU/Memory cost factor (N)
        row += 1
        ttk.Label(scrypt_frame, text="CPU/Memory cost (N):").grid(row=row, column=0, sticky=tk.W, padx=5, pady=5)
        self.scrypt_vars['n'] = tk.IntVar(value=self.config['scrypt']['n'])
        n_values = [1024, 2048, 4096, 8192, 16384, 32768, 65536, 131072, 262144, 524288, 1048576]
        n_combo = ttk.Combobox(scrypt_frame, textvariable=self.scrypt_vars['n'], values=n_values, width=10)
        n_combo.grid(row=row, column=1, sticky=tk.W, padx=5, pady=5)
        ttk.Label(scrypt_frame, text="(must be power of 2, 16384 is standard)").grid(
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
        
        # KDF rounds
        row += 1
        ttk.Label(scrypt_frame, text="Chained KDF rounds:").grid(row=row, column=0, sticky=tk.W, padx=5, pady=5)
        self.scrypt_vars['rounds'] = tk.IntVar(value=self.config['scrypt']['rounds'])
        rounds_values = [1, 5, 10, 25, 50, 100, 250, 500, 1000]
        rounds_combo = ttk.Combobox(scrypt_frame, textvariable=self.scrypt_vars['rounds'], values=rounds_values, width=10)
        rounds_combo.grid(row=row, column=1, sticky=tk.W, padx=5, pady=5)
        rounds_help = ttk.Label(scrypt_frame, text="(number of times to apply KDF sequentially)")
        rounds_help.grid(row=row, column=2, sticky=tk.W, padx=5, pady=5)
        
        # Add tooltip for rounds
        self.create_tooltip(rounds_help,
                           "Specifies how many times to chain the KDF function. Each round uses the output "
                           "of the previous round as input, significantly increasing attack difficulty "
                           "while using less memory than increasing other parameters.")

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
        
        # KDF rounds
        row += 1
        ttk.Label(argon2_frame, text="Chained KDF rounds:").grid(row=row, column=0, sticky=tk.W, padx=5, pady=5)
        self.argon2_vars['rounds'] = tk.IntVar(value=self.config['argon2']['rounds'])
        rounds_values = [1, 5, 10, 25, 50, 100, 250, 500, 1000]
        rounds_combo = ttk.Combobox(argon2_frame, textvariable=self.argon2_vars['rounds'], values=rounds_values, width=10)
        rounds_combo.grid(row=row, column=1, sticky=tk.W, padx=5, pady=5)
        argon2_rounds_help = ttk.Label(argon2_frame, text="(number of times to apply KDF sequentially)")
        argon2_rounds_help.grid(row=row, column=2, sticky=tk.W, padx=5, pady=5)
        
        # Add tooltip for rounds
        self.create_tooltip(argon2_rounds_help,
                           "Specifies how many times to chain the Argon2 function. Each round uses the output "
                           "of the previous round as input, significantly increasing attack difficulty. "
                           "This provides additional security beyond what Argon2's internal iterations provide.")
        
        # Balloon settings
        balloon_frame = ttk.LabelFrame(scrollable_frame, text="Balloon Settings (Memory-Hard Function)")
        balloon_frame.pack(fill=tk.X, expand=True, padx=10, pady=5)
        
        self.balloon_vars = {}
        
        # Enable Balloon
        row = 0
        self.balloon_vars['enabled'] = tk.BooleanVar(value=self.config['balloon']['enabled'])
        balloon_enable = ttk.Checkbutton(balloon_frame, text="Enable Balloon", variable=self.balloon_vars['enabled'])
        balloon_enable.grid(row=row, column=0, columnspan=3, sticky=tk.W, padx=5, pady=5)
        
        # Add tooltip for Balloon
        self.create_tooltip(balloon_enable,
                           "Balloon is a memory-hard hashing function designed to be resistant to "
                           "attacks from specialized hardware. It's particularly effective against "
                           "GPU-based attacks and provides strong security guarantees.")
        
        # Space cost
        row += 1
        ttk.Label(balloon_frame, text="Space cost:").grid(row=row, column=0, sticky=tk.W, padx=5, pady=5)
        self.balloon_vars['space_cost'] = tk.IntVar(value=self.config['balloon']['space_cost'])
        space_values = [8, 16, 32, 64, 128, 256]
        space_combo = ttk.Combobox(balloon_frame, textvariable=self.balloon_vars['space_cost'],
                                 values=space_values, width=10)
        space_combo.grid(row=row, column=1, sticky=tk.W, padx=5, pady=5)
        ttk.Label(balloon_frame, text="(memory usage factor, higher is more secure)").grid(
            row=row, column=2, sticky=tk.W, padx=5, pady=5)
        
        # Time cost
        row += 1
        ttk.Label(balloon_frame, text="Time cost:").grid(row=row, column=0, sticky=tk.W, padx=5, pady=5)
        self.balloon_vars['time_cost'] = tk.IntVar(value=self.config['balloon']['time_cost'])
        time_values = [10, 20, 30, 40, 50]
        time_combo = ttk.Combobox(balloon_frame, textvariable=self.balloon_vars['time_cost'],
                               values=time_values, width=10)
        time_combo.grid(row=row, column=1, sticky=tk.W, padx=5, pady=5)
        ttk.Label(balloon_frame, text="(number of rounds, higher is more secure)").grid(
            row=row, column=2, sticky=tk.W, padx=5, pady=5)
        
        # Delta
        row += 1
        ttk.Label(balloon_frame, text="Delta:").grid(row=row, column=0, sticky=tk.W, padx=5, pady=5)
        self.balloon_vars['delta'] = tk.IntVar(value=self.config['balloon']['delta'])
        delta_values = [3, 4, 5, 6]
        delta_combo = ttk.Combobox(balloon_frame, textvariable=self.balloon_vars['delta'],
                               values=delta_values, width=10)
        delta_combo.grid(row=row, column=1, sticky=tk.W, padx=5, pady=5)
        delta_help = ttk.Label(balloon_frame, text="(number of random blocks, 4 is standard)")
        delta_help.grid(row=row, column=2, sticky=tk.W, padx=5, pady=5)
        
        # Parallel cost
        row += 1
        ttk.Label(balloon_frame, text="Parallel cost:").grid(row=row, column=0, sticky=tk.W, padx=5, pady=5)
        self.balloon_vars['parallel_cost'] = tk.IntVar(value=self.config['balloon']['parallel_cost'])
        parallel_values = [1, 2, 4, 8, 16]
        parallel_combo = ttk.Combobox(balloon_frame, textvariable=self.balloon_vars['parallel_cost'],
                                    values=parallel_values, width=10)
        parallel_combo.grid(row=row, column=1, sticky=tk.W, padx=5, pady=5)
        ttk.Label(balloon_frame, text="(concurrent instances, use CPU core count)").grid(
            row=row, column=2, sticky=tk.W, padx=5, pady=5)
            
        # KDF rounds
        row += 1
        ttk.Label(balloon_frame, text="Chained KDF rounds:").grid(row=row, column=0, sticky=tk.W, padx=5, pady=5)
        self.balloon_vars['rounds'] = tk.IntVar(value=self.config['balloon']['rounds'] if 'rounds' in self.config['balloon'] else 1)
        rounds_values = [1, 5, 10, 25, 50, 100, 250, 500, 1000]
        rounds_combo = ttk.Combobox(balloon_frame, textvariable=self.balloon_vars['rounds'], values=rounds_values, width=10)
        rounds_combo.grid(row=row, column=1, sticky=tk.W, padx=5, pady=5)
        balloon_rounds_help = ttk.Label(balloon_frame, text="(number of times to apply KDF sequentially)")
        balloon_rounds_help.grid(row=row, column=2, sticky=tk.W, padx=5, pady=5)
        
        # Add tooltip for rounds
        self.create_tooltip(balloon_rounds_help,
                           "Specifies how many times to chain the Balloon function. Each round uses the output "
                           "of the previous round as input, significantly increasing attack difficulty. "
                           "This improves security with minimal memory overhead compared to increasing space_cost.")

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
                     "The Paranoid preset is extremely secure but may be slow on older hardware.\n\n"
                     "SHA3-256 is recommended as a modern, secure hash algorithm.")

        ttk.Label(info_frame, text=info_text, wraplength=550, justify=tk.LEFT).pack(padx=10, pady=10)

    def create_tooltip(self, widget, text):
        """Create a tooltip for a given widget with the provided text"""

        # This is a simple implementation - will show tooltip on hover
        def enter(event):
            # Create a toplevel window
            tooltip = tk.Toplevel(self.parent)
            # No window manager decorations
            tooltip.wm_overrideredirect(True)

            # Position tooltip near the widget
            x = widget.winfo_rootx() + 20
            y = widget.winfo_rooty() + 20
            tooltip.wm_geometry(f"+{x}+{y}")

            # Create the tooltip content
            label = ttk.Label(tooltip, text=text, justify=tk.LEFT,
                              background="#FFFFDD", relief=tk.SOLID, borderwidth=1,
                              wraplength=300)
            label.pack(padx=5, pady=5)

            # Store the tooltip window
            widget.tooltip = tooltip

        def leave(event):
            # Destroy the tooltip when the mouse leaves
            if hasattr(widget, "tooltip"):
                widget.tooltip.destroy()
                delattr(widget, "tooltip")

        # Bind the events to the widget
        widget.bind("<Enter>", enter)
        widget.bind("<Leave>", leave)

    def load_preset(self, preset_name):
        """Load a predefined security preset"""
        if preset_name == "standard":
            # Standard preset - good balance of security and performance
            preset = {
                'sha512': 10000,
                'sha256': 0,
                'sha3_256': 10000,  # Added SHA3-256 as a primary hash
                'sha3_512': 0,
                'blake2b': 0,       # No BLAKE2b in standard preset
                'shake256': 0,      # No SHAKE-256 in standard preset  
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
                'balloon': {
                    'enabled': False,
                    'rounds': 1,
                    'space_cost': 16,
                    'time_cost': 20,
                    'delta': 4,
                    'parallel_cost': 4
                },
                'pbkdf2_iterations': 100000
            }
        elif preset_name == "high":
            # High security preset - stronger but slower
            preset = {
                'sha512': 50000,
                'sha256': 0,
                'sha3_256': 20000,  # Added higher SHA3-256 iteration count
                'sha3_512': 5000,
                'blake2b': 10000,   # Added BLAKE2b for high security preset
                'shake256': 0,      # No SHAKE-256 in high security preset
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
                'balloon': {
                    'enabled': False,
                    'rounds': 5,
                    'space_cost': 32,
                    'time_cost': 30,
                    'delta': 4,
                    'parallel_cost': 4
                },
                'pbkdf2_iterations': 200000
            }
        elif preset_name == "paranoid":
            # Paranoid preset - extremely secure but very slow
            preset = {
                'sha512': 100000,
                'sha256': 10000,
                'sha3_256': 50000,  # Higher SHA3-256 iterations for paranoid preset
                'sha3_512': 10000,
                'blake2b': 20000,   # Add BLAKE2b for paranoid preset
                'shake256': 15000,  # Add SHAKE-256 for paranoid preset 
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
                'balloon': {
                    'enabled': True,
                    'rounds': 25,
                    'space_cost': 64,
                    'time_cost': 40,
                    'delta': 5,
                    'parallel_cost': 8
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
                'blake2b': 0,       # No BLAKE2b in legacy preset
                'shake256': 0,      # No SHAKE-256 in legacy preset
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
                'balloon': {
                    'enabled': False,
                    'rounds': 1,
                    'space_cost': 16,
                    'time_cost': 20,
                    'delta': 4,
                    'parallel_cost': 4
                },
                'pbkdf2_iterations': 10000
            }
        else:
            # Default to standard preset if an unknown preset is provided
            return self.load_preset("standard")

        # Create a deep copy of the preset using the copy module
        import copy
        self.config = copy.deepcopy(preset)

        # Update UI variables to reflect the new configuration
        self.update_ui_from_config()

        # Show info message using tkinter messagebox
        import tkinter.messagebox
        tkinter.messagebox.showinfo(
            "Preset Loaded",
            f"The {preset_name} security preset has been loaded.\n\n"
            "Remember to click 'Save Settings' to apply these changes."
        )

        # Return the new configuration for potential further use
        return self.config
    
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
                
        # Update Balloon variables
        for key in self.balloon_vars:
            if key in self.config['balloon']:
                self.balloon_vars[key].set(self.config['balloon'][key])
    
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
                
        # Update Balloon settings
        for key in self.balloon_vars:
            if key in self.config['balloon']:
                self.config['balloon'][key] = self.balloon_vars[key].get()
    
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
                
        # Validate Balloon settings if enabled
        if self.balloon_vars['enabled'].get():
            # Ensure space_cost is at least 8
            space_cost = self.balloon_vars['space_cost'].get()
            if space_cost < 8:
                messagebox.showerror("Invalid Setting",
                                  "Balloon space cost must be at least 8 for adequate security.")
                return False
                
            # Ensure time_cost is at least 10
            time_cost = self.balloon_vars['time_cost'].get()
            if time_cost < 10:
                messagebox.showerror("Invalid Setting",
                                  "Balloon time cost must be at least 10 for adequate security.")
                return False
                
            # Ensure delta is at least 3
            delta = self.balloon_vars['delta'].get()
            if delta < 3:
                messagebox.showerror("Invalid Setting",
                                  "Balloon delta must be at least 3 for proper security.")
                return False
                
        # Check if at least one hashing algorithm is enabled
        all_disabled = (
            self.hash_vars['sha512'].get() == 0 and
            self.hash_vars['sha256'].get() == 0 and
            self.hash_vars['sha3_256'].get() == 0 and
            self.hash_vars['sha3_512'].get() == 0 and
            self.hash_vars['blake2b'].get() == 0 and
            self.hash_vars['shake256'].get() == 0 and
            self.hash_vars['whirlpool'].get() == 0 and
            (not self.scrypt_vars['enabled'].get()) and
            (not self.argon2_vars['enabled'].get()) and
            (not self.balloon_vars['enabled'].get())
        )
        
        if all_disabled:
            messagebox.showwarning("Security Warning", 
                                 "You have disabled all hash algorithms except for base PBKDF2.\n\n"
                                 "While this will work, it's recommended to enable at least one "
                                 "additional algorithm for better security.")
        
        return True

    import os
    import json
    import tkinter.messagebox as messagebox  # Ensure this import is at the top of the file

    def save_settings(self):
        """Save settings to configuration file"""
        # Update config from UI
        self.update_config_from_ui()

        # Validate before saving
        if not self.validate_settings():
            return False

        try:
            # Ensure the directory exists
            config_dir = os.path.dirname(CONFIG_FILE)

            # Create directory if it doesn't exist
            if config_dir:
                os.makedirs(config_dir, exist_ok=True)

            # Save to file
            with open(CONFIG_FILE, 'w') as f:
                json.dump(self.config, f, indent=4)

            # Explicitly import messagebox
            import tkinter.messagebox

            # Call showinfo
            tkinter.messagebox.showinfo(
                "Settings Saved",
                "Your encryption settings have been saved successfully.\n\n"
                "These settings will be applied to all future encryption operations."
            )

            return True

        except Exception as e:
            # Print detailed error information
            print(f"[SETTINGS] Error saving settings: {e}")
            import traceback
            traceback.print_exc()

            # Try to show error message
            try:
                import tkinter.messagebox
                tkinter.messagebox.showerror("Error", f"Failed to save settings: {str(e)}")
            except Exception as show_err:
                print(f"[SETTINGS] Could not show error message: {show_err}")

            return False

    def load_settings(self):
        """Load settings from configuration file"""
        try:
            if os.path.exists(CONFIG_FILE):
                with open(CONFIG_FILE, 'r') as f:
                    loaded_config = json.load(f)

                # Merge with default config to ensure all keys exist
                self.merge_config(loaded_config)

                # For debugging in tests
                # print(f"Loaded config: {self.config}")
        except Exception as e:
            print(f"Failed to load settings: {str(e)}")
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
            "SHA3-256: {sha3_256} rounds {sha3_recommended}\n"
            "SHA3-512: {sha3_512} rounds\n"
            "BLAKE2b: {blake2b} rounds {blake2b_recommended}\n"
            "SHAKE-256: {shake256} rounds {shake256_recommended}\n"
            "Whirlpool: {whirlpool} rounds\n"
            "Scrypt: {scrypt_enabled} (N={scrypt_n}, r={scrypt_r}, p={scrypt_p}, rounds={scrypt_rounds})\n"
            "Argon2: {argon2_enabled} (t={argon2_t}, m={argon2_m}KB, p={argon2_p}, rounds={argon2_rounds})\n"
            "Balloon: {balloon_enabled} (s={balloon_s}, t={balloon_t}, d={balloon_d}, p={balloon_p}, rounds={balloon_rounds})\n"
            "PBKDF2: {pbkdf2} iterations\n\n"
        ).format(
            sha512=self.config['sha512'],
            sha256=self.config['sha256'],
            sha3_256=self.config['sha3_256'],
            # Add recommendation indicator for SHA3-256
            sha3_recommended="★ (recommended)" if self.config[
                                                      'sha3_256'] > 0 else "- consider enabling for better security",
            sha3_512=self.config['sha3_512'],
            # Add BLAKE2b with recommendation
            blake2b=self.config['blake2b'],
            blake2b_recommended="★ (high performance)" if self.config[
                                                      'blake2b'] > 0 else "",
            # Add SHAKE-256 with recommendation
            shake256=self.config['shake256'],
            shake256_recommended="★ (variable-length output)" if self.config[
                                                      'shake256'] > 0 else "",
            whirlpool=self.config['whirlpool'],
            scrypt_enabled="Enabled" if self.config['scrypt']['enabled'] else "Disabled",
            scrypt_n=self.config['scrypt']['n'],
            scrypt_r=self.config['scrypt']['r'],
            scrypt_p=self.config['scrypt']['p'],
            scrypt_rounds=self.config['scrypt']['rounds'],
            argon2_enabled="Enabled" if self.config['argon2']['enabled'] else "Disabled",
            argon2_t=self.config['argon2']['time_cost'],
            argon2_m=self.config['argon2']['memory_cost'],
            argon2_p=self.config['argon2']['parallelism'],
            argon2_rounds=self.config['argon2']['rounds'],
            balloon_enabled="Enabled" if self.config['balloon']['enabled'] else "Disabled",
            balloon_s=self.config['balloon']['space_cost'],
            balloon_t=self.config['balloon']['time_cost'],
            balloon_d=self.config['balloon']['delta'],
            balloon_p=self.config['balloon']['parallel_cost'],
            balloon_rounds=self.config['balloon']['rounds'],
            pbkdf2=self.config['pbkdf2_iterations']
        )

        # Add note about SHA3-256
        if self.config['sha3_256'] == 0:
            message += (
                "Security Note: SHA3-256 is a modern hash function standardized by NIST. It offers\n"
                "improved security over older hash functions. Consider enabling it with at least\n"
                "10,000 rounds for better protection.\n\n"
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
        # SHA3-256 is slightly more efficient than SHA-256
        score += self.config['sha3_256'] / 12000  # Adjusted weight for SHA3-256
        score += self.config['sha3_512'] / 10000
        # BLAKE2b is significantly faster than other hash functions, adjust weight accordingly
        score += self.config['blake2b'] / 15000   # BLAKE2b is more efficient
        # SHAKE-256 is a bit slower than SHA3-256
        score += self.config['shake256'] / 11000  # Adjusted weight for SHAKE-256
        score += self.config['whirlpool'] / 5000

        # Score PBKDF2
        score += self.config['pbkdf2_iterations'] / 50000

        # Score Scrypt (higher impact)
        if self.config['scrypt']['n'] > 0:
            # Logarithmic scale since Scrypt impact grows quickly with N
            score += (2 * (self.config['scrypt']['n'] / 8192)) * (self.config['scrypt']['r'] / 8) * \
                     self.config['scrypt']['p'] * (self.config['scrypt']['rounds'] / 10)

        # Score Argon2 (higher impact)
        if self.config['argon2']['enabled']:
            score += (2 * (self.config['argon2']['memory_cost'] / 65536)) * \
                     (self.config['argon2']['time_cost'] / 3) * \
                     (self.config['argon2']['parallelism'] / 4) * \
                     (self.config['argon2']['rounds'] / 10)
                     
        # Score Balloon (higher impact)
        if self.config['balloon']['enabled']:
            score += (1.5 * (self.config['balloon']['space_cost'] / 16)) * \
                     (self.config['balloon']['time_cost'] / 20) * \
                     (self.config['balloon']['delta'] / 4) * \
                     (self.config['balloon']['parallel_cost'] / 4) * \
                     (self.config['balloon']['rounds'] / 10)

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
