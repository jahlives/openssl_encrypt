#!/usr/bin/env python3
"""
Simple GUI for the encryption tool with the new password generation features.
This can replace or supplement crypt_gui.py if it's not working.
"""

import os
import sys
import tkinter as tk
from time import sleep
from tkinter import ttk, filedialog, messagebox, simpledialog
import subprocess
import threading
import random
import string
import time

# Import the settings module
try:
    from .modules.crypt_settings import SettingsTab, DEFAULT_CONFIG
except ImportError:
    # Fallback if module is not found
    print("Settings module not found, using default configuration")
    DEFAULT_CONFIG = {
        'sha512': 10000,
        'sha256': 0,
        'sha3_256': 0,
        'sha3_512': 0,
        'whirlpool': 0,
        'blake2b': 0,
        'shake256': 0,
        'scrypt': {
            'enabled': False,
            'n': 16384,
            'r': 8,
            'p': 1,
            'rounds': 100
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


    # Create a basic fallback settings tab class
    class SettingsTab:
        def __init__(self, parent, gui_instance):
            self.parent = parent
            self.gui = gui_instance
            self.config = DEFAULT_CONFIG.copy()

            ttk.Label(self.parent, text="Settings module not available.",
                      font=("TkDefaultFont", 12, "bold")).pack(pady=20)

        def get_current_config(self):
            return self.config

class CryptGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure File Encryption Tool")
        self.root.geometry("650x1200")
        self.root.minsize(650, 580)

        # Configure style
        self.style = ttk.Style()
        self.style.configure("TNotebook.Tab", padding=[12, 5])
        self.style.configure("TButton", padding=[10, 5])

        # Create notebook (tabs)
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Create tab frames
        self.encrypt_frame = ttk.Frame(self.notebook)
        self.decrypt_frame = ttk.Frame(self.notebook)
        self.shred_frame = ttk.Frame(self.notebook)
        self.password_frame = ttk.Frame(self.notebook)
        self.settings_frame = ttk.Frame(self.notebook)  # New settings frame

        # Add frames to notebook
        self.notebook.add(self.encrypt_frame, text="Encrypt")
        self.notebook.add(self.decrypt_frame, text="Decrypt")
        self.notebook.add(self.shred_frame, text="Shred")
        self.notebook.add(self.password_frame, text="Password Generator")
        self.notebook.add(self.settings_frame, text="Settings")  # Add settings tab

        # Set up the tabs
        self.setup_encrypt_tab()
        self.setup_decrypt_tab()
        self.setup_shred_tab()
        self.setup_password_tab()
        self.setup_settings_tab()  # Initialize settings tab

        # Add text display area for command output
        self.output_frame = ttk.LabelFrame(root, text="Output")
        self.output_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Add text widget with scrollbar
        self.output_text = tk.Text(self.output_frame, wrap=tk.WORD, height=10)
        self.output_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)

        scrollbar = ttk.Scrollbar(self.output_frame, command=self.output_text.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.output_text.config(yscrollcommand=scrollbar.set)

        # Button frame for Clear and Copy buttons
        button_frame = ttk.Frame(root)
        button_frame.pack(fill=tk.X, padx=10, pady=5)

        # Clear button for output
        clear_button = ttk.Button(button_frame, text="Clear Output",
                                  command=lambda: self.output_text.delete(1.0, tk.END))
        clear_button.pack(side=tk.LEFT, padx=5)

        # Copy to clipboard button
        copy_button = ttk.Button(button_frame, text="Copy to Clipboard",
                                 command=self.copy_to_clipboard)
        copy_button.pack(side=tk.LEFT, padx=5)

        # Status bar at the bottom
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        self.status_bar = ttk.Label(root, textvariable=self.status_var, 
                                   relief=tk.SUNKEN, anchor=tk.W, padding=(5, 3))
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X, pady=(5, 5))
        # Change the status bar padding to not have bottom padding
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X, pady=(5, 0))

        # Progress bar for hashing and encryption/decryption operations
        self.progress_var = tk.DoubleVar()
        self.progress_var.set(0)
        self.progress_bar = ttk.Progressbar(root, variable=self.progress_var,
                                            mode="determinate", length=100)
        self.progress_bar.pack(side=tk.BOTTOM, fill=tk.X, padx=5, pady=(0, 5))
        self.progress_bar.pack_forget()  # Hide initially

        # Add tracking variables for progress
        self.current_algorithm = ""
        self.last_progress_text = ""
        
        # Variables for password timeout
        self.password_timer_id = None
        self.password_timer_active = False
        self.countdown_seconds = 0
        self.countdown_label = None
        
        # Bind tab change event to clear password
        self.notebook.bind("<<NotebookTabChanged>>", self.on_tab_changed)
        
        # Center the window
        self.center_window()

    def copy_to_clipboard(self):
        """Copy the contents of the output text widget to clipboard"""
        self.root.clipboard_append(self.output_text.get(1.0, tk.END))  # Add the text to clipboard
        self.root.update()  # Make sure the clipboard content is available after the function returns

    def setup_settings_tab(self):
        """Set up the encryption settings tab"""
        # Initialize the settings tab with the parent frame and a reference to this GUI instance
        self.settings_tab = SettingsTab(self.settings_frame, self)

    def center_window(self):
        """Center the window on the screen and adjust initial size"""
        self.root.update_idletasks()
        width = max(self.root.winfo_width(), 700)  # Ensure minimum width
        height = max(self.root.winfo_height(), 650)  # Ensure minimum height
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f'{width}x{height}+{x}+{y}')

    def setup_encrypt_tab(self):
        """Set up the encryption tab"""
        # Input group
        input_group = ttk.LabelFrame(self.encrypt_frame, text="Input", padding=5)
        input_group.pack(fill="x", padx=5, pady=5)

        # Input file entry and browse button
        input_frame = ttk.Frame(input_group)
        input_frame.pack(fill="x", padx=5, pady=2)

        self.encrypt_input_var = tk.StringVar()
        input_entry = ttk.Entry(input_frame, textvariable=self.encrypt_input_var)
        input_entry.pack(side="left", fill="x", expand=True)

        browse_button = ttk.Button(
            input_frame,
            text="Browse",
            command=lambda: self.browse_file(
                self.encrypt_input_var, file_type="input"
            )
        )
        browse_button.pack(side="right", padx=(5, 0))

        # Output group
        output_group = ttk.LabelFrame(self.encrypt_frame, text="Output", padding=5)
        output_group.pack(fill="x", padx=5, pady=5)

        # Output file entry and browse button
        output_frame = ttk.Frame(output_group)
        output_frame.pack(fill="x", padx=5, pady=2)

        self.encrypt_output_var = tk.StringVar()
        output_entry = ttk.Entry(output_frame, textvariable=self.encrypt_output_var)
        output_entry.pack(side="left", fill="x", expand=True)

        browse_button = ttk.Button(
            output_frame,
            text="Browse",
            command=lambda: self.browse_file(
                self.encrypt_output_var, file_type="output"
            )
        )
        browse_button.pack(side="right", padx=(5, 0))

        # Password group
        password_group = ttk.LabelFrame(self.encrypt_frame, text="Password", padding=5)
        password_group.pack(fill="x", padx=5, pady=5)

        # Password entry
        self.encrypt_password_var = tk.StringVar()
        password_entry = ttk.Entry(
            password_group, textvariable=self.encrypt_password_var, show="*"
        )
        password_entry.pack(fill="x", padx=5, pady=2)

        # Confirm password entry
        self.encrypt_confirm_var = tk.StringVar()
        confirm_entry = ttk.Entry(
            password_group, textvariable=self.encrypt_confirm_var, show="*"
        )
        confirm_entry.pack(fill="x", padx=5, pady=2)

        # Algorithm group
        algorithm_group = ttk.LabelFrame(self.encrypt_frame, text="Encryption Algorithm", padding=5)
        algorithm_group.pack(fill="x", padx=5, pady=5)

        # Create the dropdown menu
        algorithms = [
            ("fernet", "AES-128-CBC"),
            ("aes-gcm", "AES-GCM"),
            ("aes-gcm-siv", "AES-GCM-SIV"),
            ("aes-ocb3", "AES-OCB3"),
            ("aes-siv", "AES-SIV"),
            ("chacha20-poly1305", "ChaCha20Poly1305"),
            ("xchacha20-poly1305", "XChaCha20Poly1305"),
            ("camellia", "Camellia-128-CBC")
        ]

        self.encrypt_algorithm_var = tk.StringVar(value="fernet")  # default to fernet
        algorithm_menu = ttk.OptionMenu(
            algorithm_group,
            self.encrypt_algorithm_var,
            algorithms[0][0],  # default value
            *[algo[0] for algo in algorithms],  # values
            style="Custom.TMenubutton"
        )
        algorithm_menu.pack(fill="x", padx=5, pady=2)

        # Add a label to show the full name
        algorithm_label = ttk.Label(algorithm_group, text=algorithms[0][1])
        self.encrypt_algorithm_var.trace('w', lambda *args: algorithm_label.configure(
            text=dict(algorithms)[self.encrypt_algorithm_var.get()]
        ))
        algorithm_label.pack(fill="x", padx=5, pady=2)

        # Options group
        options_group = ttk.LabelFrame(self.encrypt_frame, text="Options", padding=5)
        options_group.pack(fill="x", padx=5, pady=5)

        # Overwrite existing file checkbox
        self.encrypt_overwrite_var = tk.BooleanVar(value=False)
        overwrite_check = ttk.Checkbutton(
            options_group,
            text="Overwrite existing file",
            variable=self.encrypt_overwrite_var
        )
        overwrite_check.pack(fill="x", padx=5, pady=2)

        # Shred original file checkbox
        self.encrypt_shred_var = tk.BooleanVar(value=False)
        shred_check = ttk.Checkbutton(
            options_group,
            text="Shred original file",
            variable=self.encrypt_shred_var
        )
        shred_check.pack(fill="x", padx=5, pady=2)

        # Button frame
        button_frame = ttk.Frame(self.encrypt_frame)
        button_frame.pack(fill="x", padx=5, pady=5)

        # Encrypt button
        encrypt_button = ttk.Button(
            button_frame,
            text="Encrypt",
            command=lambda: self.root.after(
                100, self.run_encrypt
            )
        )
        encrypt_button.pack(side="left", fill="x", expand=True, padx=5)

        # Clear button
        clear_button = ttk.Button(
            button_frame,
            text="Clear",
            command=lambda: [
                var.set('') for var in [
                    self.encrypt_input_var,
                    self.encrypt_output_var,
                    self.encrypt_password_var,
                    self.encrypt_confirm_var
                ]
            ]
        )
        clear_button.pack(side="left", fill="x", expand=True, padx=5)

    def setup_decrypt_tab(self):
        """Set up the decryption tab"""
        frame = self.decrypt_frame
        
        # Input file
        input_frame = ttk.LabelFrame(frame, text="Encrypted File")
        input_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.decrypt_input_var = tk.StringVar()
        ttk.Entry(input_frame, textvariable=self.decrypt_input_var).pack(
            side=tk.LEFT, fill=tk.X, expand=True, padx=5, pady=5)
        ttk.Button(input_frame, text="Browse...", 
                  command=lambda: self.browse_file(self.decrypt_input_var)).pack(
                      side=tk.RIGHT, padx=5, pady=5)
        
        # Output file
        output_frame = ttk.LabelFrame(frame, text="Output File")
        output_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.decrypt_output_var = tk.StringVar()
        ttk.Entry(output_frame, textvariable=self.decrypt_output_var).pack(
            side=tk.LEFT, fill=tk.X, expand=True, padx=5, pady=5)
        ttk.Button(output_frame, text="Browse...", 
                  command=lambda: self.browse_file(self.decrypt_output_var, save=True)).pack(
                      side=tk.RIGHT, padx=5, pady=5)
        
        # Display to screen option
        self.decrypt_to_screen_var = tk.BooleanVar()
        ttk.Checkbutton(output_frame, text="Display content to screen (for text files)",
                       variable=self.decrypt_to_screen_var).pack(anchor=tk.W, padx=5, pady=2)
        
        # Password entry
        password_frame = ttk.LabelFrame(frame, text="Password")
        password_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.decrypt_password_var = tk.StringVar()
        ttk.Label(password_frame, text="Password:").pack(side=tk.LEFT, padx=5, pady=5)
        password_entry = ttk.Entry(password_frame, textvariable=self.decrypt_password_var, show="*")
        password_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5, pady=5)
        
        # Options 
        options_frame = ttk.LabelFrame(frame, text="Options")
        options_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.decrypt_overwrite_var = tk.BooleanVar()
        ttk.Checkbutton(options_frame, text="Overwrite encrypted file with decrypted content",
                       variable=self.decrypt_overwrite_var).pack(anchor=tk.W, padx=5, pady=2)
        
        self.decrypt_shred_var = tk.BooleanVar()
        ttk.Checkbutton(options_frame, text="Securely shred encrypted file after decryption",
                       variable=self.decrypt_shred_var).pack(anchor=tk.W, padx=5, pady=2)

        # Button frame
        button_frame = ttk.Frame(self.decrypt_frame)
        button_frame.pack(fill="x", padx=5, pady=5)

        # Encrypt button
        decrypt_button = ttk.Button(
            button_frame,
            text="Decrypt",
            command=lambda: self.root.after(
                100, self.run_decrypt
            )
        )
        decrypt_button.pack(side="left", fill="x", expand=True, padx=5)

        # Clear button
        clear_button = ttk.Button(
            button_frame,
            text="Clear",
            command=lambda: [
                var.set('') for var in [
                    self.encrypt_input_var,
                    self.encrypt_output_var,
                    self.encrypt_password_var,
                    self.encrypt_confirm_var
                ]
            ]
        )
        clear_button.pack(side="left", fill="x", expand=True, padx=5)
    
    def setup_shred_tab(self):
        """Set up the secure shredding tab"""
        frame = self.shred_frame
        
        # Input files
        input_frame = ttk.LabelFrame(frame, text="Files/Directories to Shred")
        input_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.shred_input_var = tk.StringVar()
        ttk.Entry(input_frame, textvariable=self.shred_input_var).pack(
            side=tk.LEFT, fill=tk.X, expand=True, padx=5, pady=5)
        ttk.Button(input_frame, text="Browse...", 
                  command=lambda: self.browse_file(self.shred_input_var, multi=True)).pack(
                      side=tk.RIGHT, padx=5, pady=5)
        
        # Shred options
        options_frame = ttk.LabelFrame(frame, text="Options")
        options_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.shred_passes_var = tk.IntVar(value=3)
        ttk.Label(options_frame, text="Number of passes:").grid(
            row=0, column=0, padx=5, pady=5, sticky=tk.W)
        passes_combo = ttk.Combobox(options_frame, textvariable=self.shred_passes_var, 
                                   values=[1, 3, 7, 12, 20, 35], width=5)
        passes_combo.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)
        
        self.shred_recursive_var = tk.BooleanVar()
        ttk.Checkbutton(options_frame, text="Recursively shred directories",
                       variable=self.shred_recursive_var).grid(
                           row=1, column=0, columnspan=2, padx=5, pady=5, sticky=tk.W)
        
        # Warning
        warning_frame = ttk.LabelFrame(frame, text="⚠️ WARNING")
        warning_frame.pack(fill=tk.X, padx=10, pady=10)
        
        warning_text = ("Securely shredded files CANNOT be recovered! This operation is permanent.\n"
                        "Please ensure you have selected the correct files before proceeding.")
        ttk.Label(warning_frame, text=warning_text, foreground="red").pack(padx=10, pady=10)
        
        # Action button
        button_frame = ttk.Frame(frame)
        button_frame.pack(fill=tk.X, padx=10, pady=20)
        
        ttk.Button(button_frame, text="Shred", command=self.run_shred).pack(padx=5, pady=5)
    
    def setup_password_tab(self):
        """Set up the password generation tab"""
        frame = self.password_frame
        
        # Length selection
        length_frame = ttk.Frame(frame)
        length_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(length_frame, text="Password Length:").pack(side=tk.LEFT, padx=5)
        self.password_length_var = tk.IntVar(value=16)
        length_scale = ttk.Scale(length_frame, from_=8, to=64, 
                              orient=tk.HORIZONTAL, variable=self.password_length_var,
                              length=300)
        length_scale.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        
        length_display = ttk.Label(length_frame, textvariable=self.password_length_var, width=3)
        length_display.pack(side=tk.LEFT, padx=5)
        
        # Character sets
        charset_frame = ttk.LabelFrame(frame, text="Character Sets")
        charset_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.use_lowercase_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(charset_frame, text="Lowercase letters (a-z)",
                       variable=self.use_lowercase_var).pack(anchor=tk.W, padx=5, pady=2)
        
        self.use_uppercase_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(charset_frame, text="Uppercase letters (A-Z)",
                       variable=self.use_uppercase_var).pack(anchor=tk.W, padx=5, pady=2)
        
        self.use_digits_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(charset_frame, text="Digits (0-9)",
                       variable=self.use_digits_var).pack(anchor=tk.W, padx=5, pady=2)
        
        self.use_special_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(charset_frame, text="Special characters (!@#$%...)",
                       variable=self.use_special_var).pack(anchor=tk.W, padx=5, pady=2)
        
        # Password display
        display_frame = ttk.LabelFrame(frame, text="Generated Password")
        display_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.generated_password_var = tk.StringVar()
        password_entry = ttk.Entry(display_frame, textvariable=self.generated_password_var,
                                 font=("Courier", 12), justify=tk.CENTER)
        password_entry.pack(fill=tk.X, padx=10, pady=10, ipady=5)
        
        # Security notice and countdown
        security_frame = ttk.Frame(display_frame)
        security_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
        
        self.countdown_var = tk.StringVar()
        self.countdown_var.set("Password will be cleared automatically after 20 seconds for security")
        
        security_label = ttk.Label(security_frame, textvariable=self.countdown_var, 
                                 foreground="red", justify=tk.CENTER)
        security_label.pack(fill=tk.X)
        self.countdown_label = security_label
        
        # Buttons
        button_frame = ttk.Frame(frame)
        button_frame.pack(fill=tk.X, padx=10, pady=20)
        
        ttk.Button(button_frame, text="Generate Password", 
                  command=self.generate_password).pack(side=tk.LEFT, padx=5, pady=5)
        
        ttk.Button(button_frame, text="Copy to Clipboard", 
                  command=self.copy_password_to_clipboard).pack(side=tk.LEFT, padx=5, pady=5)
        
        ttk.Button(button_frame, text="Clear", 
                  command=self.clear_generated_password).pack(side=tk.LEFT, padx=5, pady=5)
    
    def browse_file(self, string_var, save=False, multi=False, file_type=None):
        """Browse for a file and update the StringVar"""
        if save:
            filename = filedialog.asksaveasfilename()
        elif multi:
            filename = filedialog.askopenfilename(multiple=True)
            if filename:
                filename = " ".join(filename)  # Join multiple filenames
        else:
            filename = filedialog.askopenfilename()
        
        if filename:
            string_var.set(filename)
    
    def generate_strong_password(self, length, use_lowercase=True, use_uppercase=True, 
                               use_digits=True, use_special=True):
        """Generate a strong random password"""
        if length < 8:
            length = 8  # Enforce minimum safe length
        
        # Create the character pool based on selected options
        char_pool = ""
        required_chars = []
        
        if use_lowercase:
            char_pool += string.ascii_lowercase
            required_chars.append(random.choice(string.ascii_lowercase))
            
        if use_uppercase:
            char_pool += string.ascii_uppercase
            required_chars.append(random.choice(string.ascii_uppercase))
            
        if use_digits:
            char_pool += string.digits
            required_chars.append(random.choice(string.digits))
            
        if use_special:
            char_pool += string.punctuation
            required_chars.append(random.choice(string.punctuation))
        
        # If no options selected, default to alphanumeric
        if not char_pool:
            char_pool = string.ascii_lowercase + string.ascii_uppercase + string.digits
            required_chars = [
                random.choice(string.ascii_lowercase),
                random.choice(string.ascii_uppercase),
                random.choice(string.digits)
            ]
        
        # Ensure we have room for all required characters
        if len(required_chars) > length:
            required_chars = required_chars[:length]
        
        # Fill remaining length with random characters from the pool
        remaining_length = length - len(required_chars)
        password_chars = required_chars + [random.choice(char_pool) for _ in range(remaining_length)]
        
        # Shuffle to ensure required characters aren't in predictable positions
        random.shuffle(password_chars)
        
        return ''.join(password_chars)
    
    def on_tab_changed(self, event):
        """Handle tab change events"""
        # Clear the generated password when changing tabs for security
        if self.password_timer_active:
            self.clear_generated_password()
            self.status_var.set("Password cleared for security")
    
    def start_password_countdown(self, seconds=20):
        """Start a countdown timer to clear the password"""
        # Cancel any existing timer
        self.cancel_password_timer()
        
        self.password_timer_active = True
        self.countdown_seconds = seconds
        self.update_countdown_label()
        
        # Start the countdown
        self._countdown_step()
    
    def _countdown_step(self):
        """Update the countdown timer"""
        if self.countdown_seconds > 0:
            self.update_countdown_label()
            self.countdown_seconds -= 1
            self.password_timer_id = self.root.after(1000, self._countdown_step)
        else:
            self.clear_generated_password()
            self.countdown_var.set("Password has been cleared for security")
    
    def update_countdown_label(self):
        """Update the countdown timer label"""
        self.countdown_var.set(f"Password will be cleared automatically in {self.countdown_seconds} seconds")
    
    def cancel_password_timer(self):
        """Cancel the password timer if it's running"""
        if self.password_timer_id:
            self.root.after_cancel(self.password_timer_id)
            self.password_timer_id = None
        self.password_timer_active = False
    
    def clear_generated_password(self):
        """Clear the generated password and reset the timer"""
        self.generated_password_var.set("")
        self.cancel_password_timer()
        if self.countdown_label:
            self.countdown_var.set("Password will be cleared automatically after 20 seconds for security")
    
    def generate_password(self):
        """Generate a password based on the selected options"""
        length = self.password_length_var.get()
        use_lowercase = self.use_lowercase_var.get()
        use_uppercase = self.use_uppercase_var.get()
        use_digits = self.use_digits_var.get()
        use_special = self.use_special_var.get()
        
        # Ensure at least one character set is selected
        if not (use_lowercase or use_uppercase or use_digits or use_special):
            messagebox.showwarning("Warning", "Please select at least one character set.")
            return
        
        # Generate and display the password
        password = self.generate_strong_password(
            length, use_lowercase, use_uppercase, use_digits, use_special)
        self.generated_password_var.set(password)
        self.status_var.set("Password generated successfully")
        
        # Start the countdown timer
        self.start_password_countdown(20)
    
    def copy_password_to_clipboard(self):
        """Copy the generated password to clipboard"""
        password = self.generated_password_var.get()
        if password:
            self.root.clipboard_clear()
            self.root.clipboard_append(password)
            self.status_var.set("Password copied to clipboard")
            
            # Reset the countdown timer after copying to give more time
            if self.password_timer_active:
                self.start_password_countdown(20)
        else:
            self.status_var.set("No password to copy")
    
    def generate_encrypt_password(self):
        """Generate a password for encryption"""
        length = simpledialog.askinteger("Password Length", 
                                        "Enter password length (8-64):", 
                                        minvalue=8, maxvalue=64, 
                                        initialvalue=16,
                                        parent=self.root)
        if length:
            # Generate password with default options (all character sets)
            password = self.generate_strong_password(length)
            self.encrypt_password_var.set(password)
            self.encrypt_confirm_var.set(password)
            messagebox.showinfo("Password Generated", 
                              "A random password has been generated and filled in.\n\n"
                              "Please save this password in a secure location! "
                              "If you lose it, you won't be able to decrypt your file.")

    def run_command(self, cmd, callback=None, show_output=False):
        """Run a command in a separate thread and update the UI when done"""

        def run_in_thread():
            # Show the progress bar
            self.progress_bar.pack(side=tk.BOTTOM, fill=tk.X, padx=5, pady=(0, 5))
            self.progress_var.set(0)

            try:
                self.status_var.set("Running...")

                # Run the command with real-time output parsing
                result = subprocess.run(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    bufsize=1,  # Line buffered
                    universal_newlines=True
                )

                # Process the result
                if result.returncode == 0:
                    status = "Command completed successfully"

                    if show_output and result.stdout:
                        # Display the output in a scrollable window
                        self.show_output_dialog("Command Output", result.stdout)
                    elif callback:
                        callback(result)
                else:
                    status = f"Error: {result.stderr}"
                    messagebox.showerror("Error", f"Command failed:\n{result.stderr}")

                self.status_var.set(status)

            except Exception as e:
                self.status_var.set(f"Error: {str(e)}")
                messagebox.showerror("Error", str(e))
            finally:
                # Hide the progress bar
                self.progress_bar.pack_forget()
                self.progress_var.set(0)
                self.current_algorithm = ""
                self.last_progress_text = ""

        # Start the command in a separate thread
        threading.Thread(target=run_in_thread, daemon=True).start()

    def run_command_with_progress(self, cmd, callback=None, show_output=False):
        """Run a command with real-time progress updates in the UI"""

        def run_in_thread():
            # Show the progress bar
            self.progress_bar.pack(side=tk.BOTTOM, fill=tk.X, padx=5, pady=(0, 5))
            self.progress_var.set(0)

            try:
                self.status_var.set("Running...")

                # Start the process with pipe for stdout to capture output in real-time
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    bufsize=1,  # Line buffered
                    universal_newlines=True
                )

                # Process output in real-time
                stdout_lines = []
                stderr_lines = []
                important_output_lines = []  # For integrity check results and decrypted content

                # Regular expressions to match different types of progress outputs
                import re
                # Match standard hashing progress: "SHA-512 hashing: [████████        ] 40.0% (400000/1000000)"
                hash_progress_regex = re.compile(r'([\w\-]+) hashing: \[(.*?)\] (\d+\.\d+)% \((\d+)/(\d+)\)')
                # Match newer format progress message (from argon2, scrypt, balloon, etc):
                # "Argon2 processing: 50.0% complete"
                simple_progress_regex = re.compile(r'([\w\-]+) processing: (\d+\.\d+)% complete')
                # Match processing messages like "Applying 1000000 rounds of SHA-512..."
                processing_regex = re.compile(r'Applying (\d+) rounds of ([\w\-]+).*')
                # Match processing with parameters like "Applying scrypt with n=16384, r=8, p=1..."
                param_processing_regex = re.compile(r'Applying ([\w\-]+) with.*')
                # Match processing messages for Argon2 and other memory-hard functions
                memory_processing_regex = re.compile(r'([\w\-]+) processing')
                # Match Balloon specific messages
                balloon_regex = re.compile(r'Balloon hashing.*')
                # Match integrity check results 
                integrity_regex = re.compile(r'(✓|⚠️).*integrity.*')

                # Process stdout and update progress
                for line in iter(process.stdout.readline, ''):
                    stdout_lines.append(line)

                    # Check if this is an integrity check result or decrypted content
                    if integrity_regex.search(line) or "Decrypted content:" in line:
                        important_output_lines.append(line)
                        # If it's decrypted content, add all subsequent lines too
                        if "Decrypted content:" in line:
                            for content_line in iter(process.stdout.readline, ''):
                                stdout_lines.append(content_line)
                                important_output_lines.append(content_line)
                        continue

                    # Check for different types of progress indicators
                    hash_match = hash_progress_regex.search(line)
                    simple_match = simple_progress_regex.search(line)
                    processing_match = processing_regex.search(line)
                    param_match = param_processing_regex.search(line)
                    memory_match = memory_processing_regex.search(line)
                    balloon_match = balloon_regex.search(line)

                    if hash_match:
                        # Standard hashing progress
                        algorithm, bar, percent, current, total = hash_match.groups()
                        percent_float = float(percent)

                        # Update progress bar
                        self.progress_var.set(percent_float)

                        # Update status text with algorithm and percentage
                        if algorithm != self.current_algorithm:
                            self.current_algorithm = algorithm

                        progress_text = f"{algorithm} hashing: {percent}% ({current}/{total})"
                        if progress_text != self.last_progress_text:
                            self.status_var.set(progress_text)
                            self.last_progress_text = progress_text
                    
                    elif simple_match:
                        # Simpler progress format
                        algorithm, percent = simple_match.groups()
                        percent_float = float(percent)
                        
                        # Update progress bar
                        self.progress_var.set(percent_float)
                        
                        # Update status text with algorithm and percentage
                        if algorithm != self.current_algorithm:
                            self.current_algorithm = algorithm
                            
                        progress_text = f"{algorithm} processing: {percent}% complete"
                        if progress_text != self.last_progress_text:
                            self.status_var.set(progress_text)
                            self.last_progress_text = progress_text
                            
                    elif balloon_match:
                        # For balloon hashing, which may not report percentage
                        self.current_algorithm = "Balloon"
                        progress_text = "Balloon hashing in progress..."
                        if progress_text != self.last_progress_text:
                            self.status_var.set(progress_text)
                            self.last_progress_text = progress_text
                            # Use indeterminate progress for balloon
                            self.progress_bar.configure(mode="indeterminate")
                            self.progress_bar.start()

                    elif processing_match:
                        # Starting a new hashing process
                        iterations, algorithm = processing_match.groups()
                        self.current_algorithm = algorithm
                        progress_text = f"Starting {algorithm} with {iterations} iterations..."
                        self.status_var.set(progress_text)
                        self.last_progress_text = progress_text
                        self.progress_var.set(0)  # Reset progress for new algorithm

                    elif param_match:
                        # Algorithm with parameters
                        algorithm = param_match.group(1)
                        self.current_algorithm = algorithm
                        progress_text = f"Processing with {algorithm}..."
                        self.status_var.set(progress_text)
                        self.last_progress_text = progress_text
                        self.progress_var.set(0)  # Reset progress for new algorithm

                    elif memory_match:
                        # Memory-hard functions like Argon2 or Scrypt
                        algorithm = memory_match.group(1)
                        self.current_algorithm = algorithm
                        progress_text = f"{algorithm} in progress..."
                        self.status_var.set(progress_text)
                        self.last_progress_text = progress_text
                        # For these algorithms we use an indeterminate progress
                        # since they don't report percentage
                        self.progress_bar.configure(mode="indeterminate")
                        self.progress_bar.start()

                    # Additional pattern: check for "Key generation" and other processing messages
                    elif "Key" in line or "Generating" in line or "Encrypting" in line or "Decrypting" in line:
                        progress_text = line.strip()
                        self.status_var.set(progress_text)
                        self.last_progress_text = progress_text

                # Collect any stderr output
                for line in iter(process.stderr.readline, ''):
                    stderr_lines.append(line)

                # Wait for the process to complete
                process.wait()

                # Process the result
                stdout = ''.join(stdout_lines)
                stderr = ''.join(stderr_lines)
                important_output = ''.join(important_output_lines)

                if process.returncode == 0:
                    status = "Command completed successfully"

                    # Show important output if present
                    if important_output:
                        # Clear previous output
                        self.output_text.delete(1.0, tk.END)
                        # Add new output
                        self.output_text.insert(tk.END, important_output)
                        # Scroll to the beginning
                        self.output_text.see(1.0)
                    elif callback:
                        # Create a simple result object to match subprocess.run
                        class SimpleResult:
                            def __init__(self, returncode, stdout, stderr):
                                self.returncode = returncode
                                self.stdout = stdout
                                self.stderr = stderr

                        result = SimpleResult(process.returncode, stdout, stderr)
                        callback(result)
                else:
                    status = f"Error: {stderr}"
                    # Display error in the output text
                    self.output_text.delete(1.0, tk.END)
                    self.output_text.insert(tk.END, f"ERROR:\n{stderr}")
                    # Also show error dialog
                    messagebox.showerror("Error", f"Command failed:\n{stderr}")

                self.status_var.set(status)

            except Exception as e:
                self.status_var.set(f"Error: {str(e)}")
                messagebox.showerror("Error", str(e))
            finally:
                # Stop the progress bar if it's in indeterminate mode
                self.progress_bar.stop()
                # Reset to determinate mode
                self.progress_bar.configure(mode="determinate")
                # Hide the progress bar
                self.progress_bar.pack_forget()
                self.progress_var.set(0)
                self.current_algorithm = ""
                self.last_progress_text = ""

        # Start the command in a separate thread
        threading.Thread(target=run_in_thread, daemon=True).start()

    def show_output_dialog(self, title, text):
        """Show output directly in the main GUI instead of creating a new dialog window"""
        # Clear previous output
        self.output_text.delete(1.0, tk.END)

        # Add a title to distinguish different outputs
        self.output_text.insert(tk.END, f"--- {title} ---\n\n", "title")

        # Add the main output text
        self.output_text.insert(tk.END, text)

        # Configure the "title" tag to be bold
        self.output_text.tag_configure("title", font=("TkDefaultFont", 10, "bold"))

        # Scroll to the beginning
        self.output_text.see(1.0)

        # Make sure the output frame is visible
        self.output_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Update the status bar
        self.status_var.set(f"Output displayed: {title}")

    def run_encrypt(self):
        """Run the encryption command"""
        self.output_text.delete('1.0', tk.END)  # Clear output before starting
        self.root.update_idletasks()
        input_file = self.encrypt_input_var.get()
        if not input_file:
            messagebox.showerror("Error", "Please select an input file.")
            return

        password = self.encrypt_password_var.get()
        confirm = self.encrypt_confirm_var.get()

        if not password:
            messagebox.showerror("Error", "Please enter a password.")
            return

        if password != confirm:
            messagebox.showerror("Error", "Passwords do not match.")
            return

        output_file = self.encrypt_output_var.get()
        if not output_file and not self.encrypt_overwrite_var.get():
            messagebox.showerror("Error", "Please select an output file or enable overwrite.")
            return

        # Get current hash configuration and encryption algorithm
        hash_config = self.settings_tab.get_current_config()
        encryption_algorithm = self.encrypt_algorithm_var.get()

        # Build the command - use full path to crypt.py
        cmd = [sys.executable, os.path.join(os.path.dirname(__file__), "crypt.py"), "encrypt", "-i", input_file]

        if output_file and not self.encrypt_overwrite_var.get():
            cmd.extend(["-o", output_file])

        if self.encrypt_overwrite_var.get():
            cmd.append("--overwrite")

        if self.encrypt_shred_var.get():
            cmd.append("-s")

        # Add password
        cmd.extend(["-p", password])

        # Add encryption algorithm
        cmd.extend(["--algorithm", encryption_algorithm])

        # Add individual hash configuration parameters
        if hash_config:
            # Iterative hash algorithms
            if hash_config.get('sha512', 0) > 0:
                cmd.extend(["--sha512-rounds", str(hash_config['sha512'])])

            if hash_config.get('sha256', 0) > 0:
                cmd.extend(["--sha256-rounds", str(hash_config['sha256'])])

            if hash_config.get('sha3_256', 0) > 0:
                cmd.extend(["--sha3-256-rounds", str(hash_config['sha3_256'])])

            if hash_config.get('sha3_512', 0) > 0:
                cmd.extend(["--sha3-512-rounds", str(hash_config['sha3_512'])])

            if hash_config.get('whirlpool', 0) > 0:
                cmd.extend(["--whirlpool-rounds", str(hash_config['whirlpool'])])

            # PBKDF2 iterations
            cmd.extend(["--pbkdf2-iterations", str(hash_config['pbkdf2_iterations'])])

            # Scrypt parameters - check if enabled
            if hash_config['scrypt'].get('enabled', False) or hash_config['scrypt']['n'] > 0:
                cmd.append("--enable-scrypt")
                cmd.extend([
                    "--scrypt-n", str(hash_config['scrypt']['n']),
                    "--scrypt-r", str(hash_config['scrypt']['r']),
                    "--scrypt-p", str(hash_config['scrypt']['p'])
                ])
                
                # Add rounds parameter if present
                if 'rounds' in hash_config['scrypt'] and hash_config['scrypt']['rounds'] > 1:
                    cmd.extend(["--scrypt-rounds", str(hash_config['scrypt']['rounds'])])

            # Argon2 parameters
            if hash_config['argon2']['enabled']:
                cmd.extend([
                    "--enable-argon2",
                    "--argon2-time", str(hash_config['argon2']['time_cost']),
                    "--argon2-memory", str(hash_config['argon2']['memory_cost']),
                    "--argon2-parallelism", str(hash_config['argon2']['parallelism']),
                    "--argon2-hash-len", str(hash_config['argon2']['hash_len']),
                    "--argon2-type", hash_config['argon2']['type']
                ])
                
                # Add rounds parameter if present
                if 'rounds' in hash_config['argon2'] and hash_config['argon2']['rounds'] > 1:
                    cmd.extend(["--argon2-rounds", str(hash_config['argon2']['rounds'])])
                    
            # Balloon parameters (if present)
            if 'balloon' in hash_config and hash_config['balloon'].get('enabled', False):
                cmd.append("--enable-balloon")
                
                balloon_config = hash_config['balloon']
                
                if 'time_cost' in balloon_config:
                    cmd.extend(["--balloon-time-cost", str(balloon_config['time_cost'])])
                
                if 'space_cost' in balloon_config:
                    cmd.extend(["--balloon-space-cost", str(balloon_config['space_cost'])])
                
                # Handle both 'parallel_cost' and 'parallelism' as keys might vary
                if 'parallel_cost' in balloon_config:
                    cmd.extend(["--balloon-parallelism", str(balloon_config['parallel_cost'])])
                
                # Add rounds parameter if present
                if 'rounds' in balloon_config and balloon_config['rounds'] > 1:
                    cmd.extend(["--balloon-rounds", str(balloon_config['rounds'])])

        # Run the command
        self.output_text.insert(tk.END, f" ".join(cmd) + "\n")
        self.output_text.see(tk.END)  # Scroll to the bottom
        self.root.update_idletasks()
        try:
            self.disable_buttons()
            # Add --progress flag to show progress information in the output
            if "--progress" not in cmd:
                cmd.append("--progress")
            # Add --verbose flag to show more detail about the hashing process
            if "--verbose" not in cmd:
                cmd.append("--verbose")
            self.run_command_with_progress(cmd)
            self.enable_buttons()
        finally:
            self.enable_buttons()

    def disable_buttons(self):
        """Disable all buttons during processing"""
        # Find all buttons and disable them
        for child in self.root.winfo_children():
            self._disable_widget_recursive(child)

    def enable_buttons(self):
        """Re-enable all buttons after processing"""
        # Find all buttons and enable them
        for child in self.root.winfo_children():
            self._enable_widget_recursive(child)

    def _disable_widget_recursive(self, widget):
        """Recursively disable all buttons in a widget"""
        if isinstance(widget, (ttk.Button, tk.Button)):
            widget['state'] = 'disabled'
        # Also check child widgets (for frames, notebooks, etc)
        for child in widget.winfo_children():
            self._disable_widget_recursive(child)

    def _enable_widget_recursive(self, widget):
        """Recursively enable all buttons in a widget"""
        if isinstance(widget, (ttk.Button, tk.Button)):
            widget['state'] = 'normal'
        # Also check child widgets (for frames, notebooks, etc)
        for child in widget.winfo_children():
            self._enable_widget_recursive(child)

    def run_decrypt(self):
        """Run the decryption command"""
        self.output_text.delete('1.0', tk.END)  # Clear output before starting
        self.root.update_idletasks()
        input_file = self.decrypt_input_var.get()
        if not input_file:
            messagebox.showerror("Error", "Please select an input file.")
            return

        password = self.decrypt_password_var.get()
        if not password:
            messagebox.showerror("Error", "Please enter a password.")
            return

        output_file = self.decrypt_output_var.get()
        show_output = self.decrypt_to_screen_var.get()

        if not output_file and not self.decrypt_overwrite_var.get() and not show_output:
            messagebox.showerror("Error",
                                 "Please select an output file, enable overwrite, or select display to screen.")
            return

        # Get current hash configuration
        hash_config = self.settings_tab.get_current_config()

        # Build the command - use full path to crypt.py
        cmd = [sys.executable, os.path.join(os.path.dirname(__file__), "crypt.py"), "decrypt", "-i", input_file]

        if output_file and not self.decrypt_overwrite_var.get():
            cmd.extend(["-o", output_file])

        if self.decrypt_overwrite_var.get():
            cmd.append("--overwrite")

        if self.decrypt_shred_var.get():
            cmd.append("-s")

        # Add password
        cmd.extend(["-p", password])

        # Run the command
        self.output_text.insert(tk.END, f" ".join(cmd) + "\n")
        self.output_text.see(tk.END)  # Scroll to the bottom
        self.root.update_idletasks()
        try:
            self.disable_buttons()
            # Add --progress flag to show progress information in the output
            if "--progress" not in cmd:
                cmd.append("--progress")
            # Add --verbose flag to show more detail about the hashing process
            if "--verbose" not in cmd:
                cmd.append("--verbose")
            self.run_command_with_progress(cmd, show_output=show_output)
            self.enable_buttons()
        finally:
            self.enable_buttons()
    
    def run_shred(self):
        """Run the shred command"""
        input_files = self.shred_input_var.get()
        if not input_files:
            messagebox.showerror("Error", "Please select files or directories to shred.")
            return
        
        # Ask for confirmation
        if not messagebox.askyesno("Confirm Shred", 
                                 "WARNING: This operation cannot be undone!\n\n"
                                 "Are you absolutely sure you want to securely shred "
                                 f"the selected files or directories?\n\n{input_files}"):
            return
        
        # Build the command - use full path to crypt.py
        cmd = [sys.executable, os.path.join(os.path.dirname(__file__), "crypt.py"), "shred", "-i", input_files]
        
        if self.shred_recursive_var.get():
            cmd.append("-r")
        
        cmd.extend(["--shred-passes", str(self.shred_passes_var.get())])
        
        # Add progress flags
        if "--progress" not in cmd:
            cmd.append("--progress")
        if "--verbose" not in cmd:
            cmd.append("--verbose")
        
        # Run the command
        self.run_command_with_progress(cmd)


def main():
    """Main entry point for the application"""
    root = tk.Tk()
    app = CryptGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()

