#!/usr/bin/env python3
"""
GUI for crypt.py - A secure file encryption and shredding tool

This provides a graphical interface to the crypt.py encryption utility,
allowing users to encrypt, decrypt, and securely shred files using a 
simple interface instead of command-line options.
"""

import os
import sys
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import threading
import subprocess
import queue

# Try to import functions from crypt.py
try:
    from crypt import (
        encrypt_file, decrypt_file, secure_shred_file,
        expand_glob_patterns
    )
    DIRECT_IMPORT = True
except ImportError:
    DIRECT_IMPORT = False
    print("Could not import functions from crypt.py - will use subprocess mode")


class RedirectText:
    """Class to redirect stdout to a tkinter Text widget"""
    
    def __init__(self, text_widget):
        self.text_widget = text_widget
        self.queue = queue.Queue()
        self.update_timer = None
        
    def write(self, string):
        self.queue.put(string)
        
    def flush(self):
        pass

    def update_text(self):
        while not self.queue.empty():
            text = self.queue.get_nowait()
            self.text_widget.configure(state='normal')
            self.text_widget.insert(tk.END, text)
            self.text_widget.see(tk.END)
            self.text_widget.configure(state='disabled')
        
        # Schedule the next update
        self.update_timer = self.text_widget.after(100, self.update_text)
    
    def stop_update(self):
        if self.update_timer:
            self.text_widget.after_cancel(self.update_timer)
            self.update_timer = None


class CryptGUI(tk.Tk):
    """Main GUI application for the crypt.py utility"""
    
    def __init__(self):
        super().__init__()
        
        self.title("Secure File Encryption Tool")
        self.geometry("800x600")
        self.minsize(700, 500)
        
        # Find crypt.py
        self.crypt_script = self.find_crypt_script()
        
        # Create the UI
        self.create_ui()
        
        # Initialize process variables
        self.current_process = None
        self.original_stdout = sys.stdout
        self.redirect = None
        
    def find_crypt_script(self):
        """Find the crypt.py script file"""
        # First, check current directory
        if os.path.exists('./crypt.py'):
            return os.path.abspath('./crypt.py')
        
        # Then check the directory of this script
        script_dir = os.path.dirname(os.path.abspath(__file__))
        if os.path.exists(os.path.join(script_dir, 'crypt.py')):
            return os.path.join(script_dir, 'crypt.py')
        
        # Ask the user if we couldn't find it
        path = filedialog.askopenfilename(
            title="Select crypt.py script",
            filetypes=[("Python files", "*.py"), ("All files", "*.*")]
        )
        
        if not path:
            messagebox.showerror(
                "Error", 
                "Could not find crypt.py. The application will exit."
            )
            sys.exit(1)
            
        return path
        
    def create_ui(self):
        """Create the user interface"""
        # Create main frame
        main_frame = ttk.Frame(self, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create notebook for tabs
        notebook = ttk.Notebook(main_frame)
        notebook.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # Create tabs for different actions
        encrypt_tab = ttk.Frame(notebook, padding="10")
        decrypt_tab = ttk.Frame(notebook, padding="10")
        shred_tab = ttk.Frame(notebook, padding="10")
        advanced_tab = ttk.Frame(notebook, padding="10")
        
        notebook.add(encrypt_tab, text="Encrypt")
        notebook.add(decrypt_tab, text="Decrypt")
        notebook.add(shred_tab, text="Shred")
        notebook.add(advanced_tab, text="Advanced")
        
        # Build each tab
        self.build_encrypt_tab(encrypt_tab)
        self.build_decrypt_tab(decrypt_tab)
        self.build_shred_tab(shred_tab)
        self.build_advanced_tab(advanced_tab)
        
        # Create output area
        output_frame = ttk.LabelFrame(main_frame, text="Output", padding="5")
        output_frame.pack(fill=tk.BOTH, expand=True)
        
        self.output_text = scrolledtext.ScrolledText(
            output_frame, 
            wrap=tk.WORD, 
            height=10, 
            state='disabled'
        )
        self.output_text.pack(fill=tk.BOTH, expand=True)
        
        # Clear button for output
        clear_btn = ttk.Button(
            output_frame, 
            text="Clear Output", 
            command=self.clear_output
        )
        clear_btn.pack(anchor=tk.E, pady=(5, 0))
        
        # Redirect stdout to the output text widget
        self.redirect = RedirectText(self.output_text)
        sys.stdout = self.redirect
        self.redirect.update_text()
        
        # Protocol for window close
        self.protocol("WM_DELETE_WINDOW", self.on_close)
        
    def build_encrypt_tab(self, parent):
        """Build the encrypt tab UI"""
        # File selection
        file_frame = ttk.Frame(parent)
        file_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(file_frame, text="File to encrypt:").pack(side=tk.LEFT)
        self.encrypt_file_var = tk.StringVar()
        ttk.Entry(file_frame, textvariable=self.encrypt_file_var).pack(
            side=tk.LEFT, fill=tk.X, expand=True, padx=(5, 0)
        )
        ttk.Button(
            file_frame, 
            text="Browse...", 
            command=lambda: self.browse_file(self.encrypt_file_var)
        ).pack(side=tk.LEFT, padx=(5, 0))
        
        # Output file
        output_frame = ttk.Frame(parent)
        output_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(output_frame, text="Output file:").pack(side=tk.LEFT)
        self.encrypt_output_var = tk.StringVar()
        ttk.Entry(output_frame, textvariable=self.encrypt_output_var).pack(
            side=tk.LEFT, fill=tk.X, expand=True, padx=(5, 0)
        )
        ttk.Button(
            output_frame, 
            text="Browse...", 
            command=lambda: self.browse_file(self.encrypt_output_var, save=True)
        ).pack(side=tk.LEFT, padx=(5, 0))
        
        # Password
        pw_frame = ttk.Frame(parent)
        pw_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(pw_frame, text="Password:").pack(side=tk.LEFT)
        self.encrypt_pw_var = tk.StringVar()
        ttk.Entry(pw_frame, textvariable=self.encrypt_pw_var, show='*').pack(
            side=tk.LEFT, fill=tk.X, expand=True, padx=(5, 0)
        )
        
        # Confirm password
        confirm_frame = ttk.Frame(parent)
        confirm_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(confirm_frame, text="Confirm:").pack(side=tk.LEFT)
        self.encrypt_confirm_var = tk.StringVar()
        ttk.Entry(confirm_frame, textvariable=self.encrypt_confirm_var, show='*').pack(
            side=tk.LEFT, fill=tk.X, expand=True, padx=(5, 0)
        )
        
        # Options
        options_frame = ttk.LabelFrame(parent, text="Options", padding="5")
        options_frame.pack(fill=tk.X, pady=(10, 5))
        
        # Shred original
        self.encrypt_shred_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            options_frame, 
            text="Securely shred original file after encryption", 
            variable=self.encrypt_shred_var
        ).pack(anchor=tk.W)
        
        # Overwrite
        self.encrypt_overwrite_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            options_frame, 
            text="Overwrite original file with encrypted version", 
            variable=self.encrypt_overwrite_var
        ).pack(anchor=tk.W)
        
        # Hash options
        hash_frame = ttk.Frame(options_frame)
        hash_frame.pack(fill=tk.X, pady=(5, 0))
        
        ttk.Label(hash_frame, text="Hash algorithm:").pack(side=tk.LEFT, padx=(0, 5))
        self.encrypt_hash_var = tk.StringVar(value="None")
        hash_combo = ttk.Combobox(
            hash_frame, 
            textvariable=self.encrypt_hash_var,
            values=["None", "SHA-256", "SHA-512", "SHA3-256", "SHA3-512", "Scrypt"]
        )
        hash_combo.pack(side=tk.LEFT)
        
        # Encrypt button
        button_frame = ttk.Frame(parent)
        button_frame.pack(fill=tk.X, pady=(10, 0))
        
        ttk.Button(
            button_frame, 
            text="Encrypt File", 
            command=self.encrypt_file
        ).pack(side=tk.RIGHT)
        
    def build_decrypt_tab(self, parent):
        """Build the decrypt tab UI"""
        # File selection
        file_frame = ttk.Frame(parent)
        file_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(file_frame, text="File to decrypt:").pack(side=tk.LEFT)
        self.decrypt_file_var = tk.StringVar()
        ttk.Entry(file_frame, textvariable=self.decrypt_file_var).pack(
            side=tk.LEFT, fill=tk.X, expand=True, padx=(5, 0)
        )
        ttk.Button(
            file_frame, 
            text="Browse...", 
            command=lambda: self.browse_file(self.decrypt_file_var)
        ).pack(side=tk.LEFT, padx=(5, 0))
        
        # Output file
        output_frame = ttk.Frame(parent)
        output_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(output_frame, text="Output file:").pack(side=tk.LEFT)
        self.decrypt_output_var = tk.StringVar()
        ttk.Entry(output_frame, textvariable=self.decrypt_output_var).pack(
            side=tk.LEFT, fill=tk.X, expand=True, padx=(5, 0)
        )
        ttk.Button(
            output_frame, 
            text="Browse...", 
            command=lambda: self.browse_file(self.decrypt_output_var, save=True)
        ).pack(side=tk.LEFT, padx=(5, 0))
        
        # Password
        pw_frame = ttk.Frame(parent)
        pw_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(pw_frame, text="Password:").pack(side=tk.LEFT)
        self.decrypt_pw_var = tk.StringVar()
        ttk.Entry(pw_frame, textvariable=self.decrypt_pw_var, show='*').pack(
            side=tk.LEFT, fill=tk.X, expand=True, padx=(5, 0)
        )
        
        # Options
        options_frame = ttk.LabelFrame(parent, text="Options", padding="5")
        options_frame.pack(fill=tk.X, pady=(10, 5))
        
        # Shred encrypted
        self.decrypt_shred_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            options_frame, 
            text="Securely shred encrypted file after decryption", 
            variable=self.decrypt_shred_var
        ).pack(anchor=tk.W)
        
        # Overwrite
        self.decrypt_overwrite_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            options_frame, 
            text="Overwrite encrypted file with decrypted version", 
            variable=self.decrypt_overwrite_var
        ).pack(anchor=tk.W)
        
        # Display to screen
        self.decrypt_to_screen_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            options_frame, 
            text="Display content to screen (for text files)", 
            variable=self.decrypt_to_screen_var
        ).pack(anchor=tk.W)
        
        # Decrypt button
        button_frame = ttk.Frame(parent)
        button_frame.pack(fill=tk.X, pady=(10, 0))
        
        ttk.Button(
            button_frame, 
            text="Decrypt File", 
            command=self.decrypt_file
        ).pack(side=tk.RIGHT)
        
    def build_shred_tab(self, parent):
        """Build the secure shred tab UI"""
        # Path selection
        path_frame = ttk.Frame(parent)
        path_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(path_frame, text="File/pattern to shred:").pack(side=tk.LEFT)
        self.shred_path_var = tk.StringVar()
        ttk.Entry(path_frame, textvariable=self.shred_path_var).pack(
            side=tk.LEFT, fill=tk.X, expand=True, padx=(5, 0)
        )
        ttk.Button(
            path_frame, 
            text="Browse...", 
            command=lambda: self.browse_file(self.shred_path_var)
        ).pack(side=tk.LEFT, padx=(5, 0))
        
        # Help text for patterns
        ttk.Label(
            parent, 
            text="You can use patterns like *.tmp or backup_*.dat to shred multiple files",
            font=("", 9, "italic")
        ).pack(anchor=tk.W, pady=(0, 10))
        
        # Options
        options_frame = ttk.LabelFrame(parent, text="Options", padding="5")
        options_frame.pack(fill=tk.X, pady=(10, 5))
        
        # Number of passes
        passes_frame = ttk.Frame(options_frame)
        passes_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(passes_frame, text="Overwrite passes:").pack(side=tk.LEFT)
        self.shred_passes_var = tk.IntVar(value=3)
        pass_spin = ttk.Spinbox(
            passes_frame, 
            from_=1, 
            to=10, 
            textvariable=self.shred_passes_var,
            width=5
        )
        pass_spin.pack(side=tk.LEFT, padx=(5, 0))
        
        # Recursive
        self.shred_recursive_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            options_frame, 
            text="Recursively shred directories (USE WITH CAUTION!)", 
            variable=self.shred_recursive_var
        ).pack(anchor=tk.W, pady=(0, 5))
        
        # Preview button
        preview_frame = ttk.Frame(parent)
        preview_frame.pack(fill=tk.X, pady=(10, 5))
        
        ttk.Button(
            preview_frame, 
            text="Preview Files To Be Shredded", 
            command=self.preview_shred
        ).pack(side=tk.LEFT)
        
        # Shred button with warning
        warning_frame = ttk.Frame(parent)
        warning_frame.pack(fill=tk.X, pady=(10, 0))
        
        ttk.Label(
            warning_frame,
            text="WARNING: Securely shredded files CANNOT be recovered!",
            foreground="red"
        ).pack(side=tk.LEFT)
        
        ttk.Button(
            warning_frame, 
            text="Securely Shred Files", 
            command=self.shred_files,
            style="Accent.TButton"
        ).pack(side=tk.RIGHT)
        
        # Create a custom style for the shred button
        self.style = ttk.Style(self)
        self.style.configure("Accent.TButton", foreground="red")
        
    def build_advanced_tab(self, parent):
        """Build the advanced options tab UI"""
        # PBKDF2 Iterations
        pbkdf_frame = ttk.Frame(parent)
        pbkdf_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(pbkdf_frame, text="PBKDF2 Iterations:").pack(side=tk.LEFT)
        self.pbkdf2_var = tk.IntVar(value=100000)
        ttk.Entry(pbkdf_frame, textvariable=self.pbkdf2_var, width=10).pack(
            side=tk.LEFT, padx=(5, 0)
        )
        
        # Hash iterations
        hash_frame = ttk.LabelFrame(parent, text="Hash Iterations", padding="5")
        hash_frame.pack(fill=tk.X, pady=(10, 5))
        
        # SHA-256
        sha256_frame = ttk.Frame(hash_frame)
        sha256_frame.pack(fill=tk.X, pady=2)
        
        self.sha256_enabled_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            sha256_frame,
            text="SHA-256",
            variable=self.sha256_enabled_var
        ).pack(side=tk.LEFT)
        
        self.sha256_iter_var = tk.IntVar(value=1000000)
        ttk.Entry(sha256_frame, textvariable=self.sha256_iter_var, width=10).pack(
            side=tk.RIGHT
        )
        ttk.Label(sha256_frame, text="iterations:").pack(side=tk.RIGHT, padx=(5, 5))
        
        # SHA-512
        sha512_frame = ttk.Frame(hash_frame)
        sha512_frame.pack(fill=tk.X, pady=2)
        
        self.sha512_enabled_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            sha512_frame,
            text="SHA-512",
            variable=self.sha512_enabled_var
        ).pack(side=tk.LEFT)
        
        self.sha512_iter_var = tk.IntVar(value=1000000)
        ttk.Entry(sha512_frame, textvariable=self.sha512_iter_var, width=10).pack(
            side=tk.RIGHT
        )
        ttk.Label(sha512_frame, text="iterations:").pack(side=tk.RIGHT, padx=(5, 5))
        
        # SHA3-256
        sha3_256_frame = ttk.Frame(hash_frame)
        sha3_256_frame.pack(fill=tk.X, pady=2)
        
        self.sha3_256_enabled_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            sha3_256_frame,
            text="SHA3-256",
            variable=self.sha3_256_enabled_var
        ).pack(side=tk.LEFT)
        
        self.sha3_256_iter_var = tk.IntVar(value=1000000)
        ttk.Entry(sha3_256_frame, textvariable=self.sha3_256_iter_var, width=10).pack(
            side=tk.RIGHT
        )
        ttk.Label(sha3_256_frame, text="iterations:").pack(side=tk.RIGHT, padx=(5, 5))
        
        # SHA3-512
        sha3_512_frame = ttk.Frame(hash_frame)
        sha3_512_frame.pack(fill=tk.X, pady=2)
        
        self.sha3_512_enabled_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            sha3_512_frame,
            text="SHA3-512",
            variable=self.sha3_512_enabled_var
        ).pack(side=tk.LEFT)
        
        self.sha3_512_iter_var = tk.IntVar(value=1000000)
        ttk.Entry(sha3_512_frame, textvariable=self.sha3_512_iter_var, width=10).pack(
            side=tk.RIGHT
        )
        ttk.Label(sha3_512_frame, text="iterations:").pack(side=tk.RIGHT, padx=(5, 5))
        
        # Whirlpool
        whirlpool_frame = ttk.Frame(hash_frame)
        whirlpool_frame.pack(fill=tk.X, pady=2)
        
        self.whirlpool_enabled_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            whirlpool_frame,
            text="Whirlpool",
            variable=self.whirlpool_enabled_var
        ).pack(side=tk.LEFT)
        
        self.whirlpool_iter_var = tk.IntVar(value=1000)
        ttk.Entry(whirlpool_frame, textvariable=self.whirlpool_iter_var, width=10).pack(
            side=tk.RIGHT
        )
        ttk.Label(whirlpool_frame, text="iterations:").pack(side=tk.RIGHT, padx=(5, 5))
        
        # Scrypt
        scrypt_frame = ttk.LabelFrame(parent, text="Scrypt Parameters", padding="5")
        scrypt_frame.pack(fill=tk.X, pady=(10, 5))
        
        # Scrypt enabled
        self.scrypt_enabled_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            scrypt_frame,
            text="Enable Scrypt (memory-hard function)",
            variable=self.scrypt_enabled_var
        ).pack(anchor=tk.W)
        
        # Cost factor
        cost_frame = ttk.Frame(scrypt_frame)
        cost_frame.pack(fill=tk.X, pady=2)
        
        ttk.Label(cost_frame, text="Cost factor (N=2^x):").pack(side=tk.LEFT)
        self.scrypt_cost_var = tk.IntVar(value=14)
        ttk.Spinbox(
            cost_frame,
            from_=10,
            to=20,
            textvariable=self.scrypt_cost_var,
            width=5
        ).pack(side=tk.LEFT, padx=(5, 0))
        
        # Block size
        block_frame = ttk.Frame(scrypt_frame)
        block_frame.pack(fill=tk.X, pady=2)
        
        ttk.Label(block_frame, text="Block size (r):").pack(side=tk.LEFT)
        self.scrypt_r_var = tk.IntVar(value=8)
        ttk.Spinbox(
            block_frame,
            from_=1,
            to=32,
            textvariable=self.scrypt_r_var,
            width=5
        ).pack(side=tk.LEFT, padx=(5, 0))
        
        # Parallelization
        parallel_frame = ttk.Frame(scrypt_frame)
        parallel_frame.pack(fill=tk.X, pady=2)
        
        ttk.Label(parallel_frame, text="Parallelization (p):").pack(side=tk.LEFT)
        self.scrypt_p_var = tk.IntVar(value=1)
        ttk.Spinbox(
            parallel_frame,
            from_=1,
            to=8,
            textvariable=self.scrypt_p_var,
            width=5
        ).pack(side=tk.LEFT, padx=(5, 0))
        
    def browse_file(self, string_var, save=False):
        """Open a file dialog to select a file"""
        if save:
            path = filedialog.asksaveasfilename(
                title="Save file as",
                filetypes=[("All files", "*.*")]
            )
        else:
            path = filedialog.askopenfilename(
                title="Select file",
                filetypes=[("All files", "*.*")]
            )
        
        if path:
            string_var.set(path)
            
    def clear_output(self):
        """Clear the output text area"""
        self.output_text.configure(state='normal')
        self.output_text.delete(1.0, tk.END)
        self.output_text.configure(state='disabled')
            
    def encrypt_file(self):
        """Encrypt a file with the specified options"""
        input_file = self.encrypt_file_var.get()
        if not input_file:
            messagebox.showerror("Error", "Please select a file to encrypt")
            return
        
        if not os.path.exists(input_file):
            messagebox.showerror("Error", f"File not found: {input_file}")
            return
        
        # Check password
        password = self.encrypt_pw_var.get()
        confirm = self.encrypt_confirm_var.get()
        
        if not password:
            messagebox.showerror("Error", "Please enter a password")
            return
        
        if password != confirm:
            messagebox.showerror("Error", "Passwords do not match")
            return
        
        # Determine output file
        output_file = self.encrypt_output_var.get()
        overwrite = self.encrypt_overwrite_var.get()
        
        if overwrite:
            output_file = input_file
        elif not output_file:
            output_file = input_file + ".encrypted"
        
        # Prepare arguments
        args = ["encrypt", "-i", input_file]
        
        if not overwrite:
            args.extend(["-o", output_file])
        else:
            args.append("--overwrite")
            
        # Add password
        args.extend(["-p", password])
        
        # Add shred option if selected
        if self.encrypt_shred_var.get() and not overwrite:
            args.append("-s")
            
        # Add hash algorithm if selected
        selected_hash = self.encrypt_hash_var.get()
        
        if selected_hash == "SHA-256":
            args.append("--sha256")
        elif selected_hash == "SHA-512":
            args.append("--sha512") 
        elif selected_hash == "SHA3-256":
            args.append("--sha3-256")
        elif selected_hash == "SHA3-512":
            args.append("--sha3-512")
        elif selected_hash == "Scrypt":
            args.append("--scrypt-cost")
            args.append(str(14))  # Default to 2^14
            
        # Add advanced options if enabled
        if self.sha256_enabled_var.get():
            args.append("--sha256")
            args.append(str(self.sha256_iter_var.get()))
            
        if self.sha512_enabled_var.get():
            args.append("--sha512")
            args.append(str(self.sha512_iter_var.get()))
            
        if self.sha3_256_enabled_var.get():
            args.append("--sha3-256")
            args.append(str(self.sha3_256_iter_var.get()))
            
        if self.sha3_512_enabled_var.get():
            args.append("--sha3-512")
            args.append(str(self.sha3_512_iter_var.get()))
            
        if self.whirlpool_enabled_var.get():
            args.append("--whirlpool")
            args.append(str(self.whirlpool_iter_var.get()))
            
        if self.scrypt_enabled_var.get():
            args.append("--scrypt-cost")
            args.append(str(self.scrypt_cost_var.get()))
            args.append("--scrypt-r")
            args.append(str(self.scrypt_r_var.get()))
            args.append("--scrypt-p")
            args.append(str(self.scrypt_p_var.get()))
            
        # Add PBKDF2 iterations
        args.append("--pbkdf2")
        args.append(str(self.pbkdf2_var.get()))
        
        # Run the command
        self.run_crypt_command(args)
        
    def decrypt_file(self):
        """Decrypt a file with the specified options"""
        input_file = self.decrypt_file_var.get()
        if not input_file:
            messagebox.showerror("Error", "Please select a file to decrypt")
            return
        
        if not os.path.exists(input_file):
            messagebox.showerror("Error", f"File not found: {input_file}")
            return
        
        # Check password
        password = self.decrypt_pw_var.get()
        
        if not password:
            messagebox.showerror("Error", "Please enter a password")
            return
        
        # Determine output file
        overwrite = self.decrypt_overwrite_var.get()
        output_file = self.decrypt_output_var.get()
        to_screen = self.decrypt_to_screen_var.get()
        
        # Prepare arguments
        args = ["decrypt", "-i", input_file]
        
        if overwrite:
            args.append("--overwrite")
        elif to_screen:
            pass  # No output file needed
        elif output_file:
            args.extend(["-o", output_file])
        else:
            messagebox.showerror(
                "Error", 
                "Please specify an output file or select 'Display to screen' or 'Overwrite'"
            )
            return
        
        # Add password
        args.extend(["-p", password])
        
        # Add shred option if selected
        if self.decrypt_shred_var.get() and not overwrite:
            args.append("-s")
            
        # Run the command
        self.run_crypt_command(args)
        
    def preview_shred(self):
        """Preview which files would be shredded"""
        path = self.shred_path_var.get()
        if not path:
            messagebox.showerror("Error", "Please enter a file path or pattern")
            return
            
        # Use glob to find matching files
        if DIRECT_IMPORT:
            matched_files = expand_glob_patterns(path)
        else:
            import glob
            matched_files = glob.glob(path)
            
        if not matched_files:
            messagebox.showinfo("No Files Found", "No files match the specified pattern")
            return
            
        # Display the list of files
        print(f"Files that would be shredded with pattern '{path}':")
        for i, file_path in enumerate(matched_files):
            print(f"{i+1}. {file_path}")
            
        if any(os.path.isdir(p) for p in matched_files):
            if self.shred_recursive_var.get():
                print("\nWARNING: Some paths are directories and will be recursively shredded!")
            else:
                print("\nWARNING: Some paths are directories but recursive mode is NOT enabled!")
                print("Only empty directories will be removed.")
                
        print(f"\nTotal: {len(matched_files)} files/directories matched")
        
    def shred_files(self):
        """Securely shred files matching the pattern"""
        path = self.shred_path_var.get()
        if not path:
            messagebox.showerror("Error", "Please enter a file path or pattern")
            return
            
        # Confirm shredding
        confirmation = messagebox.askyesno(
            "Confirm Secure Deletion", 
            "Are you sure you want to PERMANENTLY and IRREVERSIBLY "
            "delete the selected files?\n\n"
            "This operation CANNOT be undone!"
        )
        
        if not confirmation:
            return
            
        # Prepare arguments
        args = ["shred", "-i", path]
        
        # Add options
        if self.shred_recursive_var.get():
            args.append("-r")
            
        args.extend(["--shred-passes", str(self.shred_passes_var.get())])
        
        # Run the command
        self.run_crypt_command(args)
        
    def run_crypt_command(self, args):
        """Run a crypt.py command either directly or via subprocess"""
        print(f"\n--- Running crypt.py {' '.join(args)} ---\n")
        
        # Disable UI while running
        self.set_ui_state(tk.DISABLED)
        
        # Run in a separate thread to avoid freezing the UI
        threading.Thread(target=self._run_command_thread, args=(args,), daemon=True).start()
        
    def _run_command_thread(self, args):
        """Thread function to run the command"""
        try:
            # Choose between direct import or subprocess mode
            if DIRECT_IMPORT:
                # TODO: Implement direct function calls if needed
                # For now, use subprocess in all cases
                self._run_subprocess(args)
            else:
                self._run_subprocess(args)
        except Exception as e:
            print(f"\nError: {str(e)}")
        finally:
            # Re-enable UI
            self.after(100, lambda: self.set_ui_state(tk.NORMAL))
        
    def _run_subprocess(self, args):
        """Run crypt.py as a subprocess"""
        cmd = [sys.executable, self.crypt_script] + args
        
        try:
            # Run the process and capture output
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            
            self.current_process = process
            
            # Read and print output in real-time
            for line in iter(process.stdout.readline, ''):
                print(line.rstrip())
                
            # Wait for process to complete
            return_code = process.wait()
            
            if return_code == 0:
                print("\nOperation completed successfully!")
            else:
                print(f"\nOperation failed with return code {return_code}")
                
        except subprocess.SubprocessError as e:
            print(f"\nError running command: {e}")
        finally:
            self.current_process = None
        
    def set_ui_state(self, state):
        """Enable or disable UI elements"""
        for child in self.winfo_children():
            for widget in self.all_children(child):
                if isinstance(widget, (ttk.Button, ttk.Entry, ttk.Combobox, ttk.Checkbutton, ttk.Spinbox)):
                    try:
                        widget.configure(state=state)
                    except tk.TclError:
                        pass  # Some widgets might not support state
                        
    def all_children(self, widget):
        """Recursively get all children of a widget"""
        children = [widget]
        if hasattr(widget, 'winfo_children'):
            for child in widget.winfo_children():
                children.extend(self.all_children(child))
        return children
        
    def on_close(self):
        """Handle window close event"""
        # Kill any running process
        if self.current_process:
            try:
                self.current_process.terminate()
            except:
                pass
        
        # Restore stdout
        if self.redirect:
            self.redirect.stop_update()
            sys.stdout = self.original_stdout
            
        # Destroy the window
        self.destroy()


if __name__ == '__main__':
    app = CryptGUI()
    app.mainloop()