#!/usr/bin/env python3
"""
Simple GUI for the encryption tool with the new password generation features.
This can replace or supplement crypt_gui.py if it's not working.
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

class CryptGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure File Encryption Tool")
        self.root.geometry("650x580")  # Increased height from 550 to 580
        self.root.minsize(650, 580)    # Increased minimum height as well
        
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
        
        # Add frames to notebook
        self.notebook.add(self.encrypt_frame, text="Encrypt")
        self.notebook.add(self.decrypt_frame, text="Decrypt")
        self.notebook.add(self.shred_frame, text="Shred")
        self.notebook.add(self.password_frame, text="Password Generator")
        
        # Set up the tabs
        self.setup_encrypt_tab()
        self.setup_decrypt_tab()
        self.setup_shred_tab()
        self.setup_password_tab()
        
        # Status bar at the bottom
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        self.status_bar = ttk.Label(root, textvariable=self.status_var, 
                                   relief=tk.SUNKEN, anchor=tk.W, padding=(5, 3))
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X, pady=(5, 5))
        
        # Variables for password timeout
        self.password_timer_id = None
        self.password_timer_active = False
        self.countdown_seconds = 0
        self.countdown_label = None
        
        # Bind tab change event to clear password
        self.notebook.bind("<<NotebookTabChanged>>", self.on_tab_changed)
        
        # Center the window
        self.center_window()
    
    def center_window(self):
        """Center the window on the screen"""
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f'{width}x{height}+{x}+{y}')
    
    def setup_encrypt_tab(self):
        """Set up the encryption tab"""
        frame = self.encrypt_frame
        
        # Input file
        input_frame = ttk.LabelFrame(frame, text="Input File")
        input_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.encrypt_input_var = tk.StringVar()
        ttk.Entry(input_frame, textvariable=self.encrypt_input_var).pack(
            side=tk.LEFT, fill=tk.X, expand=True, padx=5, pady=5)
        ttk.Button(input_frame, text="Browse...", 
                  command=lambda: self.browse_file(self.encrypt_input_var)).pack(
                      side=tk.RIGHT, padx=5, pady=5)
        
        # Output file
        output_frame = ttk.LabelFrame(frame, text="Output File")
        output_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.encrypt_output_var = tk.StringVar()
        ttk.Entry(output_frame, textvariable=self.encrypt_output_var).pack(
            side=tk.LEFT, fill=tk.X, expand=True, padx=5, pady=5)
        ttk.Button(output_frame, text="Browse...", 
                  command=lambda: self.browse_file(self.encrypt_output_var, save=True)).pack(
                      side=tk.RIGHT, padx=5, pady=5)
        
        # Password options
        password_frame = ttk.LabelFrame(frame, text="Password")
        password_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.encrypt_password_var = tk.StringVar()
        ttk.Label(password_frame, text="Password:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        password_entry = ttk.Entry(password_frame, textvariable=self.encrypt_password_var, show="*")
        password_entry.grid(row=0, column=1, padx=5, pady=5, sticky=tk.EW)
        
        self.encrypt_confirm_var = tk.StringVar()
        ttk.Label(password_frame, text="Confirm:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        confirm_entry = ttk.Entry(password_frame, textvariable=self.encrypt_confirm_var, show="*")
        confirm_entry.grid(row=1, column=1, padx=5, pady=5, sticky=tk.EW)
        
        # Add "Generate" button
        ttk.Button(password_frame, text="Generate Password",
                  command=self.generate_encrypt_password).grid(
                      row=0, column=2, rowspan=2, padx=5, pady=5)
        
        password_frame.columnconfigure(1, weight=1)
        
        # Options 
        options_frame = ttk.LabelFrame(frame, text="Options")
        options_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.encrypt_overwrite_var = tk.BooleanVar()
        ttk.Checkbutton(options_frame, text="Overwrite original file",
                       variable=self.encrypt_overwrite_var).pack(anchor=tk.W, padx=5, pady=2)
        
        self.encrypt_shred_var = tk.BooleanVar()
        ttk.Checkbutton(options_frame, text="Securely shred original file",
                       variable=self.encrypt_shred_var).pack(anchor=tk.W, padx=5, pady=2)
        
        # Action button
        button_frame = ttk.Frame(frame)
        button_frame.pack(fill=tk.X, padx=10, pady=(20, 25))
        
        # Increased button height with more padding
        encrypt_button = ttk.Button(button_frame, text="Encrypt", command=self.run_encrypt)
        encrypt_button.pack(padx=5, pady=5)
        self.style.configure("TButton", padding=[10, 8])  # Slightly increase button padding
    
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
        
        # Action button
        button_frame = ttk.Frame(frame)
        button_frame.pack(fill=tk.X, padx=10, pady=20)
        
        ttk.Button(button_frame, text="Decrypt", command=self.run_decrypt).pack(padx=5, pady=5)
    
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
    
    def browse_file(self, string_var, save=False, multi=False):
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
            try:
                self.status_var.set("Running...")
                
                # Run the command
                result = subprocess.run(
                    cmd, 
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
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
        
        # Start the command in a separate thread
        threading.Thread(target=run_in_thread, daemon=True).start()
    
    def show_output_dialog(self, title, text):
        """Show a dialog with scrollable text output"""
        dialog = tk.Toplevel(self.root)
        dialog.title(title)
        dialog.geometry("600x400")
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Add text widget with scrollbar
        text_frame = ttk.Frame(dialog)
        text_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        scrollbar = ttk.Scrollbar(text_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        text_widget = tk.Text(text_frame, wrap=tk.WORD, yscrollcommand=scrollbar.set)
        text_widget.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.config(command=text_widget.yview)
        
        # Insert the text
        text_widget.insert(tk.END, text)
        text_widget.config(state=tk.DISABLED)  # Make it read-only
        
        # Add a close button
        ttk.Button(dialog, text="Close", command=dialog.destroy).pack(pady=10)
        
        # Center the dialog
        dialog.update_idletasks()
        width = dialog.winfo_width()
        height = dialog.winfo_height()
        x = (dialog.winfo_screenwidth() // 2) - (width // 2)
        y = (dialog.winfo_screenheight() // 2) - (height // 2)
        dialog.geometry(f'{width}x{height}+{x}+{y}')
    
    def run_encrypt(self):
        """Run the encryption command"""
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
        
        # Build the command
        cmd = [sys.executable, "crypt.py", "encrypt", "-i", input_file]
        
        if output_file and not self.encrypt_overwrite_var.get():
            cmd.extend(["-o", output_file])
        
        if self.encrypt_overwrite_var.get():
            cmd.append("--overwrite")
        
        if self.encrypt_shred_var.get():
            cmd.append("-s")
        
        # Add password
        cmd.extend(["-p", password])
        
        # Run the command
        self.run_command(cmd)
    
    def run_decrypt(self):
        """Run the decryption command"""
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
        
        # Build the command
        cmd = [sys.executable, "crypt.py", "decrypt", "-i", input_file]
        
        if output_file and not self.decrypt_overwrite_var.get():
            cmd.extend(["-o", output_file])
        
        if self.decrypt_overwrite_var.get():
            cmd.append("--overwrite")
        
        if self.decrypt_shred_var.get():
            cmd.append("-s")
        
        # Add password
        cmd.extend(["-p", password])
        
        # Run the command
        self.run_command(cmd, show_output=show_output)
    
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
        
        # Build the command
        cmd = [sys.executable, "crypt.py", "shred", "-i", input_files]
        
        if self.shred_recursive_var.get():
            cmd.append("-r")
        
        cmd.extend(["--shred-passes", str(self.shred_passes_var.get())])
        
        # Run the command
        self.run_command(cmd)


def main():
    """Main entry point for the application"""
    root = tk.Tk()
    app = CryptGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
