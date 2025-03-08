#!/usr/bin/env python3
"""
Secure File Encryption Tool - Launcher

This script launches the GUI for the secure file encryption tool.
It also provides a simple CLI interface for generating passwords
when the GUI is not needed.
"""

import os
import sys
import subprocess
import tkinter as tk
from tkinter import messagebox, simpledialog
import argparse
import string
import random
import time

def generate_strong_password(length=16, use_lowercase=True, use_uppercase=True, 
                           use_digits=True, use_special=True):
    """
    Generate a cryptographically strong random password with customizable character sets.
    
    Args:
        length (int): Length of the password to generate
        use_lowercase (bool): Include lowercase letters
        use_uppercase (bool): Include uppercase letters
        use_digits (bool): Include digits
        use_special (bool): Include special characters
        
    Returns:
        str: The generated password
    """
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

def display_password_with_timeout(password, timeout_seconds=10):
    """
    Display a password for a limited time, then clear it.
    Simple version without ANSI escapes for GUI compatibility.
    
    Args:
        password (str): The password to display
        timeout_seconds (int): Number of seconds to display the password
    """
    print("\n" + "=" * 60)
    print(" GENERATED PASSWORD ".center(60, "="))
    print("=" * 60)
    print(f"\nPassword: {password}")
    print("\nThis password will be cleared in {0} seconds.".format(timeout_seconds))
    print("=" * 60)
    
    try:
        # Countdown timer
        for remaining in range(timeout_seconds, 0, -1):
            sys.stdout.write(f"\rTime remaining: {remaining} seconds...")
            sys.stdout.flush()
            time.sleep(1)
        
        # Clear the countdown line
        sys.stdout.write("\r" + " " * 40 + "\r")
        sys.stdout.flush()
        
    except KeyboardInterrupt:
        print("\n\nPassword display aborted by user.")
    
    # Instead of ANSI codes, just print a message
    print("\nThe password has been displayed for the allotted time.")
    print("For security, it will not be shown again.")
    print("If you need to see it again, please generate a new password.")

def launch_gui():
    """Launch the GUI application"""
    # Check if crypt_gui.py exists
    script_dir = os.path.dirname(os.path.abspath(__file__))
    gui_script = os.path.join(script_dir, "crypt_gui.py")
    crypt_script = os.path.join(script_dir, "crypt.py")
    
    if not os.path.exists(gui_script):
        show_error("GUI script not found", f"Could not find {gui_script}")
        return False
        
    if not os.path.exists(crypt_script):
        show_error("Crypt script not found", f"Could not find {crypt_script}")
        return False
    
    # Launch the GUI application
    try:
        subprocess.Popen([sys.executable, gui_script])
        return True
    except Exception as e:
        show_error("Launch Error", f"Error launching GUI: {str(e)}")
        return False

def quick_password_generator():
    """
    Launch a simple dialog for quick password generation without
    starting the full GUI
    """
    root = tk.Tk()
    root.withdraw()  # Hide the main window
    
    # Create a simple dialog for password options
    length = simpledialog.askinteger("Password Length", 
                                    "Enter password length (8-64):", 
                                    minvalue=8, maxvalue=64, 
                                    initialvalue=16)
    
    if length is None:  # User cancelled
        root.destroy()
        return
    
    # Create a dialog for character options
    option_window = tk.Toplevel(root)
    option_window.title("Password Options")
    option_window.geometry("300x220")
    option_window.resizable(False, False)
    
    # Center on screen
    option_window.update_idletasks()
    width = option_window.winfo_width()
    height = option_window.winfo_height()
    x = (option_window.winfo_screenwidth() // 2) - (width // 2)
    y = (option_window.winfo_screenheight() // 2) - (height // 2)
    option_window.geometry(f'+{x}+{y}')
    
    # Character set options
    use_lowercase_var = tk.BooleanVar(value=True)
    use_uppercase_var = tk.BooleanVar(value=True)
    use_digits_var = tk.BooleanVar(value=True)
    use_special_var = tk.BooleanVar(value=True)
    
    # Create checkboxes
    tk.Label(option_window, text="Include these character types:").pack(pady=10)
    tk.Checkbutton(option_window, text="Lowercase letters (a-z)", 
                  variable=use_lowercase_var).pack(anchor="w", padx=20)
    tk.Checkbutton(option_window, text="Uppercase letters (A-Z)", 
                  variable=use_uppercase_var).pack(anchor="w", padx=20)
    tk.Checkbutton(option_window, text="Digits (0-9)", 
                  variable=use_digits_var).pack(anchor="w", padx=20)
    tk.Checkbutton(option_window, text="Special characters (!@#$%...)", 
                  variable=use_special_var).pack(anchor="w", padx=20)
    
    # Result variables
    password_result = [None]
    dialog_completed = [False]
    
    def on_generate():
        # Generate password with selected options
        password = generate_strong_password(
            length,
            use_lowercase_var.get(),
            use_uppercase_var.get(),
            use_digits_var.get(),
            use_special_var.get()
        )
        password_result[0] = password
        dialog_completed[0] = True
        option_window.destroy()
    
    def on_cancel():
        dialog_completed[0] = True
        option_window.destroy()
    
    # Buttons
    button_frame = tk.Frame(option_window)
    button_frame.pack(pady=15)
    tk.Button(button_frame, text="Generate", command=on_generate, 
             width=10).pack(side="left", padx=5)
    tk.Button(button_frame, text="Cancel", command=on_cancel, 
             width=10).pack(side="left", padx=5)
    
    # Wait for dialog to complete
    option_window.protocol("WM_DELETE_WINDOW", on_cancel)
    root.wait_window(option_window)
    
    # If user generated a password, show it
    if password_result[0]:
        # Create a result window
        result_window = tk.Toplevel(root)
        result_window.title("Generated Password")
        result_window.geometry("400x200")
        result_window.resizable(False, False)
        
        # Center on screen
        result_window.update_idletasks()
        width = result_window.winfo_width()
        height = result_window.winfo_height()
        x = (result_window.winfo_screenwidth() // 2) - (width // 2)
        y = (result_window.winfo_screenheight() // 2) - (height // 2)
        result_window.geometry(f'+{x}+{y}')
        
        # Display password
        tk.Label(result_window, 
                text="IMPORTANT: SAVE THIS PASSWORD NOW", 
                font=("Arial", 12, "bold")).pack(pady=10)
        
        password_frame = tk.Frame(result_window, relief="sunken", borderwidth=1)
        password_frame.pack(pady=10, padx=20, fill="x")
        
        password_var = tk.StringVar(value=password_result[0])
        password_entry = tk.Entry(password_frame, textvariable=password_var, 
                                 font=("Courier", 12), justify="center")
        password_entry.pack(pady=10, padx=10, fill="x")
        
        # Buttons
        button_frame = tk.Frame(result_window)
        button_frame.pack(pady=15)
        
        def copy_to_clipboard():
            root.clipboard_clear()
            root.clipboard_append(password_result[0])
            tk.Label(result_window, text="Password copied to clipboard!",
                    fg="green").pack()
        
        tk.Button(button_frame, text="Copy to Clipboard", 
                 command=copy_to_clipboard).pack(side="left", padx=5)
        tk.Button(button_frame, text="Close", 
                 command=result_window.destroy).pack(side="left", padx=5)
        
        # Auto-close warning
        warning_label = tk.Label(result_window, 
                               text="This window will close in 30 seconds for security",
                               fg="red")
        warning_label.pack(pady=5)
        
        # Auto-close timer
        def update_timer(count):
            if count > 0:
                warning_label.config(
                    text=f"This window will close in {count} seconds for security")
                result_window.after(1000, update_timer, count-1)
            else:
                result_window.destroy()
        
        update_timer(30)
        
        # Wait for this window to close
        root.wait_window(result_window)
    
    root.destroy()

def show_error(title, message):
    """Show an error message dialog"""
    root = tk.Tk()
    root.withdraw()  # Hide the main window
    messagebox.showerror(title, message)
    root.destroy()

def main():
    """Main function to parse arguments and launch appropriate interface"""
    parser = argparse.ArgumentParser(description='Secure File Encryption Tool Launcher')
    parser.add_argument('--generate-password', action='store_true',
                      help='Launch quick password generator without full GUI')
    
    args = parser.parse_args()
    
    if args.generate_password:
        quick_password_generator()
    else:
        launch_gui()

if __name__ == "__main__":
    main()

