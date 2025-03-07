#!/usr/bin/env python3
"""
Secure File Encryption Tool - Launcher

This script launches the GUI for the secure file encryption tool.
"""

import os
import sys
import subprocess
import tkinter as tk
from tkinter import messagebox

def main():
    """Main function to launch the GUI application"""
    # Check if crypt_gui.py exists
    script_dir = os.path.dirname(os.path.abspath(__file__))
    gui_script = os.path.join(script_dir, "crypt_gui.py")
    crypt_script = os.path.join(script_dir, "crypt.py")
    
    if not os.path.exists(gui_script):
        show_error("GUI script not found", f"Could not find {gui_script}")
        return
        
    if not os.path.exists(crypt_script):
        show_error("Crypt script not found", f"Could not find {crypt_script}")
        return
    
    # Launch the GUI application
    try:
        subprocess.Popen([sys.executable, gui_script])
    except Exception as e:
        show_error("Launch Error", f"Error launching GUI: {str(e)}")

def show_error(title, message):
    """Show an error message dialog"""
    root = tk.Tk()
    root.withdraw()  # Hide the main window
    messagebox.showerror(title, message)
    root.destroy()

if __name__ == "__main__":
    main()
