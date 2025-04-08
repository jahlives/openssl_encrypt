#!/usr/bin/env python3
"""
Simple test GUI to verify that tkinter is working properly
"""

import tkinter as tk
import sys
import os

def main():
    """Create a simple test window"""
    print("Starting test GUI...")
    print(f"Python version: {sys.version}")
    print(f"Running from: {os.path.abspath(__file__)}")
    
    try:
        # Create the main window
        root = tk.Tk()
        root.title("GUI Test Window")
        root.geometry("400x300")
        
        # Add a label
        label = tk.Label(root, text="If you can see this, tkinter is working correctly!", 
                        font=("Arial", 14))
        label.pack(pady=50)
        
        # Add a button that closes the window
        button = tk.Button(root, text="Close", command=root.destroy)
        button.pack(pady=20)
        
        print("GUI window created successfully, should be visible now.")
        
        # Start the main loop
        root.mainloop()
        print("GUI closed normally.")
        
    except Exception as e:
        print(f"Error creating GUI: {str(e)}")
        raise

if __name__ == "__main__":
    main()
