#!/usr/bin/env python
"""
######################################################
#                   DuckHunter                       #
#                 Pedro M. Sosa                      #
# Tool to prevent getting attacked by a rubberducky! #
######################################################

This script monitors keyboard input to detect potential key injection attacks 
(e.g., via a "rubberducky"). It supports four protection policies:
    - Paranoid: Blocks further input until the correct password is entered.
    - Normal: Temporarily disallows keyboard input when an attack is detected.
    - Sneaky: Drops some keys to disrupt the attack.
    - LogOnly: Simply logs the attack without interfering with input.

A Tkinter GUI provides controls for starting/stopping the script, configuring
startup options, and displaying an "About" window.

Usage:
    - Configure settings in duckhunt.conf.
    - Run as a windowless .pyw (or use py2exe/pyinstaller to build an .exe).
"""

import os
import sys
import time
import getpass
import logging
import webbrowser
import pythoncom

# For Python 3, use "import pyWinhook as pyHook" (if installed) instead of pyHook.
import pyHook  

try:
    # For Python 3, use import tkinter and tkinter.ttk
    from tkinter import Tk, Menu, Button, Toplevel
    from tkinter import messagebox
except ImportError:
    # Python 2 fallback
    from Tkinter import Tk, Menu, Button, Toplevel
    import tkMessageBox as messagebox

# Use importlib instead of deprecated imp module.
import importlib.util

# -------------------------------
# Load configuration from duckhunt.conf
# -------------------------------
def load_config(config_path='duckhunt.conf'):
    spec = importlib.util.spec_from_file_location("duckhunt", config_path)
    config_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(config_module)
    return config_module

config = load_config()

# Global configuration variables
THRESHOLD = config.threshold                  # Speed threshold (ms)
HISTORY_SIZE = config.size                    # Size of history array
POLICY = config.policy.lower()                # Policy type: paranoid, normal, sneaky, log
PASSWORD = config.password                    # Password for Paranoid mode
ALLOW_AUTO = config.allow_auto_type_software   # Allow auto-type software (e.g., KeyPass)
RANDDROP_INTERVAL = config.randdrop           # For Sneaky mode (drop every nth key)
LOG_FILENAME = config.filename                # Log file path
BLACKLIST = [w.strip() for w in config.blacklist.split(",") if w.strip()]

# Setup logging for attacks
logging.basicConfig(
    filename=LOG_FILENAME,
    level=logging.INFO,
    format='[%(asctime)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# -------------------------------
# DuckHunterHook Class
# -------------------------------
class DuckHunterHook:
    def __init__(self):
        # State variables for key injection detection
        self.threshold = THRESHOLD
        self.history = [self.threshold + 1] * HISTORY_SIZE
        self.history_index = 0
        self.prev_time = -1
        self.average_speed = 0.0
        self.is_intrusion = False
        self.policy = POLICY
        self.password = PASSWORD
        self.password_counter = 0
        self.randdrop_counter = 0
        self.allow_auto = ALLOW_AUTO
        self.blacklist = BLACKLIST
        self.last_window = ""
        # Create a hook manager
        self.hm = pyHook.HookManager()
        self.hm.KeyDown = self.on_key_down

    def log_event(self, event):
        """Log the key event (window name and key pressed)."""
        try:
            if self.last_window != event.WindowName:
                logging.info("\n[ %s ]", event.WindowName)
                self.last_window = event.WindowName
            if 32 < event.Ascii < 127:
                logging.info("%s", chr(event.Ascii))
            else:
                logging.info("[%s]", event.Key)
        except Exception as e:
            logging.exception("Logging error: %s", e)

    def handle_intrusion(self, event):
        """Handle intrusion based on the active policy."""
        print("Quack! Quack! -- Time to go Duckhunting!")
        self.is_intrusion = True

        if self.policy == "paranoid":
            # Block input until correct password is entered.
            messagebox.showinfo("KeyInjection Detected",
                                "Someone might be trying to inject keystrokes into your computer.\n"
                                "Please check your ports or any strange programs running.\n"
                                "Enter your password to unlock keyboard.")
            return False

        elif self.policy == "sneaky":
            self.randdrop_counter += 1
            # Drop every nth keystroke (e.g., every 7th key)
            if self.randdrop_counter % RANDDROP_INTERVAL == 0:
                return False
            return True

        elif self.policy == "logonly":
            self.log_event(event)
            return True

        # Normal policy: log event and block this keystroke.
        self.log_event(event)
        return False

    def on_key_down(self, event):
        """
        Called for every key press event.
        Processes keystroke timing, checks for injection, and applies the active policy.
        """
        # Debug output
        # print("Key:", event.Key, "Injected:", event.Injected, "Window:", event.WindowName)
        if event.Injected and self.allow_auto:
            print("Injected by auto-type software; allowed.")
            return True

        # In Paranoid mode, if intrusion is flagged, require password input.
        if self.policy == "paranoid" and self.is_intrusion:
            self.log_event(event)
            try:
                char = chr(event.Ascii)
            except Exception:
                char = ''
            if self.password and self.password[self.password_counter] == char:
                self.password_counter += 1
                if self.password_counter == len(self.password):
                    messagebox.showinfo("KeyInjection Detected", "Correct Password! Keyboard unlocked.")
                    self.is_intrusion = False
                    self.password_counter = 0
            else:
                self.password_counter = 0
            return False

        # Initialize prev_time on first keypress.
        if self.prev_time == -1:
            self.prev_time = event.Time
            return True

        # Compute interval (keystroke speed)
        interval = event.Time - self.prev_time
        self.prev_time = event.Time
        self.history[self.history_index] = interval
        self.history_index = (self.history_index + 1) % len(self.history)
        self.average_speed = sum(self.history) / float(len(self.history))
        print("Average Speed:", self.average_speed)

        # Check if the active window is blacklisted.
        for window in self.blacklist:
            if window and window in event.WindowName:
                return self.handle_intrusion(event)

        # If the average speed is below the threshold, treat as an intrusion.
        if self.average_speed < self.threshold:
            return self.handle_intrusion(event)
        else:
            self.is_intrusion = False

        return True

    def start(self):
        """Install the keyboard hook and start the message pump."""
        self.hm.HookKeyboard()
        try:
            pythoncom.PumpMessages()
        except Exception as e:
            logging.exception("Error in message pump: %s", e)
            sys.exit(1)

# -------------------------------
# DuckHunterGUI Class
# -------------------------------
class DuckHunterGUI:
    def __init__(self):
        self.root = Tk()
        self.root.title("DuckHunter")
        try:
            # Use a custom icon if available.
            self.root.iconbitmap('favicon.ico')
        except Exception:
            pass
        self.root.resizable(False, False)
        self.root.geometry("300x45+300+300")
        self.root.attributes("-topmost", True)
        self.username = getpass.getuser()
        self.dir_path = os.path.dirname(os.path.realpath(__file__))
        self.create_menu()
        self.create_widgets()

    def create_menu(self):
        """Create the application menu."""
        menubar = Menu(self.root)
        # Main Menu
        main_menu = Menu(menubar, tearoff=0)
        main_menu.add_command(label="START", command=self.start_hook)
        main_menu.add_command(label="CLOSE", command=self.stop_script)
        main_menu.add_separator()
        main_menu.add_command(label="ABOUT", command=self.show_about)
        menubar.add_cascade(label="Menu", menu=main_menu)
        # Settings Menu
        settings_menu = Menu(menubar, tearoff=0)
        settings_menu.add_command(label="RUN SCRIPT ON STARTUP", command=self.add_to_startup)
        settings_menu.add_command(label="FULLSCREEN", command=self.fullscreen)
        settings_menu.add_command(label="HIDE TITLE BAR", command=self.hide_title_bar)
        menubar.add_cascade(label="Settings", menu=settings_menu)
        self.root.config(menu=menubar)

    def create_widgets(self):
        """Create buttons on the main window."""
        btn_start = Button(self.root, text="Start", command=self.start_hook)
        btn_close = Button(self.root, text="Close", command=self.stop_script)
        btn_start.grid(column=1, row=0, padx=5, pady=5)
        btn_close.grid(column=2, row=0, padx=5, pady=5)
        btn_startup = Button(self.root, text="RUN SCRIPT ON STARTUP", command=self.add_to_startup)
        btn_startup.grid(column=3, row=0, padx=5, pady=5)

    def stop_script(self):
        """Stop the script and exit."""
        self.root.destroy()
        sys.exit(0)

    def show_about(self):
        """Open the project's About page in the default browser."""
        webbrowser.open_new(r"https://github.com/pmsosa/duckhunt/blob/master/README.md")

    def fullscreen(self):
        """Set the window to fullscreen."""
        self.root.attributes('-fullscreen', True)
        self.root.bind('<Escape>', lambda e: self.root.attributes('-fullscreen', False))

    def hide_title_bar(self):
        """Remove the window title bar."""
        self.root.overrideredirect(True)

    def add_to_startup(self):
        """Create a batch file to add the script to Windows startup."""
        bat_dir = r'C:\Users\%s\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup' % self.username
        bat_file_path = os.path.join(bat_dir, "duckhunt.bat")
        # Adjust the path to your built executable or script as needed.
        with open(bat_file_path, "w+") as bat_file:
            bat_file.write(r'start "" "%s\AutoRunDuckHunt.exe"' % self.dir_path)
        messagebox.showinfo("Startup", "DuckHunter has been added to startup.")

    def start_hook(self):
        """Start the hook and hide the main window (or launch a secondary control window)."""
        self.root.destroy()
        gui = DuckHunterControlWindow()
        gui.start()

    def run(self):
        """Run the GUI main loop."""
        self.root.mainloop()

# -------------------------------
# DuckHunterControlWindow Class
# -------------------------------
class DuckHunterControlWindow:
    """
    A secondary control window that appears after starting the hook.
    It provides additional controls such as 'Stop Script', 'Close Window',
    and settings for startup, fullscreen, etc.
    """
    def __init__(self):
        self.window = Toplevel()
        self.window.title("DuckHunter")
        try:
            self.window.iconbitmap('favicon.ico')
        except Exception:
            pass
        self.window.geometry("310x45+300+300")
        self.window.resizable(False, False)
        self.window.attributes("-topmost", True)
        self.create_menu()
        self.create_widgets()

    def create_menu(self):
        menubar = Menu(self.window)
        main_menu = Menu(menubar, tearoff=0)
        main_menu.add_command(label="STOP SCRIPT", command=self.stop_script)
        main_menu.add_command(label="CLOSE WINDOW", command=self.window.destroy)
        main_menu.add_separator()
        main_menu.add_command(label="ABOUT", command=self.show_about)
        menubar.add_cascade(label="Menu", menu=main_menu)
        settings_menu = Menu(menubar, tearoff=0)
        settings_menu.add_command(label="RUN SCRIPT ON STARTUP", command=self.add_to_startup)
        settings_menu.add_command(label="FULLSCREEN", command=self.fullscreen)
        settings_menu.add_command(label="HIDE TITLE BAR", command=self.hide_title_bar)
        menubar.add_cascade(label="Settings", menu=settings_menu)
        self.window.config(menu=menubar)

    def create_widgets(self):
        btn_stop = Button(self.window, text="Stop Script", command=self.stop_script)
        btn_close = Button(self.window, text="Close Window", command=self.window.destroy)
        btn_startup = Button(self.window, text="RUN SCRIPT ON STARTUP", command=self.add_to_startup)
        btn_stop.grid(column=1, row=0, padx=5, pady=5)
        btn_close.grid(column=2, row=0, padx=5, pady=5)
        btn_startup.grid(column=3, row=0, padx=5, pady=5)

    def stop_script(self):
        self.window.destroy()
        sys.exit(0)

    def show_about(self):
        webbrowser.open_new(r"https://github.com/pmsosa/duckhunt/blob/master/README.md")

    def fullscreen(self):
        self.window.attributes('-fullscreen', True)
        self.window.bind('<Escape>', lambda e: self.window.attributes('-fullscreen', False))

    def hide_title_bar(self):
        self.window.overrideredirect(True)

    def add_to_startup(self):
        username = getpass.getuser()
        dir_path = os.path.dirname(os.path.realpath(__file__))
        bat_dir = r'C:\Users\%s\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup' % username
        bat_file_path = os.path.join(bat_dir, "duckhunt.bat")
        with open(bat_file_path, "w+") as bat_file:
            bat_file.write(r'start "" "%s\builds\duckhunt.0.9.exe"' % dir_path)
        messagebox.showinfo("Startup", "DuckHunter has been added to startup.")

    def start(self):
        """Start the keyboard hook and begin message pumping."""
        hook = DuckHunterHook()
        hook.start()

# -------------------------------
# Main Execution
# -------------------------------
def main():
    # Start the GUI which in turn starts the hook.
    gui = DuckHunterGUI()
    gui.run()

if __name__ == '__main__':
    main()
