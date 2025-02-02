#!/usr/bin/env python
"""
######################################################
#                   DuckHunter                       #
#                 Pedro M. Sosa                      #
# Tool to prevent getting attacked by a rubberducky! #
######################################################

Description:
    DuckHunter monitors keyboard input to detect potential key injection attacks—
    such as those from a "rubberducky"—by analyzing keystroke timing. When an attack
    is detected (based on a configurable speed threshold), the tool responds according
    to one of several policies:
        - Paranoid: Locks down keyboard input until the correct password is entered.
        - Normal: Temporarily disables keyboard input.
        - Sneaky: Drops certain keystrokes to disrupt the attack.
        - LogOnly: Only logs the attack without interfering with input.

Usage:
    1. Configure parameters in duckhunt.conf.
    2. Run this script as a windowless .pyw (or convert to an .exe via py2exe).
    3. Enjoy advanced protection against key injection!

Author: Pedro M. Sosa
Date: [Current Date]
"""

import os
import sys
import time
import logging
import importlib.util
from ctypes import *
import pythoncom
import pyHook  # Ensure you have pyHook installed (or use pyWinhook for Python 3)
import win32ui

# -------------------------
# Configuration Loading
# -------------------------
def load_config(config_path='duckhunt.conf'):
    """
    Dynamically load configuration from duckhunt.conf.
    This file should define:
      - threshold         : Speed threshold (ms) for keystroke intervals.
      - size              : Number of keystrokes to average.
      - policy            : Protection policy ("paranoid", "normal", "sneaky", "log").
      - password          : Password for Paranoid mode.
      - allow_auto_type_software: Boolean flag for allowing auto-typing software.
      - randdrop          : Interval for dropping keys in Sneaky mode.
      - filename          : Log file path.
      - blacklist         : Comma-separated list of window name substrings to monitor.
    """
    spec = importlib.util.spec_from_file_location("duckhunt", config_path)
    duckhunt = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(duckhunt)
    return duckhunt

config = load_config()

# Global configuration parameters
THRESHOLD = config.threshold                # Speed threshold (ms)
HISTORY_SIZE = config.size                  # Number of intervals to average
POLICY = config.policy.lower()              # Protection policy type
PASSWORD = config.password                  # Password for Paranoid mode
ALLOW_AUTO_TYPE = config.allow_auto_type_software  # Allow known auto-type software
RANDDROP_INTERVAL = config.randdrop         # Interval for dropping keys (Sneaky mode)
LOG_FILENAME = config.filename              # Log file to record attacks
BLACKLIST = [w.strip() for w in config.blacklist.split(",") if w.strip()]

# Set up logging for attack events and errors.
logging.basicConfig(
    filename=LOG_FILENAME,
    level=logging.INFO,
    format='[%(asctime)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# -------------------------
# DuckHunter Class
# -------------------------
class DuckHunter:
    def __init__(self):
        # Policy and configuration variables
        self.policy = POLICY
        self.password = PASSWORD
        self.allow_auto = ALLOW_AUTO_TYPE
        self.randdrop_interval = RANDDROP_INTERVAL
        self.threshold = THRESHOLD
        self.history_size = HISTORY_SIZE
        self.blacklist = BLACKLIST

        # Internal state variables
        self.history = [self.threshold + 1] * self.history_size  # List to track keystroke intervals
        self.history_index = 0
        self.previous_time = -1
        self.is_intrusion = False
        self.password_counter = 0
        self.last_window = ""
        self.average_speed = 0.0
        self.randdrop_counter = 0  # Counter for Sneaky mode dropped keys

        # Set up hook manager and assign the key down handler.
        self.hook_manager = pyHook.HookManager()
        self.hook_manager.KeyDown = self.on_key_down

    def log_attack(self, event):
        """
        Log the attack event, including the window name and key pressed.
        Uses the logging module for timestamped logging.
        """
        window_name = event.WindowName
        if self.last_window != window_name:
            logging.info("\n[ %s ]", window_name)
            self.last_window = window_name
        try:
            if 32 < event.Ascii < 127:
                logging.info("%s", chr(event.Ascii))
            else:
                logging.info("[%s]", event.Key)
        except Exception as e:
            logging.exception("Error logging key: %s", e)

    def handle_intrusion(self, event):
        """
        Respond to a detected intrusion event based on the configured policy.
        Returns False to block the keystroke or True to allow it.
        """
        print("Quack! Quack! -- Intrusion detected!")
        self.is_intrusion = True

        if self.policy == "paranoid":
            # In Paranoid mode, lock keyboard input until correct password is entered.
            win32ui.MessageBox(
                "Key injection detected!\nCheck your ports or running programs.\nEnter your password to unlock the keyboard.",
                "KeyInjection Detected",
                4096  # MB_SYSTEMMODAL to ensure the dialog is always on top.
            )
            return False

        elif self.policy == "sneaky":
            # In Sneaky mode, drop every nth keypress.
            self.randdrop_counter += 1
            if self.randdrop_counter % self.randdrop_interval == 0:
                return False
            return True

        elif self.policy == "logonly":
            # In LogOnly mode, simply log the event.
            self.log_attack(event)
            return True

        # Normal policy: log the event and block this keystroke.
        self.log_attack(event)
        return False

    def on_key_down(self, event):
        """
        Handler function called for every key press event.
        Monitors keystroke timing, checks for injected keystrokes,
        applies blacklist filtering, and enforces protection policies.
        """
        # Debug output for monitoring
        # print("Key:", event.Key, "Injected:", event.Injected, "Window:", event.WindowName)

        # Allow keystrokes injected by approved auto-type software.
        if event.Injected and self.allow_auto:
            print("Injected by auto-type software; allowed.")
            return True

        # If in Paranoid mode and intrusion has been flagged, require password input.
        if self.policy == "paranoid" and self.is_intrusion:
            self.log_attack(event)
            try:
                char = chr(event.Ascii)
            except Exception:
                char = ''
            if self.password and self.password[self.password_counter] == char:
                self.password_counter += 1
                if self.password_counter == len(self.password):
                    win32ui.MessageBox(
                        "Correct Password! Keyboard unlocked.",
                        "KeyInjection Detected",
                        4096
                    )
                    self.is_intrusion = False
                    self.password_counter = 0
            else:
                self.password_counter = 0
            return False

        # On first key press, initialize previous_time.
        if self.previous_time == -1:
            self.previous_time = event.Time
            return True

        # Compute the interval (keystroke speed) between keypresses.
        interval = event.Time - self.previous_time
        self.previous_time = event.Time
        self.history[self.history_index] = interval
        self.history_index = (self.history_index + 1) % self.history_size
        self.average_speed = sum(self.history) / float(len(self.history))
        # Uncomment for debugging:
        # print("Average Speed:", self.average_speed)

        # If the active window is blacklisted, enforce intrusion handling.
        for window in self.blacklist:
            if window and window in event.WindowName:
                return self.handle_intrusion(event)

        # If the average keystroke interval is below the threshold, treat as an intrusion.
        if self.average_speed < self.threshold:
            return self.handle_intrusion(event)
        else:
            self.is_intrusion = False

        # Otherwise, allow the keystroke.
        return True

    def run(self):
        """
        Install the keyboard hook and start the message pump.
        """
        self.hook_manager.HookKeyboard()
        try:
            pythoncom.PumpMessages()
        except Exception as e:
            logging.exception("An error occurred in the message pump: %s", e)
            sys.exit(1)

# -------------------------
# Main Execution
# -------------------------
if __name__ == '__main__':
    duckhunter = DuckHunter()
    try:
        duckhunter.run()
    except KeyboardInterrupt:
        print("DuckHunter terminated by user.")
    except Exception as ex:
        logging.exception("DuckHunter encountered an error: %s", ex)
