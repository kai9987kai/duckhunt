#!/usr/bin/env python
"""
######################################################
#                   DuckHunter                       #
#                 Pedro M. Sosa                      #
# Tool to prevent getting attacked by a rubberducky! #
######################################################

This script monitors keyboard input to detect potential keystroke injection attacks.
"""

import importlib.util
import logging
import os
import sys
import threading
import webbrowser
from ctypes import windll

import pythoncom

try:
    # Python 2 + pyHook
    import pyHook  # type: ignore
except ImportError:
    # Python 3 + pyWinhook
    import pyWinhook as pyHook  # type: ignore

try:
    # For Python 3
    from tkinter import Tk, Menu, Button, Label
    from tkinter import messagebox
except ImportError:
    # Python 2 fallback
    from Tkinter import Tk, Menu, Button, Label  # type: ignore
    import tkMessageBox as messagebox  # type: ignore


WM_QUIT = 0x0012


def load_config(config_path='duckhunt.conf'):
    spec = importlib.util.spec_from_file_location("duckhunt", config_path)
    config_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(config_module)
    return config_module


def as_bool(value, default=False):
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        return value.strip().lower() in ("1", "true", "yes", "y", "on")
    return default


def as_int(value, default, minimum=None):
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    if minimum is not None and parsed < minimum:
        return minimum
    return parsed


def as_csv_list(value):
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        items = value
    else:
        items = str(value).split(",")
    return [str(item).strip() for item in items if str(item).strip()]


def normalize_policy(raw_policy):
    policy = str(raw_policy or "normal").strip().lower()
    if policy == "log":
        return "logonly"
    if policy in ("paranoid", "normal", "sneaky", "logonly"):
        return policy
    return "normal"


config = load_config()

THRESHOLD = as_int(getattr(config, "threshold", 30), 30, minimum=1)
HISTORY_SIZE = as_int(getattr(config, "size", 25), 25, minimum=3)
POLICY = normalize_policy(getattr(config, "policy", "normal"))
PASSWORD = str(getattr(config, "password", ""))
ALLOW_AUTO = as_bool(getattr(config, "allow_auto_type_software", True), default=True)
RANDDROP_INTERVAL = as_int(getattr(config, "randdrop", 6), 6, minimum=1)
LOG_FILENAME = str(getattr(config, "filename", "log.txt"))
BLACKLIST = [item.lower() for item in as_csv_list(getattr(config, "blacklist", ""))]
WHITELIST = [item.lower() for item in as_csv_list(getattr(config, "whitelist", ""))]
LOG_LEVEL = str(getattr(config, "log_level", "INFO")).upper()
DEBUG = as_bool(getattr(config, "debug", False), default=False)

# Advanced options (all backward-compatible defaults)
NORMAL_LOCKOUT_MS = as_int(getattr(config, "normal_lockout_ms", 1200), 1200, minimum=0)
RAPID_BURST_INTERVAL_MS = as_int(getattr(config, "rapid_burst_interval_ms", 12), 12, minimum=1)
RAPID_BURST_COUNT = as_int(getattr(config, "rapid_burst_count", 8), 8, minimum=0)
INJECTED_BURST_COUNT = as_int(getattr(config, "injected_burst_count", 0), 0, minimum=0)

logging.basicConfig(
    filename=LOG_FILENAME,
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format='[%(asctime)s] %(levelname)s %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)


def startup_directory_for_user():
    return os.path.join(
        os.path.expanduser("~"),
        "AppData",
        "Roaming",
        "Microsoft",
        "Windows",
        "Start Menu",
        "Programs",
        "Startup",
    )


def find_best_startup_target(base_dir):
    candidates = [
        os.path.join(base_dir, "AutoRunDuckHunt.exe"),
        os.path.join(base_dir, "builds", "duckhunt.0.9.exe"),
        os.path.join(base_dir, "duckhunt-configurable.pyw"),
        os.path.join(base_dir, "duckhunt.pyw"),
    ]
    for candidate in candidates:
        if os.path.exists(candidate):
            return 'start "" "{}"'.format(candidate)

    pythonw = os.path.join(os.path.dirname(sys.executable), "pythonw.exe")
    launcher = pythonw if os.path.exists(pythonw) else sys.executable
    script_path = os.path.realpath(__file__)
    return 'start "" "{}" "{}"'.format(launcher, script_path)


def write_startup_batch(base_dir):
    bat_dir = startup_directory_for_user()
    if not os.path.isdir(bat_dir):
        os.makedirs(bat_dir)
    bat_file_path = os.path.join(bat_dir, "duckhunt.bat")
    command = find_best_startup_target(base_dir)
    with open(bat_file_path, "w") as bat_file:
        bat_file.write(command)
    return bat_file_path


class DuckHunterHook:
    def __init__(self):
        self.threshold = THRESHOLD
        self.history_size = HISTORY_SIZE
        self.policy = POLICY
        self.password = PASSWORD
        self.allow_auto = ALLOW_AUTO
        self.randdrop_interval = RANDDROP_INTERVAL
        self.blacklist = BLACKLIST
        self.whitelist = WHITELIST
        self.normal_lockout_ms = NORMAL_LOCKOUT_MS
        self.rapid_burst_interval = RAPID_BURST_INTERVAL_MS
        self.rapid_burst_count = RAPID_BURST_COUNT
        self.injected_burst_count = INJECTED_BURST_COUNT
        self.debug = DEBUG

        self.history = [self.threshold + 1] * self.history_size
        self.history_index = 0
        self.history_total = float(sum(self.history))
        self.average_speed = self.history_total / self.history_size

        self.prev_time = -1
        self.is_intrusion = False
        self.password_counter = 0
        self.randdrop_counter = 0
        self.last_window = ""
        self.normal_block_until = 0
        self.rapid_burst_counter = 0
        self.injected_burst_counter = 0

        self.thread_id = None
        self.running = False

        self.hm = pyHook.HookManager()
        self.hm.KeyDown = self.on_key_down

    def debug_log(self, message, *args):
        if self.debug:
            logging.debug(message, *args)

    def is_window_whitelisted(self, window_name):
        lowered = (window_name or "").lower()
        return any(token in lowered for token in self.whitelist)

    def is_window_blacklisted(self, window_name):
        lowered = (window_name or "").lower()
        return any(token in lowered for token in self.blacklist)

    def update_interval_metrics(self, interval):
        old_value = self.history[self.history_index]
        self.history[self.history_index] = interval
        self.history_index = (self.history_index + 1) % self.history_size
        self.history_total += interval - old_value
        self.average_speed = self.history_total / float(self.history_size)

    def log_event(self, event):
        try:
            window_name = event.WindowName or "<unknown>"
            if self.last_window != window_name:
                logging.info("\n[ %s ]", window_name)
                self.last_window = window_name
            if 32 < event.Ascii < 127:
                logging.info("%s", chr(event.Ascii))
            else:
                logging.info("[%s]", event.Key)
        except Exception as exc:
            logging.exception("Logging error: %s", exc)

    def log_intrusion(self, event, reason):
        logging.warning(
            "Intrusion detected reason=%s policy=%s avg_interval_ms=%.2f threshold_ms=%d "
            "rapid_streak=%d injected_streak=%d window=%r key=%r injected=%r",
            reason,
            self.policy,
            self.average_speed,
            self.threshold,
            self.rapid_burst_counter,
            self.injected_burst_counter,
            event.WindowName,
            event.Key,
            event.Injected,
        )

    def handle_intrusion(self, event, reason):
        was_intrusion = self.is_intrusion
        self.is_intrusion = True
        self.log_intrusion(event, reason)

        if self.policy == "normal":
            self.normal_block_until = int(event.Time) + self.normal_lockout_ms
            self.log_event(event)
            return False

        if self.policy == "paranoid":
            if not was_intrusion:
                messagebox.showinfo(
                    "KeyInjection Detected",
                    "Someone might be trying to inject keystrokes into your computer.\n"
                    "Please check your ports or suspicious programs.\n"
                    "Enter your password to unlock keyboard."
                )
            return False

        if self.policy == "sneaky":
            self.randdrop_counter += 1
            should_drop = (self.randdrop_counter % self.randdrop_interval == 0)
            if should_drop:
                self.log_event(event)
            return not should_drop

        if self.policy == "logonly":
            self.log_event(event)
            return True

        self.log_event(event)
        return False

    def handle_paranoid_unlock(self, event):
        self.log_event(event)
        try:
            char = chr(event.Ascii)
        except Exception:
            char = ''

        if (
            self.password and
            self.password_counter < len(self.password) and
            self.password[self.password_counter] == char
        ):
            self.password_counter += 1
            if self.password_counter == len(self.password):
                messagebox.showinfo("KeyInjection Detected", "Correct Password! Keyboard unlocked.")
                self.is_intrusion = False
                self.password_counter = 0
        else:
            self.password_counter = 0
        return False

    def on_key_down(self, event):
        window_name = event.WindowName or ""
        event_time = int(event.Time)

        if self.is_window_whitelisted(window_name):
            self.prev_time = event_time
            self.rapid_burst_counter = 0
            self.injected_burst_counter = 0
            return True

        if self.policy == "normal" and event_time < self.normal_block_until:
            return False

        if self.policy == "paranoid" and self.is_intrusion:
            return self.handle_paranoid_unlock(event)

        if self.prev_time == -1:
            self.prev_time = event_time
            return True

        interval = max(0, event_time - self.prev_time)
        self.prev_time = event_time
        self.update_interval_metrics(interval)

        if interval <= self.rapid_burst_interval:
            self.rapid_burst_counter += 1
        else:
            self.rapid_burst_counter = 0

        if event.Injected:
            self.injected_burst_counter += 1
        else:
            self.injected_burst_counter = 0

        self.debug_log(
            "event key=%r injected=%r interval=%d avg=%.2f rapid=%d injected_streak=%d",
            event.Key,
            event.Injected,
            interval,
            self.average_speed,
            self.rapid_burst_counter,
            self.injected_burst_counter,
        )

        if self.is_window_blacklisted(window_name):
            return self.handle_intrusion(event, "blacklisted_window")

        if (
            event.Injected and
            self.allow_auto and
            (self.injected_burst_count <= 0 or self.injected_burst_counter < self.injected_burst_count)
        ):
            return True

        if self.rapid_burst_count > 0 and self.rapid_burst_counter >= self.rapid_burst_count:
            return self.handle_intrusion(event, "rapid_burst")

        if self.injected_burst_count > 0 and self.injected_burst_counter >= self.injected_burst_count:
            return self.handle_intrusion(event, "injected_burst")

        if self.average_speed < self.threshold:
            return self.handle_intrusion(event, "average_speed")

        self.is_intrusion = False
        return True

    def start(self):
        self.running = True
        self.thread_id = windll.kernel32.GetCurrentThreadId()
        pythoncom.CoInitialize()
        self.hm.HookKeyboard()
        try:
            pythoncom.PumpMessages()
        except Exception as exc:
            logging.exception("Error in message pump: %s", exc)
        finally:
            try:
                self.hm.UnhookKeyboard()
            except Exception:
                pass
            self.running = False
            pythoncom.CoUninitialize()

    def stop(self):
        if not self.running:
            return
        try:
            self.hm.UnhookKeyboard()
        except Exception:
            pass
        if self.thread_id:
            windll.user32.PostThreadMessageW(self.thread_id, WM_QUIT, 0, 0)


class BaseWindowMixin:
    def show_about(self):
        webbrowser.open_new(r"https://github.com/pmsosa/duckhunt/blob/master/README.md")

    def fullscreen(self):
        self.window.attributes('-fullscreen', True)
        self.window.bind('<Escape>', lambda e: self.window.attributes('-fullscreen', False))

    def hide_title_bar(self):
        self.window.overrideredirect(True)

    def add_to_startup(self):
        try:
            bat_file_path = write_startup_batch(self.dir_path)
            messagebox.showinfo("Startup", "DuckHunter has been added to startup:\n{}".format(bat_file_path))
        except Exception as exc:
            logging.exception("Failed to add startup entry: %s", exc)
            messagebox.showerror("Startup", "Unable to add startup entry. See log for details.")

    def open_log_file(self):
        try:
            log_path = os.path.abspath(LOG_FILENAME)
            if not os.path.exists(log_path):
                messagebox.showinfo("Log", "Log file does not exist yet: {}".format(log_path))
                return
            os.startfile(log_path)
        except Exception:
            try:
                webbrowser.open_new(os.path.abspath(LOG_FILENAME))
            except Exception as exc:
                logging.exception("Failed to open log file: %s", exc)
                messagebox.showerror("Log", "Unable to open the log file.")


class DuckHunterGUI(BaseWindowMixin):
    def __init__(self):
        self.window = Tk()
        self.window.title("DuckHunter")
        try:
            self.window.iconbitmap('favicon.ico')
        except Exception:
            pass
        self.window.resizable(False, False)
        self.window.geometry("370x82+300+300")
        self.window.attributes("-topmost", True)
        self.dir_path = os.path.dirname(os.path.realpath(__file__))
        self.create_menu()
        self.create_widgets()

    def create_menu(self):
        menubar = Menu(self.window)

        main_menu = Menu(menubar, tearoff=0)
        main_menu.add_command(label="START", command=self.start_hook)
        main_menu.add_command(label="CLOSE", command=self.stop_script)
        main_menu.add_separator()
        main_menu.add_command(label="ABOUT", command=self.show_about)
        menubar.add_cascade(label="Menu", menu=main_menu)

        settings_menu = Menu(menubar, tearoff=0)
        settings_menu.add_command(label="RUN SCRIPT ON STARTUP", command=self.add_to_startup)
        settings_menu.add_command(label="OPEN LOG FILE", command=self.open_log_file)
        settings_menu.add_command(label="FULLSCREEN", command=self.fullscreen)
        settings_menu.add_command(label="HIDE TITLE BAR", command=self.hide_title_bar)
        menubar.add_cascade(label="Settings", menu=settings_menu)

        self.window.config(menu=menubar)

    def create_widgets(self):
        btn_start = Button(self.window, text="Start Protection", width=16, command=self.start_hook)
        btn_close = Button(self.window, text="Close", width=8, command=self.stop_script)
        btn_startup = Button(self.window, text="Run On Startup", width=16, command=self.add_to_startup)
        btn_log = Button(self.window, text="Open Log", width=10, command=self.open_log_file)

        btn_start.grid(column=0, row=0, padx=5, pady=8)
        btn_startup.grid(column=1, row=0, padx=5, pady=8)
        btn_log.grid(column=2, row=0, padx=5, pady=8)
        btn_close.grid(column=3, row=0, padx=5, pady=8)

        policy_label = Label(self.window, text="Policy: {} | Threshold: {}ms".format(POLICY, THRESHOLD))
        policy_label.grid(column=0, row=1, columnspan=4, pady=(0, 6))

    def stop_script(self):
        self.window.destroy()
        sys.exit(0)

    def start_hook(self):
        self.window.destroy()
        control_window = DuckHunterControlWindow()
        control_window.start()

    def run(self):
        self.window.mainloop()


class DuckHunterControlWindow(BaseWindowMixin):
    """Control window shown while protection is active."""

    def __init__(self):
        self.window = Tk()
        self.window.title("DuckHunter Protection")
        try:
            self.window.iconbitmap('favicon.ico')
        except Exception:
            pass
        self.window.geometry("430x82+300+300")
        self.window.resizable(False, False)
        self.window.attributes("-topmost", True)

        self.dir_path = os.path.dirname(os.path.realpath(__file__))
        self.hook = DuckHunterHook()
        self.hook_thread = None

        self.create_menu()
        self.create_widgets()

    def create_menu(self):
        menubar = Menu(self.window)

        main_menu = Menu(menubar, tearoff=0)
        main_menu.add_command(label="STOP SCRIPT", command=self.stop_script)
        main_menu.add_command(label="CLOSE WINDOW", command=self.close_window)
        main_menu.add_separator()
        main_menu.add_command(label="ABOUT", command=self.show_about)
        menubar.add_cascade(label="Menu", menu=main_menu)

        settings_menu = Menu(menubar, tearoff=0)
        settings_menu.add_command(label="RUN SCRIPT ON STARTUP", command=self.add_to_startup)
        settings_menu.add_command(label="OPEN LOG FILE", command=self.open_log_file)
        settings_menu.add_command(label="FULLSCREEN", command=self.fullscreen)
        settings_menu.add_command(label="HIDE TITLE BAR", command=self.hide_title_bar)
        menubar.add_cascade(label="Settings", menu=settings_menu)

        self.window.config(menu=menubar)

    def create_widgets(self):
        btn_stop = Button(self.window, text="Stop Script", width=12, command=self.stop_script)
        btn_close = Button(self.window, text="Close Window", width=12, command=self.close_window)
        btn_startup = Button(self.window, text="Run On Startup", width=16, command=self.add_to_startup)
        btn_log = Button(self.window, text="Open Log", width=10, command=self.open_log_file)

        btn_stop.grid(column=0, row=0, padx=5, pady=8)
        btn_close.grid(column=1, row=0, padx=5, pady=8)
        btn_startup.grid(column=2, row=0, padx=5, pady=8)
        btn_log.grid(column=3, row=0, padx=5, pady=8)

        self.status_label = Label(self.window, text="Status: active")
        self.status_label.grid(column=0, row=1, columnspan=4, pady=(0, 6))

    def start_hook_async(self):
        self.hook_thread = threading.Thread(target=self.hook.start, name="duckhunt-hook")
        self.hook_thread.daemon = False
        self.hook_thread.start()

    def close_window(self):
        self.window.destroy()

    def stop_script(self):
        self.status_label.config(text="Status: stopping...")
        self.window.update_idletasks()
        self.hook.stop()
        if self.hook_thread and self.hook_thread.is_alive():
            self.hook_thread.join(timeout=1.5)
        self.window.destroy()
        sys.exit(0)

    def start(self):
        self.start_hook_async()
        self.window.mainloop()


def main():
    gui = DuckHunterGUI()
    gui.run()


if __name__ == '__main__':
    main()
