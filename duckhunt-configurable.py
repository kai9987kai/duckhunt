#!/usr/bin/env python
"""
######################################################
#                   DuckHunter                       #
#                 Pedro M. Sosa                      #
# Tool to prevent getting attacked by a rubberducky! #
######################################################
"""

import importlib.util
import logging
import sys

import pythoncom

try:
    # Python 2 + pyHook
    import pyHook  # type: ignore
except ImportError:
    # Python 3 + pyWinhook
    import pyWinhook as pyHook  # type: ignore

import win32ui


def load_config(config_path='duckhunt.conf'):
    """Dynamically load configuration from duckhunt.conf."""
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
ALLOW_AUTO_TYPE = as_bool(getattr(config, "allow_auto_type_software", True), default=True)
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


class DuckHunter:
    def __init__(self):
        self.policy = POLICY
        self.password = PASSWORD
        self.allow_auto = ALLOW_AUTO_TYPE
        self.randdrop_interval = RANDDROP_INTERVAL
        self.threshold = THRESHOLD
        self.history_size = HISTORY_SIZE
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

        self.previous_time = -1
        self.is_intrusion = False
        self.password_counter = 0
        self.last_window = ""
        self.randdrop_counter = 0
        self.normal_block_until = 0
        self.rapid_burst_counter = 0
        self.injected_burst_counter = 0

        self.hook_manager = pyHook.HookManager()
        self.hook_manager.KeyDown = self.on_key_down

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

    def log_attack(self, event):
        window_name = event.WindowName or "<unknown>"
        if self.last_window != window_name:
            logging.info("\n[ %s ]", window_name)
            self.last_window = window_name
        try:
            if 32 < event.Ascii < 127:
                logging.info("%s", chr(event.Ascii))
            else:
                logging.info("[%s]", event.Key)
        except Exception as exc:
            logging.exception("Error logging key: %s", exc)

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
            self.normal_block_until = event.Time + self.normal_lockout_ms

        if self.policy == "paranoid":
            if not was_intrusion:
                win32ui.MessageBox(
                    "Key injection detected!\nCheck your ports or running programs.\n"
                    "Enter your password to unlock the keyboard.",
                    "KeyInjection Detected",
                    4096
                )
            return False

        if self.policy == "sneaky":
            self.randdrop_counter += 1
            should_drop = (self.randdrop_counter % self.randdrop_interval == 0)
            if should_drop:
                self.log_attack(event)
            return not should_drop

        if self.policy == "logonly":
            self.log_attack(event)
            return True

        self.log_attack(event)
        return False

    def handle_paranoid_unlock(self, event):
        self.log_attack(event)
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

    def on_key_down(self, event):
        window_name = event.WindowName or ""
        event_time = int(event.Time)

        if self.is_window_whitelisted(window_name):
            self.previous_time = event_time
            self.rapid_burst_counter = 0
            self.injected_burst_counter = 0
            return True

        if self.policy == "normal" and event_time < self.normal_block_until:
            return False

        if self.policy == "paranoid" and self.is_intrusion:
            return self.handle_paranoid_unlock(event)

        if self.previous_time == -1:
            self.previous_time = event_time
            return True

        interval = max(0, event_time - self.previous_time)
        self.previous_time = event_time
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

    def run(self):
        self.hook_manager.HookKeyboard()
        try:
            pythoncom.PumpMessages()
        except Exception as exc:
            logging.exception("An error occurred in the message pump: %s", exc)
            sys.exit(1)


if __name__ == '__main__':
    duckhunter = DuckHunter()
    try:
        duckhunter.run()
    except KeyboardInterrupt:
        print("DuckHunter terminated by user.")
    except Exception as ex:
        logging.exception("DuckHunter encountered an error: %s", ex)
