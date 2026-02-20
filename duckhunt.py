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
import json
import logging
import os
import statistics
import sys
import threading
import time
import webbrowser
from collections import deque
from ctypes import windll
from logging.handlers import RotatingFileHandler

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


def as_float(value, default, minimum=None):
    try:
        parsed = float(value)
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


def normalize_key_name(key_name):
    return str(key_name or "").strip().replace(" ", "").upper()


def parse_pattern_signatures(value):
    signatures = []
    if value is None:
        return signatures

    if isinstance(value, (list, tuple)):
        raw_groups = value
    else:
        raw_groups = str(value).split(";")

    for group in raw_groups:
        if isinstance(group, (list, tuple)):
            tokens = [normalize_key_name(token) for token in group]
        else:
            tokens = [normalize_key_name(token) for token in str(group).split(",")]
        tokens = [token for token in tokens if token]
        if len(tokens) >= 2:
            signatures.append(tuple(tokens))
    return signatures


def parse_window_threshold_overrides(value):
    """Parse 'window:threshold' pairs separated by ';'."""
    overrides = []
    if value is None:
        return overrides

    if isinstance(value, (list, tuple)):
        raw_items = value
    else:
        raw_items = str(value).split(";")

    for item in raw_items:
        chunk = str(item).strip()
        if not chunk or ":" not in chunk:
            continue
        name, threshold_text = chunk.split(":", 1)
        token = name.strip().lower()
        threshold = as_int(threshold_text.strip(), default=-1, minimum=1)
        if token and threshold > 0:
            overrides.append((token, threshold))
    return overrides


def show_system_message(title, body):
    try:
        windll.user32.MessageBoxW(0, body, title, 0x00001000)
    except Exception:
        logging.warning("Unable to display alert dialog: %s", body)


def current_tick_ms():
    # Keyboard event timestamps are based on system uptime, not wall-clock epoch.
    try:
        return int(windll.kernel32.GetTickCount64())
    except AttributeError:
        return int(windll.kernel32.GetTickCount())


def configure_logging(filename, level_name, max_bytes, backup_count):
    logger = logging.getLogger()
    logger.handlers = []
    logger.setLevel(getattr(logging, level_name, logging.INFO))

    formatter = logging.Formatter(
        '[%(asctime)s] %(levelname)s %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    if max_bytes > 0:
        handler = RotatingFileHandler(filename, maxBytes=max_bytes, backupCount=backup_count)
    else:
        handler = logging.FileHandler(filename)

    handler.setFormatter(formatter)
    logger.addHandler(handler)


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

# Advanced options
NORMAL_LOCKOUT_MS = as_int(getattr(config, "normal_lockout_ms", 1200), 1200, minimum=0)
RAPID_BURST_INTERVAL_MS = as_int(getattr(config, "rapid_burst_interval_ms", 12), 12, minimum=1)
RAPID_BURST_COUNT = as_int(getattr(config, "rapid_burst_count", 8), 8, minimum=0)
INJECTED_BURST_COUNT = as_int(getattr(config, "injected_burst_count", 0), 0, minimum=0)

# Optional signature + adaptive detection
PATTERN_SIGNATURES = parse_pattern_signatures(getattr(config, "pattern_signatures", ""))
KEY_BUFFER_SIZE = as_int(getattr(config, "key_buffer_size", 18), 18, minimum=4)
ADAPTIVE_THRESHOLD_ENABLED = as_bool(getattr(config, "adaptive_threshold_enabled", False), default=False)
ADAPTIVE_MIN_SAMPLES = as_int(getattr(config, "adaptive_min_samples", 40), 40, minimum=5)
ADAPTIVE_SAMPLE_SIZE = as_int(getattr(config, "adaptive_sample_size", 140), 140, minimum=ADAPTIVE_MIN_SAMPLES)
ADAPTIVE_MULTIPLIER = as_float(getattr(config, "adaptive_multiplier", 0.35), 0.35, minimum=0.05)
ADAPTIVE_FLOOR_MS = as_int(getattr(config, "adaptive_floor_ms", 12), 12, minimum=1)
ADAPTIVE_CEILING_MS = as_int(getattr(config, "adaptive_ceiling_ms", 90), 90, minimum=ADAPTIVE_FLOOR_MS)
WINDOW_THRESHOLD_OVERRIDES = parse_window_threshold_overrides(getattr(config, "window_threshold_overrides", ""))

# Low-variance detector for machine-like key bursts.
LOW_VARIANCE_DETECTION = as_bool(getattr(config, "low_variance_detection", True), default=True)
LOW_VARIANCE_STDDEV_MS = as_float(getattr(config, "low_variance_stddev_ms", 2.5), 2.5, minimum=0.1)
LOW_VARIANCE_SPEED_CEILING_MS = as_int(getattr(config, "low_variance_speed_ceiling_ms", 55), 55, minimum=1)
LOW_VARIANCE_STREAK_COUNT = as_int(getattr(config, "low_variance_streak_count", 6), 6, minimum=1)

# Optional runtime status export and temporary pause controls
STATUS_FILENAME = str(getattr(config, "status_filename", ""))
STATUS_FLUSH_INTERVAL = as_int(getattr(config, "status_flush_interval", 250), 250, minimum=1)
PAUSE_DURATION_MS = as_int(getattr(config, "pause_duration_ms", 30000), 30000, minimum=1000)
LOG_MAX_BYTES = as_int(getattr(config, "log_max_bytes", 1048576), 1048576, minimum=0)
LOG_BACKUP_COUNT = as_int(getattr(config, "log_backup_count", 5), 5, minimum=1)

# Warmup mode: avoid blocking on speed heuristics during startup calibration.
WARMUP_EVENTS = as_int(getattr(config, "warmup_events", 0), 0, minimum=0)
WARMUP_ACTION = str(getattr(config, "warmup_action", "logonly")).strip().lower()
if WARMUP_ACTION not in ("logonly", "enforce"):
    WARMUP_ACTION = "logonly"

configure_logging(LOG_FILENAME, LOG_LEVEL, LOG_MAX_BYTES, LOG_BACKUP_COUNT)


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
        self.pattern_signatures = PATTERN_SIGNATURES
        self.key_buffer = deque(maxlen=KEY_BUFFER_SIZE)
        self.window_threshold_overrides = WINDOW_THRESHOLD_OVERRIDES

        self.adaptive_threshold_enabled = ADAPTIVE_THRESHOLD_ENABLED
        self.adaptive_min_samples = ADAPTIVE_MIN_SAMPLES
        self.adaptive_multiplier = ADAPTIVE_MULTIPLIER
        self.adaptive_floor_ms = ADAPTIVE_FLOOR_MS
        self.adaptive_ceiling_ms = ADAPTIVE_CEILING_MS
        self.baseline_intervals = deque(maxlen=ADAPTIVE_SAMPLE_SIZE)
        self.effective_threshold = self.threshold
        self.active_threshold = self.threshold

        self.low_variance_detection = LOW_VARIANCE_DETECTION
        self.low_variance_stddev = LOW_VARIANCE_STDDEV_MS
        self.low_variance_speed_ceiling = LOW_VARIANCE_SPEED_CEILING_MS
        self.low_variance_streak_count = LOW_VARIANCE_STREAK_COUNT

        self.status_filename = STATUS_FILENAME.strip()
        self.status_flush_interval = STATUS_FLUSH_INTERVAL
        self.pause_duration_ms = PAUSE_DURATION_MS
        self.pause_until = 0
        self.events_since_flush = 0
        self.warmup_events = WARMUP_EVENTS
        self.warmup_action = WARMUP_ACTION

        self.debug = DEBUG

        self.history = [self.threshold + 1] * self.history_size
        self.history_index = 0
        self.history_total = float(sum(self.history))
        self.history_square_total = float(sum(value * value for value in self.history))
        self.average_speed = self.history_total / self.history_size
        self.interval_stddev = 0.0

        self.prev_time = -1
        self.is_intrusion = False
        self.password_counter = 0
        self.randdrop_counter = 0
        self.last_window = ""
        self.normal_block_until = 0
        self.rapid_burst_counter = 0
        self.injected_burst_counter = 0
        self.low_variance_counter = 0

        self.total_events = 0
        self.allowed_events = 0
        self.blocked_events = 0
        self.intrusion_count = 0
        self.last_intrusion_reason = ""
        self.last_intrusion_window = ""
        self.last_intrusion_key = ""
        self.last_intrusion_at_ms = 0

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

    def get_window_threshold_override(self, window_name):
        lowered = (window_name or "").lower()
        for token, threshold in self.window_threshold_overrides:
            if token in lowered:
                return threshold
        return None

    def update_interval_metrics(self, interval):
        old_value = self.history[self.history_index]
        self.history[self.history_index] = interval
        self.history_index = (self.history_index + 1) % self.history_size
        self.history_total += interval - old_value
        self.history_square_total += (interval * interval) - (old_value * old_value)
        self.average_speed = self.history_total / float(self.history_size)
        mean = self.average_speed
        variance = (self.history_square_total / float(self.history_size)) - (mean * mean)
        if variance < 0:
            variance = 0
        self.interval_stddev = variance ** 0.5

    def compute_effective_threshold(self):
        if not self.adaptive_threshold_enabled:
            self.effective_threshold = self.threshold
            return self.effective_threshold

        if len(self.baseline_intervals) < self.adaptive_min_samples:
            self.effective_threshold = self.threshold
            return self.effective_threshold

        baseline_median = statistics.median(self.baseline_intervals)
        adaptive_value = baseline_median * self.adaptive_multiplier
        adaptive_value = max(self.adaptive_floor_ms, min(self.adaptive_ceiling_ms, adaptive_value))

        blended_threshold = (self.threshold + adaptive_value) / 2.0
        self.effective_threshold = int(round(max(self.threshold, blended_threshold)))
        return self.effective_threshold

    def remember_clean_interval(self, interval, event):
        if event.Injected:
            return
        if interval <= 0:
            return
        self.baseline_intervals.append(interval)

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
            "effective_threshold_ms=%d active_threshold_ms=%d stddev_ms=%.2f "
            "rapid_streak=%d injected_streak=%d low_variance_streak=%d window=%r key=%r injected=%r",
            reason,
            self.policy,
            self.average_speed,
            self.threshold,
            self.effective_threshold,
            self.active_threshold,
            self.interval_stddev,
            self.rapid_burst_counter,
            self.injected_burst_counter,
            self.low_variance_counter,
            event.WindowName,
            event.Key,
            event.Injected,
        )

    def pattern_match_reason(self):
        if not self.pattern_signatures:
            return ""

        buffer_list = list(self.key_buffer)
        for signature in self.pattern_signatures:
            sig_len = len(signature)
            if len(buffer_list) >= sig_len and tuple(buffer_list[-sig_len:]) == signature:
                return "pattern_match:{}".format("->".join(signature))
        return ""

    def in_warmup_phase(self):
        return self.warmup_events > 0 and self.total_events <= self.warmup_events

    def should_enforce_during_warmup(self, reason):
        if reason == "blacklisted_window":
            return True
        if reason.startswith("pattern_match"):
            return True
        return False

    def handle_warmup_intrusion(self, event, reason):
        warmup_reason = "warmup_{}".format(reason)
        self.intrusion_count += 1
        self.last_intrusion_reason = warmup_reason
        self.last_intrusion_window = event.WindowName or ""
        self.last_intrusion_key = event.Key or ""
        self.last_intrusion_at_ms = int(time.time() * 1000)
        self.log_intrusion(event, warmup_reason)
        self.log_event(event)
        return True

    def trigger_intrusion(self, event, reason):
        if (
            self.in_warmup_phase() and
            self.warmup_action == "logonly" and
            not self.should_enforce_during_warmup(reason)
        ):
            result = self.handle_warmup_intrusion(event, reason)
        else:
            result = self.handle_intrusion(event, reason)

        self.record_decision(result, force_status=True)
        return result

    def record_decision(self, allowed, force_status=False):
        if allowed:
            self.allowed_events += 1
        else:
            self.blocked_events += 1
        self.flush_status(force=force_status)

    def flush_status(self, force=False):
        if not self.status_filename:
            return
        self.events_since_flush += 1
        if not force and self.events_since_flush < self.status_flush_interval:
            return

        payload = self.get_status_snapshot()
        payload["timestamp_epoch_ms"] = int(time.time() * 1000)

        try:
            with open(self.status_filename, "w") as status_file:
                json.dump(payload, status_file, sort_keys=True)
        except Exception as exc:
            logging.exception("Unable to write status file %r: %s", self.status_filename, exc)

        self.events_since_flush = 0

    def get_status_snapshot(self):
        now_ms = current_tick_ms()
        pause_remaining_ms = max(0, self.pause_until - now_ms)
        return {
            "running": self.running,
            "policy": self.policy,
            "threshold_ms": self.threshold,
            "effective_threshold_ms": self.effective_threshold,
            "active_threshold_ms": self.active_threshold,
            "average_speed_ms": round(self.average_speed, 2),
            "interval_stddev_ms": round(self.interval_stddev, 3),
            "total_events": self.total_events,
            "allowed_events": self.allowed_events,
            "blocked_events": self.blocked_events,
            "intrusion_count": self.intrusion_count,
            "last_intrusion_reason": self.last_intrusion_reason,
            "last_intrusion_window": self.last_intrusion_window,
            "last_intrusion_key": self.last_intrusion_key,
            "pause_remaining_ms": pause_remaining_ms,
            "adaptive_threshold_enabled": self.adaptive_threshold_enabled,
            "adaptive_samples": len(self.baseline_intervals),
            "low_variance_detection": self.low_variance_detection,
            "low_variance_streak": self.low_variance_counter,
            "warmup_events": self.warmup_events,
            "warmup_remaining_events": max(0, self.warmup_events - self.total_events),
        }

    def pause_protection(self, duration_ms=None):
        duration = duration_ms if duration_ms is not None else self.pause_duration_ms
        duration = max(1000, int(duration))
        self.pause_until = current_tick_ms() + duration

    def resume_protection(self):
        self.pause_until = 0

    def handle_intrusion(self, event, reason):
        was_intrusion = self.is_intrusion
        self.is_intrusion = True
        self.intrusion_count += 1
        self.last_intrusion_reason = reason
        self.last_intrusion_window = event.WindowName or ""
        self.last_intrusion_key = event.Key or ""
        self.last_intrusion_at_ms = int(time.time() * 1000)

        self.log_intrusion(event, reason)

        if self.policy == "normal":
            self.normal_block_until = int(event.Time) + self.normal_lockout_ms
            self.log_event(event)
            return False

        if self.policy == "paranoid":
            if not was_intrusion:
                show_system_message(
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
                show_system_message("KeyInjection Detected", "Correct Password! Keyboard unlocked.")
                self.is_intrusion = False
                self.password_counter = 0
        else:
            self.password_counter = 0
        return False

    def on_key_down(self, event):
        window_name = event.WindowName or ""
        event_time = int(event.Time)

        self.total_events += 1

        # Temporary pause mode for short trusted workflows.
        if self.pause_until and event_time < self.pause_until:
            self.record_decision(True)
            return True

        if self.is_window_whitelisted(window_name):
            self.prev_time = event_time
            self.rapid_burst_counter = 0
            self.injected_burst_counter = 0
            self.record_decision(True)
            return True

        if self.policy == "normal" and event_time < self.normal_block_until:
            self.record_decision(False)
            return False

        if self.policy == "paranoid" and self.is_intrusion:
            result = self.handle_paranoid_unlock(event)
            self.record_decision(result)
            return result

        if self.prev_time == -1:
            self.prev_time = event_time
            self.record_decision(True)
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

        key_name = normalize_key_name(event.Key)
        if key_name:
            self.key_buffer.append(key_name)

        self.effective_threshold = self.compute_effective_threshold()
        threshold_override = self.get_window_threshold_override(window_name)
        self.active_threshold = threshold_override if threshold_override is not None else self.effective_threshold

        if (
            self.low_variance_detection and
            self.average_speed <= self.low_variance_speed_ceiling and
            self.interval_stddev <= self.low_variance_stddev
        ):
            self.low_variance_counter += 1
        else:
            self.low_variance_counter = 0

        self.debug_log(
            "event key=%r injected=%r interval=%d avg=%.2f stddev=%.3f "
            "rapid=%d injected_streak=%d low_variance=%d effective=%d active=%d",
            event.Key,
            event.Injected,
            interval,
            self.average_speed,
            self.interval_stddev,
            self.rapid_burst_counter,
            self.injected_burst_counter,
            self.low_variance_counter,
            self.effective_threshold,
            self.active_threshold,
        )

        if self.is_window_blacklisted(window_name):
            return self.trigger_intrusion(event, "blacklisted_window")

        if (
            event.Injected and
            self.allow_auto and
            (self.injected_burst_count <= 0 or self.injected_burst_counter < self.injected_burst_count)
        ):
            self.record_decision(True)
            return True

        if self.rapid_burst_count > 0 and self.rapid_burst_counter >= self.rapid_burst_count:
            return self.trigger_intrusion(event, "rapid_burst")

        if self.injected_burst_count > 0 and self.injected_burst_counter >= self.injected_burst_count:
            return self.trigger_intrusion(event, "injected_burst")

        if self.low_variance_counter >= self.low_variance_streak_count:
            return self.trigger_intrusion(event, "low_variance_burst")

        pattern_reason = self.pattern_match_reason()
        if pattern_reason:
            return self.trigger_intrusion(event, pattern_reason)

        if self.average_speed < self.active_threshold:
            return self.trigger_intrusion(event, "average_speed")

        self.is_intrusion = False
        self.remember_clean_interval(interval, event)
        self.record_decision(True)
        return True

    def start(self):
        self.running = True
        self.thread_id = windll.kernel32.GetCurrentThreadId()
        pythoncom.CoInitialize()
        self.hm.HookKeyboard()
        self.flush_status(force=True)
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
            self.flush_status(force=True)
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
        self.window.geometry("390x92+300+300")
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

        summary = "Policy: {} | Base threshold: {}ms".format(POLICY, THRESHOLD)
        policy_label = Label(self.window, text=summary)
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
        self.window.geometry("520x110+300+300")
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
        settings_menu.add_command(label="PAUSE 30s", command=self.pause_temporarily)
        settings_menu.add_command(label="RESUME", command=self.resume_now)
        settings_menu.add_command(label="FULLSCREEN", command=self.fullscreen)
        settings_menu.add_command(label="HIDE TITLE BAR", command=self.hide_title_bar)
        menubar.add_cascade(label="Settings", menu=settings_menu)

        self.window.config(menu=menubar)

    def create_widgets(self):
        btn_stop = Button(self.window, text="Stop Script", width=12, command=self.stop_script)
        btn_close = Button(self.window, text="Close Window", width=12, command=self.close_window)
        btn_startup = Button(self.window, text="Run On Startup", width=16, command=self.add_to_startup)
        btn_log = Button(self.window, text="Open Log", width=10, command=self.open_log_file)
        btn_pause = Button(self.window, text="Pause 30s", width=10, command=self.pause_temporarily)
        btn_resume = Button(self.window, text="Resume", width=8, command=self.resume_now)

        btn_stop.grid(column=0, row=0, padx=5, pady=8)
        btn_close.grid(column=1, row=0, padx=5, pady=8)
        btn_startup.grid(column=2, row=0, padx=5, pady=8)
        btn_log.grid(column=3, row=0, padx=5, pady=8)
        btn_pause.grid(column=4, row=0, padx=5, pady=8)
        btn_resume.grid(column=5, row=0, padx=5, pady=8)

        self.status_label = Label(self.window, text="Status: active")
        self.status_label.grid(column=0, row=1, columnspan=6, pady=(0, 6))

    def start_hook_async(self):
        self.hook_thread = threading.Thread(target=self.hook.start, name="duckhunt-hook")
        self.hook_thread.daemon = False
        self.hook_thread.start()

    def pause_temporarily(self):
        self.hook.pause_protection(self.hook.pause_duration_ms)
        self.update_status_label()

    def resume_now(self):
        self.hook.resume_protection()
        self.update_status_label()

    def update_status_label(self):
        status = self.hook.get_status_snapshot()
        mode = "paused" if status["pause_remaining_ms"] > 0 else "active"
        text = (
            "Status: {} | Intrusions: {} | Blocked: {} | Avg: {}ms | StdDev: {} | Threshold: {}ms"
            .format(
                mode,
                status["intrusion_count"],
                status["blocked_events"],
                status["average_speed_ms"],
                status["interval_stddev_ms"],
                status["active_threshold_ms"],
            )
        )
        if status["pause_remaining_ms"] > 0:
            text += " | Pause left: {}ms".format(status["pause_remaining_ms"])
        if status["warmup_remaining_events"] > 0:
            text += " | Warmup left: {} ev".format(status["warmup_remaining_events"])
        if status["last_intrusion_reason"]:
            text += " | Last: {}".format(status["last_intrusion_reason"])
        self.status_label.config(text=text)

    def poll_status(self):
        self.update_status_label()
        self.window.after(700, self.poll_status)

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
        self.poll_status()
        self.window.mainloop()


def main():
    gui = DuckHunterGUI()
    gui.run()


if __name__ == '__main__':
    main()
