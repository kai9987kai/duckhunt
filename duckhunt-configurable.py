#!/usr/bin/env python
"""
######################################################
#                   DuckHunter                       #
#                 Pedro M. Sosa                      #
# Tool to prevent getting attacked by a rubberducky! #
######################################################
"""

import importlib.util
import json
import logging
import statistics
import sys
import time
from collections import deque
from logging.handlers import RotatingFileHandler

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
ALLOW_AUTO_TYPE = as_bool(getattr(config, "allow_auto_type_software", True), default=True)
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

# Optional runtime status export
STATUS_FILENAME = str(getattr(config, "status_filename", ""))
STATUS_FLUSH_INTERVAL = as_int(getattr(config, "status_flush_interval", 250), 250, minimum=1)
LOG_MAX_BYTES = as_int(getattr(config, "log_max_bytes", 1048576), 1048576, minimum=0)
LOG_BACKUP_COUNT = as_int(getattr(config, "log_backup_count", 5), 5, minimum=1)

configure_logging(LOG_FILENAME, LOG_LEVEL, LOG_MAX_BYTES, LOG_BACKUP_COUNT)


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
        self.events_since_flush = 0

        self.debug = DEBUG

        self.history = [self.threshold + 1] * self.history_size
        self.history_index = 0
        self.history_total = float(sum(self.history))
        self.history_square_total = float(sum(value * value for value in self.history))
        self.average_speed = self.history_total / self.history_size
        self.interval_stddev = 0.0

        self.previous_time = -1
        self.is_intrusion = False
        self.password_counter = 0
        self.last_window = ""
        self.randdrop_counter = 0
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
        self.average_speed = self.history_total / float(self.history_size)
        mean = self.average_speed
        self.history_square_total += (interval * interval) - (old_value * old_value)
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
            "effective_threshold_ms=%d rapid_streak=%d injected_streak=%d window=%r key=%r injected=%r",
            reason,
            self.policy,
            self.average_speed,
            self.threshold,
            self.effective_threshold,
            self.rapid_burst_counter,
            self.injected_burst_counter,
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
        return {
            "policy": self.policy,
            "threshold_ms": self.threshold,
            "effective_threshold_ms": self.effective_threshold,
            "average_speed_ms": round(self.average_speed, 2),
            "total_events": self.total_events,
            "allowed_events": self.allowed_events,
            "blocked_events": self.blocked_events,
            "intrusion_count": self.intrusion_count,
            "last_intrusion_reason": self.last_intrusion_reason,
            "last_intrusion_window": self.last_intrusion_window,
            "last_intrusion_key": self.last_intrusion_key,
            "adaptive_threshold_enabled": self.adaptive_threshold_enabled,
            "adaptive_samples": len(self.baseline_intervals),
        }

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

        self.total_events += 1

        if self.is_window_whitelisted(window_name):
            self.previous_time = event_time
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

        if self.previous_time == -1:
            self.previous_time = event_time
            self.record_decision(True)
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

        key_name = normalize_key_name(event.Key)
        if key_name:
            self.key_buffer.append(key_name)

        self.effective_threshold = self.compute_effective_threshold()

        self.debug_log(
            "event key=%r injected=%r interval=%d avg=%.2f rapid=%d injected_streak=%d effective=%d",
            event.Key,
            event.Injected,
            interval,
            self.average_speed,
            self.rapid_burst_counter,
            self.injected_burst_counter,
            self.effective_threshold,
        )

        if self.is_window_blacklisted(window_name):
            result = self.handle_intrusion(event, "blacklisted_window")
            self.record_decision(result, force_status=True)
            return result

        if (
            event.Injected and
            self.allow_auto and
            (self.injected_burst_count <= 0 or self.injected_burst_counter < self.injected_burst_count)
        ):
            self.record_decision(True)
            return True

        if self.rapid_burst_count > 0 and self.rapid_burst_counter >= self.rapid_burst_count:
            result = self.handle_intrusion(event, "rapid_burst")
            self.record_decision(result, force_status=True)
            return result

        if self.injected_burst_count > 0 and self.injected_burst_counter >= self.injected_burst_count:
            result = self.handle_intrusion(event, "injected_burst")
            self.record_decision(result, force_status=True)
            return result

        pattern_reason = self.pattern_match_reason()
        if pattern_reason:
            result = self.handle_intrusion(event, pattern_reason)
            self.record_decision(result, force_status=True)
            return result

        if self.average_speed < self.effective_threshold:
            result = self.handle_intrusion(event, "average_speed")
            self.record_decision(result, force_status=True)
            return result

        self.is_intrusion = False
        self.remember_clean_interval(interval, event)
        self.record_decision(True)
        return True

    def run(self):
        self.hook_manager.HookKeyboard()
        self.flush_status(force=True)
        try:
            pythoncom.PumpMessages()
        except Exception as exc:
            logging.exception("An error occurred in the message pump: %s", exc)
            sys.exit(1)
        finally:
            self.flush_status(force=True)


if __name__ == '__main__':
    duckhunter = DuckHunter()
    try:
        duckhunter.run()
    except KeyboardInterrupt:
        print("DuckHunter terminated by user.")
    except Exception as ex:
        logging.exception("DuckHunter encountered an error: %s", ex)
