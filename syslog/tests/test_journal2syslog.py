"""Unit tests for journal2syslog.py.

These tests run on macOS / CI without systemd. The systemd module is mocked
before journal2syslog is imported, and required env vars are injected via
importlib so the module-level initialization succeeds.
"""
from __future__ import annotations

import importlib
import logging
import os
import sys
from datetime import datetime, timezone
from types import ModuleType
from unittest.mock import MagicMock

import pytest

# ---------------------------------------------------------------------------
# Bootstrap: mock systemd before importing the module under test
# ---------------------------------------------------------------------------

_mock_systemd = MagicMock()
sys.modules.setdefault("systemd", _mock_systemd)
sys.modules.setdefault("systemd.journal", _mock_systemd.journal)

_ENV_DEFAULTS = {
    "SYSLOG_HOST": "localhost",
    "SYSLOG_PORT": "514",
    "SYSLOG_PROTO": "udp",
    "SYSLOG_SSL": "false",
    "SYSLOG_SSL_VERIFY": "false",
    "HAOS_HOSTNAME": "test-host",
    "SYSLOG_FORMAT": "rfc5424",
}

for _k, _v in _ENV_DEFAULTS.items():
    os.environ.setdefault(_k, _v)

# Add the syslog directory to sys.path so we can import journal2syslog
_syslog_dir = os.path.dirname(os.path.dirname(__file__))
if _syslog_dir not in sys.path:
    sys.path.insert(0, _syslog_dir)

import journal2syslog as j2s  # noqa: E402

# ---------------------------------------------------------------------------
# Fixtures — real HAOS journal entries (ANSI codes intact where applicable)
# ---------------------------------------------------------------------------

# homeassistant container: PRIORITY=3 in journal, but text carries ERROR
HA_ERROR_RAW = (
    "\x1b[31m2026-03-04 21:23:37.121 ERROR (MainThread) "
    "[homeassistant.components.mqtt] MQTT disconnected\x1b[0m"
)

# hassio_supervisor: PRIORITY=3 in journal, but text carries INFO
SUPERVISOR_INFO_RAW = (
    "\x1b[32m2026-03-04 21:32:42.480 INFO (MainThread) "
    "[supervisor.core] Supervisor started\x1b[0m"
)

# hassio_dns container: no level pattern, PRIORITY=6
HASSIO_DNS_MSG = '[INFO] 127.0.0.1:42164 - 42572 "PTR IN local. 60 udp"'

# Traceback continuation line (no level marker, should inherit last known)
HA_TRACEBACK_LINE = "  File /usr/lib/python3.11/traceback.py, line 100, in format_exception"

# System unit (no CONTAINER_NAME): PRIORITY=6
KERNEL_MSG = "hassio: port 6(veth3b2a5f4) entered blocking state"

# System unit with no PRIORITY field at all (e.g. audit)
AUDIT_MSG = "BPF prog-id=944 op=UNLOAD"

# ---------------------------------------------------------------------------
# ANSI stripping
# ---------------------------------------------------------------------------


def test_ansi_stripping_removes_codes():
    stripped = j2s.ANSI_COLOR_PATTERN.sub("", HA_ERROR_RAW)
    assert "\x1b" not in stripped
    assert "ERROR" in stripped


def test_ansi_stripping_preserves_content():
    stripped = j2s.ANSI_COLOR_PATTERN.sub("", SUPERVISOR_INFO_RAW)
    assert "Supervisor started" in stripped


def test_ansi_stripping_plain_message_unchanged():
    msg = "no ansi here"
    assert j2s.ANSI_COLOR_PATTERN.sub("", msg) == msg


# ---------------------------------------------------------------------------
# parse_log_level: level extraction from container message text
# ---------------------------------------------------------------------------


def test_parse_log_level_homeassistant_error():
    stripped = j2s.ANSI_COLOR_PATTERN.sub("", HA_ERROR_RAW)
    assert j2s.parse_log_level(stripped, "homeassistant") == logging.ERROR


def test_parse_log_level_supervisor_info_despite_priority_3():
    """hassio_supervisor journal PRIORITY=3 (err) but message text says INFO."""
    stripped = j2s.ANSI_COLOR_PATTERN.sub("", SUPERVISOR_INFO_RAW)
    assert j2s.parse_log_level(stripped, "hassio_supervisor") == logging.INFO


def test_parse_log_level_unknown_container_returns_notset():
    """Containers not in CONTAINER_PATTERN_MAPPING return NOTSET."""
    assert j2s.parse_log_level(HASSIO_DNS_MSG, "hassio_dns") == logging.NOTSET


def test_parse_log_level_no_match_returns_notset():
    """homeassistant message without level marker (traceback) returns NOTSET."""
    assert j2s.parse_log_level(HA_TRACEBACK_LINE, "homeassistant") == logging.NOTSET


# ---------------------------------------------------------------------------
# _determine_log_level: full decision logic
# ---------------------------------------------------------------------------


def test_determine_level_homeassistant_error():
    stripped = j2s.ANSI_COLOR_PATTERN.sub("", HA_ERROR_RAW)
    entry = {"PRIORITY": 3, "CONTAINER_NAME": "homeassistant"}
    last: dict[str, int] = {}
    level = j2s._determine_log_level(entry, "homeassistant", stripped, last)
    assert level == logging.ERROR
    assert last["homeassistant"] == logging.ERROR


def test_determine_level_supervisor_text_overrides_journal_priority():
    stripped = j2s.ANSI_COLOR_PATTERN.sub("", SUPERVISOR_INFO_RAW)
    entry = {"PRIORITY": 3, "CONTAINER_NAME": "hassio_supervisor"}
    last: dict[str, int] = {}
    level = j2s._determine_log_level(entry, "hassio_supervisor", stripped, last)
    assert level == logging.INFO


def test_determine_level_non_pattern_container_defaults_info():
    """hassio_dns is not in CONTAINER_PATTERN_MAPPING → always INFO."""
    entry = {"PRIORITY": 6, "CONTAINER_NAME": "hassio_dns"}
    last: dict[str, int] = {}
    level = j2s._determine_log_level(entry, "hassio_dns", HASSIO_DNS_MSG, last)
    assert level == logging.INFO


def test_determine_level_system_unit_uses_priority_field():
    """Non-container (kernel) uses journal PRIORITY directly."""
    entry = {"PRIORITY": 6}
    last: dict[str, int] = {}
    level = j2s._determine_log_level(entry, None, KERNEL_MSG, last)
    assert level == logging.INFO


def test_determine_level_no_priority_defaults_info():
    """Missing PRIORITY field (e.g. audit) falls back to index 6 → INFO."""
    entry: dict = {}  # no PRIORITY key
    last: dict[str, int] = {}
    level = j2s._determine_log_level(entry, None, AUDIT_MSG, last)
    assert level == logging.INFO


def test_determine_level_continuation_inherits_last_known():
    """Traceback/continuation line has no level marker → uses last known level."""
    last = {"homeassistant": logging.ERROR}
    entry = {"PRIORITY": 6, "CONTAINER_NAME": "homeassistant"}
    level = j2s._determine_log_level(entry, "homeassistant", HA_TRACEBACK_LINE, last)
    assert level == logging.ERROR


def test_determine_level_continuation_no_prior_defaults_info():
    """Continuation line with no prior level → INFO default."""
    last: dict[str, int] = {}
    entry = {"PRIORITY": 6, "CONTAINER_NAME": "homeassistant"}
    level = j2s._determine_log_level(entry, "homeassistant", HA_TRACEBACK_LINE, last)
    assert level == logging.INFO


def test_determine_level_system_priority_error():
    """PRIORITY=3 for a system unit (containerd, no CONTAINER_NAME) → ERROR."""
    entry = {"PRIORITY": 3}
    last: dict[str, int] = {}
    level = j2s._determine_log_level(entry, None, "containerd shim disconnected", last)
    assert level == logging.ERROR


# ---------------------------------------------------------------------------
# _format_rfc5424: output format correctness
# ---------------------------------------------------------------------------


def test_format_rfc5424_structure():
    ts = datetime(2026, 3, 4, 21, 23, 37, 121000, tzinfo=timezone.utc)
    result = j2s._format_rfc5424(11, ts, "homeassistant", "homeassistant", "test msg")
    # <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID SD MSG
    assert result.startswith("<11>1 ")
    assert "homeassistant homeassistant - - - test msg" in result


def test_format_rfc5424_iso8601_timestamp():
    ts = datetime(2026, 3, 4, 21, 23, 37, 121000, tzinfo=timezone.utc)
    result = j2s._format_rfc5424(14, ts, "host", "app", "msg")
    assert "2026-03-04T21:23:37.121000+00:00" in result


def test_format_rfc5424_colon_in_utc_offset():
    """RFC 5424 requires +HH:MM, not +HHMM."""
    ts = datetime(2026, 3, 4, 21, 23, 37, 0, tzinfo=timezone.utc)
    result = j2s._format_rfc5424(14, ts, "host", "app", "msg")
    # Timezone offset must have colon
    assert "+00:00" in result


def test_format_rfc5424_naive_datetime_treated_as_utc():
    ts = datetime(2026, 3, 4, 21, 23, 37)  # no tzinfo
    result = j2s._format_rfc5424(14, ts, "host", "app", "msg")
    assert "+00:00" in result


# ---------------------------------------------------------------------------
# _format_rfc3164: BSD syslog format
# ---------------------------------------------------------------------------


def test_format_rfc3164_structure():
    ts = datetime(2026, 3, 4, 21, 23, 37)
    result = j2s._format_rfc3164(14, ts, "host", "app", "msg")
    assert result.startswith("<14>")
    assert "host app: msg" in result
