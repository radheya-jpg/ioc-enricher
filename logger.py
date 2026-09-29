"""
Central logging setup for IOC Enricher.

Two handlers:
- Console: human-readable, respects --verbose flag
- File (optional): structured JSON lines, one log event per line,
  suitable for feeding into Splunk/Wazuh or any log shipper later.

Usage:
    from logger import get_logger
    log = get_logger(__name__)
    log.info("checked source", extra={"source": "VirusTotal", "ioc": "8.8.8.8"})
"""

import json
import logging
import sys
from pathlib import Path

import config


class JsonFormatter(logging.Formatter):
    """Formats log records as single-line JSON for machine consumption."""

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        # pull in any structured fields passed via extra={}
        for key, value in record.__dict__.items():
            if key in ("args", "msg", "levelname", "levelno", "pathname", "filename",
                        "module", "exc_info", "exc_text", "stack_info", "lineno",
                        "funcName", "created", "msecs", "relativeCreated", "thread",
                        "threadName", "processName", "process", "name", "message",
                        "taskName"):
                continue
            payload[key] = value
        return json.dumps(payload)


_configured = False


def configure(verbose: bool = False, log_file: str = None):
    """Call once at program startup to set up handlers. Safe to call multiple
    times — later calls with different args will reconfigure from scratch."""
    global _configured

    root = logging.getLogger("ioc_enricher")
    root.setLevel(logging.DEBUG if verbose else logging.INFO)
    root.handlers.clear()  # avoid duplicate handlers if called more than once

    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setLevel(logging.DEBUG if verbose else logging.WARNING)
    console_handler.setFormatter(logging.Formatter(
        "%(levelname)s %(name)s: %(message)s"
    ))
    root.addHandler(console_handler)

    log_path = log_file or getattr(config, "LOG_FILE", None)
    if log_path:
        Path(log_path).parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_path)
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(JsonFormatter())
        root.addHandler(file_handler)

    _configured = True


def get_logger(name: str) -> logging.Logger:
    """Returns a namespaced logger. Does NOT auto-configure handlers —
    only the CLI entry point's explicit configure() call should do that,
    otherwise it locks in default settings before CLI flags are parsed.
    If configure() is never called, Python's logging module just uses
    its own lastResort handler (prints warnings+ to stderr) — safe default."""
    return logging.getLogger(f"ioc_enricher.{name}")
