"""
utils/logger.py — Structured logging for the Hybrid NIDS.

Why this exists:
  Consistent log formatting across all modules makes debugging easier
  and gives a chronological audit trail of detections.

How it connects to the NIDS architecture:
  Every module (rule engine, ML detector, API routes) calls get_logger()
  to obtain a named logger.  All loggers inherit from the root 'nids'
  logger, so a single handler captures everything.
"""

import logging
import sys
import os

_INITIALIZED = False


class SafeStreamHandler(logging.StreamHandler):
    """Stream handler that safely ignores writes to closed streams during test teardown."""
    def emit(self, record):
        try:
            if self.stream is None or getattr(self.stream, "closed", False):
                return
            super().emit(record)
        except (ValueError, IOError, OSError):
            pass

    def handleError(self, record):
        _, exc_value, _ = sys.exc_info()
        if isinstance(exc_value, (ValueError, IOError, OSError)):
            return
        super().handleError(record)


def setup_logging(level: str = "INFO") -> None:
    """Configure the root NIDS logger once at application start-up."""
    global _INITIALIZED
    if _INITIALIZED:
        return

    numeric_level = getattr(logging, level.upper(), logging.INFO)
    formatter = logging.Formatter(
        fmt="%(asctime)s [%(levelname)-8s] %(name)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Console handler with closed-stream safety
    console_handler = SafeStreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)

    root_logger = logging.getLogger("nids")
    root_logger.setLevel(numeric_level)
    if not root_logger.handlers:
        root_logger.addHandler(console_handler)

    _INITIALIZED = True


def get_logger(name: str) -> logging.Logger:
    """Return a named child logger under the 'nids' namespace."""
    setup_logging()
    return logging.getLogger(f"nids.{name}")
