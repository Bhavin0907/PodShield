"""Structured (JSON-lines) logging for journald."""

from __future__ import annotations

import json
import logging
import sys
from datetime import UTC, datetime
from typing import IO

_STANDARD_ATTRS = set(logging.LogRecord("", 0, "", 0, "", (), None).__dict__) | {
    "message",
    "asctime",
}


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, object] = {
            "ts": datetime.fromtimestamp(record.created, tz=UTC).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        for key, value in record.__dict__.items():
            if key not in _STANDARD_ATTRS and not key.startswith("_"):
                payload[key] = value
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


def configure_logging(level: str = "INFO", stream: IO[str] | None = None) -> None:
    """Install a single JSON handler on the root logger (idempotent)."""
    handler = logging.StreamHandler(stream or sys.stderr)
    handler.setFormatter(JsonFormatter())
    handler.set_name("podshield-json")
    root = logging.getLogger()
    root.handlers = [h for h in root.handlers if h.get_name() != "podshield-json"]
    root.addHandler(handler)
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
