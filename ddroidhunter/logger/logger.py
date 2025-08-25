import json
import logging
import os
import traceback

from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from typing import Any, Dict, Iterable, Optional

_STD_ATTRS = {
    "name", "msg", "args", "levelname", "levelno", "pathname", "filename",
    "module", "exc_info", "exc_text", "stack_info", "lineno", "funcName",
    "created", "msecs", "relativeCreated", "thread", "threatName",
    "processname", "process"
}

class JSONFormatter(logging.Formatter):
    """
    Structured JSON logs with ISO-8601 timestamps and optional ECS-ish keys.

    - Includes "@timestamp", "log.level", "message", "logger", "process", "thread"
    - Merges `extra={...}` fields at top-level (without clobbering standard keys)
    - Serializes non-JSON types with `default=str`
    - Captures exception/stack automatically on .exception() / exc_info=True
    """
    def __init__(
            self,
            *,
            ecs_like: bool = True,
            redacted_keys: Optional[Iterable[str]] = None,
            static_fields: Optional[Dict[str, Any]] = None
    ):
        super().__init__()
        self.ecs_like = ecs_like
        self.redacted_keys = set(redacted_keys or [])
        self.static_fields = static_fields or {}


    def format(self, record: logging.LogRecord) -> str:
        ts = datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat()

        base = {
            ("@timestamp" if self.ecs_like else "timestamp"): ts,
            ("log.level" if self.ecs_like else "level"): record.levelname,
            "message": record.getMessage(),
            ("logger" if self.ecs_like else "name"): record.name,
            "module": record.module,
            "filename": record.filename,
            "func": record.funcName,
            "line": record.lineno,
            "process": record.process,
            "thread": record.thread
        }

        if record.exc_info:
            base["error"] = {
                "type": str(record.exc_info[0].__name__ if record.exc_info[0] else None),
                "message": str(record.exc_info[1]),
                "stack": "".join(traceback.format_exception(*record.exc_info))
            }
        if record.stack_info:
            base["stack"] = record.stack_info

        # Merger user extras (anything not in standard attrs)
        for k, v in record.__dict__.items():
            if k not in _STD_ATTRS and k not in base:
                base[k] = v

        # Add static fields (e.g. app/env/version)
        for k, v in self.static_fields.items():
            base.setdefault(k, v)

        for k in self.redacted_keys:
            if k in base:
                base[k] = "***REDACTED***"

        return json.dumps(base, ensure_ascii=False, default=str, indent=4)


class JsonArrayRotatingFileHandler(RotatingFileHandler):
    """
    Writes a *valid JSON array* file that remains valid after each emit.
    Implementation:
      - Initializes file as "[\\n]\\n"
      - On each emit, seeks to the final ']' and inserts ",\\n<obj>\\n]\\n" (or "<obj>\\n]\\n" if first)
    Notes:
      - Thread-safe (uses handler lock). For multi-*process*, use a single writer.
    """
    def __init__(self, filename, maxBytes=0, backupCount=0, encoding="utf-8", delay=False, fsync=False):
        super().__init__(filename, mode="r+", maxBytes=maxBytes, backupCount=backupCount,
                         encoding=encoding, delay=delay)
        self.fsync = fsync
        self._ensure_initialized_array()


    def _open(self):
        d = os.path.dirname(self.baseFilename)
        if d:
            os.makedirs(d, exist_ok=True)
        if not os.path.exists(self.baseFilename):
            with open(self.baseFilename, "w", encoding=self.encoding or "utf-8") as f:
                f.write("[]\n")
        return open(self.baseFilename, "r+", encoding=self.encoding or "utf-8")


    def _ensure_initialized_array(self):
        if self.stream is None:
            self.stream = self._open()
        self.stream.seek(0, os.SEEK_END)
        if self.stream.tell() == 0:
            self.stream.write("[\n]\n")
            self.stream.flush()

    def _has_items(self):
        """
        Check whether array already has at least one object.
        Looks for the last non-space before the final ']' and sees if it's '[' or not.
        """
        self.stream.seek(0, os.SEEK_END)
        end = self.stream.tell()

        if end == 0:
            return False
        # Find the position of the last non-space char (should be ']')
        pos = end - 1
        while pos >= 0:
            self.stream.seek(pos)
            ch = self.stream.read(1)
            if ch not in (" ", "\t", "\r", "\n"):
                break
            pos -= 1

        if pos < 0 or ch != "]":
            # Corrupt footer; treat as empty to avoid crash
            return False
        # Look before the ']' for the last non-space
        pos -= 1
        while pos >= 0:
            self.stream.seek(pos)
            ch2 = self.stream.read(1)
            if ch2 not in (" ", "\t", "\r", "\n"):
                break
            pos -= 1
        return ch2 != "[" # '[' means empty array: "[\n]\n"


    def emit(self, record: logging.LogRecord) -> None:
        try:
            if self.shouldRollover(record):
                self.doRollover()
                # After rotation, re-seed new file
                if self.stream is None:
                    self.stream = self._open()
                self.stream.seek(0)
                self.stream.truncate()
                self.stream.write("[\n]\n")
                self.stream.flush()

            obj = self.format(record) # JSON string of the log object

            with self.lock:
                if self.stream is None:
                    self.stream = self._open()

                # Seek to the last ']' and overwrite it
                self.stream.seek(0, os.SEEK_END)
                end = self.stream.tell()
                # Find final ']' (skip whitespace at file end)
                pos = end - 1
                while pos >= 0:
                    self.stream.seek(pos)
                    ch = self.stream.read(1)
                    if ch not in (" ", "\t", "\r", "\n"):
                        break
                    pos -= 1
                end_bracket_pos = pos # should be ']'

                # Decide whether to prepend a comma (if array already has items)
                first = not self._has_items()
                insert = ("" if first else ",\n") + obj + "]\n"

                # Overwritten from the ']' with our insert (object + close bracket)
                self.stream.seek(end_bracket_pos)
                self.stream.write(insert)
                self.stream.flush()
                if self.fsync:
                    os.fsync(self.stream.fileno())
        except Exception:
            self.handleError(record)


class Logger:
    """
    Turn-key JSON logger.

    Example:
        log = Logger(__name__, "logs/app.jsonl", level=logging.DEBUG,
                     ecs_like=True,
                     static_fields={"service.name": "d-droidhunter", "env": "prod"},
                     redacted_keys={"api_key"}).get()
        log.info("scan started", extra={"task_id": "abc123", "api_key": "XYZ"})
    """
    def __init__(
            self,
            name: str,
            log_file: Optional[str] = "log/app_log.json",
            level: int = logging.INFO,
            *,
            ecs_like: bool = True,
            redacted_keys: Optional[Iterable[str]] = None,
            static_fields: Optional[Dict[str, Any]] = None,
            max_bytes: int = 10 * 1024 * 1024,
            backup_count: int = 5,
            console: bool = True,
            fsync: bool = False
    ):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(level)

        if self.logger.handlers:
            return

        fmt = JSONFormatter(
            ecs_like=ecs_like,
            redacted_keys=redacted_keys,
            static_fields=static_fields
        )

        if console:
            ch = logging.StreamHandler()
            ch.setFormatter(fmt)
            self.logger.addHandler(ch)

        # if log_file:
        #     d = os.path.dirname(log_file)
        #     if d:
        #         os.makedirs(d, exist_ok=True)
        #     fh = RotatingFileHandler(log_file, maxBytes=max_bytes, backupCount=backup_count)
        #     fh.setFormatter(fmt)
        #     self.logger.addHandler(fh)
        fh = JsonArrayRotatingFileHandler(
            log_file,
            maxBytes=max_bytes,
            backupCount=backup_count,
            fsync=fsync
        )
        fh.setFormatter(fmt)
        self.logger.addHandler(fh)
        self.logger.propagate = False

    def get(self) -> logging.Logger:
        return self.logger
