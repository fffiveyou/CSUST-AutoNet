"""Daily UTF-8 logs with five-calendar-day retention and redaction."""

from __future__ import annotations

import logging
import re
from datetime import date, datetime, timedelta
from pathlib import Path

from app.constants import LOG_RETENTION_DAYS, log_dir


_LOG_NAME = re.compile(r"^(\d{4}-\d{2}-\d{2})\.log$")
_SENSITIVE = re.compile(
    r"(?i)\b(password|passwd|authorization|cookie|session[_ -]?token|auth[_ -]?token|token)"
    r"\s*[:=]\s*([^\s,;]+)"
)


def today_log_path(directory: Path | None = None, *, today: date | None = None) -> Path:
    current = today or date.today()
    return (directory or log_dir()) / f"{current.isoformat()}.log"


def delete_logs_older_than(
    directory: Path,
    days: int = LOG_RETENTION_DAYS,
    *,
    today: date | None = None,
) -> list[Path]:
    """Keep exactly `days` calendar log dates, including today."""

    if days < 1:
        raise ValueError("days must be at least 1")
    if not directory.exists():
        return []

    cutoff = (today or date.today()) - timedelta(days=days - 1)
    deleted: list[Path] = []
    for candidate in directory.iterdir():
        match = _LOG_NAME.match(candidate.name)
        if not candidate.is_file() or not match:
            continue
        try:
            log_date = date.fromisoformat(match.group(1))
        except ValueError:
            continue
        if log_date < cutoff:
            candidate.unlink()
            deleted.append(candidate)
    return deleted


class SensitiveDataFilter(logging.Filter):
    """Redact common credential fields if a caller accidentally logs them."""

    def filter(self, record: logging.LogRecord) -> bool:
        rendered = record.getMessage()
        record.msg = _SENSITIVE.sub(lambda match: f"{match.group(1)}=[REDACTED]", rendered)
        record.args = ()
        return True


class DailyFileHandler(logging.Handler):
    """Write directly to YYYY-MM-DD.log and switch files after midnight."""

    def __init__(self, directory: Path, retention_days: int = LOG_RETENTION_DAYS) -> None:
        super().__init__()
        self.directory = directory
        self.retention_days = retention_days
        self._active_date: date | None = None
        self._stream = None
        self.directory.mkdir(parents=True, exist_ok=True)
        delete_logs_older_than(self.directory, self.retention_days)

    def _ensure_stream(self, current: date) -> None:
        if self._active_date == current and self._stream is not None:
            return
        if self._stream is not None:
            self._stream.close()
        self._active_date = current
        self._stream = today_log_path(self.directory, today=current).open(
            "a", encoding="utf-8", newline=""
        )
        delete_logs_older_than(self.directory, self.retention_days, today=current)

    def emit(self, record: logging.LogRecord) -> None:
        try:
            current = datetime.fromtimestamp(record.created).date()
            self._ensure_stream(current)
            assert self._stream is not None
            self._stream.write(self.format(record) + "\n")
            self._stream.flush()
        except Exception:
            self.handleError(record)

    def close(self) -> None:
        if self._stream is not None:
            self._stream.close()
            self._stream = None
        super().close()


def setup_logging(directory: Path | None = None, *, logger_name: str = "csust_autonet") -> logging.Logger:
    target = directory or log_dir()
    logger = logging.getLogger(logger_name)
    logger.setLevel(logging.INFO)
    logger.propagate = False

    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        handler.close()

    handler = DailyFileHandler(target)
    handler.addFilter(SensitiveDataFilter())
    handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", "%Y-%m-%d %H:%M:%S"))
    logger.addHandler(handler)
    return logger
