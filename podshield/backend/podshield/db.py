"""SQLite engine and session helpers."""

from __future__ import annotations

import logging
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from sqlalchemy import Engine, event, text
from sqlalchemy.exc import DatabaseError as SaDatabaseError
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

log = logging.getLogger(__name__)


class DatabaseProblem(RuntimeError):
    """The database cannot be used; the message says why and how to recover.

    Safe to show to users: it never contains SQL or parameters.
    """


def _db_path(engine: Engine) -> str:
    return engine.url.database or ":memory:"


def explain_db_error(exc: BaseException, path: str = "the PodShield database") -> str | None:
    """Turn a low-level SQLite failure into an actionable message, or None if unrelated."""
    orig = exc.orig if isinstance(exc, SaDatabaseError) else None
    cause: BaseException = orig if orig is not None else exc
    if isinstance(cause, DatabaseProblem):
        return str(cause)
    if not isinstance(cause, sqlite3.Error):
        return None
    msg = str(cause).lower()
    if "disk is full" in msg or "database or disk is full" in msg:
        return (
            f"The disk holding {path} is full, so PodShield cannot save results. "
            "Free space on that volume (for example `journalctl --vacuum-size=200M`, "
            "or remove unused images with `podman image prune`), then run the scan again."
        )
    if "readonly" in msg or "read-only" in msg or "unable to open" in msg or "permission" in msg:
        return (
            f"PodShield cannot write to {path}. Check that the service user owns the file and its "
            "directory, and that the SELinux label is right: `restorecon -Rv /var/lib/podshield`. "
            "Do not disable SELinux."
        )
    if "locked" in msg or "busy" in msg:
        return (
            f"{path} is locked by another process. This is usually temporary (another scan or "
            "the watcher is writing); try again in a moment."
        )
    if "not a database" in msg or "malformed" in msg or "corrupt" in msg or "integrity" in msg:
        return (
            f"The PodShield database {path} is corrupted ({cause}). Recovery: "
            "1) stop the service (`systemctl stop podshield`); "
            f"2) keep a copy (`cp {path} {path}.corrupt`); "
            f"3) try `sqlite3 {path} .recover | sqlite3 {path}.recovered` and swap the recovered "
            "file in, or move the damaged file away to start fresh; "
            "4) start the service again. Starting fresh loses scan history and saved rule "
            "overrides, but the next scan rebuilds the image results."
        )
    return f"Database error: {cause.__class__.__name__}. See the service log for details."


def make_engine(db_path: str) -> Engine:
    """Create an engine; ``db_path`` may be a file path or ``:memory:``."""
    if db_path != ":memory:":
        Path(db_path).expanduser().parent.mkdir(parents=True, exist_ok=True)
    engine = create_engine(
        f"sqlite:///{db_path}",
        # The API, the watcher, the timer and the CLI write to the same file from different
        # processes; wait for a lock instead of failing with "database is locked".
        connect_args={"check_same_thread": False, "timeout": 30},
        poolclass=StaticPool if db_path == ":memory:" else None,
    )

    @event.listens_for(engine, "connect")
    def _pragmas(dbapi_conn: sqlite3.Connection, _record: object) -> None:
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA foreign_keys=ON")
        cur.execute("PRAGMA journal_mode=WAL")
        cur.close()

    return engine


def init_db(engine: Engine) -> None:
    """Create tables, first checking that an existing file is a healthy SQLite database.

    Raises ``DatabaseProblem`` (with recovery steps) instead of a raw SQLAlchemy traceback.
    """
    path = _db_path(engine)
    try:
        if path != ":memory:" and Path(path).is_file() and Path(path).stat().st_size > 0:
            with engine.connect() as conn:
                rows = conn.execute(text("PRAGMA quick_check")).fetchall()
            if [r[0] for r in rows] != ["ok"]:
                detail = "; ".join(str(r[0]) for r in rows[:3])
                raise DatabaseProblem(
                    explain_db_error(sqlite3.DatabaseError(f"database is corrupt: {detail}"), path)
                    or detail
                )
        SQLModel.metadata.create_all(engine)
    except DatabaseProblem:
        raise
    except (SaDatabaseError, sqlite3.DatabaseError) as exc:
        raise DatabaseProblem(explain_db_error(exc, path) or str(exc)) from exc


@contextmanager
def session_scope(engine: Engine) -> Iterator[Session]:
    with Session(engine) as session:
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
