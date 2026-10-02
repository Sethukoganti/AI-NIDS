"""Database engine / session management (SQLAlchemy 2.x)."""

from __future__ import annotations

import logging
from contextlib import contextmanager
from typing import Iterator

from sqlalchemy import create_engine, event, inspect, literal, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker
from sqlalchemy.schema import CreateColumn

from app.core.config import settings

logger = logging.getLogger("ainids.db")


class Base(DeclarativeBase):
    """Declarative base for every ORM model."""


def _build_engine() -> Engine:
    if settings.is_sqlite:
        # SQLite in the same process as the API: allow cross-thread use for the
        # background analysis workers and enable foreign keys + WAL.
        engine = create_engine(
            settings.DATABASE_URL,
            echo=settings.DB_ECHO,
            future=True,
            connect_args={"check_same_thread": False, "timeout": 30},
        )

        @event.listens_for(engine, "connect")
        def _sqlite_pragmas(dbapi_connection, _record):  # pragma: no cover - driver hook
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA synchronous=NORMAL")
            cursor.close()

        return engine

    return create_engine(
        settings.DATABASE_URL,
        echo=settings.DB_ECHO,
        future=True,
        pool_pre_ping=True,
        pool_size=settings.DB_POOL_SIZE,
        max_overflow=settings.DB_MAX_OVERFLOW,
    )


engine: Engine = _build_engine()
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False, future=True)


def get_db() -> Iterator[Session]:
    """FastAPI dependency yielding a request-scoped session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@contextmanager
def session_scope() -> Iterator[Session]:
    """Context manager for background workers / scripts."""
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def init_db() -> None:
    """Create tables if they do not exist (see docs/RUNBOOK.md for migrations)."""
    from app.models import database_models  # noqa: F401  (register metadata)

    Base.metadata.create_all(bind=engine)
    _add_missing_columns(engine)


def _add_missing_columns(bind: Engine) -> None:
    """Apply additive model-column changes to databases created by older releases."""
    with bind.begin() as connection:
        inspector = inspect(connection)
        existing_tables = set(inspector.get_table_names())
        preparer = connection.dialect.identifier_preparer

        for table in Base.metadata.sorted_tables:
            if table.name not in existing_tables:
                continue

            existing_columns = {column["name"] for column in inspector.get_columns(table.name)}
            for column in table.columns:
                if column.name in existing_columns:
                    continue

                definition = str(CreateColumn(column).compile(dialect=connection.dialect))
                if not column.nullable and column.default is not None:
                    default = column.default.arg
                    if not callable(default):
                        value = str(
                            literal(default).compile(
                                dialect=connection.dialect,
                                compile_kwargs={"literal_binds": True},
                            )
                        )
                        definition += f" DEFAULT {value}"

                for foreign_key in column.foreign_keys:
                    target = foreign_key.column
                    definition += (
                        f" REFERENCES {preparer.format_table(target.table)}"
                        f" ({preparer.quote(target.name)})"
                    )

                connection.execute(
                    text(
                        f"ALTER TABLE {preparer.format_table(table)} "
                        f"ADD COLUMN {definition}"
                    )
                )
                existing_columns.add(column.name)


def check_connection() -> tuple[bool, str | None]:
    """Ping the database; used by /api/health."""
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return True, None
    except Exception as exc:  # pragma: no cover - depends on environment
        logger.error("database connection failed: %s", type(exc).__name__)
        return False, str(exc)
