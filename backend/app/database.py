"""Database engine and session with SQLite fallback for local dev."""

import os

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import sessionmaker, declarative_base

from .config import settings

_dbfallback = False
db_url = settings.database_url

# If PG is explicitly set but unreachable, fall back to SQLite
_engine = None
try:
    connect_args = {}
    if db_url.startswith("sqlite"):
        connect_args["check_same_thread"] = False
    _engine = create_engine(db_url, pool_pre_ping=True, connect_args=connect_args)
    _engine.connect().close()
except Exception:
    _dbfallback = True
    db_url = "sqlite:///./coreids.db"
    connect_args = {"check_same_thread": False}
    _engine = create_engine(db_url, pool_pre_ping=True, connect_args=connect_args)

engine = _engine
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)
Base = declarative_base()

print(f"  Database: {db_url}" + (" (auto-fallback from PostgreSQL)" if _dbfallback else ""))


def _migrate_sqlite():
    """Add missing columns to existing tables for SQLite."""
    if not db_url.startswith("sqlite"):
        return
    inspector = inspect(engine)
    try:
        existing_cols = {c["name"] for c in inspector.get_columns("traffic_events")}
    except Exception:
        return
    if "processed" not in existing_cols:
        with engine.begin() as conn:
            conn.execute(text("ALTER TABLE traffic_events ADD COLUMN processed BOOLEAN DEFAULT 0"))
            print("  Added column: traffic_events.processed")


_migrate_sqlite()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
