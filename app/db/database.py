from __future__ import annotations

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

# DB path (SQLite)
DB_URL = "sqlite:///cti_watch.db"

# Engine
ENGINE = create_engine(
    DB_URL,
    echo=False,
    future=True,
)

# Session factory
SessionLocal = sessionmaker(
    bind=ENGINE,
    autoflush=False,
    autocommit=False,
    future=True,
)

# Base class for models
Base = declarative_base()


def init_db():
    """
    Import all model modules so SQLAlchemy registers tables into Base.metadata,
    then create tables if missing.
    """
    from app.db import tables  # noqa: F401
    from app.db import enriched_tables  # noqa: F401
    from app.db import mitre_tables  # noqa: F401

    Base.metadata.create_all(bind=ENGINE)
