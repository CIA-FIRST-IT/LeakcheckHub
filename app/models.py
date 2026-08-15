"""Shared SQLAlchemy declarative base.

Models start in M1; keeping one base now makes Alembic metadata discovery deterministic.
"""

from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """Declarative base for all portal tables."""
