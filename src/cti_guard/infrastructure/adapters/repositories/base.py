"""
Base repository with common SQLite functionality.

Provides database connection and common operations.
"""

from __future__ import annotations

import threading

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, declarative_base, sessionmaker

from cti_guard.infrastructure.config.logging_config import get_logger
from cti_guard.infrastructure.config.settings import settings

logger = get_logger(__name__)

# SQLAlchemy base for ORM models
Base = declarative_base()

# Global lock for table creation (prevents SQLite concurrency issues)
_table_creation_lock = threading.Lock()
_initialised_urls: set[str] = set()


class BaseRepository:
    """Base repository with database connection management."""

    def __init__(self, db_url: str | None = None) -> None:
        """
        Initialize repository with database connection.

        Args:
            db_url: Database URL (defaults to settings.database_url)
        """
        self.db_url = db_url or settings.database_url

        # Create engine
        self.engine = create_engine(
            self.db_url,
            echo=False,  # Set to True for SQL debugging
            connect_args={"check_same_thread": False} if "sqlite" in self.db_url else {},
        )

        # Create session factory
        self.SessionLocal = sessionmaker(
            autocommit=False,
            autoflush=False,
            bind=self.engine,
        )

        # Create tables once per database URL (guarded to avoid concurrent SQLite DDL)
        with _table_creation_lock:
            if self.db_url not in _initialised_urls:
                Base.metadata.create_all(bind=self.engine, checkfirst=True)
                _initialised_urls.add(self.db_url)

        logger.info(
            "✅ Database initialized",
            source=self.__class__.__name__,
            db_url=self._sanitize_url(self.db_url),
        )

    def get_session(self) -> Session:
        """Get a new database session."""
        return self.SessionLocal()

    @staticmethod
    def _sanitize_url(url: str) -> str:
        """Sanitize database URL for logging (remove credentials)."""
        if "@" in url:
            # Hide password
            parts = url.split("@")
            return parts[-1]
        return url
