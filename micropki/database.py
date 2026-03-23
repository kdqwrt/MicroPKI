# micropki/database.py
from __future__ import annotations

import sqlite3
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, List, Dict, Any, Tuple


class CertificateDatabase:

    SCHEMA_VERSION = 1

    def __init__(self, db_path: Path, logger: Optional[logging.Logger] = None):

        self.db_path = Path(db_path)
        self.logger = logger or logging.getLogger("micropki.db")
        self.conn: Optional[sqlite3.Connection] = None

    def connect(self) -> sqlite3.Connection:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.db_path))
        self.conn.row_factory = sqlite3.Row

        self.conn.execute("PRAGMA foreign_keys = ON")

        return self.conn

    def close(self):
        if self.conn:
            self.conn.close()
            self.conn = None

    def init_schema(self, force: bool = False) -> bool:

        try:
            self.connect()

            if not force and self._table_exists("certificates"):
                self.logger.info("Database schema already exists, skipping initialization")
                return True

            if force:
                self.logger.warning("Force mode enabled, dropping existing tables...")
                self.conn.execute("DROP TABLE IF EXISTS certificates")
                self.conn.execute("DROP TABLE IF EXISTS metadata")

            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS certificates (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    serial_hex TEXT UNIQUE NOT NULL,
                    subject TEXT NOT NULL,
                    issuer TEXT NOT NULL,
                    not_before TEXT NOT NULL,
                    not_after TEXT NOT NULL,
                    cert_pem TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'valid',
                    revocation_reason TEXT,
                    revocation_date TEXT,
                    created_at TEXT NOT NULL
                )
            """)


            self.conn.execute("CREATE INDEX IF NOT EXISTS idx_serial ON certificates(serial_hex)")
            self.conn.execute("CREATE INDEX IF NOT EXISTS idx_status ON certificates(status)")
            self.conn.execute("CREATE INDEX IF NOT EXISTS idx_not_after ON certificates(not_after)")


            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )
            """)

            self.conn.execute(
                "INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)",
                ("schema_version", str(self.SCHEMA_VERSION))
            )

            self.conn.commit()

            self.logger.info(f"Database schema initialized successfully at {self.db_path}")
            return True

        except Exception as e:
            self.logger.error(f"Failed to initialize database: {e}")
            if self.conn:
                self.conn.rollback()
            raise
        finally:
            self.close()

    def _table_exists(self, table_name: str) -> bool:
        result = self.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
            (table_name,)
        ).fetchone()
        return result is not None

    def execute(self, sql: str, params: Tuple = ()) -> sqlite3.Cursor:
        if not self.conn:
            self.connect()
        return self.conn.execute(sql, params)

    def executemany(self, sql: str, params: List[Tuple]) -> sqlite3.Cursor:
        if not self.conn:
            self.connect()
        return self.conn.executemany(sql, params)

    def commit(self):
        if self.conn:
            self.conn.commit()

    def rollback(self):
        if self.conn:
            self.conn.rollback()

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type:
            self.rollback()
        self.close()

    def get_schema_version(self) -> int:
        try:
            self.connect()
            result = self.conn.execute(
                "SELECT value FROM metadata WHERE key = 'schema_version'"
            ).fetchone()
            if result:
                return int(result['value'])
            return 0
        except Exception:
            return 0
        finally:
            self.close()

    def migrate_schema(self) -> bool:
        current_version = self.get_schema_version()

        if current_version >= self.SCHEMA_VERSION:
            if self.logger:
                self.logger.info(f"Schema is up to date (version {current_version})")
            return True

        if self.logger:
            self.logger.info(f"Migrating schema from version {current_version} to {self.SCHEMA_VERSION}")

        try:
            self.connect()

            # Миграция с версии 0 до 1
            if current_version < 1:
                # Создаем таблицу certificates если её нет
                self.conn.execute("""
                    CREATE TABLE IF NOT EXISTS certificates (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        serial_hex TEXT UNIQUE NOT NULL,
                        subject TEXT NOT NULL,
                        issuer TEXT NOT NULL,
                        not_before TEXT NOT NULL,
                        not_after TEXT NOT NULL,
                        cert_pem TEXT NOT NULL,
                        status TEXT NOT NULL DEFAULT 'valid',
                        revocation_reason TEXT,
                        revocation_date TEXT,
                        created_at TEXT NOT NULL
                    )
                """)

                # Создаем индексы
                self.conn.execute("CREATE INDEX IF NOT EXISTS idx_serial ON certificates(serial_hex)")
                self.conn.execute("CREATE INDEX IF NOT EXISTS idx_status ON certificates(status)")
                self.conn.execute("CREATE INDEX IF NOT EXISTS idx_not_after ON certificates(not_after)")

                # Создаем таблицу metadata
                self.conn.execute("""
                    CREATE TABLE IF NOT EXISTS metadata (
                        key TEXT PRIMARY KEY,
                        value TEXT NOT NULL
                    )
                """)

                # Устанавливаем версию
                self.conn.execute(
                    "INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)",
                    ("schema_version", "1")
                )

            self.conn.commit()

            if self.logger:
                self.logger.info(f"Schema migrated successfully to version {self.SCHEMA_VERSION}")

            return True

        except Exception as e:
            self.conn.rollback()
            if self.logger:
                self.logger.error(f"Schema migration failed: {e}")
            raise
        finally:
            self.close()