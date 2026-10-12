import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

from .config import Settings

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS ioc (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type TEXT NOT NULL,
    value TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE (type, value)
);

CREATE TABLE IF NOT EXISTS scan (
    id TEXT PRIMARY KEY,
    ioc_id INTEGER NOT NULL REFERENCES ioc(id),
    verdict TEXT NOT NULL,
    source TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scan_result (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL REFERENCES scan(id),
    provider TEXT NOT NULL,
    verdict TEXT NOT NULL,
    raw TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS quarantine (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    original_path TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    size INTEGER NOT NULL,
    origin TEXT NOT NULL,
    status TEXT NOT NULL,
    error TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS purge_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_at TEXT NOT NULL,
    deleted_count INTEGER NOT NULL,
    expired_before TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_scan_ioc_created ON scan(ioc_id, created_at);
CREATE INDEX IF NOT EXISTS idx_scan_verdict ON scan(verdict);
"""


@contextmanager
def connect(database_url: str) -> Iterator[sqlite3.Connection]:
    """Commit or roll back the unit of work, then always close its connection."""
    path = Path(database_url)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    try:
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        with conn:
            yield conn
    finally:
        conn.close()


def init_db(settings: Settings) -> None:
    with connect(settings.database_url) as conn:
        conn.executescript(SCHEMA_SQL)
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS account (
            id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL, salt TEXT NOT NULL,
            password_hash TEXT NOT NULL, created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS auth_session (
            token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES account(id),
            csrf TEXT NOT NULL, expires_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS auth_attempt (key TEXT NOT NULL, attempted_at REAL NOT NULL);
        """)
        columns = {row["name"] for row in conn.execute("PRAGMA table_info(account)")}
        if "is_admin" not in columns:
            conn.execute("ALTER TABLE account ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0")
        conn.execute("""CREATE TABLE IF NOT EXISTS admin_audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT, actor_id TEXT NOT NULL,
            action TEXT NOT NULL, target_id TEXT NOT NULL, created_at TEXT NOT NULL
        )""")
        for table in ("scan", "quarantine"):
            columns = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}
            if "owner_id" not in columns:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN owner_id TEXT REFERENCES account(id)")
            conn.execute(f"CREATE INDEX IF NOT EXISTS idx_{table}_owner ON {table}(owner_id)")


def upsert_ioc(conn: sqlite3.Connection, ioc_type: str, value: str) -> int:
    conn.execute(
        "INSERT INTO ioc(type, value, created_at) VALUES (?, ?, ?) "
        "ON CONFLICT(type, value) DO NOTHING",
        (ioc_type, value, now()),
    )
    row = conn.execute(
        "SELECT id FROM ioc WHERE type = ? AND value = ?", (ioc_type, value)
    ).fetchone()
    return int(row["id"])


def insert_scan(
    conn: sqlite3.Connection,
    scan_id: str,
    ioc_id: int,
    verdict: str,
    source: str,
    status: str,
    created_at: str,
) -> None:
    from .auth import owner

    conn.execute(
        "INSERT INTO scan(id, ioc_id, verdict, source, status, created_at, owner_id) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (scan_id, ioc_id, verdict, source, status, created_at, owner.get()),
    )


def insert_scan_result(
    conn: sqlite3.Connection,
    scan_id: str,
    provider: str,
    verdict: str,
    raw: str,
    created_at: str,
) -> None:
    conn.execute(
        "INSERT INTO scan_result(scan_id, provider, verdict, raw, created_at) "
        "VALUES (?, ?, ?, ?, ?)",
        (scan_id, provider, verdict, raw, created_at),
    )


def now() -> str:
    return datetime.now(UTC).isoformat()
