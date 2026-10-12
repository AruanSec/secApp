import os

import pytest

os.environ["CLAMD_HOST"] = ""
os.environ["VIRUSTOTAL_API_KEY"] = ""
os.environ["ALIENVAULT_API_KEY"] = ""
os.environ["ABUSECH_API_KEY"] = ""
os.environ["CACHE_TTL_HOURS"] = "0"


@pytest.fixture(scope="session")
def client(tmp_path_factory):
    db_path = tmp_path_factory.mktemp("data") / "test.db"
    os.environ["DATABASE_URL"] = str(db_path)

    from app.config import get_settings
    from app.db import init_db

    get_settings.cache_clear()
    init_db(get_settings())

    from fastapi.testclient import TestClient

    from app.main import app

    with TestClient(app, base_url="http://localhost") as test_client:
        test_client.headers["X-Sentinel-Request"] = "1"
        session = test_client.post(
            "/api/v1/auth/register", json={"username": "testuser", "password": "test-password-123"}
        )
        assert session.status_code == 201
        test_client.headers["X-CSRF-Token"] = session.json()["csrf"]
        yield test_client


def copy_test_account(target_settings):
    """Copy the authenticated fixture identity into an isolated scanner database."""
    from app.config import get_settings
    from app.db import connect

    with connect(get_settings().database_url) as conn:
        row = conn.execute("SELECT * FROM account WHERE username='testuser'").fetchone()
    with connect(target_settings.database_url) as conn:
        conn.execute("INSERT OR IGNORE INTO account VALUES (?, ?, ?, ?, ?, ?)", tuple(row))
    return row["id"]
