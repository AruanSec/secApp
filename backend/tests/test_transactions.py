import base64
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from threading import Barrier

import pytest

from app.config import get_settings
from app.db import connect, init_db, upsert_ioc
from app.models import Verdict
from app.services import clamd, providers, scanner


@pytest.fixture
def settings(tmp_path):
    config = replace(
        get_settings(), database_url=str(tmp_path / "scan.db"), clamd_host="", cache_ttl_hours=0
    )
    init_db(config)
    return config


@pytest.mark.parametrize("stage", ["provider", "clamd"])
def test_external_work_leaves_database_available(settings, monkeypatch, stage):
    def verify_write_available(*args):
        # A second connection must be able to commit while scanning is underway.
        with sqlite3.connect(settings.database_url, timeout=0) as conn:
            conn.execute("INSERT INTO purge_log VALUES (NULL, 'now', 0, 'now')")
        return Verdict.CLEAN if stage == "clamd" else (Verdict.CLEAN, {})

    if stage == "clamd":
        settings = replace(settings, clamd_host="clamd")
        monkeypatch.setattr(clamd, "scan_file", verify_write_available)
        kind, value = "file", base64.b64encode(b"content").decode()
    else:
        monkeypatch.setattr(providers, "query_provider", verify_write_available)
        kind, value = "hash", "a" * 64
    assert scanner.scan_one(settings, kind, value)["verdict"] == Verdict.CLEAN


@pytest.mark.parametrize("same_ioc", [True, False])
def test_concurrent_scans_commit(settings, monkeypatch, same_ioc):
    barrier = Barrier(2)

    def provider(provider, config, kind, value):
        if provider == "virustotal":
            # Both scans must reach external work before either persists.
            barrier.wait(timeout=3)
        return Verdict.MALICIOUS, {"value": value}

    monkeypatch.setattr(providers, "query_provider", provider)
    values = ["a" * 64, ("a" if same_ioc else "b") * 64]
    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(
            executor.map(lambda value: scanner.scan_one(settings, "hash", value), values)
        )
    assert len({result["scan_id"] for result in results}) == 2
    with connect(settings.database_url) as conn:
        assert conn.execute("SELECT COUNT(*) FROM ioc").fetchone()[0] == (1 if same_ioc else 2)
        assert conn.execute("SELECT COUNT(*) FROM scan").fetchone()[0] == 2
        assert conn.execute("SELECT COUNT(*) FROM scan_result").fetchone()[0] == 6


def test_failed_persistence_rolls_back_all_rows(settings, monkeypatch):
    monkeypatch.setattr(providers, "query_provider", lambda *args: (Verdict.MALICIOUS, {}))
    original = scanner.insert_scan_result
    calls = 0

    def fail_second_result(*args):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise sqlite3.IntegrityError("simulated failure")
        return original(*args)

    monkeypatch.setattr(scanner, "insert_scan_result", fail_second_result)
    with pytest.raises(sqlite3.IntegrityError, match="simulated failure"):
        scanner.scan_one(settings, "hash", "a" * 64)
    with connect(settings.database_url) as conn:
        for table in ("ioc", "scan", "scan_result"):
            assert conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] == 0


@pytest.mark.parametrize("fail", [True, False])
def test_connection_commits_or_rolls_back_and_closes(settings, fail):
    def unit_of_work():
        with connect(settings.database_url) as conn:
            upsert_ioc(conn, "hash", "a" * 64)
            if fail:
                raise RuntimeError("rollback")
        return conn

    if fail:
        with pytest.raises(RuntimeError, match="rollback"):
            unit_of_work()
    else:
        closed = unit_of_work()
        with pytest.raises(sqlite3.ProgrammingError, match="closed"):
            closed.execute("SELECT 1")
    with connect(settings.database_url) as conn:
        assert conn.execute("SELECT COUNT(*) FROM ioc").fetchone()[0] == (0 if fail else 1)
