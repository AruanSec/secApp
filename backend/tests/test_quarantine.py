import hashlib
from dataclasses import replace
from pathlib import Path

import pytest

from app.config import get_settings
from app.db import connect, init_db
from app.services import quarantine


@pytest.fixture
def settings(tmp_path):
    value = replace(
        get_settings(),
        database_url=str(tmp_path / "data" / "db.sqlite"),
        quarantine_dir=str(tmp_path / "isolated"),
        clamd_host="mock",
    )
    init_db(value)
    return value


def result(path="file.txt", verdict="malicious"):
    return {
        "scan_id": "test-scan",
        "path": path,
        "verdict": verdict,
        "value": hashlib.sha256(b"infected").hexdigest(),
        "type": "hash",
    }


def test_uploaded_copy_is_private_and_persistent(settings):
    scanned = result("folder/nested/file.txt")
    quarantine.isolate(settings, b"infected", scanned)
    assert scanned["quarantine_status"] == "copy"
    stored = Path(settings.quarantine_dir) / f"{scanned['quarantine_id']}.bin"
    assert stored.read_bytes() == b"infected"
    assert stored.stat().st_mode & 0o777 == 0o600
    assert stored.parent.stat().st_mode & 0o777 == 0o700
    with connect(settings.database_url) as conn:
        row = conn.execute("SELECT * FROM quarantine").fetchone()
        assert row["original_path"] == "folder/nested/file.txt"
        assert row["origin"] == "upload"
        assert row["sha256"] == hashlib.sha256(b"infected").hexdigest()


@pytest.mark.parametrize("verdict", ["clean", "suspicious", "unknown"])
def test_nonmalicious_files_are_not_quarantined(settings, verdict):
    scanned = result(verdict=verdict)
    quarantine.isolate(settings, b"good", scanned)
    assert "quarantine_id" not in scanned
    assert not Path(settings.quarantine_dir).exists()


def test_quarantine_metadata_api(client, settings, monkeypatch):
    from conftest import copy_test_account

    from app.auth import owner

    identity = copy_test_account(settings)
    scanned = result()
    marker = owner.set(identity)
    try:
        quarantine.isolate(settings, b"infected", scanned)
    finally:
        owner.reset(marker)
    monkeypatch.setattr("app.api.routes.get_settings", lambda: settings)
    response = client.get("/api/v1/quarantine")
    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 1
    assert body["items"][0]["id"] == scanned["quarantine_id"]
    assert "infected" not in response.text
    assert client.get("/api/v1/quarantine?page=2").json()["items"] == []
    assert client.get(f"/api/v1/quarantine/{scanned['quarantine_id']}").status_code == 404


def test_storage_failure_keeps_original_and_malicious_verdict(settings, monkeypatch, tmp_path):
    source = tmp_path / "chosen.txt"
    source.write_bytes(b"infected")
    monkeypatch.setattr(quarantine, "storage_root", lambda s: (_ for _ in ()).throw(OSError()))
    scanned = result()
    quarantine.isolate(settings, source.read_bytes(), scanned)
    assert source.read_bytes() == b"infected"
    assert scanned["verdict"] == "malicious"
    assert scanned["quarantine_status"] == "failed"


def test_same_filename_has_separate_quarantine_payloads(settings):
    first, second = result(), result()
    quarantine.isolate(settings, b"first", first)
    quarantine.isolate(settings, b"second", second)
    assert first["quarantine_id"] != second["quarantine_id"]
    assert len(list(Path(settings.quarantine_dir).glob("*.bin"))) == 2


def test_metadata_failure_cleans_incomplete_payload(settings, monkeypatch):
    def fail(database_url):
        raise OSError("Database unavailable")

    monkeypatch.setattr(quarantine, "connect", fail)
    scanned = result()
    quarantine.isolate(settings, b"infected", scanned)
    assert scanned["quarantine_status"] == "failed"
    assert not list(Path(settings.quarantine_dir).glob("*.bin"))
