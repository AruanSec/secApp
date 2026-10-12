import hashlib
from dataclasses import replace

import pytest

from app.config import get_settings
from app.db import init_db
from app.models import Verdict
from app.services import clamd, folders, providers


@pytest.fixture
def folder_settings(tmp_path, client):
    settings = replace(
        get_settings(),
        database_url=str(tmp_path / "scan.db"),
        quarantine_dir=str(tmp_path / "quarantine"),
        clamd_host="mock-clamd",
        cache_ttl_hours=0,
    )
    init_db(settings)
    from conftest import copy_test_account

    copy_test_account(settings)
    return settings


@pytest.fixture
def scan_stub(monkeypatch):
    seen = []

    def inspect(settings, data):
        seen.append(data)
        return Verdict.MALICIOUS if data == b"infected" else Verdict.CLEAN

    monkeypatch.setattr(clamd, "scan_file", inspect)
    monkeypatch.setattr(providers, "query_provider", lambda *args: (Verdict.SKIPPED, {}))
    return seen


def test_selected_folder_recursive_upload(client, folder_settings, scan_stub, monkeypatch):
    from app.api.routes import JOBS

    monkeypatch.setattr("app.api.routes.get_settings", lambda: folder_settings)
    response = client.post(
        "/api/v1/selected-folder-scan",
        json={
            "files": [
                {"path": "chosen/good.txt", "size": 4},
                {"path": "chosen/nested/bad.bin", "size": 8},
            ]
        },
    )
    assert response.status_code == 202
    job_id = response.json()["job_id"]
    try:
        for index, data in enumerate([b"good", b"infected"]):
            assert (
                client.put(
                    f"/api/v1/selected-folder-scan/{job_id}/files/{index}", content=data
                ).status_code
                == 200
            )
        job = client.get(f"/api/v1/scan/{job_id}").json()
        assert job["status"] == "completed"
        assert job["scanned"] == job["processed"] == 2
        assert {r["path"]: r["verdict"] for r in job["results"]} == {
            "chosen/good.txt": "clean",
            "chosen/nested/bad.bin": "malicious",
        }
        assert scan_stub == [b"good", b"infected"]
        assert job["results"][1]["quarantine_status"] == "copy"
        assert job["results"][1]["quarantine_id"]
        assert (
            client.put(
                f"/api/v1/selected-folder-scan/{job_id}/files/1", content=b"infected"
            ).status_code
            == 409
        )
    finally:
        JOBS.pop(job_id, None)


@pytest.mark.parametrize("path", ["/etc/passwd", "../secret", "chosen/../../secret", "."])
def test_selected_folder_rejects_invalid_paths(client, folder_settings, monkeypatch, path):
    monkeypatch.setattr("app.api.routes.get_settings", lambda: folder_settings)
    assert (
        client.post(
            "/api/v1/selected-folder-scan",
            json={
                "files": [
                    {"path": path, "size": 0},
                ]
            },
        ).status_code
        == 400
    )


def test_selected_folder_limits_and_interruption(client, folder_settings, scan_stub, monkeypatch):
    from app.api.routes import JOBS

    monkeypatch.setattr("app.api.routes.get_settings", lambda: folder_settings)
    monkeypatch.setattr(folders, "MAX_FILE_BYTES", 3)
    job_id = client.post(
        "/api/v1/selected-folder-scan",
        json={
            "files": [
                {"path": "chosen/large", "size": 5},
                {"path": "chosen/changed", "size": 2},
            ]
        },
    ).json()["job_id"]
    try:
        assert (
            client.post(
                "/api/v1/selected-folder-scan", json={"files": [{"path": "other/file", "size": 0}]}
            ).status_code
            == 409
        )
        assert (
            client.put(f"/api/v1/selected-folder-scan/{job_id}/files/1", content=b"hi").status_code
            == 409
        )
        assert (
            client.put(f"/api/v1/selected-folder-scan/{job_id}/files/0", content=b"").status_code
            == 200
        )
        assert (
            client.put(
                f"/api/v1/selected-folder-scan/{job_id}/files/1", content=b"changed"
            ).status_code
            == 413
        )
        job = client.get(f"/api/v1/scan/{job_id}").json()
        assert job["status"] == "failed"
        assert job["skipped"] == 1
        assert not scan_stub
    finally:
        JOBS.pop(job_id, None)


def test_selected_folder_cancel_and_expire(client, folder_settings, monkeypatch):
    from app.api.routes import JOBS

    monkeypatch.setattr("app.api.routes.get_settings", lambda: folder_settings)
    manifest = {"files": [{"path": "chosen/file", "size": 0}]}
    first = client.post("/api/v1/selected-folder-scan", json=manifest).json()["job_id"]
    second = None
    try:
        assert client.post("/api/v1/selected-folder-scan", json=manifest).status_code == 409
        JOBS[first].touched -= 601
        response = client.post("/api/v1/selected-folder-scan", json=manifest)
        assert response.status_code == 202
        second = response.json()["job_id"]
        assert JOBS[first].status == "failed"
        assert client.delete(f"/api/v1/selected-folder-scan/{second}").status_code == 200
        assert JOBS[second].status == "failed"
    finally:
        JOBS.pop(first, None)
        if second:
            JOBS.pop(second, None)


def test_selected_folder_size_mismatch(client, folder_settings, scan_stub, monkeypatch):
    from app.api.routes import JOBS

    monkeypatch.setattr("app.api.routes.get_settings", lambda: folder_settings)
    job_id = client.post(
        "/api/v1/selected-folder-scan", json={"files": [{"path": "chosen/file", "size": 3}]}
    ).json()["job_id"]
    try:
        assert (
            client.put(f"/api/v1/selected-folder-scan/{job_id}/files/0", content=b"hi").status_code
            == 400
        )
        assert JOBS[job_id].status == "failed"
        assert not scan_stub
    finally:
        JOBS.pop(job_id, None)


def test_selected_folder_scan_error_continues(client, folder_settings, monkeypatch):
    from app.api.routes import JOBS

    monkeypatch.setattr("app.api.routes.get_settings", lambda: folder_settings)

    def inspect(settings, data):
        if data:
            raise RuntimeError("simulated scanner failure")
        return {"type": "hash", "value": hashlib.sha256(data).hexdigest(), "verdict": "clean"}

    monkeypatch.setattr("app.api.routes.scanner.scan_file_content", inspect)
    job_id = client.post(
        "/api/v1/selected-folder-scan",
        json={
            "files": [
                {"path": "chosen/error", "size": 1},
                {"path": "chosen/empty", "size": 0},
            ]
        },
    ).json()["job_id"]
    try:
        for index, data in enumerate([b"a", b""]):
            assert (
                client.put(
                    f"/api/v1/selected-folder-scan/{job_id}/files/{index}", content=data
                ).status_code
                == 200
            )
        job = client.get(f"/api/v1/scan/{job_id}").json()
        assert job["status"] == "completed"
        assert job["errors"] == job["scanned"] == 1
        assert job["processed"] == 2
    finally:
        JOBS.pop(job_id, None)


def test_selected_folder_manifest_validation(client, folder_settings, monkeypatch):
    monkeypatch.setattr("app.api.routes.get_settings", lambda: folder_settings)
    assert client.post("/api/v1/selected-folder-scan", json={"files": []}).status_code == 422
    assert (
        client.post(
            "/api/v1/selected-folder-scan",
            json={
                "files": [
                    {"path": "folder/file", "size": -1},
                ]
            },
        ).status_code
        == 422
    )
    assert (
        client.post(
            "/api/v1/selected-folder-scan",
            json={
                "files": [
                    {"path": "folder/file", "size": 0},
                    {"path": "folder/file", "size": 0},
                ]
            },
        ).status_code
        == 400
    )
    monkeypatch.setattr(
        "app.api.routes.get_settings", lambda: replace(folder_settings, clamd_host="")
    )
    assert (
        client.post(
            "/api/v1/selected-folder-scan",
            json={
                "files": [
                    {"path": "folder/file", "size": 0},
                ]
            },
        ).status_code
        == 503
    )


def test_only_selected_folder_mode_is_available(client, folder_settings, monkeypatch):
    monkeypatch.setattr("app.api.routes.get_settings", lambda: folder_settings)
    assert client.get("/api/v1/folder-config").json() == {
        "scanner_enabled": True,
        "max_file_bytes": folders.MAX_FILE_BYTES,
        "max_entries": folders.MAX_ENTRIES,
    }
    assert client.post("/api/v1/folder-scan", json={"path": "."}).status_code == 404
