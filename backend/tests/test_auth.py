from dataclasses import replace

import pytest
from fastapi.testclient import TestClient

from app import admin, auth
from app.api import routes
from app.config import get_settings
from app.db import connect, init_db, insert_scan, now, upsert_ioc
from app.main import app

PASSWORD = "a-long-test-password-123"


@pytest.fixture
def auth_clients(tmp_path, monkeypatch):
    settings = replace(
        get_settings(),
        database_url=str(tmp_path / "auth.db"),
        quarantine_dir=str(tmp_path / "quarantine"),
        clamd_host="mock",
        cache_ttl_hours=24,
    )
    init_db(settings)
    monkeypatch.setattr(auth, "get_settings", lambda: settings)
    monkeypatch.setattr(admin, "get_settings", lambda: settings)
    monkeypatch.setattr(routes, "get_settings", lambda: settings)
    monkeypatch.setattr("app.services.clamd.scan_file", lambda *args: "malicious")
    monkeypatch.setattr("app.services.providers.query_provider", lambda *args: ("malicious", {}))
    with (
        TestClient(app, base_url="http://localhost") as alice,
        TestClient(app, base_url="http://localhost") as bob,
    ):
        for client, name in [(alice, "alice"), (bob, "bob")]:
            client.headers["X-Sentinel-Request"] = "1"
            response = client.post(
                "/api/v1/auth/register", json={"username": name, "password": PASSWORD}
            )
            assert response.status_code == 201
            client.headers["X-CSRF-Token"] = response.json()["csrf"]
        yield alice, bob, settings
        routes.JOBS.clear()


def test_anonymous_access_denied(auth_clients):
    with TestClient(app, base_url="http://localhost") as anonymous:
        for path in ["/reports", "/stats", "/quarantine", "/folder-config", "/scan/unknown"]:
            assert anonymous.get("/api/v1" + path).status_code == 401
        assert (
            anonymous.post("/api/v1/scan", json={"type": "ip", "value": "1.1.1.1"}).status_code
            == 401
        )
        assert anonymous.get("/openapi.json").status_code == 404


def test_password_sessions_and_csrf(auth_clients):
    alice, _, settings = auth_clients
    session_cookie = alice.cookies.get(auth.COOKIE)
    assert alice.get("/api/v1/auth/me").json()["username"] == "alice"
    with connect(settings.database_url) as conn:
        row = conn.execute("SELECT * FROM account WHERE username='alice'").fetchone()
        assert row["password_hash"] != PASSWORD
        assert (
            conn.execute(
                "SELECT 1 FROM auth_session WHERE token_hash=?", (session_cookie,)
            ).fetchone()
            is None
        )
    assert (
        alice.post(
            "/api/v1/scan",
            headers={"X-CSRF-Token": "wrong"},
            json={"type": "ip", "value": "1.1.1.1"},
        ).status_code
        == 403
    )
    assert (
        alice.post(
            "/api/v1/scan",
            headers={"Origin": "https://evil.invalid"},
            json={"type": "ip", "value": "1.1.1.1"},
        ).status_code
        == 403
    )
    assert alice.get("/api/v1/reports", headers={"Host": "evil.invalid"}).status_code == 400
    assert alice.post("/api/v1/auth/logout").status_code == 200
    assert alice.get("/api/v1/auth/me").status_code == 401
    alice.cookies.set(auth.COOKIE, session_cookie, domain="localhost.local", path="/api/v1")
    assert alice.get("/api/v1/auth/me").status_code == 401
    invalid = alice.post(
        "/api/v1/auth/login", json={"username": "alice", "password": "incorrect-password"}
    )
    assert invalid.status_code == 401
    response = alice.post("/api/v1/auth/login", json={"username": "ALICE", "password": PASSWORD})
    assert response.status_code == 200
    assert response.cookies.get(auth.COOKIE) != session_cookie
    cookie = response.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=strict" in cookie
    with connect(settings.database_url) as conn:
        conn.execute("UPDATE auth_session SET expires_at='2000-01-01'")
    assert alice.get("/api/v1/auth/me").status_code == 401


def test_reports_stats_cache_and_legacy_are_private(auth_clients):
    alice, bob, settings = auth_clients
    payload = {"type": "domain", "value": "evil.example.org"}
    a = alice.post("/api/v1/scan", json=payload).json()
    assert alice.post("/api/v1/scan", json=payload).json()["scan_id"] == a["scan_id"]
    assert bob.get("/api/v1/reports").json()["total"] == 0
    assert bob.get("/api/v1/stats").json()["total_scans"] == 0
    b = bob.post("/api/v1/scan", json=payload).json()
    assert b["scan_id"] != a["scan_id"]
    with connect(settings.database_url) as conn:
        ioc = upsert_ioc(conn, "domain", "legacy.example.org")
        insert_scan(conn, "legacy", ioc, "malicious", "old", "completed", now())
    for client, scan in [(alice, a), (bob, b)]:
        reports = client.get("/api/v1/reports").json()
        assert [row["scan_id"] for row in reports["items"]] == [scan["scan_id"]]
        assert client.get("/api/v1/stats").json()["total_scans"] == 1


def test_folder_job_and_quarantine_ownership(auth_clients):
    alice, bob, _ = auth_clients
    response = alice.post(
        "/api/v1/selected-folder-scan", json={"files": [{"path": "chosen/bad.bin", "size": 3}]}
    )
    job_id = response.json()["job_id"]
    assert bob.get(f"/api/v1/scan/{job_id}").status_code == 404
    assert bob.delete(f"/api/v1/selected-folder-scan/{job_id}").status_code == 404
    assert (
        bob.put(f"/api/v1/selected-folder-scan/{job_id}/files/0", content=b"bad").status_code == 404
    )
    assert (
        alice.put(f"/api/v1/selected-folder-scan/{job_id}/files/0", content=b"bad").status_code
        == 200
    )
    assert alice.get("/api/v1/quarantine").json()["total"] == 1
    assert bob.get("/api/v1/quarantine").json()["total"] == 0
    assert alice.get("/api/v1/reports").json()["total"] == 1
    assert bob.get("/api/v1/reports").json()["total"] == 0


def test_batch_background_context_ownership(auth_clients):
    import time

    alice, bob, _ = auth_clients
    response = alice.post("/api/v1/batch-scan", json={"iocs": [{"type": "ip", "value": "1.1.1.1"}]})
    job_id = response.json()["job_id"]
    assert bob.get(f"/api/v1/scan/{job_id}").status_code == 404
    for _ in range(100):
        result = alice.get(f"/api/v1/scan/{job_id}").json()
        if result["status"] == "completed":
            break
        time.sleep(0.01)
    assert result["status"] == "completed"
    assert alice.get("/api/v1/reports").json()["total"] == 1
    assert bob.get("/api/v1/reports").json()["total"] == 0


def test_login_throttling_and_request_guard(auth_clients):
    alice, _, _ = auth_clients
    body = {"username": "nonexistent", "password": PASSWORD}
    assert (
        alice.post("/api/v1/auth/login", headers={"X-Sentinel-Request": ""}, json=body).status_code
        == 403
    )
    for _ in range(10):
        assert alice.post("/api/v1/auth/login", json=body).status_code == 401
    assert alice.post("/api/v1/auth/login", json=body).status_code == 429


def test_registration_validation_and_throttle(auth_clients):
    alice, _, _ = auth_clients
    assert (
        alice.post(
            "/api/v1/auth/register", json={"username": "alice", "password": PASSWORD}
        ).status_code
        == 409
    )
    assert (
        alice.post(
            "/api/v1/auth/register", json={"username": "other", "password": "short"}
        ).status_code
        == 422
    )
    assert (
        alice.post(
            "/api/v1/auth/register",
            headers={"Origin": "https://evil.invalid"},
            json={"username": "other", "password": PASSWORD},
        ).status_code
        == 403
    )
    for _ in range(7):
        assert (
            alice.post(
                "/api/v1/auth/register", json={"username": "alice", "password": PASSWORD}
            ).status_code
            == 409
        )
    assert (
        alice.post(
            "/api/v1/auth/register", json={"username": "other", "password": PASSWORD}
        ).status_code
        == 429
    )


def test_legacy_database_migration_is_idempotent(tmp_path):
    from app.db import SCHEMA_SQL

    settings = replace(get_settings(), database_url=str(tmp_path / "legacy.db"))
    with connect(settings.database_url) as conn:
        conn.executescript(SCHEMA_SQL)
        ioc = upsert_ioc(conn, "ip", "1.1.1.1")
        conn.execute(
            "INSERT INTO scan VALUES (?, ?, ?, ?, ?, ?)",
            ("old", ioc, "unknown", "none", "completed", now()),
        )
        conn.execute(
            "INSERT INTO quarantine VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ("q", "old", "old/file", "a" * 64, 3, "upload", "copy", None, now()),
        )
    init_db(settings)
    init_db(settings)
    with connect(settings.database_url) as conn:
        assert conn.execute("SELECT owner_id FROM scan WHERE id='old'").fetchone()[0] is None
        assert (
            conn.execute("SELECT original_path, owner_id FROM quarantine").fetchone()[0]
            == "old/file"
        )


def promote(alice, settings):
    with connect(settings.database_url) as conn:
        conn.execute("UPDATE account SET is_admin=1 WHERE username='alice'")
    assert alice.get("/api/v1/auth/me").json()["is_admin"] is True


def test_admin_global_visibility_and_private_accounts(auth_clients):
    alice, bob, settings = auth_clients
    assert alice.get("/api/v1/admin/users").status_code == 403
    assert alice.get("/api/v1/admin/jobs").status_code == 403
    assert alice.get("/api/v1/admin/audit").status_code == 403
    scanned = bob.post("/api/v1/scan", json={"type": "domain", "value": "bob.example.org"}).json()
    with connect(settings.database_url) as conn:
        ioc = upsert_ioc(conn, "domain", "legacy.example.org")
        insert_scan(conn, "legacy", ioc, "unknown", "none", "completed", now())
    promote(alice, settings)
    assert alice.get("/api/v1/stats").json()["total_scans"] == 2
    reports = alice.get("/api/v1/reports").json()
    assert reports["total"] == 2
    assert {r["owner_username"] for r in reports["items"]} == {"bob", None}
    assert bob.get("/api/v1/reports").json()["total"] == 1
    assert bob.get("/api/v1/reports").json()["items"][0]["scan_id"] == scanned["scan_id"]
    users = alice.get("/api/v1/admin/users").json()
    assert users["total"] == 2
    assert all("password_hash" not in u and "salt" not in u for u in users["items"])
    assert alice.get("/api/v1/admin/users?page=2").json()["items"] == []


def test_admin_job_control_keeps_original_owner(auth_clients):
    alice, bob, settings = auth_clients
    job_id = bob.post(
        "/api/v1/selected-folder-scan", json={"files": [{"path": "bob/malicious", "size": 3}]}
    ).json()["job_id"]
    promote(alice, settings)
    assert alice.get("/api/v1/admin/jobs").json()["items"][0]["owner_username"] == "bob"
    assert alice.get(f"/api/v1/admin/jobs/{job_id}").json()["files"][0]["path"] == "bob/malicious"
    assert alice.get(f"/api/v1/scan/{job_id}").status_code == 200
    assert (
        alice.put(f"/api/v1/selected-folder-scan/{job_id}/files/0", content=b"bad").status_code
        == 200
    )
    assert bob.get("/api/v1/quarantine").json()["total"] == 1
    assert alice.get("/api/v1/quarantine").json()["items"][0]["owner_username"] == "bob"
    with connect(settings.database_url) as conn:
        conn.execute(
            "INSERT INTO quarantine (id,scan_id,original_path,sha256,size,origin,status,"
            "created_at) "
            "VALUES ('oldq','old','legacy/file','hash',1,'upload','copy',?)",
            (now(),),
        )
    assert alice.get("/api/v1/quarantine").json()["total"] == 2
    assert bob.get("/api/v1/quarantine").json()["total"] == 1
    next_job = bob.post(
        "/api/v1/selected-folder-scan", json={"files": [{"path": "bob/next", "size": 0}]}
    ).json()["job_id"]
    assert alice.delete(f"/api/v1/selected-folder-scan/{next_job}").status_code == 200
    assert bob.get(f"/api/v1/scan/{next_job}").json()["status"] == "failed"


def test_admin_roles_sessions_and_last_admin(auth_clients):
    alice, bob, settings = auth_clients
    with connect(settings.database_url) as conn:
        ids = {r["username"]: r["id"] for r in conn.execute("SELECT id, username FROM account")}
    assert (
        bob.patch(f"/api/v1/admin/users/{ids['alice']}/role", json={"is_admin": True}).status_code
        == 403
    )
    promote(alice, settings)
    assert (
        alice.patch(
            f"/api/v1/admin/users/{ids['alice']}/role", json={"is_admin": False}
        ).status_code
        == 409
    )
    assert (
        alice.patch(
            f"/api/v1/admin/users/{ids['bob']}/role",
            headers={"X-CSRF-Token": "bad"},
            json={"is_admin": True},
        ).status_code
        == 403
    )
    assert (
        alice.patch(f"/api/v1/admin/users/{ids['bob']}/role", json={"is_admin": True}).status_code
        == 200
    )
    assert bob.get("/api/v1/admin/users").status_code == 401
    session = bob.post("/api/v1/auth/login", json={"username": "bob", "password": PASSWORD}).json()
    assert session["is_admin"] is True
    bob.headers["X-CSRF-Token"] = session["csrf"]
    assert bob.get("/api/v1/admin/users").status_code == 200
    assert (
        alice.patch(f"/api/v1/admin/users/{ids['bob']}/role", json={"is_admin": False}).status_code
        == 200
    )
    assert bob.get("/api/v1/admin/users").status_code == 401
    session = bob.post("/api/v1/auth/login", json={"username": "bob", "password": PASSWORD}).json()
    bob.headers["X-CSRF-Token"] = session["csrf"]
    assert bob.get("/api/v1/admin/users").status_code == 403
    assert alice.post(f"/api/v1/admin/users/{ids['bob']}/revoke-sessions").status_code == 200
    assert bob.get("/api/v1/auth/me").status_code == 401
    assert alice.get("/api/v1/admin/audit").json()["total"] == 3


def test_registration_cannot_claim_admin_role(auth_clients):
    alice, _, _ = auth_clients
    response = alice.post(
        "/api/v1/auth/register",
        json={"username": "newadmin", "password": PASSWORD, "is_admin": True},
    )
    assert response.status_code == 201
    assert response.json()["is_admin"] is False
    assert alice.get("/api/v1/admin/users").status_code == 403


def test_bootstrap_cli_promotes_and_revokes(auth_clients, monkeypatch):
    from app import manage_admin

    alice, _, settings = auth_clients
    monkeypatch.setattr(manage_admin, "get_settings", lambda: settings)
    monkeypatch.setattr("sys.argv", ["manage_admin", "promote", "ALICE"])
    manage_admin.main()
    assert alice.get("/api/v1/auth/me").status_code == 401
    response = alice.post("/api/v1/auth/login", json={"username": "alice", "password": PASSWORD})
    assert response.json()["is_admin"] is True


def test_admin_changes_password_and_revokes_all_sessions(auth_clients):
    alice, bob, settings = auth_clients
    promote(alice, settings)
    new_password = "changed-user-password-456"
    with connect(settings.database_url) as conn:
        old = conn.execute("SELECT * FROM account WHERE username='bob'").fetchone()
        conn.execute(
            "INSERT INTO auth_session VALUES ('second-session', ?, 'csrf', '2999-01-01')",
            (old["id"],),
        )
    response = alice.post(
        f"/api/v1/admin/users/{old['id']}/password", json={"new_password": new_password}
    )
    assert response.status_code == 200
    assert new_password not in response.text
    assert bob.get("/api/v1/auth/me").status_code == 401
    assert (
        bob.post("/api/v1/auth/login", json={"username": "bob", "password": PASSWORD}).status_code
        == 401
    )
    assert (
        bob.post(
            "/api/v1/auth/login", json={"username": "bob", "password": new_password}
        ).status_code
        == 200
    )
    with connect(settings.database_url) as conn:
        updated = conn.execute("SELECT * FROM account WHERE id=?", (old["id"],)).fetchone()
        assert updated["salt"] != old["salt"]
        assert updated["password_hash"] not in {old["password_hash"], new_password}
        assert updated["is_admin"] == old["is_admin"]
        assert (
            conn.execute("SELECT 1 FROM auth_session WHERE token_hash='second-session'").fetchone()
            is None
        )
    audit = alice.get("/api/v1/admin/audit").json()
    assert audit["items"][0]["action"] == "change_password"
    assert new_password not in str(audit)


def test_password_change_requires_admin_csrf_and_valid_password(auth_clients):
    alice, bob, settings = auth_clients
    with connect(settings.database_url) as conn:
        target = conn.execute("SELECT id FROM account WHERE username='bob'").fetchone()[0]
        self_id = conn.execute("SELECT id FROM account WHERE username='alice'").fetchone()[0]
    url = f"/api/v1/admin/users/{target}/password"
    body = {"new_password": "a-valid-new-password-456"}
    assert bob.post(url, json=body).status_code == 403
    promote(alice, settings)
    assert alice.post(url, headers={"X-CSRF-Token": "bad"}, json=body).status_code == 403
    assert alice.post(url, headers={"Origin": "https://evil.invalid"}, json=body).status_code == 403
    for password in ["short", "x" * 129]:
        response = alice.post(url, json={"new_password": password})
        assert response.status_code == 400
        assert password not in response.text
    assert alice.post("/api/v1/admin/users/missing/password", json=body).status_code == 404
    assert alice.post(f"/api/v1/admin/users/{self_id}/password", json=body).status_code == 403
    assert bob.get("/api/v1/auth/me").status_code == 200
    assert alice.get("/api/v1/admin/audit").json()["total"] == 0


def test_password_change_prevents_stale_login_session(auth_clients):
    from fastapi import HTTPException, Response
    from starlette.requests import Request

    alice, _, settings = auth_clients
    with connect(settings.database_url) as conn:
        row = conn.execute("SELECT * FROM account WHERE username='bob'").fetchone()
    promote(alice, settings)
    assert (
        alice.post(
            f"/api/v1/admin/users/{row['id']}/password",
            json={"new_password": "changed-password-789"},
        ).status_code
        == 200
    )
    request = Request(
        {"type": "http", "scheme": "http", "headers": [], "server": ("localhost", 80), "path": "/"}
    )
    with pytest.raises(HTTPException) as error:
        auth.start_session(Response(), row["id"], "bob", request, row["password_hash"])
    assert error.value.status_code == 401


@pytest.mark.parametrize(
    "keys,expected",
    [
        (("", "", ""), {"virustotal": False, "alienvault": False, "abusech": False}),
        (
            ("private-vt-value", "   ", ""),
            {"virustotal": True, "alienvault": False, "abusech": False},
        ),
        (
            ("private-vt-value", "private-otx-value", "private-abuse-value"),
            {"virustotal": True, "alienvault": True, "abusech": True},
        ),
    ],
)
def test_provider_configuration_presence_never_exposes_keys(
    auth_clients, monkeypatch, keys, expected
):
    alice, _, settings = auth_clients
    value = replace(
        settings, virustotal_api_key=keys[0], alienvault_api_key=keys[1], abusech_api_key=keys[2]
    )
    monkeypatch.setattr(routes, "get_settings", lambda: value)
    response = alice.get("/api/v1/provider-config")
    assert response.status_code == 200
    assert response.json() == {"providers": expected}
    assert "private-" not in response.text
    assert response.headers["cache-control"] == "no-store"
    with TestClient(app, base_url="http://localhost") as anonymous:
        assert anonymous.get("/api/v1/provider-config").status_code == 401


def test_whitespace_api_keys_skip_provider_without_outbound_request(monkeypatch):
    from app.services import providers

    settings = replace(get_settings(), virustotal_api_key="   ")

    def unexpected_request(*args, **kwargs):
        raise AssertionError("A blank API key must not make an outbound request")

    monkeypatch.setattr(providers.httpx, "Client", unexpected_request)
    assert providers.query_provider("virustotal", settings, "hash", "a" * 64) == ("skipped", {})
