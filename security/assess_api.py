"""Bounded security probes; run inside the backend container with a temporary database.

  docker compose exec -T backend /app/lib/bin/python < security/assess_api.py

Mocks scanner/provider responses where needed; no external indicator requests,
no real quarantine payloads, and no writes to the application's live database.
"""

import asyncio
import json
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import httpx
from app import auth
from app.api import routes
from app.config import get_settings
from app.db import connect, init_db
from app.main import app
from app.services import folders, providers

observations = []


def observe(name, passed, evidence):
    observations.append({"check": name, "control_passed": passed, "evidence": evidence})


async def main():
    with TemporaryDirectory() as temporary:
        settings = replace(
            get_settings(),
            database_url=str(Path(temporary) / "audit.db"),
            quarantine_dir=str(Path(temporary) / "quarantine"),
            clamd_host="audit-mock",
            virustotal_api_key="",
            alienvault_api_key="",
            abusech_api_key="",
        )
        init_db(settings)
        with (
            patch.object(routes, "get_settings", lambda: settings),
            patch.object(auth, "get_settings", lambda: settings),
        ):
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="http://localhost"
            ) as client:
                for path in ["/api/v1/reports", "/api/v1/quarantine", "/openapi.json"]:
                    response = await client.get(path)
                    observe(
                        f"unauthenticated {path}",
                        response.status_code in {401, 403, 404},
                        {"status": response.status_code},
                    )
                client.headers["X-Sentinel-Request"] = "1"
                registered = await client.post(
                    "/api/v1/auth/register",
                    json={"username": "audit", "password": "audit-test-password-123"},
                )
                assert registered.status_code == 201
                client.headers["X-CSRF-Token"] = registered.json()["csrf"]
                response = await client.get(
                    "/api/v1/stats", headers={"Host": "audit.invalid"}
                )
                observe(
                    "untrusted Host rejected",
                    response.status_code == 400,
                    {"status": response.status_code},
                )
                response = await client.post(
                    "/api/v1/selected-folder-scan",
                    content=json.dumps({"files": [{"path": "chosen/file", "size": 0}]}),
                    headers={
                        "Origin": "https://audit.invalid",
                        "X-Sentinel-Request": "",
                        "X-CSRF-Token": "",
                    },
                )
                observe(
                    "cross-origin POST without Content-Type blocked",
                    response.status_code in {400, 401, 403, 415},
                    {"status": response.status_code, "content_type_sent": False},
                )
                response = await client.post(
                    "/api/v1/selected-folder-scan",
                    json={"files": [{"path": "chosen/file", "size": 0}]},
                )
                job_id = response.json().get("job_id")
                if job_id:
                    async with httpx.AsyncClient(
                        transport=httpx.ASGITransport(app=app),
                        base_url="http://localhost",
                    ) as anonymous:
                        response = await anonymous.get(f"/api/v1/scan/{job_id}")
                    observe(
                        "job ownership enforced",
                        response.status_code in {401, 403},
                        {"anonymous_read_status": response.status_code},
                    )
                    await client.delete(f"/api/v1/selected-folder-scan/{job_id}")
                response = await client.options(
                    "/api/v1/selected-folder-scan",
                    headers={
                        "Origin": "https://audit.invalid",
                        "Access-Control-Request-Method": "POST",
                        "Access-Control-Request-Headers": "content-type",
                    },
                )
                observe(
                    "CORS does not grant arbitrary origins",
                    "access-control-allow-origin" not in response.headers,
                    {
                        "status": response.status_code,
                        "allow_origin": response.headers.get(
                            "access-control-allow-origin"
                        ),
                    },
                )
                for path in [
                    "../secret",
                    "/etc/passwd",
                    "chosen/../../secret",
                    ".",
                    "~/.ssh/key",
                ]:
                    response = await client.post(
                        "/api/v1/selected-folder-scan",
                        json={"files": [{"path": path, "size": 0}]},
                    )
                    observe(
                        f"upload path rejected: {path}",
                        response.status_code == 400,
                        {"status": response.status_code},
                    )
                response = await client.get(
                    "/api/v1/reports",
                    params={
                        "verdict": "' OR 1=1; DROP TABLE scan;--",
                        "type": "<script>alert(1)</script>",
                    },
                )
                with connect(settings.database_url) as conn:
                    exists = (
                        conn.execute("SELECT COUNT(*) FROM scan").fetchone()[0] == 0
                    )
                observe(
                    "report SQL injection payload harmless",
                    response.status_code == 200
                    and exists
                    and response.json()["total"] == 0,
                    {"status": response.status_code, "table_preserved": exists},
                )
                response = await client.get("/api/v1/quarantine/payload.bin")
                observe(
                    "quarantine payload endpoint absent",
                    response.status_code == 404,
                    {"status": response.status_code},
                )
                for path, body in [
                    ("/api/v1/scan", {"type": "hash", "value": "not-a-hash"}),
                    ("/api/v1/selected-folder-scan", {"files": []}),
                ]:
                    response = await client.post(path, json=body)
                    observe(
                        f"invalid input handled: {path}",
                        response.status_code in {400, 422},
                        {"status": response.status_code},
                    )
                before = len(routes.JOBS)
                for _ in range(8):
                    response = await client.post(
                        "/api/v1/selected-folder-scan",
                        json={"files": [{"path": "chosen/file", "size": 0}]},
                    )
                    assert response.status_code == 202
                    await client.delete(
                        f"/api/v1/selected-folder-scan/{response.json()['job_id']}"
                    )
                observe(
                    "terminal jobs bounded or evicted",
                    len(routes.JOBS) - before < 8,
                    {
                        "sequential_cancelled_jobs": 8,
                        "retained_jobs": len(routes.JOBS) - before,
                    },
                )
                for oversized, content in [(False, b"1234"), (True, b"")]:
                    response = await client.post(
                        "/api/v1/selected-folder-scan",
                        json={
                            "files": [
                                {"path": "chosen/file", "size": 10 if oversized else 1}
                            ]
                        },
                    )
                    job_id = response.json()["job_id"]
                    with patch.object(folders, "MAX_FILE_BYTES", 3):
                        response = await client.put(
                            f"/api/v1/selected-folder-scan/{job_id}/files/0",
                            content=content,
                        )
                    job = (await client.get(f"/api/v1/scan/{job_id}")).json()
                    passed = (
                        (response.status_code == 200 and job["skipped"] == 1)
                        if oversized
                        else (response.status_code == 413 and job["status"] == "failed")
                    )
                    observe(
                        "declared oversized files skipped"
                        if oversized
                        else "stream size limit enforced",
                        passed,
                        {"status": response.status_code, "job_status": job["status"]},
                    )

                def broken(*args):
                    raise RuntimeError("SECURITY_AUDIT_INTERNAL_DETAIL")

                with patch.object(routes.scanner, "run_batch", broken):
                    response = await client.post(
                        "/api/v1/batch-scan",
                        json={"iocs": [{"type": "hash", "value": "a" * 64}]},
                    )
                    job_id = response.json()["job_id"]
                    for _ in range(100):
                        job = (await client.get(f"/api/v1/scan/{job_id}")).json()
                        if job["status"] == "failed":
                            break
                        await asyncio.sleep(0.01)
                    observe(
                        "internal batch exceptions are redacted",
                        "SECURITY_AUDIT_INTERNAL_DETAIL" not in json.dumps(job),
                        {"status": job["status"], "error": job.get("error")},
                    )
                # DNS names in indicators must not select the outbound request host.
                requested = []

                class FakeClient:
                    def __init__(self, **kwargs):
                        pass

                    def __enter__(self):
                        return self

                    def __exit__(self, *args):
                        pass

                    def get(self, url, **kwargs):
                        requested.append(url)
                        return httpx.Response(
                            200,
                            request=httpx.Request("GET", url),
                            json={"pulse_info": {"count": 0}},
                        )

                with patch.object(providers.httpx, "Client", FakeClient):
                    providers._query_alienvault(
                        "test", "url", "http://127.0.0.1:8000/private"
                    )
                observe(
                    "URL indicator does not select outbound host",
                    all(
                        httpx.URL(url).host == "otx.alienvault.com" for url in requested
                    ),
                    {
                        "outbound_hosts": [httpx.URL(url).host for url in requested],
                        "scope": "mocked OTX URL branch; other providers reviewed in source",
                    },
                )
        print(
            "SECURITY_AUDIT_JSON="
            + json.dumps(
                {
                    "observations": observations,
                    "controls_passed": sum(o["control_passed"] for o in observations),
                    "total_checks": len(observations),
                }
            )
        )


asyncio.run(main())
