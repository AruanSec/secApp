"""Verify selected-folder uploads and real ClamAV quarantine with isolated fixtures.

    docker compose exec -T backend /app/lib/bin/python < deploy/verify_container.py

All test bytes, quarantine payloads, and database records use temporary storage.
"""

import asyncio
import json
import os
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory

import httpx

from app.api import routes
from app.config import get_settings
from app.db import connect, init_db
from app.main import app


async def verify():
    assert os.geteuid() != 0, "Backend must run as a non-root user"
    settings = get_settings()
    assert settings.clamd_enabled, "ClamAV must be configured"
    with TemporaryDirectory() as temp:
        root = Path(temp) / "chosen"
        (root / "nested").mkdir(parents=True)
        (root / "clean.txt").write_bytes(b"Harmless container scanner verification")
        (root / "nested" / "eicar.txt").write_bytes(
            b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        )
        config = replace(
            settings,
            database_url=str(Path(temp) / "verification.db"),
            quarantine_dir=str(Path(temp) / "quarantine"),
            virustotal_api_key="",
            alienvault_api_key="",
            abusech_api_key="",
        )
        init_db(config)
        routes.get_settings = lambda: config
        paths = [root / "clean.txt", root / "nested" / "eicar.txt"]
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.post(
                "/api/v1/selected-folder-scan",
                json={
                    "files": [
                        {"path": str(path.relative_to(Path(temp))), "size": path.stat().st_size}
                        for path in paths
                    ]
                },
            )
            assert response.status_code == 202, response.text
            job_id = response.json()["job_id"]
            for index, path in enumerate(paths):
                response = await client.put(
                    f"/api/v1/selected-folder-scan/{job_id}/files/{index}",
                    content=path.read_bytes(),
                )
                assert response.status_code == 200, response.text
            job = (await client.get(f"/api/v1/scan/{job_id}")).json()
            assert job["status"] == "completed", job
            verdicts = {result["path"]: result["verdict"] for result in job["results"]}
            assert verdicts == {"chosen/clean.txt": "clean", "chosen/nested/eicar.txt": "malicious"}
            infected = job["results"][1]
            assert infected["quarantine_status"] == "copy", infected
            assert all(path.exists() for path in paths), "Selected originals must remain"
            payload = Path(config.quarantine_dir) / f"{infected['quarantine_id']}.bin"
            assert payload.read_bytes() == paths[1].read_bytes()
            assert payload.stat().st_mode & 0o777 == 0o600
            assert (await client.get("/api/v1/quarantine")).json()["total"] == 1
            assert (await client.post("/api/v1/folder-scan", json={"path": "."})).status_code == 404
        with connect(config.database_url) as conn:
            assert conn.execute("SELECT COUNT(*) FROM scan").fetchone()[0] == 2
            assert conn.execute("SELECT status FROM quarantine").fetchone()[0] == "copy"
        print(
            json.dumps(
                {
                    "backend_uid": os.geteuid(),
                    "selected_folder_scan": verdicts,
                    "quarantine": "copy",
                }
            )
        )


asyncio.run(verify())
