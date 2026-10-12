def test_health(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_scan_clean_ip(client):
    response = client.post("/api/v1/scan", json={"type": "ip", "value": "8.8.8.8"})
    assert response.status_code == 200
    body = response.json()
    assert body["type"] == "ip"
    assert body["verdict"] in {"clean", "unknown", "malicious", "suspicious"}
    assert body["scan_id"]


def test_scan_invalid_hash_is_400(client):
    response = client.post("/api/v1/scan", json={"type": "hash", "value": "not-a-hash"})
    assert response.status_code == 400
    assert "error" in response.json() or "detail" in response.json()


def test_scan_malicious_domain_with_mocked_provider(client, monkeypatch):
    def fake_query(provider, settings, ioc_type, value):
        return ("malicious", {"mock": True})

    monkeypatch.setattr("app.services.providers.query_provider", fake_query)
    response = client.post("/api/v1/scan", json={"type": "domain", "value": "evil.example.org"})
    assert response.status_code == 200
    body = response.json()
    assert body["verdict"] == "malicious"
    assert body["providers"]["virustotal"] == "malicious"


def test_batch_scan_returns_job_and_job_completes(client):
    response = client.post(
        "/api/v1/batch-scan",
        json={
            "iocs": [{"type": "ip", "value": "1.1.1.1"}, {"type": "domain", "value": "example.com"}]
        },
    )
    assert response.status_code == 202
    job_id = response.json()["job_id"]

    import time

    for _ in range(50):
        job = client.get(f"/api/v1/scan/{job_id}").json()
        if job["status"] in {"completed", "failed"}:
            break
        time.sleep(0.05)
    assert job["status"] == "completed"
    assert len(job["results"]) == 2


def test_batch_job_not_found_is_404(client):
    response = client.get("/api/v1/scan/does-not-exist")
    assert response.status_code == 404


def test_reports_pagination_and_stats(client):
    client.post("/api/v1/scan", json={"type": "ip", "value": "9.9.9.9"})
    reports = client.get("/api/v1/reports", params={"page": 1, "page_size": 5})
    assert reports.status_code == 200
    body = reports.json()
    assert body["page"] == 1
    assert body["total"] >= 1
    assert isinstance(body["items"], list)

    stats = client.get("/api/v1/stats").json()
    assert stats["total_scans"] >= 1
    assert isinstance(stats["by_verdict"], dict)
    assert isinstance(stats["by_type"], dict)
