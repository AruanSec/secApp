import base64
import hashlib
from dataclasses import replace

import httpx
import pytest

from app.config import get_settings
from app.db import init_db
from app.models import Verdict
from app.services import clamd, providers, scanner


@pytest.mark.parametrize(
    ("verdicts", "expected"),
    [
        ([], "unknown"),
        (["skipped"], "unknown"),
        (["clean", "unknown"], "unknown"),
        (["clean", "skipped"], "clean"),
        (["unknown", "suspicious"], "suspicious"),
        (["unknown", "malicious"], "malicious"),
    ],
)
def test_aggregate(verdicts, expected):
    assert scanner.aggregate(verdicts) == expected


@pytest.mark.parametrize(
    ("stats", "expected"),
    [
        ({}, "unknown"),
        ({"undetected": 10}, "unknown"),
        ({"harmless": 2}, "clean"),
        ({"malicious": 1, "harmless": 2}, "malicious"),
        ({"suspicious": 1}, "suspicious"),
    ],
)
def test_vt_counts(stats, expected):
    assert providers._verdict_from_vt_counts(stats) == expected


def mock_http(monkeypatch, handler):
    real_client = httpx.Client
    monkeypatch.setattr(
        providers.httpx,
        "Client",
        lambda **kwargs: real_client(transport=httpx.MockTransport(handler), **kwargs),
    )


@pytest.mark.parametrize("provider", ["virustotal", "alienvault"])
def test_not_found_is_unknown(monkeypatch, provider):
    mock_http(monkeypatch, lambda request: httpx.Response(404))
    settings = replace(get_settings(), virustotal_api_key="test", alienvault_api_key="test")
    assert providers.query_provider(provider, settings, "hash", "a" * 64)[0] == Verdict.UNKNOWN


@pytest.mark.parametrize("status", ["queued", "in-progress", "completed"])
def test_url_analysis_status(monkeypatch, status):
    def handler(request):
        if request.method == "POST":
            return httpx.Response(200, json={"data": {"id": "analysis"}})
        return httpx.Response(
            200,
            json={
                "data": {
                    "attributes": {
                        "status": status,
                        "stats": {"harmless": 1},
                    }
                }
            },
        )

    mock_http(monkeypatch, handler)
    expected = Verdict.CLEAN if status == "completed" else Verdict.UNKNOWN
    assert providers._query_virustotal("test", "url", "https://example.com")[0] == expected


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"query_status": "hash_not_found"},
        {"query_status": "illegal_hash"},
        {"query_status": "ok", "data": [{"sha256_hash": "a" * 64}]},
    ],
)
def test_abusech_status(monkeypatch, payload):
    mock_http(monkeypatch, lambda request: httpx.Response(200, json=payload))
    expected = Verdict.MALICIOUS if payload.get("data") else Verdict.UNKNOWN
    assert providers._query_abusech("test", "hash", "a" * 64)[0] == expected


@pytest.mark.parametrize("count", [0, 1])
def test_otx_pulses_are_not_clean_or_confirmed_malware(monkeypatch, count):
    mock_http(
        monkeypatch, lambda request: httpx.Response(200, json={"pulse_info": {"count": count}})
    )
    expected = Verdict.SUSPICIOUS if count else Verdict.UNKNOWN
    assert providers._query_alienvault("test", "domain", "example.com")[0] == expected


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"data": None},
        {
            "data": {
                "attributes": {
                    "last_analysis_stats": {"malicious": "invalid"},
                }
            }
        },
    ],
)
def test_malformed_provider_response_is_unknown(monkeypatch, payload):
    mock_http(monkeypatch, lambda request: httpx.Response(200, json=payload))
    settings = replace(get_settings(), virustotal_api_key="test")
    assert providers.query_provider("virustotal", settings, "hash", "a" * 64)[0] == Verdict.UNKNOWN


@pytest.mark.parametrize("ioc_type", ["hash", "file"])
def test_scan_reputation_lookup(tmp_path, monkeypatch, ioc_type):
    settings = replace(get_settings(), database_url=str(tmp_path / "scan.db"), clamd_host="clamd")
    init_db(settings)
    calls = []

    def fake_provider(provider, settings, kind, value):
        calls.append((kind, value))
        return Verdict.MALICIOUS, {}

    def fake_clamd(settings, data):
        assert ioc_type == "file", "hashes must never be scanned as file bytes"
        return Verdict.UNKNOWN

    monkeypatch.setattr(providers, "query_provider", fake_provider)
    monkeypatch.setattr(clamd, "scan_file", fake_clamd)
    content = b"test file"
    value = "a" * 64 if ioc_type == "hash" else base64.b64encode(content).decode()
    result = scanner.scan_one(settings, ioc_type, value)
    expected = value if ioc_type == "hash" else hashlib.sha256(content).hexdigest()
    assert calls == [("hash", expected)] * 3
    assert result["verdict"] == Verdict.MALICIOUS
    assert result["type"] == ioc_type
    assert result["value"] == value


@pytest.mark.parametrize(
    ("chunks", "expected"),
    [
        ([b"stream: O", b"K\x00"], "clean"),
        ([b"stream: Eicar FOUND\x00"], "malicious"),
        ([b"stream: scan failed ERROR\x00"], "unknown"),
        ([b"stream: OK", b""], "unknown"),
    ],
)
def test_clamd_protocol(monkeypatch, chunks, expected):
    class Socket:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def sendall(self, data):
            pass

        def recv(self, size):
            return chunks.pop(0)

    monkeypatch.setattr(clamd.socket, "create_connection", lambda *args, **kwargs: Socket())
    settings = replace(get_settings(), clamd_host="clamd")
    assert clamd.scan_file(settings, b"content") == expected


def test_clamd_failure_still_allows_reputation_lookup(tmp_path, monkeypatch):
    settings = replace(get_settings(), database_url=str(tmp_path / "scan.db"), clamd_host="clamd")
    init_db(settings)

    def unavailable(*args):
        raise OSError("unavailable")

    monkeypatch.setattr(clamd, "scan_file", unavailable)
    monkeypatch.setattr(providers, "query_provider", lambda *args: (Verdict.MALICIOUS, {}))
    result = scanner.scan_one(settings, "file", base64.b64encode(b"content").decode())
    assert result["verdict"] == Verdict.MALICIOUS
    assert result["providers"]["clamd"] == Verdict.UNKNOWN


def test_cached_clean_verdict_is_rechecked(tmp_path, monkeypatch):
    settings = replace(
        get_settings(), database_url=str(tmp_path / "scan.db"), clamd_host="", cache_ttl_hours=24
    )
    init_db(settings)
    monkeypatch.setattr(providers, "query_provider", lambda *args: (Verdict.CLEAN, {}))
    assert scanner.scan_one(settings, "hash", "a" * 64)["verdict"] == Verdict.CLEAN
    monkeypatch.setattr(providers, "query_provider", lambda *args: (Verdict.MALICIOUS, {}))
    assert scanner.scan_one(settings, "hash", "a" * 64)["verdict"] == Verdict.MALICIOUS
