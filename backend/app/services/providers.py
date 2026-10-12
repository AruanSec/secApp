import httpx

from ..config import Settings
from ..models import Verdict

_TIMEOUT = 15.0

_OTX_TYPE_MAP = {"hash": "file", "ip": "IPv4", "domain": "domain", "url": "url"}


def query_provider(
    provider: str, settings: Settings, ioc_type: str, value: str
) -> tuple[str, dict]:
    """Query a single provider. Returns (verdict, raw JSON payload)."""
    api_key = settings.provider_api_keys.get(provider)
    if not api_key:
        return Verdict.SKIPPED, {}

    try:
        if provider == "virustotal":
            verdict, raw = _query_virustotal(api_key, ioc_type, value)
        elif provider == "alienvault":
            verdict, raw = _query_alienvault(api_key, ioc_type, value)
        elif provider == "abusech":
            verdict, raw = _query_abusech(api_key, ioc_type, value)
        else:
            return Verdict.SKIPPED, {}
        return verdict, raw
    except (httpx.HTTPError, KeyError, TypeError, ValueError):
        return Verdict.UNKNOWN, {}


def _query_virustotal(api_key: str, ioc_type: str, value: str) -> tuple[str, dict]:
    headers = {"x-apikey": api_key}
    with httpx.Client(timeout=_TIMEOUT) as client:
        if ioc_type == "url":
            submit = client.post(
                "https://www.virustotal.com/api/v3/urls",
                headers=headers,
                data={"url": value},
            )
            submit.raise_for_status()
            analysis_id = submit.json()["data"]["id"]
            analysis = client.get(
                f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                headers=headers,
            )
            analysis.raise_for_status()
            payload = analysis.json()
            if payload["data"]["attributes"].get("status") != "completed":
                return Verdict.UNKNOWN, payload
            stats = payload["data"]["attributes"]["stats"]
        else:
            endpoint = {
                "hash": "files",
                "ip": "ip_addresses",
                "domain": "domains",
            }[ioc_type]
            response = client.get(
                f"https://www.virustotal.com/api/v3/{endpoint}/{value}",
                headers=headers,
            )
            if response.status_code == 404:
                return Verdict.UNKNOWN, {"detail": "not found"}
            response.raise_for_status()
            payload = response.json()
            stats = payload["data"]["attributes"]["last_analysis_stats"]

    return _verdict_from_vt_counts(stats), payload


def _verdict_from_vt_counts(stats: dict) -> str:
    if int(stats.get("malicious", 0) or 0) > 0:
        return Verdict.MALICIOUS
    if int(stats.get("suspicious", 0) or 0) > 0:
        return Verdict.SUSPICIOUS
    if int(stats.get("harmless", 0) or 0) > 0:
        return Verdict.CLEAN
    return Verdict.UNKNOWN


def _query_alienvault(api_key: str, ioc_type: str, value: str) -> tuple[str, dict]:
    otx_type = _OTX_TYPE_MAP.get(ioc_type)
    if not otx_type:
        return Verdict.SKIPPED, {}
    with httpx.Client(timeout=_TIMEOUT) as client:
        response = client.get(
            f"https://otx.alienvault.com/api/v1/indicators/{otx_type}/{value}/general",
            headers={"X-OTX-API-KEY": api_key},
        )
        if response.status_code == 404:
            return Verdict.UNKNOWN, {"detail": "not found"}
        response.raise_for_status()
        payload = response.json()

    pulses = int((payload.get("pulse_info") or {}).get("count", 0) or 0)
    verdict = Verdict.SUSPICIOUS if pulses > 0 else Verdict.UNKNOWN
    return verdict, payload


def _query_abusech(api_key: str, ioc_type: str, value: str) -> tuple[str, dict]:
    if ioc_type != "hash":
        return Verdict.SKIPPED, {}
    with httpx.Client(timeout=_TIMEOUT) as client:
        response = client.post(
            "https://mb-api.abuse.ch/api/v1/",
            data={"query": "get_info", "hash": value},
            headers={"Auth-Key": api_key},
        )
        response.raise_for_status()
        payload = response.json()

    status = payload.get("query_status")
    if status == "ok" and payload.get("data"):
        return Verdict.MALICIOUS, payload
    return Verdict.UNKNOWN, payload
