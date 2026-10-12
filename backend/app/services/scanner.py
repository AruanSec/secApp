import hashlib
import json
import logging
import sqlite3
import uuid
from datetime import UTC, datetime, timedelta

from ..auth import owner
from ..config import Settings, get_settings
from ..db import connect, insert_scan, insert_scan_result, now, upsert_ioc
from ..models import IoCType, ScanStatus, Verdict
from . import clamd, providers
from .validate import validate_ioc

logger = logging.getLogger(__name__)


def aggregate(verdicts: list[str]) -> str:
    if any(v == Verdict.MALICIOUS for v in verdicts):
        return Verdict.MALICIOUS
    if any(v == Verdict.SUSPICIOUS for v in verdicts):
        return Verdict.SUSPICIOUS
    if Verdict.UNKNOWN in verdicts:
        return Verdict.UNKNOWN
    if any(v == Verdict.CLEAN for v in verdicts):
        return Verdict.CLEAN
    return Verdict.UNKNOWN


def scan_one(settings: Settings, ioc_type: str, value: str) -> dict:
    validate_ioc(ioc_type, value)

    with connect(settings.database_url) as conn:
        cached = _fresh_cached_scan(conn, settings, ioc_type, value)
        if cached is not None:
            return cached

    file_data = clamd.clamd_data(ioc_type, value) if ioc_type == IoCType.FILE else None
    return _scan_uncached(settings, ioc_type, value, file_data)


def scan_file_content(settings: Settings, data: bytes) -> dict:
    """Scan actual file bytes and persist only their SHA-256, never their contents."""
    return _scan_uncached(settings, IoCType.HASH, hashlib.sha256(data).hexdigest(), data)


def _scan_uncached(settings: Settings, ioc_type: str, value: str, file_data: bytes | None) -> dict:
    scan_id = _scan_id()
    created_at = now()

    providers_meta = {}
    clamd_verdict = Verdict.SKIPPED
    if file_data is not None and settings.clamd_enabled:
        try:
            clamd_verdict = clamd.scan_file(settings, file_data)
        except OSError:
            logger.exception("clamd scan failed")
            clamd_verdict = Verdict.UNKNOWN
        providers_meta["clamd"] = clamd_verdict

    result_verdicts = [v for v in providers_meta.values() if v != Verdict.SKIPPED]
    provider_results: list[tuple[str, str, dict]] = []
    if clamd_verdict != Verdict.SKIPPED:
        provider_results.append(("clamd", clamd_verdict, {}))
    should_enrich = clamd_verdict == Verdict.SKIPPED or clamd_verdict in (
        Verdict.MALICIOUS,
        Verdict.SUSPICIOUS,
        Verdict.UNKNOWN,
    )
    if should_enrich:
        lookup_type = IoCType.HASH if ioc_type == IoCType.FILE else ioc_type
        lookup_value = hashlib.sha256(file_data).hexdigest() if ioc_type == IoCType.FILE else value
        for provider in settings.provider_api_keys:
            verdict, raw = providers.query_provider(provider, settings, lookup_type, lookup_value)
            providers_meta[provider] = verdict
            result_verdicts.append(verdict)
            if verdict != Verdict.SKIPPED:
                provider_results.append((provider, verdict, raw))

    with connect(settings.database_url) as conn:
        ioc_id = upsert_ioc(conn, ioc_type, value)
        return _persist_scan(
            conn,
            scan_id,
            ioc_id,
            ioc_type,
            value,
            result_verdicts,
            providers_meta,
            created_at,
            provider_results,
        )


def _fresh_cached_scan(
    conn: sqlite3.Connection, settings: Settings, ioc_type: str, value: str
) -> dict | None:
    ttl = timedelta(hours=settings.cache_ttl_hours)
    cutoff = (datetime.now(UTC) - ttl).isoformat()
    row = conn.execute(
        """
        SELECT s.*, i.type, i.value
        FROM scan s JOIN ioc i ON i.id = s.ioc_id
        WHERE i.type = ? AND i.value = ? AND s.created_at >= ? AND s.owner_id IS ?
        ORDER BY s.created_at DESC LIMIT 1
        """,
        (ioc_type, value, cutoff, owner.get()),
    ).fetchone()
    # Historical clean records may have been produced from missing provider data
    # or a scan of hash bytes. Re-evaluate them instead of trusting that verdict.
    if row is None or row["verdict"] in (Verdict.UNKNOWN, Verdict.CLEAN):
        return None

    results = conn.execute(
        "SELECT provider, verdict FROM scan_result WHERE scan_id = ?",
        (row["id"],),
    ).fetchall()
    providers_meta = {r["provider"]: r["verdict"] for r in results}
    return {
        "scan_id": row["id"],
        "type": row["type"],
        "value": row["value"],
        "verdict": row["verdict"],
        "source": "cache",
        "created_at": row["created_at"],
        "providers": providers_meta,
    }


def _scan_id() -> str:
    return str(uuid.uuid4())


def _persist_scan(
    conn: sqlite3.Connection,
    scan_id: str,
    ioc_id: int,
    ioc_type: str,
    value: str,
    result_verdicts: list[str],
    providers_meta: dict[str, str],
    created_at: str,
    provider_results: list[tuple[str, str, dict]] | None = None,
) -> dict:
    verdict = aggregate(result_verdicts)
    source = "+".join(sorted(providers_meta)) or "none"
    insert_scan(conn, scan_id, ioc_id, verdict, source, ScanStatus.COMPLETED, created_at)
    for provider, provider_verdict, raw in provider_results or []:
        insert_scan_result(conn, scan_id, provider, provider_verdict, json.dumps(raw), created_at)
    logger.info("scan %s -> %s (%s)", scan_id, verdict, source)
    return {
        "scan_id": scan_id,
        "type": ioc_type,
        "value": value,
        "verdict": verdict,
        "source": source,
        "created_at": created_at,
        "providers": providers_meta,
    }


def run_batch(settings: Settings, iocs: list[dict[str, str]]) -> list[dict]:
    results: list[dict] = []
    for ioc in iocs:
        try:
            results.append(scan_one(settings, ioc["type"], ioc["value"]))
        except ValueError as exc:
            results.append({"type": ioc["type"], "value": ioc["value"], "error": str(exc)})
        except Exception as exc:
            logger.exception("batch scan failed for %s", ioc.get("value"))
            results.append({"type": ioc["type"], "value": ioc["value"], "error": str(exc)})
    return results


def run_purge(settings: Settings | None = None) -> dict:
    settings = settings or get_settings()
    threshold = (datetime.now(UTC) - timedelta(days=settings.clean_ttl_days)).isoformat()
    run_at = now()
    deleted = 0
    with connect(settings.database_url) as conn:
        cur = conn.execute(
            "DELETE FROM scan WHERE verdict = ? AND created_at < ?", (Verdict.CLEAN, threshold)
        )
        deleted = int(cur.rowcount)
        conn.execute(
            "DELETE FROM ioc WHERE id NOT IN (SELECT DISTINCT ioc_id FROM scan)",
        )
        conn.execute(
            "INSERT INTO purge_log(run_at, deleted_count, expired_before) VALUES (?, ?, ?)",
            (run_at, deleted, threshold),
        )
    logger.info("purge removed %d clean scans older than %s", deleted, threshold)
    return {"purged": deleted, "expired_before": threshold, "run_at": run_at}
