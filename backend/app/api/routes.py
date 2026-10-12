import asyncio
import logging
import time
import uuid
from dataclasses import dataclass, field

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from ..auth import administrator, current_user, owner
from ..config import get_settings
from ..db import connect
from ..models import ScanStatus
from ..schemas import (
    BatchScanRequest,
    BatchScanResponse,
    FolderConfigResponse,
    IoCScanRequest,
    JobStatusResponse,
    QuarantineResponse,
    ReportRow,
    ReportsResponse,
    ScanResponse,
    SelectedFile,
    SelectedFolderRequest,
    StatsResponse,
)
from ..services import folders, quarantine, scanner

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1", tags=["scan"], dependencies=[Depends(current_user)])


@dataclass
class Job:
    owner_id: str | None = field(default_factory=owner.get)
    status: str = ScanStatus.PENDING
    results: list[dict] = field(default_factory=list)
    error: str | None = None
    kind: str = "batch"
    processed: int = 0
    scanned: int = 0
    skipped: int = 0
    errors: int = 0
    files: list[SelectedFile] = field(default_factory=list)
    uploading: bool = False
    touched: float = field(default_factory=time.monotonic)


JOBS: dict[str, Job] = {}
_background_tasks: set[asyncio.Task] = set()


def _record_file(job: Job, result: dict) -> None:
    job.results.append(result)
    job.processed += 1
    if result.get("skipped"):
        job.skipped += 1
    elif result.get("error"):
        job.errors += 1
    else:
        job.scanned += 1


@router.post("/selected-folder-scan", response_model=BatchScanResponse, status_code=202)
async def selected_folder_scan(body: SelectedFolderRequest) -> dict:
    if not get_settings().clamd_enabled:
        raise HTTPException(status_code=503, detail="Configure ClamAV first")
    for file in body.files:
        try:
            if not folders.relative_parts(file.path):
                raise ValueError("A file path is required")
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="Invalid relative file path") from exc
    if len({file.path for file in body.files}) != len(body.files):
        raise HTTPException(status_code=400, detail="Duplicate file paths")
    for job in JOBS.values():
        if (
            job.kind == "upload"
            and not job.uploading
            and time.monotonic() - job.touched > 600
            and job.status in (ScanStatus.PENDING, ScanStatus.RUNNING)
        ):
            job.status = ScanStatus.FAILED
            job.error = "Folder upload expired; select the folder and retry"
    if any(
        job.kind == "upload" and job.status in (ScanStatus.PENDING, ScanStatus.RUNNING)
        for job in JOBS.values()
    ):
        raise HTTPException(status_code=409, detail="A folder scan is already running")
    job_id = str(uuid.uuid4())
    JOBS[job_id] = Job(kind="upload", files=body.files)
    return {"job_id": job_id}


@router.put("/selected-folder-scan/{job_id}/files/{index}", response_model=BatchScanResponse)
async def upload_folder_file(job_id: str, index: int, request: Request) -> dict:
    job = JOBS.get(job_id)
    if (
        job is None
        or (job.owner_id != owner.get() and not administrator.get())
        or job.kind != "upload"
    ):
        raise HTTPException(status_code=404, detail="Folder job not found")
    if (
        job.status not in (ScanStatus.PENDING, ScanStatus.RUNNING)
        or job.uploading
        or index != job.processed
        or not 0 <= index < len(job.files)
    ):
        raise HTTPException(status_code=409, detail="File is out of order or job is inactive")
    owner_marker = owner.set(job.owner_id)
    job.uploading = True
    job.status = ScanStatus.RUNNING
    file = job.files[index]
    result = {"type": "file", "value": "", "path": file.path, "size": file.size}
    try:
        if file.size > folders.MAX_FILE_BYTES:
            result.update(skipped=True, error="File exceeds 25 MB limit")
        else:
            data = bytearray()
            async for chunk in request.stream():
                if len(data) + len(chunk) > folders.MAX_FILE_BYTES:
                    raise HTTPException(status_code=413, detail="File exceeds 25 MB limit")
                data.extend(chunk)
            if len(data) != file.size:
                raise HTTPException(status_code=400, detail="File size changed; retry the scan")
            try:
                result.update(
                    await asyncio.to_thread(scanner.scan_file_content, get_settings(), bytes(data))
                )
                await asyncio.to_thread(quarantine.isolate, get_settings(), bytes(data), result)
            except Exception:
                logger.exception("Selected file scan failed for job %s", job_id)
                result["error"] = "File scan failed; retry the scan"
        _record_file(job, result)
        if job.processed == len(job.files):
            job.status = ScanStatus.COMPLETED
    except BaseException:
        job.status = ScanStatus.FAILED
        job.error = "Folder upload interrupted; select the folder and retry"
        raise
    finally:
        owner.reset(owner_marker)
        job.uploading = False
        job.touched = time.monotonic()
    return {"job_id": job_id}


@router.delete("/selected-folder-scan/{job_id}", response_model=BatchScanResponse)
async def cancel_selected_folder(job_id: str) -> dict:
    job = JOBS.get(job_id)
    if (
        job is None
        or (job.owner_id != owner.get() and not administrator.get())
        or job.kind != "upload"
    ):
        raise HTTPException(status_code=404, detail="Folder job not found")
    if job.uploading:
        raise HTTPException(status_code=409, detail="A file is still being scanned")
    if job.status in (ScanStatus.PENDING, ScanStatus.RUNNING):
        job.status = ScanStatus.FAILED
        job.error = "Folder upload interrupted; select the folder and retry"
    return {"job_id": job_id}


@router.post("/scan", response_model=ScanResponse)
def scan_ioc(body: IoCScanRequest) -> dict:
    settings = get_settings()
    try:
        return scanner.scan_one(settings, body.type, body.value)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("scan failed for %s", body.value)
        raise HTTPException(status_code=500, detail="scan failed") from exc


@router.get("/scan/{job_id}", response_model=JobStatusResponse)
def scan_job(job_id: str) -> dict:
    job = JOBS.get(job_id)
    if job is None or (job.owner_id != owner.get() and not administrator.get()):
        raise HTTPException(status_code=404, detail="job not found")
    return {
        "job_id": job_id,
        "status": job.status,
        "results": job.results,
        "error": job.error,
        "processed": job.processed,
        "scanned": job.scanned,
        "skipped": job.skipped,
        "errors": job.errors,
    }


@router.get("/provider-config")
def provider_config() -> dict:
    """Expose presence only; credentials stay in the backend environment."""
    return {
        "providers": {
            name: bool(key.strip()) for name, key in get_settings().provider_api_keys.items()
        }
    }


@router.get("/folder-config", response_model=FolderConfigResponse)
def folder_config() -> dict:
    return {
        "scanner_enabled": get_settings().clamd_enabled,
        "max_file_bytes": folders.MAX_FILE_BYTES,
        "max_entries": folders.MAX_ENTRIES,
    }


@router.get("/reports", response_model=ReportsResponse)
def reports(
    type: str | None = Query(default=None, alias="type"),
    verdict: str | None = Query(default=None),
    from_: str | None = Query(default=None, alias="from"),
    to: str | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
) -> dict:
    settings = get_settings()
    conditions: list[str] = [] if administrator.get() else ["s.owner_id = ?"]
    params: list[str] = [] if administrator.get() else [owner.get()]
    if type:
        conditions.append("i.type = ?")
        params.append(type)
    if verdict:
        conditions.append("s.verdict = ?")
        params.append(verdict)
    if from_:
        conditions.append("s.created_at >= ?")
        params.append(from_)
    if to:
        conditions.append("s.created_at <= ?")
        params.append(to)

    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    offset = (page - 1) * page_size

    with connect(settings.database_url) as conn:
        total = conn.execute(
            f"SELECT COUNT(*) AS n FROM scan s JOIN ioc i ON i.id = s.ioc_id {where}", params
        ).fetchone()["n"]
        rows = conn.execute(
            f"""
            SELECT s.id, s.verdict, s.source, s.created_at, i.type, i.value,
                   a.username AS owner_username
            FROM scan s JOIN ioc i ON i.id = s.ioc_id
            LEFT JOIN account a ON a.id=s.owner_id
            {where}
            ORDER BY s.created_at DESC
            LIMIT ? OFFSET ?
            """,
            [*params, page_size, offset],
        ).fetchall()

    items = [
        ReportRow(
            scan_id=row["id"],
            owner_username=row["owner_username"],
            type=row["type"],
            value=row["value"],
            verdict=row["verdict"],
            source=row["source"],
            created_at=row["created_at"],
        )
        for row in rows
    ]
    return {"page": page, "page_size": page_size, "total": int(total), "items": items}


@router.get("/stats", response_model=StatsResponse)
def stats() -> dict:
    settings = get_settings()
    scope = "1=1" if administrator.get() else "owner_id=?"
    params = () if administrator.get() else (owner.get(),)
    with connect(settings.database_url) as conn:
        total = conn.execute(f"SELECT COUNT(*) AS n FROM scan WHERE {scope}", params).fetchone()[
            "n"
        ]
        by_verdict = {
            row["verdict"]: int(row["n"])
            for row in conn.execute(
                f"SELECT verdict, COUNT(*) AS n FROM scan WHERE {scope} GROUP BY verdict",
                params,
            )
        }
        by_type = {
            row["type"]: int(row["n"])
            for row in conn.execute(
                "SELECT i.type, COUNT(*) AS n FROM scan s JOIN ioc i ON i.id = s.ioc_id "
                f"WHERE {scope} GROUP BY i.type",
                params,
            )
        }
    return {"total_scans": int(total), "by_verdict": by_verdict, "by_type": by_type}


async def _run_batch(job_id: str, iocs: list[dict[str, str]]) -> None:
    job = JOBS[job_id]
    job.status = ScanStatus.RUNNING
    settings = get_settings()
    try:
        results = await asyncio.to_thread(scanner.run_batch, settings, iocs)
    except Exception as exc:
        logger.exception("batch job %s failed", job_id)
        job.status = ScanStatus.FAILED
        job.error = str(exc)
        return
    job.results = results
    job.status = ScanStatus.COMPLETED


@router.post("/batch-scan", response_model=BatchScanResponse, status_code=202)
async def batch_scan(body: BatchScanRequest) -> dict:
    job_id = str(uuid.uuid4())
    JOBS[job_id] = Job()
    iocs = [{"type": ioc.type, "value": ioc.value} for ioc in body.iocs]
    task = asyncio.create_task(_run_batch(job_id, iocs))
    _background_tasks.add(task)
    task.add_done_callback(_background_tasks.discard)
    return {"job_id": job_id}


@router.get("/quarantine", response_model=QuarantineResponse)
def quarantine_records(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
) -> dict:
    scope = "1=1" if administrator.get() else "q.owner_id=?"
    params = () if administrator.get() else (owner.get(),)
    with connect(get_settings().database_url) as conn:
        total = conn.execute(f"SELECT COUNT(*) FROM quarantine q WHERE {scope}", params).fetchone()[
            0
        ]
        rows = conn.execute(
            "SELECT q.*, a.username AS owner_username FROM quarantine q "
            "LEFT JOIN account a ON a.id=q.owner_id "
            f"WHERE {scope} ORDER BY q.created_at DESC LIMIT ? OFFSET ?",
            (*params, page_size, (page - 1) * page_size),
        ).fetchall()
    return {"total": total, "items": [dict(row) for row in rows]}
