from typing import Literal

from pydantic import BaseModel, Field

IoCTypeLiteral = Literal["file", "hash", "ip", "domain", "url"]


class IoCScanRequest(BaseModel):
    type: IoCTypeLiteral
    value: str = Field(min_length=1, max_length=4096)


class BatchScanRequest(BaseModel):
    iocs: list[IoCScanRequest] = Field(min_length=1, max_length=1000)


class FolderConfigResponse(BaseModel):
    scanner_enabled: bool
    max_file_bytes: int
    max_entries: int


class SelectedFile(BaseModel):
    path: str = Field(min_length=1, max_length=4096)
    size: int = Field(ge=0)


class SelectedFolderRequest(BaseModel):
    files: list[SelectedFile] = Field(min_length=1, max_length=10_000)


class ScanResponse(BaseModel):
    scan_id: str
    type: str
    value: str
    verdict: str
    source: str
    created_at: str
    providers: dict[str, str]


class BatchScanResponse(BaseModel):
    job_id: str


class JobResult(BaseModel):
    scan_id: str | None = None
    type: str
    value: str
    verdict: str | None = None
    error: str | None = None
    path: str | None = None
    size: int | None = None
    skipped: bool = False
    quarantine_id: str | None = None
    quarantine_status: str | None = None
    quarantine_error: str | None = None


class JobStatusResponse(BaseModel):
    job_id: str
    status: str
    results: list[JobResult] = []
    error: str | None = None
    processed: int = 0
    scanned: int = 0
    skipped: int = 0
    errors: int = 0


class ReportRow(BaseModel):
    owner_username: str | None = None
    scan_id: str
    type: str
    value: str
    verdict: str
    source: str
    created_at: str


class ReportsResponse(BaseModel):
    page: int
    page_size: int
    total: int
    items: list[ReportRow]


class StatsResponse(BaseModel):
    total_scans: int
    by_verdict: dict[str, int]
    by_type: dict[str, int]


class ErrorResponse(BaseModel):
    error: dict[str, str]


class QuarantineRow(BaseModel):
    owner_username: str | None = None
    id: str
    scan_id: str
    original_path: str
    sha256: str
    size: int
    origin: str
    status: str
    error: str | None
    created_at: str


class QuarantineResponse(BaseModel):
    total: int
    items: list[QuarantineRow]
