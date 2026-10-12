from enum import StrEnum


class IoCType(StrEnum):
    FILE = "file"
    HASH = "hash"
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"


class Verdict(StrEnum):
    CLEAN = "clean"
    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    UNKNOWN = "unknown"
    SKIPPED = "skipped"


class ScanStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
