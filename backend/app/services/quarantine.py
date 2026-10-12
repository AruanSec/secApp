"""Persist isolated malicious payloads; never expose payload bytes through the API."""

import hashlib
import logging
import os
import uuid
from pathlib import Path

from ..auth import owner
from ..config import Settings
from ..db import connect, now

logger = logging.getLogger(__name__)


def storage_root(settings: Settings) -> Path:
    root = Path(settings.quarantine_dir or Path(settings.database_url).parent / "quarantine")
    root = root.absolute()
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    if root.is_symlink():
        raise ValueError("Quarantine directory must not be a symbolic link")
    os.chmod(root, 0o700)
    return root


def isolate(settings: Settings, data: bytes, result: dict) -> None:
    if result.get("verdict") != "malicious":
        return
    identifier = uuid.uuid4().hex
    payload = None
    try:
        root = storage_root(settings)
        payload = root / f"{identifier}.bin"
        fd = os.open(payload, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        for directory in (root, root.parent):
            directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        digest = hashlib.sha256(data).hexdigest()
        with connect(settings.database_url) as conn:
            conn.execute(
                "INSERT INTO quarantine (id, scan_id, original_path, sha256, size, origin, "
                "status, error, created_at, owner_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    identifier,
                    result["scan_id"],
                    result["path"],
                    digest,
                    len(data),
                    "upload",
                    "copy",
                    None,
                    now(),
                    owner.get(),
                ),
            )
    except Exception:
        logger.exception("Quarantine storage failed")
        if payload is not None:
            try:
                payload.unlink(missing_ok=True)
            except OSError:
                logger.exception("Unable to remove incomplete quarantine payload")
        result.update(
            quarantine_status="failed",
            quarantine_error="Could not store quarantine file; original retained",
        )
        return
    result.update(quarantine_id=identifier, quarantine_status="copy")
