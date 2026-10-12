"""Limits and relative-path validation for browser-selected folder uploads."""

from pathlib import Path

MAX_FILE_BYTES = 25 * 1024 * 1024
MAX_ENTRIES = 10_000


def relative_parts(path: str) -> tuple[str, ...]:
    requested = Path(path)
    if requested.is_absolute() or ".." in requested.parts or path.startswith("~"):
        raise ValueError("Use a relative file path within the selected folder")
    return requested.parts
