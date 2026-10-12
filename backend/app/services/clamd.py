import socket

from ..config import Settings
from ..models import Verdict

_ERR_TIMEOUT = 10


def scan_file(settings: Settings, data: bytes) -> str:
    """Stream <data> to clamd over INSTREAM and return a Verdict value."""
    if not settings.clamd_enabled:
        return Verdict.SKIPPED
    if not data:
        return Verdict.UNKNOWN

    with socket.create_connection(
        (settings.clamd_host, settings.clamd_port), timeout=_ERR_TIMEOUT
    ) as sock:
        sock.sendall(b"zINSTREAM\x00")
        for offset in range(0, len(data), 32 * 1024):
            chunk = data[offset : offset + 32 * 1024]
            sock.sendall(len(chunk).to_bytes(4, "big") + chunk)
        sock.sendall((0).to_bytes(4, "big"))
        response_bytes = bytearray()
        while b"\x00" not in response_bytes and len(response_bytes) < 4096:
            chunk = sock.recv(4096 - len(response_bytes))
            if not chunk:
                return Verdict.UNKNOWN
            response_bytes.extend(chunk)
        if b"\x00" not in response_bytes:
            return Verdict.UNKNOWN
        response = response_bytes.split(b"\x00", 1)[0].decode(errors="replace").strip()

    if response.startswith("stream:"):
        rest = response.removeprefix("stream:").strip()
        if rest == "OK":
            return Verdict.CLEAN
        if rest.endswith(" FOUND"):
            return Verdict.MALICIOUS
    return Verdict.UNKNOWN


def clamd_data(ioc_type: str, value: str) -> bytes:
    """Convert an IoC to the bytes clamd should inspect."""
    if ioc_type == "file":
        import base64

        return base64.b64decode(value)
    return b""
