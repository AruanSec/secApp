import base64
import binascii
import ipaddress
import re
from urllib.parse import urlparse

from ..models import IoCType

_HASH_RE = re.compile(r"^[0-9a-fA-F]{32}$|^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$|^[0-9a-fA-F]{128}$")
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$"
)
_MAX_FILE_BYTES = 25 * 1024 * 1024


def validate_ioc(ioc_type: str, value: str) -> None:
    """Raise ValueError when the value does not match the declared IoC type."""
    value = value.strip()
    if not value:
        raise ValueError("value must not be empty")

    if ioc_type == IoCType.HASH:
        if not _HASH_RE.match(value):
            raise ValueError("hash must be a hex md5, sha1, sha256 or sha512 digest")
    elif ioc_type == IoCType.IP:
        try:
            ipaddress.ip_address(value)
        except ValueError as exc:
            raise ValueError("invalid IP address") from exc
    elif ioc_type == IoCType.DOMAIN:
        if not _DOMAIN_RE.match(value):
            raise ValueError("invalid domain name")
    elif ioc_type == IoCType.URL:
        parsed = urlparse(value)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("url must use http(s) and include a host")
    elif ioc_type == IoCType.FILE:
        try:
            data = base64.b64decode(value, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ValueError("file must be base64-encoded content") from exc
        if len(data) > _MAX_FILE_BYTES:
            raise ValueError("file exceeds 25 MB limit")
    else:
        raise ValueError(f"unsupported IoC type: {ioc_type}")
