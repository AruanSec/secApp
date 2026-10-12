import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

_DEFAULT_DB = Path(__file__).resolve().parent.parent / "data" / "sentinel.db"


@dataclass(frozen=True)
class Settings:
    database_url: str
    clamd_host: str
    clamd_port: int
    virustotal_api_key: str
    alienvault_api_key: str
    abusech_api_key: str
    clean_ttl_days: int
    cache_ttl_hours: int
    quarantine_dir: str = ""

    @property
    def clamd_enabled(self) -> bool:
        return bool(self.clamd_host)

    @property
    def provider_api_keys(self) -> dict[str, str]:
        return {
            "virustotal": self.virustotal_api_key.strip(),
            "alienvault": self.alienvault_api_key.strip(),
            "abusech": self.abusech_api_key.strip(),
        }


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


@lru_cache
def get_settings() -> Settings:
    return Settings(
        database_url=os.getenv("DATABASE_URL", str(_DEFAULT_DB)),
        clamd_host=os.getenv("CLAMD_HOST", ""),
        clamd_port=_env_int("CLAMD_PORT", 3310),
        virustotal_api_key=os.getenv("VIRUSTOTAL_API_KEY", ""),
        alienvault_api_key=os.getenv("ALIENVAULT_API_KEY", ""),
        abusech_api_key=os.getenv("ABUSECH_API_KEY", ""),
        clean_ttl_days=_env_int("CLEAN_TTL_DAYS", 30),
        cache_ttl_hours=_env_int("CACHE_TTL_HOURS", 24),
        quarantine_dir=os.getenv("QUARANTINE_DIR", ""),
    )
