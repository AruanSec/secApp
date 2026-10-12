import argparse

from .config import get_settings
from .services.scanner import run_purge


def main() -> None:
    parser = argparse.ArgumentParser(prog="sentinel-purge", description="Purge expired clean scans")
    parser.add_argument("--days", type=int, help="override CLEAN_TTL_DAYS")
    args = parser.parse_args()

    if args.days:
        import os

        os.environ["CLEAN_TTL_DAYS"] = str(args.days)
        get_settings.cache_clear()

    result = run_purge(get_settings())
    print(f"purged {result['purged']} clean scans (expired before {result['expired_before']})")


if __name__ == "__main__":
    main()
