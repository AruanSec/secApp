"""Explicit host-side bootstrap: python -m app.manage_admin promote USERNAME."""

import argparse

from .config import get_settings
from .db import connect, init_db, now


def main():
    parser = argparse.ArgumentParser(description="Promote an existing account to administrator")
    parser.add_argument("action", choices=["promote"])
    parser.add_argument("username")
    args = parser.parse_args()
    settings = get_settings()
    init_db(settings)
    with connect(settings.database_url) as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            "SELECT id FROM account WHERE username=?", (args.username.lower(),)
        ).fetchone()
        if row is None:
            parser.error("Account does not exist; create it through the frontend first")
        conn.execute("UPDATE account SET is_admin=1 WHERE id=?", (row["id"],))
        conn.execute("DELETE FROM auth_session WHERE user_id=?", (row["id"],))
        conn.execute(
            "INSERT INTO admin_audit(actor_id, action, target_id, created_at) VALUES (?, ?, ?, ?)",
            ("host-cli", "promote", row["id"], now()),
        )
    print(f"Administrator enabled for {args.username.lower()}. Sign in again.")


if __name__ == "__main__":
    main()
