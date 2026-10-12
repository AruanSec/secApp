"""Administrator-only account inventory and job control."""

import secrets
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, SecretStr

from .api.routes import JOBS, scan_job
from .auth import password_hash, require_admin
from .config import get_settings
from .db import connect, now

router = APIRouter(prefix="/api/v1/admin", tags=["admin"], dependencies=[Depends(require_admin)])


@router.get("/users")
def users(page: int = Query(1, ge=1), page_size: int = Query(20, ge=1, le=100)):
    with connect(get_settings().database_url) as conn:
        total = conn.execute("SELECT COUNT(*) FROM account").fetchone()[0]
        rows = conn.execute(
            "SELECT a.id, a.username, a.is_admin, a.created_at, "
            "(SELECT COUNT(*) FROM scan s WHERE s.owner_id=a.id) AS scans, "
            "(SELECT COUNT(*) FROM quarantine q WHERE q.owner_id=a.id) AS quarantined "
            "FROM account a ORDER BY a.username LIMIT ? OFFSET ?",
            (page_size, (page - 1) * page_size),
        ).fetchall()
    return {"total": total, "items": [dict(row) for row in rows]}


@router.get("/jobs")
def jobs(page: int = Query(1, ge=1), page_size: int = Query(20, ge=1, le=100)):
    with connect(get_settings().database_url) as conn:
        owners = {
            row["id"]: row["username"] for row in conn.execute("SELECT id, username FROM account")
        }
    snapshot = list(JOBS.items())[::-1]
    return {
        "total": len(snapshot),
        "items": [
            {
                "job_id": job_id,
                "owner_username": owners.get(job.owner_id),
                "kind": job.kind,
                "status": job.status,
                "processed": job.processed,
                "files": len(job.files),
            }
            for job_id, job in snapshot[(page - 1) * page_size : page * page_size]
        ],
    }


@router.get("/jobs/{job_id}")
def job_details(job_id: str):
    result = scan_job(job_id)
    result["files"] = [file.model_dump() for file in JOBS[job_id].files]
    result["kind"] = JOBS[job_id].kind
    return result


class RoleChange(BaseModel):
    is_admin: bool


@router.patch("/users/{user_id}/role")
def change_role(user_id: str, body: RoleChange, actor: Annotated[dict, Depends(require_admin)]):
    with connect(get_settings().database_url) as conn:
        conn.execute("BEGIN IMMEDIATE")
        target = conn.execute("SELECT is_admin FROM account WHERE id=?", (user_id,)).fetchone()
        if target is None:
            raise HTTPException(404, "Account not found")
        if target[0] and not body.is_admin:
            count = conn.execute("SELECT COUNT(*) FROM account WHERE is_admin=1").fetchone()[0]
            if count <= 1:
                raise HTTPException(409, "The last administrator cannot be demoted")
        conn.execute("UPDATE account SET is_admin=? WHERE id=?", (int(body.is_admin), user_id))
        conn.execute("DELETE FROM auth_session WHERE user_id=?", (user_id,))
        conn.execute(
            "INSERT INTO admin_audit(actor_id, action, target_id, created_at) VALUES (?, ?, ?, ?)",
            (actor["id"], "promote" if body.is_admin else "demote", user_id, now()),
        )
    return {"ok": True}


class PasswordChange(BaseModel):
    new_password: SecretStr


@router.post("/users/{user_id}/password")
def change_password(
    user_id: str, body: PasswordChange, actor: Annotated[dict, Depends(require_admin)]
):
    if user_id == actor["id"]:
        raise HTTPException(403, "Use a different administrator to change your password")
    password = body.new_password.get_secret_value()
    if not 12 <= len(password) <= 128:
        raise HTTPException(400, "Password must be between 12 and 128 characters")
    salt = secrets.token_hex(16)
    hashed = password_hash(password, salt)
    with connect(get_settings().database_url) as conn:
        conn.execute("BEGIN IMMEDIATE")
        updated = conn.execute(
            "UPDATE account SET salt=?, password_hash=? WHERE id=?", (salt, hashed, user_id)
        )
        if updated.rowcount != 1:
            raise HTTPException(404, "Account not found")
        conn.execute("DELETE FROM auth_session WHERE user_id=?", (user_id,))
        conn.execute(
            "DELETE FROM auth_attempt WHERE key="
            "(SELECT 'user:' || username FROM account WHERE id=?)",
            (user_id,),
        )
        conn.execute(
            "INSERT INTO admin_audit(actor_id, action, target_id, created_at) VALUES (?, ?, ?, ?)",
            (actor["id"], "change_password", user_id, now()),
        )
    return {"ok": True}


@router.post("/users/{user_id}/revoke-sessions")
def revoke_sessions(user_id: str, actor: Annotated[dict, Depends(require_admin)]):
    with connect(get_settings().database_url) as conn:
        if conn.execute("SELECT 1 FROM account WHERE id=?", (user_id,)).fetchone() is None:
            raise HTTPException(404, "Account not found")
        conn.execute("DELETE FROM auth_session WHERE user_id=?", (user_id,))
        conn.execute(
            "INSERT INTO admin_audit(actor_id, action, target_id, created_at) VALUES (?, ?, ?, ?)",
            (actor["id"], "revoke_sessions", user_id, now()),
        )
    return {"ok": True}


@router.get("/audit")
def audit(page: int = Query(1, ge=1), page_size: int = Query(20, ge=1, le=100)):
    with connect(get_settings().database_url) as conn:
        total = conn.execute("SELECT COUNT(*) FROM admin_audit").fetchone()[0]
        rows = conn.execute(
            "SELECT e.*, a.username AS actor_username, t.username AS target_username "
            "FROM admin_audit e LEFT JOIN account a ON a.id=e.actor_id "
            "LEFT JOIN account t ON t.id=e.target_id ORDER BY e.id DESC LIMIT ? OFFSET ?",
            (page_size, (page - 1) * page_size),
        ).fetchall()
    return {"total": total, "items": [dict(row) for row in rows]}
