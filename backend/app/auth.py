"""Account authentication and request-scoped resource ownership."""

import hashlib
import hmac
import secrets
import sqlite3
import time
import uuid
from contextvars import ContextVar
from datetime import UTC, datetime, timedelta
from typing import Annotated
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field

from .config import get_settings
from .db import connect, now

administrator: ContextVar[bool] = ContextVar("administrator", default=False)
owner: ContextVar[str | None] = ContextVar("owner", default=None)
router = APIRouter(prefix="/api/v1/auth", tags=["authentication"])
COOKIE = "sentinel_session"
# Persisted throttling applies across workers/restarts; generic login errors hide account existence.


class Credentials(BaseModel):
    username: str = Field(min_length=3, max_length=64, pattern=r"^[a-zA-Z0-9_.-]+$")
    password: str = Field(min_length=12, max_length=128)


def password_hash(password: str, salt: str) -> str:
    return hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=16384, r=8, p=5).hex()


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def trusted_host(request: Request) -> None:
    try:
        host = urlsplit("http://" + request.headers.get("host", "")).hostname
    except ValueError as exc:
        raise HTTPException(400, "Host not allowed") from exc
    if host not in {"localhost", "127.0.0.1", "::1"}:
        raise HTTPException(400, "Host not allowed")


def mutation_guard(request: Request) -> None:
    trusted_host(request)
    if request.headers.get("x-sentinel-request") != "1":
        raise HTTPException(403, "Request verification required")
    origin = request.headers.get("origin")
    if origin:
        parsed = urlsplit(origin)
        if parsed.scheme not in {"http", "https"} or parsed.netloc != request.headers.get("host"):
            raise HTTPException(403, "Origin not allowed")


async def current_user(request: Request):
    trusted_host(request)
    token = request.cookies.get(COOKIE, "")
    with connect(get_settings().database_url) as conn:
        row = conn.execute(
            "SELECT u.id, u.username, u.is_admin, s.csrf FROM auth_session s "
            "JOIN account u ON u.id=s.user_id "
            "WHERE s.token_hash=? AND s.expires_at>?",
            (digest(token), now()),
        ).fetchone()
    if row is None:
        raise HTTPException(401, "Sign in required")
    if request.method not in {"GET", "HEAD", "OPTIONS"}:
        mutation_guard(request)
        if not hmac.compare_digest(request.headers.get("x-csrf-token", ""), row["csrf"]):
            raise HTTPException(403, "Request verification failed")
    admin_marker = administrator.set(bool(row["is_admin"]))
    marker = owner.set(row["id"])
    try:
        yield dict(row)
    finally:
        owner.reset(marker)
        administrator.reset(admin_marker)


def start_session(
    response: Response,
    user_id: str,
    username: str,
    request: Request,
    expected_password_hash: str | None = None,
) -> dict:
    token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    expiry = (datetime.now(UTC) + timedelta(hours=12)).isoformat()
    with connect(get_settings().database_url) as conn:
        conn.execute("BEGIN IMMEDIATE")
        account = conn.execute(
            "SELECT password_hash, is_admin FROM account WHERE id=?", (user_id,)
        ).fetchone()
        if account is None or (
            expected_password_hash is not None
            and not hmac.compare_digest(account["password_hash"], expected_password_hash)
        ):
            raise HTTPException(401, "Credentials changed; sign in again")
        admin = account["is_admin"]
        conn.execute("DELETE FROM auth_session WHERE expires_at<=?", (now(),))
        conn.execute(
            "INSERT INTO auth_session VALUES (?, ?, ?, ?)", (digest(token), user_id, csrf, expiry)
        )
    response.set_cookie(
        COOKIE,
        token,
        max_age=43200,
        httponly=True,
        samesite="strict",
        secure=request.url.scheme == "https",
        path="/api/v1",
    )
    response.headers["Cache-Control"] = "no-store"
    return {"username": username, "csrf": csrf, "is_admin": bool(admin)}


def throttle(keys: list[str]) -> None:
    with connect(get_settings().database_url) as conn:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("DELETE FROM auth_attempt WHERE attempted_at<?", (time.time() - 900,))
        for key in keys:
            count = conn.execute(
                "SELECT COUNT(*) FROM auth_attempt WHERE key=?", (key,)
            ).fetchone()[0]
            if count >= 10:
                raise HTTPException(429, "Too many attempts; try again later")
        for key in keys:
            conn.execute("INSERT INTO auth_attempt VALUES (?, ?)", (key, time.time()))


@router.post("/register", status_code=201)
def register(body: Credentials, request: Request, response: Response):
    mutation_guard(request)
    throttle(["register:" + (request.client.host if request.client else "unknown")])
    username = body.username.lower()
    user_id, salt = str(uuid.uuid4()), secrets.token_hex(16)
    hashed = password_hash(body.password, salt)
    try:
        with connect(get_settings().database_url) as conn:
            conn.execute(
                "INSERT INTO account (id, username, salt, password_hash, created_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (user_id, username, salt, hashed, now()),
            )
    except sqlite3.IntegrityError as exc:
        raise HTTPException(409, "Username unavailable") from exc
    return start_session(response, user_id, username, request, hashed)


@router.post("/login")
def login(body: Credentials, request: Request, response: Response):
    mutation_guard(request)
    username = body.username.lower()
    # Both account and client address are bounded over a rolling fifteen-minute window.
    keys = ["user:" + username, "ip:" + (request.client.host if request.client else "unknown")]
    throttle(keys)
    with connect(get_settings().database_url) as conn:
        row = conn.execute("SELECT * FROM account WHERE username=?", (username,)).fetchone()
    actual = password_hash(body.password, row["salt"] if row else "00" * 16)
    if row is None or not hmac.compare_digest(actual, row["password_hash"]):
        raise HTTPException(401, "Invalid username or password")
    return start_session(response, row["id"], username, request, row["password_hash"])


@router.get("/me")
def me(response: Response, user: Annotated[dict, Depends(current_user)]):
    response.headers["Cache-Control"] = "no-store"
    return {"username": user["username"], "csrf": user["csrf"], "is_admin": bool(user["is_admin"])}


@router.post("/logout")
def logout(request: Request, response: Response, user: Annotated[dict, Depends(current_user)]):
    with connect(get_settings().database_url) as conn:
        conn.execute(
            "DELETE FROM auth_session WHERE token_hash=?",
            (digest(request.cookies.get(COOKIE, "")),),
        )
    response.delete_cookie(COOKIE, path="/api/v1")
    return {"ok": True}


async def require_admin(user: Annotated[dict, Depends(current_user)]) -> dict:
    if not user["is_admin"]:
        raise HTTPException(403, "Administrator access required")
    return user
