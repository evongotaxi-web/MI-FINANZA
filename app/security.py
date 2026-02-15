from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from itsdangerous import BadSignature, URLSafeSerializer

_PWD_ITERATIONS = 210_000


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, _PWD_ITERATIONS, dklen=32)
    salt_b64 = base64.urlsafe_b64encode(salt).decode("ascii").rstrip("=")
    dk_b64 = base64.urlsafe_b64encode(dk).decode("ascii").rstrip("=")
    return f"pbkdf2_sha256${_PWD_ITERATIONS}${salt_b64}${dk_b64}"


def verify_password(password: str, password_hash: str) -> bool:
    try:
        algo, iters_raw, salt_b64, dk_b64 = password_hash.split("$", 3)
        if algo != "pbkdf2_sha256":
            return False
        iters = int(iters_raw)
        salt = base64.urlsafe_b64decode(salt_b64 + "==")
        expected = base64.urlsafe_b64decode(dk_b64 + "==")
        dk = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt, iters, dklen=len(expected)
        )
        return hmac.compare_digest(dk, expected)
    except Exception:
        return False


@dataclass(frozen=True)
class SessionData:
    user_id: str


def _secret_key() -> str:
    key = os.environ.get("MIS_FINANZAS_SESSION_SECRET")
    if key:
        return key
    base_dir = Path(__file__).resolve().parent.parent / "data"
    base_dir.mkdir(parents=True, exist_ok=True)
    secret_file = base_dir / "session_secret.txt"
    if secret_file.exists():
        raw = secret_file.read_text(encoding="utf-8").strip()
        if raw:
            return raw
    raw = f"local-{secrets.token_urlsafe(48)}"
    secret_file.write_text(raw, encoding="utf-8")
    return raw


def _serializer() -> URLSafeSerializer:
    return URLSafeSerializer(_secret_key(), salt="mis-finanzas-session")


def _oauth_serializer() -> URLSafeSerializer:
    return URLSafeSerializer(_secret_key(), salt="mis-finanzas-oauth")


def encode_session(data: SessionData) -> str:
    return _serializer().dumps({"user_id": data.user_id})


def decode_session(value: str) -> Optional[SessionData]:
    try:
        raw: Any = _serializer().loads(value)
        user_id = raw.get("user_id")
        if not isinstance(user_id, str) or not user_id:
            return None
        return SessionData(user_id=user_id)
    except BadSignature:
        return None


def encode_oauth(data: dict[str, object]) -> str:
    return _oauth_serializer().dumps(data)


def decode_oauth(value: str) -> Optional[dict[str, object]]:
    try:
        raw: Any = _oauth_serializer().loads(value)
        if not isinstance(raw, dict):
            return None
        return raw
    except BadSignature:
        return None
