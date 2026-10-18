"""API Key 加密存储。

使用 cryptography.fernet 对称加密。密钥来源：
1. 环境变量 WEB_SECRET_KEY（生产推荐，32 字节 url-safe base64）；
2. 未设置时自动生成并写入 web/data/.secret_key 文件（单机开发用）。

如需更换密钥，请同时清空 app_config 表中的 api_key 记录。
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
import re

from fastapi import HTTPException, Request

from cryptography.fernet import Fernet, InvalidToken

from . import config

_fernet: Fernet | None = None


def access_users() -> dict[str, str]:
    """No anonymous/default credentials. Values are deployment-provided random tokens."""
    try:
        users = json.loads(os.environ.get("FIRMXPLORE_WEB_USERS", ""))
        if not isinstance(users, dict) or not users:
            raise ValueError
        for name, token in users.items():
            if (not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,32}", name)
                    or not isinstance(token, str) or not 32 <= len(token) <= 256
                    or not token.isascii() or any(c.isspace() for c in token)):
                raise ValueError
        if len(set(users.values())) != len(users):
            raise ValueError
        return users
    except (ValueError, TypeError):
        raise HTTPException(503, "Web authentication is not configured with valid unique access tokens") from None


def require_principal(request: Request) -> str:
    users = access_users()
    header = request.headers.get("authorization", "")
    scheme, _, credential = header.partition(" ")
    principal = None
    if scheme.lower() == "basic":
        try:
            name, _, token = base64.b64decode(credential, validate=True).decode("utf-8").partition(":")
            expected = users.get(name, "")
            if expected and hmac.compare_digest(hashlib.sha256(token.encode()).digest(), hashlib.sha256(expected.encode()).digest()):
                principal = name
        except (ValueError, UnicodeError, binascii.Error):
            pass
    elif scheme.lower() == "bearer":
        for name, expected in users.items():
            if hmac.compare_digest(hashlib.sha256(credential.encode()).digest(), hashlib.sha256(expected.encode()).digest()):
                principal = name
    if principal is None:
        raise HTTPException(401, "Authentication required", headers={"WWW-Authenticate": 'Basic realm="FirmXplore", charset="UTF-8"'})
    # Basic credentials are browser-managed; reject cross-site state-changing use.
    if request.method not in {"GET", "HEAD", "OPTIONS"}:
        origin = request.headers.get("origin")
        same_origin = str(request.base_url).rstrip("/")
        if ((origin is not None and origin not in {*config.CORS_ORIGINS, same_origin})
                or request.headers.get("sec-fetch-site") == "cross-site"):
            raise HTTPException(403, "Cross-site state-changing requests are not allowed")
    return principal


def _load_or_create_key() -> bytes:
    for variable in ("FIRMXPLORE_SECRET_KEY", "WEB_SECRET_KEY"):
        if variable in os.environ:
            try:
                return _validate_fernet_key(os.environ[variable].encode("ascii"))
            except (ValueError, UnicodeError) as exc:
                raise ValueError(f"{variable} must contain a canonical Fernet key; existing ciphertext is not automatically migrated") from exc
    path = config.SECRET_KEY_FILE
    if path.exists():
        from fwagent.tools.common import open_regular_file
        with open_regular_file(path) as source:
            return _validate_fernet_key(source.read(128).strip())
    key = Fernet.generate_key()
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as destination:
        destination.write(key)
    return key


def _validate_fernet_key(key: bytes) -> bytes:
    try:
        raw = base64.b64decode(key, altchars=b"-_", validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError("Invalid Fernet key encoding") from exc
    if len(key) != 44 or len(raw) != 32 or base64.urlsafe_b64encode(raw) != key:
        raise ValueError("Fernet key must encode exactly 32 bytes without padding or truncation of the secret")
    Fernet(key)
    return key


def get_fernet() -> Fernet:
    global _fernet
    if _fernet is None:
        _fernet = Fernet(_load_or_create_key())
    return _fernet


def encrypt(plaintext: str) -> str:
    return get_fernet().encrypt(plaintext.encode()).decode()


def decrypt(ciphertext: str) -> str | None:
    """解密失败（密钥更换/记录损坏）时返回 None 而不是抛异常，调用方按未配置处理。"""
    try:
        return get_fernet().decrypt(ciphertext.encode()).decode()
    except (InvalidToken, ValueError):
        return None
