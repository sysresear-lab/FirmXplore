"""Public task snapshots. Credentials never belong in this contract."""
from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

SNAPSHOT_VERSION = 2
PUBLIC_FIELDS = {"snapshot_version", "model_provider", "model_name", "base_url", "deterministic", "options"}
OPTION_TYPES = {"static_only": bool, "fast": bool, "no_dynamic": bool, "timeout": int}


def validate_endpoint(value: str) -> None:
    if not value:
        return
    parsed = urlsplit(value)
    if (parsed.scheme not in {"https", "http"} or not parsed.hostname or parsed.username is not None
            or parsed.password is not None or parsed.query or parsed.fragment):
        raise ValueError("model base_url must be an HTTP(S) endpoint without credentials, query or fragment")
    if parsed.scheme == "http" and parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
        raise ValueError("remote model endpoints require HTTPS")


def public_task_config(value: Any) -> dict[str, Any]:
    """Allowlist on output too, so legacy/nested credential fields cannot reappear."""
    source = value if isinstance(value, dict) else {}
    result: dict[str, Any] = {}
    for name in ("model_provider", "model_name", "base_url"):
        item = source.get(name)
        result[name] = item if isinstance(item, str) else ""
    try:
        validate_endpoint(result["base_url"])
    except ValueError:
        result["base_url"] = ""
    result["deterministic"] = source.get("deterministic") if type(source.get("deterministic")) is bool else True
    result["options"] = {name: item for name, item in (source.get("options") or {}).items()
                         if name in OPTION_TYPES and type(item) is OPTION_TYPES[name]} if isinstance(source.get("options"), dict) else {}
    result["snapshot_version"] = SNAPSHOT_VERSION
    return result


def validate_task_config(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) - PUBLIC_FIELDS:
        raise ValueError("task snapshot contains unsupported or private fields")
    if type(value.get("deterministic")) is not bool:
        raise ValueError("deterministic must be boolean")
    if "snapshot_version" in value and (type(value["snapshot_version"]) is not int or value["snapshot_version"] != SNAPSHOT_VERSION):
        raise ValueError("invalid task snapshot version")
    normalized = public_task_config(value)
    expected = {**value, "snapshot_version": SNAPSHOT_VERSION}
    if normalized != expected or any(type(value.get(k, {})) is not dict for k in ("options",)):
        raise ValueError("invalid public task configuration types or endpoint")
    return normalized


def is_current_snapshot(value: Any) -> bool:
    if not isinstance(value, dict) or type(value.get("snapshot_version")) is not int or value["snapshot_version"] != SNAPSHOT_VERSION:
        return False
    try:
        return validate_task_config(value) == value
    except ValueError:
        return False
