from __future__ import annotations

import re
from pathlib import Path

from fwagent.tools.common import display_path, is_regular_file, iter_files, safe_exists, safe_read_text


PRIVATE_KEY_MARKERS = (
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN PRIVATE KEY-----",
    "-----BEGIN OPENSSH PRIVATE KEY-----",
    "-----BEGIN EC PRIVATE KEY-----",
)

CREDENTIAL_PATTERNS = [
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"\bpassword\s*=",
        r"\bpasswd\s*=",
        r"\busername\s*=",
        r"\bauth\s*=",
        r"\btoken\s*=",
        r"\bsecret\s*=",
        r"\badmin\s*:",
        r"\broot\s*:",
    )
]

TEXT_SUFFIXES = {
    "",
    ".conf",
    ".cfg",
    ".ini",
    ".json",
    ".xml",
    ".yaml",
    ".yml",
    ".txt",
    ".sh",
    ".lua",
    ".php",
    ".cgi",
    ".properties",
}

CERT_SUFFIXES = {".pem", ".crt", ".cer", ".key"}
DEBUG_NAMES = {"gdbserver", "telnetd", "dropbear"}
DEBUG_TOKENS = {"debug", "test", "development"}


def scan_sensitive_files(rootfs: str | Path) -> list[dict]:
    root = Path(rootfs).resolve()
    findings: list[dict] = []

    for path in iter_files(root):
        if path.is_symlink():
            continue
        rel = display_path(path, root)
        suffix = path.suffix.lower()
        name = path.name.lower()

        if suffix in CERT_SUFFIXES:
            findings.append(
                {
                    "type": "certificate_or_key_file",
                    "path": rel,
                    "severity": "info",
                    "candidate": True,
                    "is_private_key": suffix == ".key",
                }
            )

        text = safe_read_text(path, limit=1024 * 1024) if _should_text_scan(path) else ""
        if text:
            if any(marker in text for marker in PRIVATE_KEY_MARKERS):
                findings.append({"type": "private_key", "path": rel, "severity": "medium"})
            if any(pattern.search(text) for pattern in CREDENTIAL_PATTERNS):
                findings.append(
                    {
                        "type": "credential_candidate",
                        "path": rel,
                        "severity": "info",
                        "candidate": True,
                    }
                )

        if name in DEBUG_NAMES or any(token in name for token in DEBUG_TOKENS):
            findings.append(
                {
                    "type": "debug_or_development_artifact",
                    "path": rel,
                    "severity": "info",
                    "candidate": True,
                }
            )

    findings.extend(_scan_passwd_shadow(root))
    return _dedupe_findings(findings)


def _should_text_scan(path: Path) -> bool:
    suffix = path.suffix.lower()
    if suffix in TEXT_SUFFIXES or suffix in CERT_SUFFIXES:
        return True
    try:
        return path.stat().st_size <= 128 * 1024
    except OSError:
        return False


def _scan_passwd_shadow(root: Path) -> list[dict]:
    findings: list[dict] = []
    passwd = root / "etc" / "passwd"
    if _safe_exists_regular(passwd):
        for line in safe_read_text(passwd).splitlines():
            if not line or line.startswith("#"):
                continue
            parts = line.split(":")
            if len(parts) < 7:
                continue
            username, password, uid = parts[0], parts[1], parts[2]
            if username == "root":
                findings.append(
                    {
                        "type": "passwd_root_user",
                        "path": "/etc/passwd",
                        "severity": "info",
                        "candidate": False,
                    }
                )
            if password == "":
                findings.append(
                    {
                        "type": "empty_passwd_field",
                        "path": "/etc/passwd",
                        "severity": "medium",
                        "user": username,
                        "candidate": True,
                    }
                )
            if uid == "0" and username != "root":
                findings.append(
                    {
                        "type": "uid_zero_non_root_user",
                        "path": "/etc/passwd",
                        "severity": "medium",
                        "user": username,
                        "candidate": True,
                    }
                )
    shadow = root / "etc" / "shadow"
    if _safe_exists_regular(shadow):
        for line in safe_read_text(shadow).splitlines():
            if not line or line.startswith("#"):
                continue
            parts = line.split(":")
            if len(parts) >= 2 and parts[1] == "":
                findings.append(
                    {
                        "type": "empty_shadow_hash",
                        "path": "/etc/shadow",
                        "severity": "high",
                        "user": parts[0],
                        "candidate": True,
                    }
                )
    return findings


def _safe_exists_regular(path: Path) -> bool:
    return safe_exists(path) and is_regular_file(path)


def _dedupe_findings(findings: list[dict]) -> list[dict]:
    seen: set[tuple] = set()
    deduped: list[dict] = []
    for finding in findings:
        key = (finding.get("type"), finding.get("path"), finding.get("user"))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(finding)
    return deduped
