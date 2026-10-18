"""Temporary fail-closed policy. This is an execution lock, not a sandbox.

No environment variable, configuration flag or trust label enables execution.
Remove the lock only after a separate isolation design and acceptance review.
Static inspection and parsing do not require this lock.
"""
from __future__ import annotations

import re
from typing import Any, Callable


BLOCK_CODE = "UNISOLATED_FIRMWARE_EXECUTION_BLOCKED"
BLOCK_REASON = (
    "Untrusted firmware execution is disabled: the firmware backends do not "
    "have verified syscall, network, mount and resource isolation. Use static-only "
    "analysis until a separately validated isolation backend is available."
)


def blocked_execution(entry: str) -> dict[str, Any]:
    return {
        "success": False,
        "status": "blocked",
        "dynamic_status": "blocked",
        "dynamic_feasibility": "BLOCKED",
        "error_code": BLOCK_CODE,
        "errors": [BLOCK_REASON],
        "blocking_reasons": [BLOCK_REASON],
        "diagnosis": "runtime_isolation_unavailable",
        "failure_category": "runtime_environment_incompatible",
        "deepest_verified_blocker": BLOCK_REASON,
        "entry_point": entry,
        "process_started": False,
        "backend_started": False,
        "request_sent": False,
        "runtime_observation_real": False,
        "isolation_verified": False,
    }


def deny_unisolated_execution(function: Callable) -> Callable:
    """Stop before argument-dependent I/O, including with injected fake runners."""
    def denied(*args, **kwargs):
        return blocked_execution(function.__qualname__)
    denied.__name__ = function.__name__
    denied.__qualname__ = function.__qualname__
    denied.__doc__ = BLOCK_REASON
    denied.execution_blocked = True
    return denied


def command_requires_isolation(command: list[str]) -> bool:
    """Defence in depth for direct QEMU/proot/chroot runner calls.

    Image utilities remain available for preparation. Only a direct,
    argument-free version/help query is allowed for blocked executable names.
    This recognizer is not a general shell parser or a host execution sandbox.
    """
    def executable(token: str) -> bool:
        name = token.replace("\\", "/").rsplit("/", 1)[-1].lower()
        if name.endswith(".exe"):
            name = name[:-4]
        if name in {"proot", "chroot"}:
            return True
        return name.startswith("qemu-") and name not in {"qemu-img", "qemu-io", "qemu-nbd", "qemu-storage-daemon", "qemu-pr-helper", "qemu-keymap"}

    if not command:
        return False
    if executable(str(command[0])):
        return not (len(command) == 2 and command[1] in {"--version", "-version", "--help", "-h"})
    # Also catch the in-tree style of env or shell wrappers, without executing it.
    wrapper = str(command[0]).replace("\\", "/").rsplit("/", 1)[-1].lower()
    if wrapper not in {"sh", "bash", "dash", "ash", "env", "sudo", "doas", "timeout"}:
        return False
    return any(executable(part) for token in command[1:] for part in re.split(r"[\s\"';|&()]+", str(token)) if part)
