"""Shared helpers: logging, process execution, tool discovery."""

from __future__ import annotations

import shutil
import subprocess
import sys
from typing import Optional, Sequence


class IphError(Exception):
    """A user-facing error. The CLI prints its message and exits non-zero."""


# ----------------------------------------------------------------------------
# Pretty, color-aware logging to stderr (so stdout stays parseable).
# ----------------------------------------------------------------------------
_USE_COLOR = sys.stderr.isatty()


def _c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _USE_COLOR else text


def info(msg: str) -> None:
    print(_c("36", "[*]") + " " + msg, file=sys.stderr)


def ok(msg: str) -> None:
    print(_c("32", "[+]") + " " + msg, file=sys.stderr)


def warn(msg: str) -> None:
    print(_c("33", "[!]") + " " + msg, file=sys.stderr)


def err(msg: str) -> None:
    print(_c("31", "[-]") + " " + msg, file=sys.stderr)


def step(msg: str) -> None:
    print(_c("1;35", "==>") + " " + _c("1", msg), file=sys.stderr)


# ----------------------------------------------------------------------------
# Tool discovery
# ----------------------------------------------------------------------------
def which(name: str) -> Optional[str]:
    return shutil.which(name)


def require(name: str, hint: str = "") -> str:
    path = which(name)
    if not path:
        extra = f"  {hint}" if hint else ""
        raise IphError(f"required tool '{name}' not found on PATH.{extra}")
    return path


# ----------------------------------------------------------------------------
# Process execution
# ----------------------------------------------------------------------------
def run(
    cmd: Sequence[str],
    *,
    check: bool = True,
    capture: bool = False,
    env: Optional[dict] = None,
    input_text: Optional[str] = None,
    timeout: Optional[float] = None,
) -> subprocess.CompletedProcess:
    """Run a command. On check=True a non-zero exit raises IphError."""
    try:
        proc = subprocess.run(
            list(cmd),
            check=False,
            text=True,
            env=env,
            input=input_text,
            timeout=timeout,
            stdout=subprocess.PIPE if capture else None,
            stderr=subprocess.PIPE if capture else None,
        )
    except FileNotFoundError as e:
        raise IphError(f"command not found: {cmd[0]}") from e
    except subprocess.TimeoutExpired as e:
        raise IphError(f"command timed out after {timeout}s: {' '.join(cmd)}") from e

    if check and proc.returncode != 0:
        detail = ""
        if capture:
            detail = (proc.stderr or proc.stdout or "").strip()
            detail = f"\n{detail}" if detail else ""
        raise IphError(f"command failed ({proc.returncode}): {' '.join(cmd)}{detail}")
    return proc


def human_size(num: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(num) < 1024.0:
            return f"{num:3.1f} {unit}"
        num /= 1024.0
    return f"{num:.1f} PB"
