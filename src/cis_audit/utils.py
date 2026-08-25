"""Small stdlib-only helpers shared by check modules.

Every function here is defensive about the real conditions this tool runs
under: files that don't exist, files that exist but aren't readable by the
current (possibly unprivileged) user, binaries that aren't installed. None of
these ever raise for those conditions - they return ``None`` (or an
appropriate empty/failure value) so callers can turn that into an honest
NOT_APPLICABLE result instead of crashing.
"""

from __future__ import annotations

import grp
import os
import pwd
import stat as stat_mod
import subprocess
from pathlib import Path
from shutil import which as _which


def run_cmd(args: list[str], timeout: float = 5.0) -> tuple[int, str, str]:
    """Run a command, never raising.

    Returns (returncode, stdout, stderr). returncode -1 means the binary
    wasn't found at all; -2 means it timed out.
    """
    try:
        proc = subprocess.run(
            args, capture_output=True, text=True, timeout=timeout, check=False
        )
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except FileNotFoundError:
        return -1, "", f"{args[0]}: command not found"
    except subprocess.TimeoutExpired:
        return -2, "", f"{args[0]}: timed out after {timeout}s"
    except PermissionError as exc:
        return -1, "", f"{args[0]}: {exc}"


def which(binary: str) -> str | None:
    return _which(binary)


def path_exists(path: str) -> bool:
    return os.path.exists(path)


def path_mode_octal(path: str) -> str | None:
    """3-digit octal permission string for a path, or None if it can't be stat'd."""
    try:
        st = os.stat(path)
    except (FileNotFoundError, PermissionError, NotADirectoryError):
        return None
    return oct(stat_mod.S_IMODE(st.st_mode))[2:].zfill(3)


def path_owner(path: str) -> tuple[str, str] | None:
    """(owner_name, group_name) for a path, or None if it can't be stat'd."""
    try:
        st = os.stat(path)
    except (FileNotFoundError, PermissionError, NotADirectoryError):
        return None
    try:
        owner = pwd.getpwuid(st.st_uid).pw_name
    except KeyError:
        owner = str(st.st_uid)
    try:
        group = grp.getgrgid(st.st_gid).gr_name
    except KeyError:
        group = str(st.st_gid)
    return owner, group


def read_text(path: str) -> str | None:
    try:
        return Path(path).read_text(errors="replace")
    except (FileNotFoundError, PermissionError, IsADirectoryError):
        return None


def read_lines(path: str) -> list[str] | None:
    text = read_text(path)
    if text is None:
        return None
    return text.splitlines()


def sysctl_value(key: str) -> str | None:
    """Read a live kernel parameter, preferring /proc/sys directly (always
    readable without shelling out) and falling back to the sysctl binary."""
    proc_path = "/proc/sys/" + key.replace(".", "/")
    text = read_text(proc_path)
    if text is not None:
        return text.strip()
    rc, out, _ = run_cmd(["sysctl", "-n", key])
    if rc != 0:
        return None
    return out.strip()


def redact(value: str, keep: int = 0) -> str:
    """Redact a sensitive value (e.g. a shadow hash field) for evidence output.
    Never echoes real secret material - callers use this for anything derived
    from /etc/shadow password fields."""
    if not value:
        return "(empty)"
    return f"<redacted, {len(value)} chars>"
