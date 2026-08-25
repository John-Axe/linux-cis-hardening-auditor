"""Filesystem / permissions checks (CIS section 6.x-ish: system file permissions).

These only ever call os.stat/os.lstat and read small config files - no
subprocess calls needed, which also means they work identically whether or
not the running user has root.
"""

from __future__ import annotations

import grp
import os
import pwd
import stat as stat_mod

from cis_audit.models import CheckResult, Status
from cis_audit.registry import register
from cis_audit.utils import path_mode_octal, path_owner, read_lines, read_text

CATEGORY = "filesystem"

# Directories scanned for world-writable / unowned files. Deliberately small
# and targeted (not a full "/" walk) so a run stays fast and bounded on any
# host, including one with a huge filesystem mounted under it.
_SCAN_DIRS = ["/tmp", "/var/tmp", "/home", "/etc"]
_SCAN_MAX_ENTRIES = 20000


def _scan_dirs_for(predicate) -> tuple[list[str], int, bool]:
    """Walk _SCAN_DIRS, calling predicate(path, lstat_result) for every
    non-symlink entry. Returns (matches, entries_scanned, truncated)."""
    matches: list[str] = []
    scanned = 0
    truncated = False
    for base in _SCAN_DIRS:
        if not os.path.isdir(base):
            continue
        for root, dirs, files in os.walk(base, topdown=True, onerror=lambda e: None):
            for name in dirs + files:
                scanned += 1
                if scanned > _SCAN_MAX_ENTRIES:
                    return matches, scanned, True
                full = os.path.join(root, name)
                try:
                    st = os.lstat(full)
                except (FileNotFoundError, PermissionError, OSError):
                    continue
                if stat_mod.S_ISLNK(st.st_mode):
                    continue
                if predicate(full, st):
                    matches.append(full)
    return matches, scanned, truncated


def _file_perms_check(path: str, max_mode: int, expected_owner: str, expected_group: str) -> CheckResult:
    mode = path_mode_octal(path)
    owner_group = path_owner(path)
    if mode is None or owner_group is None:
        return CheckResult(
            Status.NOT_APPLICABLE,
            f"{path} does not exist or is not stat-able on this host.",
        )
    owner, group = owner_group
    mode_int = int(mode, 8)
    perms_ok = mode_int <= max_mode
    owner_ok = owner == expected_owner
    group_ok = group == expected_group
    evidence = f"{path}: mode={mode} owner={owner} group={group}"
    if perms_ok and owner_ok and group_ok:
        return CheckResult(Status.PASS, evidence)
    return CheckResult(
        Status.FAIL,
        evidence
        + f" (expected mode <= {oct(max_mode)[2:].zfill(3)}, owner={expected_owner}, group={expected_group})",
    )


@register(
    id="CIS-6.1.2",
    title="/etc/passwd permissions are 644 or more restrictive, owned by root:root",
    category=CATEGORY,
    rationale="/etc/passwd is world-readable by design (it holds no secrets since "
    "shadow passwords split hashes into /etc/shadow), but must not be writable by "
    "non-root users or accounts could be tampered with.",
    remediation="chown root:root /etc/passwd && chmod 644 /etc/passwd",
)
def check_etc_passwd_perms() -> CheckResult:
    return _file_perms_check("/etc/passwd", 0o644, "root", "root")


@register(
    id="CIS-6.1.3",
    title="/etc/shadow permissions are 640 or more restrictive, owned by root:shadow",
    category=CATEGORY,
    rationale="/etc/shadow holds password hashes. If it is readable by non-root "
    "users, an attacker can take the hashes offline and crack them.",
    remediation="chown root:shadow /etc/shadow && chmod 640 /etc/shadow",
)
def check_etc_shadow_perms() -> CheckResult:
    return _file_perms_check("/etc/shadow", 0o640, "root", "shadow")


@register(
    id="CIS-6.1.4",
    title="/etc/group permissions are 644 or more restrictive, owned by root:root",
    category=CATEGORY,
    rationale="/etc/group defines group membership; if it's writable by "
    "non-root users, a user could add themselves to a privileged group.",
    remediation="chown root:root /etc/group && chmod 644 /etc/group",
)
def check_etc_group_perms() -> CheckResult:
    return _file_perms_check("/etc/group", 0o644, "root", "root")


@register(
    id="CIS-6.1.5",
    title="/etc/gshadow permissions are 640 or more restrictive, owned by root:shadow",
    category=CATEGORY,
    rationale="/etc/gshadow holds group password hashes and administrator "
    "lists; it must not be readable or writable by non-root users.",
    remediation="chown root:shadow /etc/gshadow && chmod 640 /etc/gshadow",
)
def check_etc_gshadow_perms() -> CheckResult:
    return _file_perms_check("/etc/gshadow", 0o640, "root", "shadow")


@register(
    id="CIS-6.1.9",
    title="No world-writable files exist in key directories",
    category=CATEGORY,
    rationale="A world-writable file can be modified by any local user, which "
    "is a common path to privilege escalation or persistence if that file is "
    "ever executed or trusted by a privileged process.",
    remediation="For each reported file: chmod o-w <file>  (review the file's "
    "purpose first - some world-writable files, e.g. under a sticky-bit /tmp, "
    "are intentional).",
)
def check_world_writable_files() -> CheckResult:
    def is_ww_file(path: str, st: os.stat_result) -> bool:
        return stat_mod.S_ISREG(st.st_mode) and bool(st.st_mode & stat_mod.S_IWOTH)

    matches, scanned, truncated = _scan_dirs_for(is_ww_file)
    scope = ", ".join(_SCAN_DIRS)
    suffix = " (scan truncated at entry cap, more may exist)" if truncated else ""
    if not matches:
        return CheckResult(
            Status.PASS,
            f"No world-writable regular files found under {scope} "
            f"({scanned} entries scanned{suffix}).",
        )
    shown = matches[:10]
    more = f" and {len(matches) - 10} more" if len(matches) > 10 else ""
    return CheckResult(
        Status.FAIL,
        f"{len(matches)} world-writable file(s) found under {scope}{suffix}: "
        + ", ".join(shown)
        + more,
    )


def _known_uids() -> set[int]:
    return {entry.pw_uid for entry in pwd.getpwall()}


def _known_gids() -> set[int]:
    return {entry.gr_gid for entry in grp.getgrall()}


@register(
    id="CIS-6.1.10",
    title="No unowned files or directories exist in key directories",
    category=CATEGORY,
    rationale="A file owned by a UID/GID with no corresponding account (e.g. "
    "left behind after a user was deleted) may be inadvertently accessible or "
    "reused by a future account created with a reused UID.",
    remediation="For each reported path: chown root:root <path>, or assign it "
    "to its correct owner after investigating why it's unowned.",
)
def check_unowned_files() -> CheckResult:
    try:
        known_uids = _known_uids()
        known_gids = _known_gids()
    except Exception as exc:  # nss lookup issues, e.g. no nss module available
        return CheckResult(
            Status.NOT_APPLICABLE,
            f"could not enumerate known users/groups to compare against: {exc}",
        )

    def is_unowned(path: str, st: os.stat_result) -> bool:
        return st.st_uid not in known_uids or st.st_gid not in known_gids

    matches, scanned, truncated = _scan_dirs_for(is_unowned)
    scope = ", ".join(_SCAN_DIRS)
    suffix = " (scan truncated at entry cap, more may exist)" if truncated else ""
    if not matches:
        return CheckResult(
            Status.PASS,
            f"No unowned files/directories found under {scope} "
            f"({scanned} entries scanned{suffix}).",
        )
    shown = matches[:10]
    more = f" and {len(matches) - 10} more" if len(matches) > 10 else ""
    return CheckResult(
        Status.FAIL,
        f"{len(matches)} unowned path(s) found under {scope}{suffix}: "
        + ", ".join(shown)
        + more,
    )


@register(
    id="CIS-6.2.9",
    title="Local interactive user home directories are not group- or other-writable",
    category=CATEGORY,
    rationale="A group- or other-writable home directory lets other local "
    "users tamper with that account's dotfiles (e.g. plant a malicious "
    ".bashrc) to escalate privilege the next time the owner logs in.",
    remediation="For each reported home directory: chmod g-w,o-w <home-dir>",
)
def check_home_dir_perms() -> CheckResult:
    lines = read_lines("/etc/passwd")
    if lines is None:
        return CheckResult(Status.NOT_APPLICABLE, "/etc/passwd could not be read.")

    bad: list[str] = []
    checked = 0
    for line in lines:
        fields = line.split(":")
        if len(fields) < 7:
            continue
        username, _, uid_s, _gid_s, _gecos, home, shell = fields[:7]
        try:
            uid = int(uid_s)
        except ValueError:
            continue
        # Regular interactive accounts only (CIS convention: UID >= 1000,
        # excluding nobody), skip system/service accounts and no-login shells.
        if uid < 1000 or username == "nobody":
            continue
        if shell.strip() in ("/usr/sbin/nologin", "/sbin/nologin", "/bin/false"):
            continue
        if not os.path.isdir(home):
            continue
        checked += 1
        mode = path_mode_octal(home)
        if mode is None:
            continue
        mode_int = int(mode, 8)
        if mode_int & (stat_mod.S_IWGRP | stat_mod.S_IWOTH):
            bad.append(f"{username}:{home} (mode={mode})")

    if checked == 0:
        return CheckResult(
            Status.NOT_APPLICABLE,
            "No interactive local user accounts (UID >= 1000 with a login shell) found.",
        )
    if not bad:
        return CheckResult(
            Status.PASS, f"Checked {checked} interactive user home director(ies); none are group/other writable."
        )
    return CheckResult(
        Status.FAIL,
        f"{len(bad)} of {checked} home director(ies) are group- or other-writable: "
        + ", ".join(bad),
    )


@register(
    id="CIS-5.4.4",
    title="Default user umask is 027 or more restrictive",
    category=CATEGORY,
    rationale="A permissive default umask (e.g. 022) means every file a user "
    "creates is world-readable by default, including ones that shouldn't be.",
    remediation="Set 'UMASK 027' in /etc/login.defs, and add 'umask 027' to "
    "/etc/profile.d/local-umask.sh for shell sessions.",
)
def check_default_umask() -> CheckResult:
    lines = read_lines("/etc/login.defs")
    if lines is None:
        return CheckResult(Status.NOT_APPLICABLE, "/etc/login.defs could not be read.")

    umask_value = None
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        parts = stripped.split()
        if len(parts) == 2 and parts[0] == "UMASK":
            umask_value = parts[1]
            break

    if umask_value is None:
        return CheckResult(
            Status.FAIL,
            "No UMASK setting found in /etc/login.defs (login.defs default of 022 applies).",
        )

    try:
        umask_int = int(umask_value, 8)
    except ValueError:
        return CheckResult(
            Status.NOT_APPLICABLE, f"UMASK value '{umask_value}' in /etc/login.defs is not valid octal."
        )

    # More restrictive means MORE bits set (more permissions blocked), i.e.
    # umask_int as a bitmask must be a superset of 027's bits.
    required = 0o027
    if (umask_int & required) == required:
        return CheckResult(Status.PASS, f"/etc/login.defs UMASK {umask_value} (>= 027 restrictiveness)")
    return CheckResult(
        Status.FAIL, f"/etc/login.defs UMASK {umask_value} is less restrictive than the recommended 027"
    )
