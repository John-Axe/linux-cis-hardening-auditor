"""Partition-separation and mount-option checks (CIS section 1.1.2).

Reads /proc/mounts directly - always readable, no root or subprocess needed.
This sandbox (and most containers/single-disk VMs) legitimately mounts
/tmp, /var, /home etc. as directories on the root filesystem rather than as
separate partitions, so several of these honestly FAIL here rather than being
faked into passing - exactly the same "report what's actually there" stance
as the rest of this tool.
"""

from __future__ import annotations

import os
import stat as stat_mod

from cis_audit.models import CheckResult, Status
from cis_audit.registry import register
from cis_audit.utils import read_lines

CATEGORY = "filesystem"

_SCAN_DIRS_FOR_STICKY = ["/tmp", "/var/tmp"]
_SCAN_MAX_ENTRIES = 20000


def _mounts() -> dict[str, tuple[str, set[str]]] | None:
    """Parses /proc/mounts into {mount_point: (fs_type, {options})}."""
    lines = read_lines("/proc/mounts")
    if lines is None:
        return None
    result: dict[str, tuple[str, set[str]]] = {}
    for line in lines:
        parts = line.split()
        if len(parts) < 4:
            continue
        _device, mount_point, fs_type, options = parts[0], parts[1], parts[2], parts[3]
        result[mount_point] = (fs_type, set(options.split(",")))
    return result


def _is_separate_partition_check(mount_point: str) -> CheckResult:
    mounts = _mounts()
    if mounts is None:
        return CheckResult(Status.NOT_APPLICABLE, "/proc/mounts could not be read.")
    if mount_point in mounts:
        fs_type, options = mounts[mount_point]
        return CheckResult(
            Status.PASS,
            f"{mount_point} is a separate mount point (fstype={fs_type}, options={','.join(sorted(options))}).",
        )
    return CheckResult(
        Status.FAIL,
        f"{mount_point} is not listed as a separate mount point in /proc/mounts "
        "(it is part of its parent filesystem).",
    )


def _mount_option_check(mount_point: str, option: str) -> CheckResult:
    mounts = _mounts()
    if mounts is None:
        return CheckResult(Status.NOT_APPLICABLE, "/proc/mounts could not be read.")
    if mount_point not in mounts:
        return CheckResult(
            Status.NOT_APPLICABLE,
            f"{mount_point} is not a separate mount point on this host, so the "
            f"'{option}' mount option does not apply.",
        )
    fs_type, options = mounts[mount_point]
    evidence = f"{mount_point} options: {','.join(sorted(options))}"
    if option in options:
        return CheckResult(Status.PASS, evidence)
    return CheckResult(Status.FAIL, evidence + f" (expected '{option}' among mount options)")


@register(
    id="CIS-1.1.2.1",
    title="/tmp is a separate partition",
    category=CATEGORY,
    rationale="Isolating /tmp on its own partition lets it be mounted with "
    "nodev/nosuid/noexec and stops a full /tmp from taking down the rest of "
    "the filesystem.",
    remediation="Add a dedicated /tmp entry to /etc/fstab (or a systemd tmp.mount unit) "
    "and remount.",
)
def check_tmp_separate_partition() -> CheckResult:
    return _is_separate_partition_check("/tmp")


@register(
    id="CIS-1.1.2.2",
    title="/tmp is mounted with nodev",
    category=CATEGORY,
    rationale="/tmp is world-writable by design; nodev stops it being used to "
    "plant device nodes as a privilege-escalation trick.",
    remediation="Add 'nodev' to /tmp's mount options in /etc/fstab and remount.",
)
def check_tmp_nodev() -> CheckResult:
    return _mount_option_check("/tmp", "nodev")


@register(
    id="CIS-1.1.2.3",
    title="/tmp is mounted with nosuid",
    category=CATEGORY,
    rationale="nosuid on /tmp prevents a SUID/SGID binary planted there from "
    "having its privilege bits honored, closing a common local privilege-"
    "escalation path.",
    remediation="Add 'nosuid' to /tmp's mount options in /etc/fstab and remount.",
)
def check_tmp_nosuid() -> CheckResult:
    return _mount_option_check("/tmp", "nosuid")


@register(
    id="CIS-1.1.2.4",
    title="/tmp is mounted with noexec",
    category=CATEGORY,
    rationale="noexec on /tmp stops binaries dropped there (e.g. by a "
    "compromised web app writing to a shared /tmp) from being executed "
    "directly out of it.",
    remediation="Add 'noexec' to /tmp's mount options in /etc/fstab and remount.",
)
def check_tmp_noexec() -> CheckResult:
    return _mount_option_check("/tmp", "noexec")


@register(
    id="CIS-1.1.2.5",
    title="/var is a separate partition",
    category=CATEGORY,
    rationale="Isolating /var (logs, spool, package cache) stops runaway log "
    "growth from filling the root filesystem and taking down the whole host.",
    remediation="Add a dedicated /var entry to /etc/fstab during install/repartition.",
)
def check_var_separate_partition() -> CheckResult:
    return _is_separate_partition_check("/var")


@register(
    id="CIS-1.1.2.6",
    title="/var/tmp is a separate partition",
    category=CATEGORY,
    rationale="Like /tmp, /var/tmp is world-writable and used for temporary "
    "files that can persist across reboots; isolating it enables the same "
    "nodev/nosuid/noexec hardening independently of the root filesystem.",
    remediation="Add a dedicated /var/tmp entry to /etc/fstab and remount.",
)
def check_var_tmp_separate_partition() -> CheckResult:
    return _is_separate_partition_check("/var/tmp")


@register(
    id="CIS-1.1.2.7",
    title="/var/tmp is mounted with nodev",
    category=CATEGORY,
    rationale="Same rationale as /tmp nodev: /var/tmp is world-writable and "
    "shouldn't be usable to plant device nodes.",
    remediation="Add 'nodev' to /var/tmp's mount options in /etc/fstab and remount.",
)
def check_var_tmp_nodev() -> CheckResult:
    return _mount_option_check("/var/tmp", "nodev")


@register(
    id="CIS-1.1.2.8",
    title="/var/tmp is mounted with nosuid",
    category=CATEGORY,
    rationale="Same rationale as /tmp nosuid, applied to /var/tmp.",
    remediation="Add 'nosuid' to /var/tmp's mount options in /etc/fstab and remount.",
)
def check_var_tmp_nosuid() -> CheckResult:
    return _mount_option_check("/var/tmp", "nosuid")


@register(
    id="CIS-1.1.2.9",
    title="/var/tmp is mounted with noexec",
    category=CATEGORY,
    rationale="Same rationale as /tmp noexec, applied to /var/tmp.",
    remediation="Add 'noexec' to /var/tmp's mount options in /etc/fstab and remount.",
)
def check_var_tmp_noexec() -> CheckResult:
    return _mount_option_check("/var/tmp", "noexec")


@register(
    id="CIS-1.1.2.10",
    title="/var/log is a separate partition",
    category=CATEGORY,
    rationale="Isolating /var/log stops a log-flooding attack (or a runaway "
    "process) from filling the root filesystem, and makes log storage easier "
    "to size and monitor independently.",
    remediation="Add a dedicated /var/log entry to /etc/fstab and remount.",
)
def check_var_log_separate_partition() -> CheckResult:
    return _is_separate_partition_check("/var/log")


@register(
    id="CIS-1.1.2.11",
    title="/var/log/audit is a separate partition",
    category=CATEGORY,
    rationale="Isolating the audit log partition protects auditd's records "
    "from being lost to a full root/var filesystem, which matters for "
    "incident response and compliance retention.",
    remediation="Add a dedicated /var/log/audit entry to /etc/fstab and remount.",
)
def check_var_log_audit_separate_partition() -> CheckResult:
    return _is_separate_partition_check("/var/log/audit")


@register(
    id="CIS-1.1.2.12",
    title="/home is a separate partition",
    category=CATEGORY,
    rationale="Isolating user home directories limits the blast radius of a "
    "single user filling the disk and makes it possible to apply nodev to "
    "user-writable storage.",
    remediation="Add a dedicated /home entry to /etc/fstab during install/repartition.",
)
def check_home_separate_partition() -> CheckResult:
    return _is_separate_partition_check("/home")


@register(
    id="CIS-1.1.2.13",
    title="/home is mounted with nodev",
    category=CATEGORY,
    rationale="User home directories don't need to host device nodes; nodev "
    "removes that as an escalation path.",
    remediation="Add 'nodev' to /home's mount options in /etc/fstab and remount.",
)
def check_home_nodev() -> CheckResult:
    return _mount_option_check("/home", "nodev")


@register(
    id="CIS-1.1.2.14",
    title="/dev/shm is mounted with nodev",
    category=CATEGORY,
    rationale="/dev/shm is world-writable shared memory; nodev stops it being "
    "used to plant device nodes.",
    remediation="Add 'nodev' to /dev/shm's mount options in /etc/fstab and remount.",
)
def check_dev_shm_nodev() -> CheckResult:
    return _mount_option_check("/dev/shm", "nodev")


@register(
    id="CIS-1.1.2.15",
    title="/dev/shm is mounted with nosuid",
    category=CATEGORY,
    rationale="nosuid on /dev/shm prevents a SUID binary planted in shared "
    "memory from having its privilege bits honored.",
    remediation="Add 'nosuid' to /dev/shm's mount options in /etc/fstab and remount.",
)
def check_dev_shm_nosuid() -> CheckResult:
    return _mount_option_check("/dev/shm", "nosuid")


@register(
    id="CIS-1.1.2.16",
    title="/dev/shm is mounted with noexec",
    category=CATEGORY,
    rationale="noexec on /dev/shm stops code staged in shared memory (a "
    "common fileless-malware technique) from being executed directly.",
    remediation="Add 'noexec' to /dev/shm's mount options in /etc/fstab and remount.",
)
def check_dev_shm_noexec() -> CheckResult:
    return _mount_option_check("/dev/shm", "noexec")


@register(
    id="CIS-1.1.2.17",
    title="All world-writable directories in key paths have the sticky bit set",
    category=CATEGORY,
    rationale="Without the sticky bit, any user can delete or rename any "
    "other user's files inside a shared world-writable directory like /tmp - "
    "the sticky bit restricts deletion/rename to the file's own owner.",
    remediation="For each reported directory: chmod +t <dir>",
)
def check_sticky_bit_on_world_writable_dirs() -> CheckResult:
    matches: list[str] = []
    checked = 0
    truncated = False
    for base in _SCAN_DIRS_FOR_STICKY:
        if not os.path.isdir(base):
            continue
        for root, dirs, _files in os.walk(base, topdown=True, onerror=lambda e: None):
            for name in dirs:
                checked += 1
                if checked > _SCAN_MAX_ENTRIES:
                    truncated = True
                    break
                full = os.path.join(root, name)
                try:
                    st = os.lstat(full)
                except (FileNotFoundError, PermissionError, OSError):
                    continue
                if stat_mod.S_ISLNK(st.st_mode):
                    continue
                is_world_writable = bool(st.st_mode & stat_mod.S_IWOTH)
                has_sticky = bool(st.st_mode & stat_mod.S_ISVTX)
                if is_world_writable and not has_sticky:
                    matches.append(full)
            if truncated:
                break
    scope = ", ".join(_SCAN_DIRS_FOR_STICKY)
    suffix = " (scan truncated at entry cap, more may exist)" if truncated else ""
    if not matches:
        return CheckResult(
            Status.PASS,
            f"No world-writable directories missing the sticky bit found under {scope} "
            f"({checked} directories scanned{suffix}).",
        )
    shown = matches[:10]
    more = f" and {len(matches) - 10} more" if len(matches) > 10 else ""
    return CheckResult(
        Status.FAIL,
        f"{len(matches)} world-writable director(ies) without the sticky bit under {scope}{suffix}: "
        + ", ".join(shown)
        + more,
    )
