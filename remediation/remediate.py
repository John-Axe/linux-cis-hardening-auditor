#!/usr/bin/env python3
"""remediate.py - fix a subset of cis-audit findings that are safe to automate.

SAFE BY DEFAULT: every fixer runs in --dry-run mode (the default) unless
--apply is passed explicitly, matching the convention used across this
portfolio's other sysadmin scripts (see John-Axe/it-helpdesk-sysadmin-portfolio).
Dry run prints exactly what command(s) it WOULD run, without touching the
system. --apply requires root for anything that touches a system file or a
live sysctl value; it will refuse (not silently no-op) if it isn't root.

Usage:
    python3 remediation/remediate.py --list
    python3 remediation/remediate.py --check CIS-6.1.3            # dry run
    python3 remediation/remediate.py --check CIS-6.1.3 --apply    # actually fix
    python3 remediation/remediate.py --all                        # dry run every fixer
    python3 remediation/remediate.py --all --apply                # apply every fixer

Only checks with an unambiguous, low-risk, single-host fix are covered here
(file permissions, sysctl hardening values, a few sshd_config directives,
login.defs password-aging values, cron access control). Checks whose fix
requires human judgment (e.g. removing an unexpected UID-0 account, deciding
which NOPASSWD sudoers line is actually intentional) are deliberately NOT
automated - cis-audit's report tells you what to look at, but a person
should decide what to do about it.

Exit codes: 0 success, 1 usage error, 2 not root when --apply needs it,
3 one or more fixers failed.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from dataclasses import dataclass
from typing import Callable

# Make this runnable directly from a checkout without installing the package.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))


@dataclass(frozen=True)
class Fixer:
    check_id: str
    description: str
    needs_root: bool
    actions: list[str]  # human-readable description of each shell action
    apply: Callable[[], None]


FIXERS: list[Fixer] = []

# Module-level path constants (rather than hardcoded literals inside each
# fixer) so tests can monkeypatch them to point at a tmp_path sandbox instead
# of real system files - see tests/test_remediate.py.
PASSWD_PATH = "/etc/passwd"
SHADOW_PATH = "/etc/shadow"
GROUP_PATH = "/etc/group"
GSHADOW_PATH = "/etc/gshadow"
LOGIN_DEFS_PATH = "/etc/login.defs"
SSHD_CONFIG_PATH = "/etc/ssh/sshd_config"
SYSCTL_CONF_PATH = "/etc/sysctl.d/60-cis-hardening.conf"
CRON_ALLOW_PATH = "/etc/cron.allow"
CRON_DENY_PATH = "/etc/cron.deny"
MODPROBE_CONF_PATH = "/etc/modprobe.d/cis-hardening.conf"
PWQUALITY_CONF_PATH = "/etc/security/pwquality.conf"
FAILLOCK_CONF_PATH = "/etc/security/faillock.conf"
MOTD_PATH = "/etc/motd"
ISSUE_PATH = "/etc/issue"
ISSUE_NET_PATH = "/etc/issue.net"
CRONTAB_PATH = "/etc/crontab"
CRON_HOURLY_PATH = "/etc/cron.hourly"
CRON_DAILY_PATH = "/etc/cron.daily"
CRON_WEEKLY_PATH = "/etc/cron.weekly"
CRON_MONTHLY_PATH = "/etc/cron.monthly"
CRON_D_PATH = "/etc/cron.d"
AT_ALLOW_PATH = "/etc/at.allow"
AT_DENY_PATH = "/etc/at.deny"
UNATTENDED_UPGRADES_PATH = "/etc/apt/apt.conf.d/50unattended-upgrades"
DEFAULT_USERADD_PATH = "/etc/default/useradd"


def fixer(check_id: str, description: str, needs_root: bool, actions: list[str]):
    def decorator(fn: Callable[[], None]) -> Callable[[], None]:
        FIXERS.append(Fixer(check_id, description, needs_root, actions, fn))
        return fn

    return decorator


def _run(cmd: list[str]) -> None:
    subprocess.run(cmd, check=True)


def _append_sysctl_conf(key: str, value: str) -> None:
    conf_path = SYSCTL_CONF_PATH
    line = f"{key}={value}\n"
    existing = ""
    if os.path.exists(conf_path):
        with open(conf_path) as f:
            existing = f.read()
    if line.strip() not in existing.splitlines():
        with open(conf_path, "a") as f:
            f.write(line)
    _run(["sysctl", "-w", f"{key}={value}"])


# --- filesystem permission fixers -------------------------------------------------

@fixer(
    "CIS-6.1.2", "Set /etc/passwd to 644 root:root", needs_root=True,
    actions=["chown root:root /etc/passwd", "chmod 644 /etc/passwd"],
)
def fix_passwd_perms() -> None:
    _run(["chown", "root:root", PASSWD_PATH])
    _run(["chmod", "644", PASSWD_PATH])


@fixer(
    "CIS-6.1.3", "Set /etc/shadow to 640 root:shadow", needs_root=True,
    actions=["chown root:shadow /etc/shadow", "chmod 640 /etc/shadow"],
)
def fix_shadow_perms() -> None:
    _run(["chown", "root:shadow", SHADOW_PATH])
    _run(["chmod", "640", SHADOW_PATH])


@fixer(
    "CIS-6.1.4", "Set /etc/group to 644 root:root", needs_root=True,
    actions=["chown root:root /etc/group", "chmod 644 /etc/group"],
)
def fix_group_perms() -> None:
    _run(["chown", "root:root", GROUP_PATH])
    _run(["chmod", "644", GROUP_PATH])


@fixer(
    "CIS-6.1.5", "Set /etc/gshadow to 640 root:shadow", needs_root=True,
    actions=["chown root:shadow /etc/gshadow", "chmod 640 /etc/gshadow"],
)
def fix_gshadow_perms() -> None:
    _run(["chown", "root:shadow", GSHADOW_PATH])
    _run(["chmod", "640", GSHADOW_PATH])


# --- login.defs fixers -------------------------------------------------------------

def _set_login_defs_key(key: str, value: str) -> None:
    path = LOGIN_DEFS_PATH
    with open(path) as f:
        lines = f.readlines()
    found = False
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        parts = stripped.split()
        if len(parts) == 2 and parts[0] == key:
            lines[i] = f"{key}\t{value}\n"
            found = True
            break
    if not found:
        lines.append(f"{key}\t{value}\n")
    with open(path, "w") as f:
        f.writelines(lines)


@fixer(
    "CIS-5.4.4", "Set default UMASK 027 in /etc/login.defs", needs_root=True,
    actions=["set UMASK 027 in /etc/login.defs"],
)
def fix_default_umask() -> None:
    _set_login_defs_key("UMASK", "027")


@fixer(
    "CIS-5.4.1.1", "Set PASS_MAX_DAYS 365 in /etc/login.defs", needs_root=True,
    actions=["set PASS_MAX_DAYS 365 in /etc/login.defs"],
)
def fix_pass_max_days() -> None:
    _set_login_defs_key("PASS_MAX_DAYS", "365")


@fixer(
    "CIS-5.4.1.2", "Set PASS_MIN_DAYS 1 in /etc/login.defs", needs_root=True,
    actions=["set PASS_MIN_DAYS 1 in /etc/login.defs"],
)
def fix_pass_min_days() -> None:
    _set_login_defs_key("PASS_MIN_DAYS", "1")


@fixer(
    "CIS-5.4.1.3", "Set PASS_WARN_AGE 7 in /etc/login.defs", needs_root=True,
    actions=["set PASS_WARN_AGE 7 in /etc/login.defs"],
)
def fix_pass_warn_age() -> None:
    _set_login_defs_key("PASS_WARN_AGE", "7")


# --- sshd_config fixers -------------------------------------------------------------

def _set_sshd_directive(key: str, value: str) -> None:
    path = SSHD_CONFIG_PATH
    with open(path) as f:
        lines = f.readlines()
    found = False
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        parts = stripped.split(None, 1)
        if len(parts) == 2 and parts[0].lower() == key.lower():
            lines[i] = f"{key} {value}\n"
            found = True
            break
    if not found:
        lines.append(f"{key} {value}\n")
    with open(path, "w") as f:
        f.writelines(lines)
    _run(["sshd", "-t"])  # validate config before reload
    _run(["systemctl", "reload", "sshd"])


@fixer(
    "CIS-5.2.4", "Set PermitRootLogin no in sshd_config and reload sshd", needs_root=True,
    actions=["set 'PermitRootLogin no' in /etc/ssh/sshd_config", "sshd -t", "systemctl reload sshd"],
)
def fix_ssh_root_login() -> None:
    _set_sshd_directive("PermitRootLogin", "no")


@fixer(
    "CIS-5.2.5", "Set PermitEmptyPasswords no in sshd_config and reload sshd", needs_root=True,
    actions=["set 'PermitEmptyPasswords no' in /etc/ssh/sshd_config", "sshd -t", "systemctl reload sshd"],
)
def fix_ssh_empty_passwords() -> None:
    _set_sshd_directive("PermitEmptyPasswords", "no")


@fixer(
    "CIS-5.2.11", "Set MaxAuthTries 4 in sshd_config and reload sshd", needs_root=True,
    actions=["set 'MaxAuthTries 4' in /etc/ssh/sshd_config", "sshd -t", "systemctl reload sshd"],
)
def fix_ssh_max_auth_tries() -> None:
    _set_sshd_directive("MaxAuthTries", "4")


@fixer(
    "CIS-5.2.16", "Set X11Forwarding no in sshd_config and reload sshd", needs_root=True,
    actions=["set 'X11Forwarding no' in /etc/ssh/sshd_config", "sshd -t", "systemctl reload sshd"],
)
def fix_ssh_x11_forwarding() -> None:
    _set_sshd_directive("X11Forwarding", "no")


# NOTE: PasswordAuthentication is deliberately NOT auto-fixed here even
# though cis-audit checks it (CIS-5.2.10). Flipping it to "no" on a host
# where the operator hasn't already confirmed a working SSH key can lock
# them out entirely - exactly the kind of judgment call this tool leaves to
# a human. Fix it manually once key-based login is confirmed working:
#   sshd_config: PasswordAuthentication no && sshd -t && systemctl reload sshd


# --- sysctl fixers -------------------------------------------------------------------

@fixer(
    "CIS-3.1.1", "Disable IP forwarding (persist + apply live)", needs_root=True,
    actions=["append net.ipv4.ip_forward=0 to /etc/sysctl.d/60-cis-hardening.conf", "sysctl -w net.ipv4.ip_forward=0"],
)
def fix_ip_forward() -> None:
    _append_sysctl_conf("net.ipv4.ip_forward", "0")


@fixer(
    "CIS-3.2.1", "Disable accepting ICMP redirects", needs_root=True,
    actions=["append net.ipv4.conf.all.accept_redirects=0", "sysctl -w net.ipv4.conf.all.accept_redirects=0"],
)
def fix_icmp_redirects() -> None:
    _append_sysctl_conf("net.ipv4.conf.all.accept_redirects", "0")


@fixer(
    "CIS-3.2.2", "Disable sending ICMP redirects", needs_root=True,
    actions=["append net.ipv4.conf.all.send_redirects=0", "sysctl -w net.ipv4.conf.all.send_redirects=0"],
)
def fix_send_redirects() -> None:
    _append_sysctl_conf("net.ipv4.conf.all.send_redirects", "0")


@fixer(
    "CIS-3.2.4", "Enable reverse path filtering", needs_root=True,
    actions=["append net.ipv4.conf.all.rp_filter=1", "sysctl -w net.ipv4.conf.all.rp_filter=1"],
)
def fix_rp_filter() -> None:
    _append_sysctl_conf("net.ipv4.conf.all.rp_filter", "1")


@fixer(
    "CIS-3.3.1", "Enable TCP SYN cookies", needs_root=True,
    actions=["append net.ipv4.tcp_syncookies=1", "sysctl -w net.ipv4.tcp_syncookies=1"],
)
def fix_syncookies() -> None:
    _append_sysctl_conf("net.ipv4.tcp_syncookies", "1")


@fixer(
    "CIS-1.6.1", "Enable full ASLR", needs_root=True,
    actions=["append kernel.randomize_va_space=2", "sysctl -w kernel.randomize_va_space=2"],
)
def fix_aslr() -> None:
    _append_sysctl_conf("kernel.randomize_va_space", "2")


@fixer(
    "CIS-1.6.2", "Restrict SUID core dumps", needs_root=True,
    actions=["append fs.suid_dumpable=0", "sysctl -w fs.suid_dumpable=0"],
)
def fix_suid_dumpable() -> None:
    _append_sysctl_conf("fs.suid_dumpable", "0")


# --- cron access control -------------------------------------------------------------

@fixer(
    "CIS-5.1.8", "Restrict cron to authorized users", needs_root=True,
    actions=["touch /etc/cron.allow && chmod 600 /etc/cron.allow", "rm -f /etc/cron.deny"],
)
def fix_cron_restricted() -> None:
    with open(CRON_ALLOW_PATH, "a"):
        pass
    os.chmod(CRON_ALLOW_PATH, 0o600)
    if os.path.exists(CRON_DENY_PATH):
        os.remove(CRON_DENY_PATH)


@fixer(
    "CIS-5.1.9", "Restrict at to authorized users", needs_root=True,
    actions=["touch /etc/at.allow && chmod 600 /etc/at.allow", "rm -f /etc/at.deny"],
)
def fix_at_restricted() -> None:
    with open(AT_ALLOW_PATH, "a"):
        pass
    os.chmod(AT_ALLOW_PATH, 0o600)
    if os.path.exists(AT_DENY_PATH):
        os.remove(AT_DENY_PATH)


# --- generic helpers used by the factory-registered fixers below ---------------------

def _fix_perms(path_global_name: str, owner: str, group: str, mode: str) -> None:
    """Looks the path up by name in this module's globals at call time (not
    at fixer-registration time), so tests can monkeypatch e.g. MOTD_PATH the
    same way they already redirect SHADOW_PATH etc."""
    path = globals()[path_global_name]
    _run(["chown", f"{owner}:{group}", path])
    _run(["chmod", mode, path])


def _set_conf_key_value(path: str, key: str, value: str) -> None:
    """Sets 'key = value' in a PAM-style config file (pwquality.conf,
    faillock.conf) - updates the first uncommented occurrence of key, or
    appends a new 'key = value' line if it isn't present yet."""
    lines: list[str] = []
    if os.path.exists(path):
        with open(path) as f:
            lines = f.readlines()
    found = False
    for i, line in enumerate(lines):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        token = stripped.split("=", 1)[0].strip() if "=" in stripped else stripped.split(None, 1)[0]
        if token == key:
            lines[i] = f"{key} = {value}\n"
            found = True
            break
    if not found:
        lines.append(f"{key} = {value}\n")
    with open(path, "w") as f:
        f.writelines(lines)


def _append_bare_directive(path: str, directive: str) -> None:
    """Appends a bare (no '=value') directive line, e.g. faillock's
    'even_deny_root', if it isn't already present."""
    existing = ""
    if os.path.exists(path):
        with open(path) as f:
            existing = f.read()
    if directive not in existing.splitlines():
        with open(path, "a") as f:
            f.write(directive + "\n")


def _set_shell_var(path: str, key: str, value: str) -> None:
    """Sets KEY=value in a shell-sourced defaults file (/etc/default/*)."""
    lines: list[str] = []
    if os.path.exists(path):
        with open(path) as f:
            lines = f.readlines()
    found = False
    for i, line in enumerate(lines):
        if line.strip().startswith(f"{key}="):
            lines[i] = f"{key}={value}\n"
            found = True
            break
    if not found:
        lines.append(f"{key}={value}\n")
    with open(path, "w") as f:
        f.writelines(lines)


def _set_apt_conf_bool(path: str, key: str, value: str = "true") -> None:
    """Sets 'key "value";' in an apt.conf.d-style file
    (/etc/apt/apt.conf.d/50unattended-upgrades)."""
    lines: list[str] = []
    if os.path.exists(path):
        with open(path) as f:
            lines = f.readlines()
    needed_line = f'{key} "{value}";\n'
    found = False
    for i, line in enumerate(lines):
        if line.strip().startswith(key):
            lines[i] = needed_line
            found = True
            break
    if not found:
        lines.append(needed_line)
    with open(path, "w") as f:
        f.writelines(lines)


def _modprobe_blacklist(module: str) -> None:
    path = MODPROBE_CONF_PATH
    existing_lines: list[str] = []
    if os.path.exists(path):
        with open(path) as f:
            existing_lines = f.read().splitlines()
    needed = [f"install {module} /bin/true", f"blacklist {module}"]
    to_add = [line for line in needed if line not in existing_lines]
    if to_add:
        with open(path, "a") as f:
            for line in to_add:
                f.write(line + "\n")
    try:
        _run(["rmmod", module])
    except subprocess.CalledProcessError:
        pass  # module most likely wasn't loaded in the first place - not a failure


# --- kernel hardening sysctl fixers (CIS-1.6.3 .. CIS-1.6.12) -------------------------
# All genuinely safe, single-value sysctl writes - same _append_sysctl_conf helper
# already covering CIS-3.1.1/3.2.1/3.2.2/3.2.4/3.3.1/1.6.1/1.6.2 above.

_KERNEL_HARDENING_SYSCTLS = [
    ("CIS-1.6.3", "kernel.kptr_restrict", "1"),
    ("CIS-1.6.4", "kernel.dmesg_restrict", "1"),
    ("CIS-1.6.5", "kernel.yama.ptrace_scope", "1"),
    ("CIS-1.6.6", "fs.protected_hardlinks", "1"),
    ("CIS-1.6.7", "fs.protected_symlinks", "1"),
    ("CIS-1.6.8", "fs.protected_fifos", "2"),
    ("CIS-1.6.9", "fs.protected_regular", "2"),
    ("CIS-1.6.10", "kernel.unprivileged_bpf_disabled", "1"),
    ("CIS-1.6.11", "net.core.bpf_jit_harden", "2"),
    ("CIS-1.6.12", "kernel.perf_event_paranoid", "2"),
]

# --- expanded network hardening sysctl fixers (CIS-3.2.3 .. CIS-3.2.18) ---------------

_NETWORK_SYSCTL_EXPANDED = [
    ("CIS-3.2.3", "net.ipv4.conf.all.accept_source_route", "0"),
    ("CIS-3.2.5", "net.ipv4.conf.default.accept_source_route", "0"),
    ("CIS-3.2.6", "net.ipv4.conf.default.accept_redirects", "0"),
    ("CIS-3.2.7", "net.ipv4.conf.default.send_redirects", "0"),
    ("CIS-3.2.8", "net.ipv4.conf.all.secure_redirects", "0"),
    ("CIS-3.2.9", "net.ipv4.conf.default.secure_redirects", "0"),
    ("CIS-3.2.10", "net.ipv4.conf.all.log_martians", "1"),
    ("CIS-3.2.11", "net.ipv4.conf.default.log_martians", "1"),
    ("CIS-3.2.12", "net.ipv4.icmp_echo_ignore_broadcasts", "1"),
    ("CIS-3.2.13", "net.ipv4.icmp_ignore_bogus_error_responses", "1"),
    ("CIS-3.2.14", "net.ipv4.conf.default.rp_filter", "1"),
    ("CIS-3.2.15", "net.ipv6.conf.all.accept_ra", "0"),
    ("CIS-3.2.16", "net.ipv6.conf.default.accept_ra", "0"),
    ("CIS-3.2.17", "net.ipv6.conf.all.accept_source_route", "0"),
    ("CIS-3.2.18", "net.ipv6.conf.default.accept_source_route", "0"),
]


def _register_sysctl_fixer(check_id: str, key: str, value: str) -> None:
    def _apply(key=key, value=value) -> None:
        _append_sysctl_conf(key, value)

    FIXERS.append(
        Fixer(
            check_id,
            f"Set {key}={value} (persist + apply live)",
            True,
            [f"append {key}={value} to /etc/sysctl.d/60-cis-hardening.conf", f"sysctl -w {key}={value}"],
            _apply,
        )
    )


for _check_id, _key, _value in _KERNEL_HARDENING_SYSCTLS + _NETWORK_SYSCTL_EXPANDED:
    _register_sysctl_fixer(_check_id, _key, _value)


# --- kernel module blacklist fixers (CIS-1.1.1.1 .. CIS-1.1.1.14) ---------------------

_KERNEL_MODULES = [
    ("CIS-1.1.1.1", "cramfs"),
    ("CIS-1.1.1.2", "freevxfs"),
    ("CIS-1.1.1.3", "hfs"),
    ("CIS-1.1.1.4", "hfsplus"),
    ("CIS-1.1.1.5", "jffs2"),
    ("CIS-1.1.1.6", "squashfs"),
    ("CIS-1.1.1.7", "udf"),
    ("CIS-1.1.1.8", "usb-storage"),
    ("CIS-1.1.1.9", "dccp"),
    ("CIS-1.1.1.10", "sctp"),
    ("CIS-1.1.1.11", "rds"),
    ("CIS-1.1.1.12", "tipc"),
    ("CIS-1.1.1.13", "firewire-core"),
    ("CIS-1.1.1.14", "bluetooth"),
]

for _check_id, _module in _KERNEL_MODULES:
    def _make_modprobe_fixer(module=_module):
        def _apply() -> None:
            _modprobe_blacklist(module)
        return _apply

    FIXERS.append(
        Fixer(
            _check_id,
            f"Blacklist kernel module '{_module}'",
            True,
            [
                f"append 'install {_module} /bin/true' and 'blacklist {_module}' to "
                f"/etc/modprobe.d/cis-hardening.conf",
                f"rmmod {_module} (best-effort, ignored if not loaded)",
            ],
            _make_modprobe_fixer(),
        )
    )


# --- banner permission fixers (CIS-1.8.1 .. CIS-1.8.3) --------------------------------

_BANNER_PERMS = [
    ("CIS-1.8.1", "MOTD_PATH", "/etc/motd"),
    ("CIS-1.8.2", "ISSUE_PATH", "/etc/issue"),
    ("CIS-1.8.3", "ISSUE_NET_PATH", "/etc/issue.net"),
]

for _check_id, _path_attr, _display_path in _BANNER_PERMS:
    def _make_perm_fixer(path_attr=_path_attr):
        def _apply() -> None:
            _fix_perms(path_attr, "root", "root", "644")
        return _apply

    FIXERS.append(
        Fixer(
            _check_id,
            f"Set {_display_path} to 644 root:root",
            True,
            [f"chown root:root {_display_path}", f"chmod 644 {_display_path}"],
            _make_perm_fixer(),
        )
    )


# --- cron directory/file permission fixers (CIS-5.1.2 .. CIS-5.1.7) -------------------

_CRON_PERMS = [
    ("CIS-5.1.2", "CRONTAB_PATH", "/etc/crontab", "600"),
    ("CIS-5.1.3", "CRON_HOURLY_PATH", "/etc/cron.hourly", "700"),
    ("CIS-5.1.4", "CRON_DAILY_PATH", "/etc/cron.daily", "700"),
    ("CIS-5.1.5", "CRON_WEEKLY_PATH", "/etc/cron.weekly", "700"),
    ("CIS-5.1.6", "CRON_MONTHLY_PATH", "/etc/cron.monthly", "700"),
    ("CIS-5.1.7", "CRON_D_PATH", "/etc/cron.d", "700"),
]

for _check_id, _path_attr, _display_path, _mode in _CRON_PERMS:
    def _make_cron_perm_fixer(path_attr=_path_attr, mode=_mode):
        def _apply() -> None:
            _fix_perms(path_attr, "root", "root", mode)
        return _apply

    FIXERS.append(
        Fixer(
            _check_id,
            f"Set {_display_path} to {_mode} root:root",
            True,
            [f"chown root:root {_display_path}", f"chmod {_mode} {_display_path}"],
            _make_cron_perm_fixer(),
        )
    )


# --- pwquality fixers (CIS-5.5.1.1 .. CIS-5.5.1.8) -------------------------------------

_PWQUALITY_VALUES = [
    ("CIS-5.5.1.1", "minlen", "14"),
    ("CIS-5.5.1.2", "dcredit", "-1"),
    ("CIS-5.5.1.3", "ucredit", "-1"),
    ("CIS-5.5.1.4", "lcredit", "-1"),
    ("CIS-5.5.1.5", "ocredit", "-1"),
    ("CIS-5.5.1.6", "maxrepeat", "3"),
    ("CIS-5.5.1.7", "difok", "2"),
    ("CIS-5.5.1.8", "retry", "3"),
]

for _check_id, _key, _value in _PWQUALITY_VALUES:
    def _make_pwquality_fixer(key=_key, value=_value):
        def _apply() -> None:
            _set_conf_key_value(PWQUALITY_CONF_PATH, key, value)
        return _apply

    FIXERS.append(
        Fixer(
            _check_id,
            f"Set pwquality {_key} = {_value}",
            True,
            [f"set '{_key} = {_value}' in /etc/security/pwquality.conf"],
            _make_pwquality_fixer(),
        )
    )


# --- faillock fixers (CIS-5.5.2.1 .. CIS-5.5.2.3) --------------------------------------

@fixer(
    "CIS-5.5.2.1", "Set faillock deny = 5", needs_root=True,
    actions=["set 'deny = 5' in /etc/security/faillock.conf"],
)
def fix_faillock_deny() -> None:
    _set_conf_key_value(FAILLOCK_CONF_PATH, "deny", "5")


@fixer(
    "CIS-5.5.2.2", "Set faillock unlock_time = 900", needs_root=True,
    actions=["set 'unlock_time = 900' in /etc/security/faillock.conf"],
)
def fix_faillock_unlock_time() -> None:
    _set_conf_key_value(FAILLOCK_CONF_PATH, "unlock_time", "900")


@fixer(
    "CIS-5.5.2.3", "Enable faillock even_deny_root", needs_root=True,
    actions=["append 'even_deny_root' to /etc/security/faillock.conf"],
)
def fix_faillock_even_deny_root() -> None:
    _append_bare_directive(FAILLOCK_CONF_PATH, "even_deny_root")


# --- expanded sshd_config directive fixers (CIS-5.2.12 .. CIS-5.2.27) ------------------
# Same _set_sshd_directive helper as the CIS-5.2.4/5/11/16 fixers above. None of these
# risk locking an operator out the way PasswordAuthentication would, so unlike that one
# they're safe to automate.

_SSHD_DIRECTIVES_EXPANDED = [
    ("CIS-5.2.12", "LoginGraceTime", "60"),
    ("CIS-5.2.13", "MaxSessions", "10"),
    ("CIS-5.2.14", "ClientAliveInterval", "300"),
    ("CIS-5.2.15", "ClientAliveCountMax", "3"),
    ("CIS-5.2.17", "AllowTcpForwarding", "no"),
    ("CIS-5.2.18", "PermitUserEnvironment", "no"),
    ("CIS-5.2.19", "IgnoreRhosts", "yes"),
    ("CIS-5.2.21", "HostbasedAuthentication", "no"),
    ("CIS-5.2.22", "LogLevel", "INFO"),
    ("CIS-5.2.26", "Compression", "no"),
    ("CIS-5.2.27", "UsePAM", "yes"),
]

for _check_id, _directive, _value in _SSHD_DIRECTIVES_EXPANDED:
    def _make_sshd_fixer(directive=_directive, value=_value):
        def _apply() -> None:
            _set_sshd_directive(directive, value)
        return _apply

    FIXERS.append(
        Fixer(
            _check_id,
            f"Set {_directive} {_value} in sshd_config and reload sshd",
            True,
            [f"set '{_directive} {_value}' in /etc/ssh/sshd_config", "sshd -t", "systemctl reload sshd"],
            _make_sshd_fixer(),
        )
    )


# --- expanded auth fixers (CIS-5.4.3, CIS-5.4.5) ---------------------------------------

@fixer(
    "CIS-5.4.3", "Set ENCRYPT_METHOD SHA512 in /etc/login.defs", needs_root=True,
    actions=["set ENCRYPT_METHOD SHA512 in /etc/login.defs"],
)
def fix_password_hash_algorithm() -> None:
    _set_login_defs_key("ENCRYPT_METHOD", "SHA512")


@fixer(
    "CIS-5.4.5", "Set INACTIVE=30 in /etc/default/useradd", needs_root=True,
    actions=["set INACTIVE=30 in /etc/default/useradd"],
)
def fix_default_inactive_lock() -> None:
    _set_shell_var(DEFAULT_USERADD_PATH, "INACTIVE", "30")


# --- unattended-upgrades detail fixers (CIS-1.7.1, CIS-1.7.2) --------------------------

@fixer(
    "CIS-1.7.1", "Enable Unattended-Upgrade::Automatic-Reboot", needs_root=True,
    actions=['set \'Unattended-Upgrade::Automatic-Reboot "true";\' in '
             "/etc/apt/apt.conf.d/50unattended-upgrades"],
)
def fix_unattended_upgrades_auto_reboot() -> None:
    _set_apt_conf_bool(UNATTENDED_UPGRADES_PATH, "Unattended-Upgrade::Automatic-Reboot", "true")


@fixer(
    "CIS-1.7.2", "Enable Unattended-Upgrade::Remove-Unused-Dependencies", needs_root=True,
    actions=['set \'Unattended-Upgrade::Remove-Unused-Dependencies "true";\' in '
             "/etc/apt/apt.conf.d/50unattended-upgrades"],
)
def fix_unattended_upgrades_remove_unused() -> None:
    _set_apt_conf_bool(UNATTENDED_UPGRADES_PATH, "Unattended-Upgrade::Remove-Unused-Dependencies", "true")


# --- CLI -------------------------------------------------------------------------------

def _print_dry_run(f: Fixer) -> None:
    print(f"[DRY RUN] {f.check_id}: {f.description}")
    for action in f.actions:
        print(f"    would run: {action}")


def _apply(f: Fixer) -> bool:
    if f.needs_root and os.geteuid() != 0:
        print(f"[SKIPPED] {f.check_id}: requires root, re-run with sudo", file=sys.stderr)
        return False
    print(f"[APPLYING] {f.check_id}: {f.description}")
    try:
        f.apply()
    except Exception as exc:
        print(f"[FAILED] {f.check_id}: {exc}", file=sys.stderr)
        return False
    print(f"[DONE] {f.check_id}")
    return True


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--list", action="store_true", help="List available fixers and exit.")
    group.add_argument("--check", metavar="CHECK_ID", help="Run the fixer for one check id, e.g. CIS-6.1.3")
    group.add_argument("--all", action="store_true", help="Run every available fixer.")
    parser.add_argument("--apply", action="store_true", help="Actually make changes (default: dry run / print only).")
    args = parser.parse_args(argv)

    if args.list:
        for f in FIXERS:
            print(f"{f.check_id:<14} {f.description}")
        return 0

    targets = FIXERS if args.all else [f for f in FIXERS if f.check_id == args.check]
    if not targets:
        print(f"No fixer registered for check id: {args.check}", file=sys.stderr)
        print("Run with --list to see available fixers.", file=sys.stderr)
        return 1

    if not args.apply:
        for f in targets:
            _print_dry_run(f)
        print(f"\n{len(targets)} fixer(s) shown in dry-run mode. Re-run with --apply to make changes.")
        return 0

    failures = 0
    for f in targets:
        if not _apply(f):
            failures += 1
    return 3 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
