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
