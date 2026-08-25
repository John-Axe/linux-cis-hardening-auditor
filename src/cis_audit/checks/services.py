"""Service inventory and misc. system-hardening checks (CIS sections 1.x, 2.x, 5.3).

Sudoers checks gracefully report NOT_APPLICABLE when /etc/sudoers isn't
readable (mode 440 root:root on a correctly configured system) rather than
failing - same "the check itself proves the permission is right" pattern as
the /etc/shadow read in checks/auth.py.
"""

from __future__ import annotations

import os

from cis_audit.models import CheckResult, Status
from cis_audit.registry import register
from cis_audit.utils import read_lines, sysctl_value, which

CATEGORY = "services"

# Binaries for legacy/plaintext-protocol services that CIS recommends be
# absent on a hardened host - each one has a modern, encrypted replacement
# (SSH/SFTP, etc.) and no business being installed by default.
_LEGACY_SERVICE_BINARIES = {
    "telnet server (in.telnetd)": ["in.telnetd", "telnetd"],
    "rsh server (rshd)": ["rshd", "in.rshd"],
    "rlogin server (rlogind)": ["rlogind", "in.rlogind"],
    "TFTP server (tftpd)": ["tftpd", "in.tftpd"],
    "NIS server (ypserv)": ["ypserv"],
}


@register(
    id="CIS-2.1.1",
    title="Legacy plaintext-protocol services (telnet/rsh/rlogin/tftp/NIS) are not installed",
    category=CATEGORY,
    rationale="These services transmit credentials and data in cleartext and "
    "have long-available encrypted replacements (SSH/SFTP). Their presence "
    "is almost always leftover cruft, not an intentional choice.",
    remediation="apt purge telnetd rsh-server rlogin nis tftpd-hpa  # remove whichever are installed",
)
def check_legacy_services_absent() -> CheckResult:
    found = []
    for label, binaries in _LEGACY_SERVICE_BINARIES.items():
        for b in binaries:
            if which(b):
                found.append(f"{label} ({which(b)})")
                break
    if not found:
        return CheckResult(
            Status.PASS,
            "No legacy service binaries found on PATH (checked: " + ", ".join(_LEGACY_SERVICE_BINARIES.keys()) + ").",
        )
    return CheckResult(Status.FAIL, "Found installed legacy service(s): " + ", ".join(found))


@register(
    id="CIS-1.1",
    title="Automatic security updates are configured",
    category=CATEGORY,
    rationale="Unpatched known vulnerabilities are one of the most common "
    "initial-access vectors. Automatic security updates close that gap "
    "without relying on a human to remember to patch.",
    remediation="apt install unattended-upgrades && dpkg-reconfigure -plow unattended-upgrades",
)
def check_automatic_updates_configured() -> CheckResult:
    lines = read_lines("/etc/apt/apt.conf.d/20auto-upgrades")
    if lines is None:
        return CheckResult(
            Status.FAIL,
            "/etc/apt/apt.conf.d/20auto-upgrades does not exist - unattended-upgrades is not configured.",
        )
    joined = "\n".join(lines)
    enabled = 'APT::Periodic::Unattended-Upgrade "1"' in joined
    evidence = f"/etc/apt/apt.conf.d/20auto-upgrades: {joined!r}"
    if enabled:
        return CheckResult(Status.PASS, evidence)
    return CheckResult(Status.FAIL, evidence + " (Unattended-Upgrade is not set to \"1\")")


@register(
    id="CIS-1.6.1",
    title="Address space layout randomization (ASLR) is enabled",
    category=CATEGORY,
    rationale="ASLR randomizes where a process's memory regions are placed, "
    "making memory-corruption exploits (buffer overflows, etc.) substantially "
    "harder to reliably exploit.",
    remediation="sysctl -w kernel.randomize_va_space=2 && echo 'kernel.randomize_va_space=2' >> /etc/sysctl.d/60-cis-hardening.conf",
)
def check_aslr_enabled() -> CheckResult:
    value = sysctl_value("kernel.randomize_va_space")
    if value is None:
        return CheckResult(Status.NOT_APPLICABLE, "kernel.randomize_va_space is not readable on this kernel.")
    evidence = f"kernel.randomize_va_space = {value}"
    if value == "2":
        return CheckResult(Status.PASS, evidence)
    return CheckResult(Status.FAIL, evidence + " (expected 2 = full randomization)")


@register(
    id="CIS-1.6.2",
    title="Core dumps are restricted for SUID programs",
    category=CATEGORY,
    rationale="A core dump of a SUID program can leak sensitive memory "
    "contents (e.g. credentials handled by that process) to any local user "
    "who can read the resulting core file.",
    remediation="sysctl -w fs.suid_dumpable=0 && echo 'fs.suid_dumpable=0' >> /etc/sysctl.d/60-cis-hardening.conf",
)
def check_suid_dumpable_disabled() -> CheckResult:
    value = sysctl_value("fs.suid_dumpable")
    if value is None:
        return CheckResult(Status.NOT_APPLICABLE, "fs.suid_dumpable is not readable on this kernel.")
    evidence = f"fs.suid_dumpable = {value}"
    if value == "0":
        return CheckResult(Status.PASS, evidence)
    return CheckResult(Status.FAIL, evidence + " (expected 0)")


def _sudoers_files() -> list[str]:
    files = []
    if os.path.exists("/etc/sudoers"):
        files.append("/etc/sudoers")
    sudoers_d = "/etc/sudoers.d"
    if os.path.isdir(sudoers_d):
        try:
            for name in sorted(os.listdir(sudoers_d)):
                if name.startswith(".") or name in ("README",):
                    continue
                files.append(os.path.join(sudoers_d, name))
        except PermissionError:
            pass
    return files


@register(
    id="CIS-5.3",
    title="No passwordless (NOPASSWD) sudo entries are configured",
    category=CATEGORY,
    rationale="A NOPASSWD sudo rule means anyone with access to that account "
    "(e.g. via a stolen SSH key or an unattended session) gets root with no "
    "second factor - it collapses 'compromise the account' and 'compromise "
    "root' into the same event.",
    remediation="Edit the offending file with visudo -f <file> and remove the NOPASSWD tag, "
    "requiring a password (or configure MFA-backed sudo) for privileged commands.",
)
def check_no_passwordless_sudo() -> CheckResult:
    files = _sudoers_files()
    if not files:
        return CheckResult(Status.NOT_APPLICABLE, "/etc/sudoers does not exist on this host.")

    unreadable = []
    offending = []
    any_readable = False
    for f in files:
        lines = read_lines(f)
        if lines is None:
            unreadable.append(f)
            continue
        any_readable = True
        for line in lines:
            stripped = line.strip()
            if stripped.startswith("#") or not stripped:
                continue
            if "NOPASSWD" in stripped:
                offending.append(f"{f}: {stripped}")

    if not any_readable:
        return CheckResult(
            Status.NOT_APPLICABLE,
            f"None of {', '.join(files)} are readable without root (expected mode 440) - cannot verify.",
        )

    note = f" ({len(unreadable)} file(s) not readable: {', '.join(unreadable)})" if unreadable else ""
    if not offending:
        return CheckResult(Status.PASS, f"Checked {len(files)} sudoers file(s); no NOPASSWD entries found." + note)
    return CheckResult(Status.FAIL, f"{len(offending)} NOPASSWD entr(y/ies) found: " + " | ".join(offending) + note)
