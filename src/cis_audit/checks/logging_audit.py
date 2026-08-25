"""Logging / auditing checks (CIS sections 4.x, plus cron access control which
CIS also files under system-hardening "restrict privileged cron access").

systemctl is-active/is-enabled are read-only queries and work fine as a
non-root user - they read unit state, not modify it.
"""

from __future__ import annotations

import os

from cis_audit.models import CheckResult, Status
from cis_audit.registry import register
from cis_audit.utils import path_mode_octal, path_owner, run_cmd, which

CATEGORY = "logging"


@register(
    id="CIS-4.2.1",
    title="auditd is installed and enabled",
    category=CATEGORY,
    rationale="auditd provides a tamper-evident record of security-relevant "
    "events (file access, syscalls, auth events) that's essential for "
    "incident response and compliance - without it, a breach investigation "
    "has far less to work with.",
    remediation="apt install auditd audispd-plugins && systemctl --now enable auditd",
)
def check_auditd_enabled() -> CheckResult:
    if which("auditctl") is None and not os.path.exists("/usr/sbin/auditd"):
        return CheckResult(Status.FAIL, "auditd is not installed (no auditctl binary, no /usr/sbin/auditd).")
    rc, out, err = run_cmd(["systemctl", "is-enabled", "auditd"])
    rc2, out2, err2 = run_cmd(["systemctl", "is-active", "auditd"])
    evidence = f"systemctl is-enabled auditd: {out or err}; is-active: {out2 or err2}"
    if out.strip() == "enabled" and out2.strip() == "active":
        return CheckResult(Status.PASS, evidence)
    return CheckResult(Status.FAIL, evidence)


@register(
    id="CIS-4.3",
    title="A system logging service (rsyslog or systemd-journald) is active",
    category=CATEGORY,
    rationale="Without a running log service, security-relevant events (auth "
    "failures, sudo use, service crashes) aren't captured anywhere, which "
    "blinds both real-time alerting and after-the-fact investigation.",
    remediation="apt install rsyslog && systemctl --now enable rsyslog  "
    "(or ensure systemd-journald is running: systemctl --now enable systemd-journald)",
)
def check_logging_service_active() -> CheckResult:
    results = {}
    for unit in ("rsyslog", "systemd-journald"):
        rc, out, err = run_cmd(["systemctl", "is-active", unit])
        results[unit] = out.strip() or err.strip()
    evidence = "; ".join(f"{u}: {s}" for u, s in results.items())
    if any(s == "active" for s in results.values()):
        return CheckResult(Status.PASS, evidence)
    return CheckResult(Status.FAIL, evidence + " (no logging service is active)")


@register(
    id="CIS-4.2.4",
    title="Authentication log file is not world-readable or writable",
    category=CATEGORY,
    rationale="Auth logs record login attempts and sudo usage; if readable by "
    "any local user they leak information useful for reconnaissance (valid "
    "usernames, login timing), and if writable by non-root they could be "
    "tampered with to cover an intruder's tracks.",
    remediation="chmod 640 /var/log/auth.log && chown syslog:adm /var/log/auth.log",
)
def check_auth_log_perms() -> CheckResult:
    for candidate in ("/var/log/auth.log", "/var/log/secure"):
        mode = path_mode_octal(candidate)
        if mode is None:
            continue
        owner_group = path_owner(candidate)
        owner, group = owner_group if owner_group else ("?", "?")
        mode_int = int(mode, 8)
        evidence = f"{candidate}: mode={mode} owner={owner} group={group}"
        # not world-readable and not group/other-writable
        if mode_int & 0o037 == 0 and mode_int & 0o022 == 0:
            return CheckResult(Status.PASS, evidence)
        return CheckResult(Status.FAIL, evidence + " (expected no world access, e.g. mode 640)")
    return CheckResult(
        Status.NOT_APPLICABLE,
        "Neither /var/log/auth.log nor /var/log/secure exists - this host likely logs auth "
        "events to the systemd journal only (check with: journalctl -u ssh).",
    )


@register(
    id="CIS-5.1.8",
    title="cron is restricted to authorized users (cron.allow present, cron.deny absent)",
    category=CATEGORY,
    rationale="Without an allow-list, every local user can schedule their own "
    "cron jobs by default, which is a common persistence/privilege-escalation "
    "vector once an account is compromised.",
    remediation="touch /etc/cron.allow && chmod 600 /etc/cron.allow && rm -f /etc/cron.deny "
    "  # list only trusted usernames, one per line, in cron.allow",
)
def check_cron_restricted() -> CheckResult:
    allow_exists = os.path.exists("/etc/cron.allow")
    deny_exists = os.path.exists("/etc/cron.deny")
    evidence = f"/etc/cron.allow exists={allow_exists}, /etc/cron.deny exists={deny_exists}"
    if allow_exists and not deny_exists:
        return CheckResult(Status.PASS, evidence)
    return CheckResult(Status.FAIL, evidence + " (expected cron.allow to exist and cron.deny to not exist)")
