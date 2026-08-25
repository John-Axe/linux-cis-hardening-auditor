"""Cron/at access-control checks (CIS section 5.1, extending the single
cron.allow check already in checks/logging_audit.py) and PAM password-
quality/lockout/history checks (CIS section 5.5) - pwquality.conf,
faillock.conf, and pwhistory settings read individually, the same way
checks/auth.py reads login.defs fields individually rather than combined.
"""

from __future__ import annotations

import os

from cis_audit.models import CheckResult, Status
from cis_audit.registry import register
from cis_audit.utils import path_mode_octal, path_owner, read_lines, read_text, run_cmd

CATEGORY_CRON = "cron_pam"
CATEGORY_PAM = "cron_pam"


# --- cron / at access control ------------------------------------------------------------

@register(
    id="CIS-5.1.1",
    title="The cron daemon is enabled and active",
    category=CATEGORY_CRON,
    rationale="Scheduled jobs (log rotation, security scans, unattended-"
    "upgrades' own timer in some configurations) depend on cron actually "
    "running - an installed-but-stopped cron daemon silently breaks all of "
    "them.",
    remediation="systemctl --now enable cron",
)
def check_cron_daemon_active() -> CheckResult:
    rc, out, err = run_cmd(["systemctl", "is-active", "cron"])
    rc2, out2, err2 = run_cmd(["systemctl", "is-enabled", "cron"])
    evidence = f"systemctl is-active cron: {out or err}; is-enabled: {out2 or err2}"
    if out.strip() == "active" and out2.strip() == "enabled":
        return CheckResult(Status.PASS, evidence)
    return CheckResult(Status.FAIL, evidence)


def _cron_perms_check(id: str, path: str, max_mode: int) -> None:
    @register(
        id=id,
        title=f"{path} permissions are {oct(max_mode)[2:].zfill(3)} or more restrictive, owned by root",
        category=CATEGORY_CRON,
        rationale=f"If {path} is writable by non-root users, a local user "
        "could plant a job that runs with root's cron privileges, a direct "
        "privilege-escalation path.",
        remediation=f"chown root:root {path} && chmod {oct(max_mode)[2:].zfill(3)} {path}",
    )
    def _check() -> CheckResult:
        mode = path_mode_octal(path)
        if mode is None:
            return CheckResult(Status.NOT_APPLICABLE, f"{path} does not exist or is not stat-able on this host.")
        owner_group = path_owner(path)
        owner, group = owner_group if owner_group else ("?", "?")
        mode_int = int(mode, 8)
        evidence = f"{path}: mode={mode} owner={owner} group={group}"
        if mode_int <= max_mode and owner == "root":
            return CheckResult(Status.PASS, evidence)
        return CheckResult(
            Status.FAIL, evidence + f" (expected mode <= {oct(max_mode)[2:].zfill(3)}, owner root)"
        )

    _check.__name__ = f"check_{id.replace('-', '_').replace('.', '_')}"


_cron_perms_check("CIS-5.1.2", "/etc/crontab", 0o600)
_cron_perms_check("CIS-5.1.3", "/etc/cron.hourly", 0o700)
_cron_perms_check("CIS-5.1.4", "/etc/cron.daily", 0o700)
_cron_perms_check("CIS-5.1.5", "/etc/cron.weekly", 0o700)
_cron_perms_check("CIS-5.1.6", "/etc/cron.monthly", 0o700)
_cron_perms_check("CIS-5.1.7", "/etc/cron.d", 0o700)


@register(
    id="CIS-5.1.9",
    title="at is restricted to authorized users (at.allow present, at.deny absent)",
    category=CATEGORY_CRON,
    rationale="Same rationale as cron.allow (CIS-5.1.8 in checks/"
    "logging_audit.py): without an allow-list, any local user can schedule "
    "a one-off privileged-context job via 'at'.",
    remediation="touch /etc/at.allow && chmod 600 /etc/at.allow && rm -f /etc/at.deny "
    "  # list only trusted usernames, one per line, in at.allow",
)
def check_at_restricted() -> CheckResult:
    allow_exists = os.path.exists("/etc/at.allow")
    deny_exists = os.path.exists("/etc/at.deny")
    evidence = f"/etc/at.allow exists={allow_exists}, /etc/at.deny exists={deny_exists}"
    if allow_exists and not deny_exists:
        return CheckResult(Status.PASS, evidence)
    return CheckResult(Status.FAIL, evidence + " (expected at.allow to exist and at.deny to not exist)")


@register(
    id="CIS-5.1.10",
    title="Access to the su command is restricted to a defined group",
    category=CATEGORY_CRON,
    rationale="Without pam_wheel restricting su, any local user can attempt "
    "to su to root (still needing root's password, but it removes an easy "
    "detection point and lets any account brute-force-guess it).",
    remediation="Add 'auth required pam_wheel.so use_uid group=sudo' to /etc/pam.d/su",
)
def check_su_restricted() -> CheckResult:
    text = read_text("/etc/pam.d/su")
    if text is None:
        return CheckResult(Status.NOT_APPLICABLE, "/etc/pam.d/su could not be read.")
    restricted = any(
        "pam_wheel.so" in line and not line.strip().startswith("#") for line in text.splitlines()
    )
    evidence = f"/etc/pam.d/su references pam_wheel.so: {restricted}"
    if restricted:
        return CheckResult(Status.PASS, evidence)
    return CheckResult(Status.FAIL, evidence)


# --- PAM pwquality / faillock / pwhistory -----------------------------------------------

_PWQUALITY_PATHS = ("/etc/security/pwquality.conf",)
_FAILLOCK_PATHS = ("/etc/security/faillock.conf",)


def _pam_conf_value(paths: tuple[str, ...], key: str) -> tuple[str | None, str]:
    """Reads a 'key = value' or 'key value' style PAM config file. Returns
    (value-or-None, source-path-checked-description)."""
    for path in paths:
        lines = read_lines(path)
        if lines is None:
            continue
        for line in lines:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if "=" in stripped:
                k, _, v = stripped.partition("=")
                k, v = k.strip(), v.strip()
            else:
                parts = stripped.split(None, 1)
                k, v = parts[0], parts[1] if len(parts) > 1 else ""
            if k == key:
                return v, path
        return None, path  # file exists and was read, key just isn't set
    return None, " or ".join(paths) + " (not found)"


def _pwquality_int_check(id: str, key: str, comparator, expected_desc: str, rationale: str) -> None:
    @register(
        id=id,
        title=f"pwquality {key} {expected_desc}",
        category=CATEGORY_PAM,
        rationale=rationale,
        remediation=f"Set '{key} = <value>' in /etc/security/pwquality.conf",
    )
    def _check() -> CheckResult:
        value, source = _pam_conf_value(_PWQUALITY_PATHS, key)
        if value is None:
            return CheckResult(Status.FAIL, f"{key} is not set in {source} (pwquality default does not enforce this).")
        try:
            value_int = int(value)
        except ValueError:
            return CheckResult(Status.NOT_APPLICABLE, f"{source} {key} = {value!r} is not an integer.")
        evidence = f"{source} {key} = {value}"
        if comparator(value_int):
            return CheckResult(Status.PASS, evidence)
        return CheckResult(Status.FAIL, evidence + f" (expected {expected_desc})")

    _check.__name__ = f"check_{id.replace('-', '_').replace('.', '_')}"


_pwquality_int_check(
    "CIS-5.5.1.1", "minlen", lambda v: v >= 14, "minlen >= 14",
    "A short minimum password length is the single biggest factor in how "
    "fast an offline attacker can brute-force a stolen hash.",
)
_pwquality_int_check(
    "CIS-5.5.1.2", "dcredit", lambda v: v <= -1, "dcredit <= -1 (at least one digit required)",
    "Requiring at least one digit meaningfully increases the password "
    "keyspace against dictionary-based guessing.",
)
_pwquality_int_check(
    "CIS-5.5.1.3", "ucredit", lambda v: v <= -1, "ucredit <= -1 (at least one uppercase letter required)",
    "Requiring at least one uppercase character increases keyspace against "
    "dictionary-based guessing.",
)
_pwquality_int_check(
    "CIS-5.5.1.4", "lcredit", lambda v: v <= -1, "lcredit <= -1 (at least one lowercase letter required)",
    "Requiring at least one lowercase character prevents all-uppercase or "
    "all-numeric trivial passwords.",
)
_pwquality_int_check(
    "CIS-5.5.1.5", "ocredit", lambda v: v <= -1, "ocredit <= -1 (at least one special character required)",
    "Requiring at least one special character further increases keyspace "
    "against dictionary-based guessing.",
)
_pwquality_int_check(
    "CIS-5.5.1.6", "maxrepeat", lambda v: 0 < v <= 3, "0 < maxrepeat <= 3",
    "Without a repeat-character limit, trivially weak passwords like "
    "'aaaaaaaaaaaa' pass a pure length requirement.",
)
_pwquality_int_check(
    "CIS-5.5.1.7", "difok", lambda v: v >= 2, "difok >= 2",
    "difok requires a new password to differ from the old one by enough "
    "characters that a trivial single-character rotation doesn't count as "
    "a real password change.",
)
_pwquality_int_check(
    "CIS-5.5.1.8", "retry", lambda v: 0 < v <= 3, "0 < retry <= 3",
    "Limiting retries during interactive password changes reduces the "
    "window for scripted guessing against the password-change prompt "
    "itself.",
)


def _faillock_value_check(id: str, key: str, title: str, rationale: str, comparator, remediation: str) -> None:
    @register(id=id, title=title, category=CATEGORY_PAM, rationale=rationale, remediation=remediation)
    def _check() -> CheckResult:
        value, source = _pam_conf_value(_FAILLOCK_PATHS, key)
        evidence = f"{source} {key} = {value!r}"
        if comparator(value):
            return CheckResult(Status.PASS, evidence)
        return CheckResult(Status.FAIL, evidence)

    _check.__name__ = f"check_{id.replace('-', '_').replace('.', '_')}"


def _deny_comparator(value: str | None) -> bool:
    if value is None:
        return False
    try:
        return 0 < int(value) <= 5
    except ValueError:
        return False


_faillock_value_check(
    "CIS-5.5.2.1", "deny", "faillock deny is set to 5 or fewer failed attempts",
    "Without a bounded failed-attempt count, an attacker can brute-force "
    "passwords indefinitely with no lockout at all.",
    _deny_comparator,
    "Set 'deny = 5' in /etc/security/faillock.conf",
)
_faillock_value_check(
    "CIS-5.5.2.2", "unlock_time", "faillock unlock_time is configured",
    "unlock_time defines how long an account stays locked after hitting "
    "the deny threshold - without it set, the lockout duration falls back "
    "to a default that may not match this host's intended policy.",
    lambda v: v is not None,
    "Set 'unlock_time = 900' in /etc/security/faillock.conf",
)
_faillock_value_check(
    "CIS-5.5.2.3", "even_deny_root", "faillock even_deny_root is enabled",
    "Without even_deny_root, the lockout policy exempts the root account "
    "entirely, leaving it open to unlimited online password guessing.",
    lambda v: v is not None,
    "Add 'even_deny_root' to /etc/security/faillock.conf",
)


@register(
    id="CIS-5.5.3.1",
    title="Password reuse (history) is restricted to at least the last 24 passwords",
    category=CATEGORY_PAM,
    rationale="Without a remembered-password history, a user can satisfy a "
    "forced password change by immediately rotating back to a password "
    "they've used before, defeating the point of periodic rotation.",
    remediation="Add 'remember = 24' to the pam_pwhistory.so line in "
    "/etc/pam.d/common-password",
)
def check_pwhistory_remember() -> CheckResult:
    text = read_text("/etc/pam.d/common-password")
    if text is None:
        return CheckResult(Status.NOT_APPLICABLE, "/etc/pam.d/common-password could not be read.")
    remember_value = None
    for line in text.splitlines():
        if "pam_pwhistory.so" not in line or line.strip().startswith("#"):
            continue
        for token in line.split():
            if token.startswith("remember="):
                remember_value = token.split("=", 1)[1]
    evidence = f"/etc/pam.d/common-password pam_pwhistory.so remember={remember_value!r}"
    try:
        if remember_value is not None and int(remember_value) >= 24:
            return CheckResult(Status.PASS, evidence)
    except ValueError:
        pass
    return CheckResult(Status.FAIL, evidence + " (expected remember >= 24)")
