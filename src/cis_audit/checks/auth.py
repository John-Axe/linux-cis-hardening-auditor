"""Authentication / password-policy checks (CIS sections 5.4.x, 6.2.x).

Anything that reads /etc/shadow gracefully degrades to NOT_APPLICABLE when
run unprivileged - /etc/shadow is 640 root:shadow on a correctly hardened
system, so an unprivileged run legitimately cannot read it. That is itself
evidence the permission check (CIS-6.1.3) is working, not a bug in this tool.
Never prints or stores a raw password hash field - see utils.redact().
"""

from __future__ import annotations

from cis_audit.models import CheckResult, Status
from cis_audit.registry import register
from cis_audit.utils import read_lines

CATEGORY = "auth"


def _login_defs_value(key: str) -> str | None:
    lines = read_lines("/etc/login.defs")
    if lines is None:
        return None
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        parts = stripped.split()
        if len(parts) == 2 and parts[0] == key:
            return parts[1]
    return None


def _login_defs_int_check(key: str, comparator, expected_desc: str) -> CheckResult:
    value = _login_defs_value(key)
    if value is None:
        return CheckResult(Status.NOT_APPLICABLE, f"{key} is not set in /etc/login.defs and could not be read.")
    try:
        value_int = int(value)
    except ValueError:
        return CheckResult(Status.NOT_APPLICABLE, f"{key} in /etc/login.defs is '{value}', not an integer.")
    evidence = f"/etc/login.defs {key} {value}"
    if comparator(value_int):
        return CheckResult(Status.PASS, evidence)
    return CheckResult(Status.FAIL, evidence + f" (expected {expected_desc})")


@register(
    id="CIS-5.4.1.1",
    title="Password maximum age is 365 days or less",
    category=CATEGORY,
    rationale="Forcing periodic password changes limits the window an "
    "already-compromised password stays useful, though CIS notes this is "
    "less important when MFA is in use.",
    remediation="Set 'PASS_MAX_DAYS 365' in /etc/login.defs (existing "
    "accounts also need: chage --maxdays 365 <user>)",
)
def check_pass_max_days() -> CheckResult:
    return _login_defs_int_check("PASS_MAX_DAYS", lambda v: 0 < v <= 365, "0 < PASS_MAX_DAYS <= 365")


@register(
    id="CIS-5.4.1.2",
    title="Password minimum age is at least 1 day",
    category=CATEGORY,
    rationale="Without a minimum age, a user can immediately change a new "
    "password back to their old one, defeating password-history rotation "
    "policies.",
    remediation="Set 'PASS_MIN_DAYS 1' in /etc/login.defs (existing accounts "
    "also need: chage --mindays 1 <user>)",
)
def check_pass_min_days() -> CheckResult:
    return _login_defs_int_check("PASS_MIN_DAYS", lambda v: v >= 1, "PASS_MIN_DAYS >= 1")


@register(
    id="CIS-5.4.1.3",
    title="Password expiration warning is at least 7 days",
    category=CATEGORY,
    rationale="Warning users before their password expires avoids surprise "
    "lockouts, which otherwise tend to get 'fixed' by disabling expiry "
    "entirely - a worse outcome.",
    remediation="Set 'PASS_WARN_AGE 7' in /etc/login.defs (existing accounts "
    "also need: chage --warndays 7 <user>)",
)
def check_pass_warn_age() -> CheckResult:
    return _login_defs_int_check("PASS_WARN_AGE", lambda v: v >= 7, "PASS_WARN_AGE >= 7")


@register(
    id="CIS-6.2.1",
    title="No accounts have an empty password field in /etc/shadow",
    category=CATEGORY,
    rationale="An empty password field (2nd colon-delimited field in "
    "/etc/shadow) means PAM may allow that account to log in with no "
    "password at all, depending on nullok settings.",
    remediation="passwd -l <user>  # lock any account found with an empty "
    "password field, or set a real password with passwd <user>",
)
def check_no_empty_shadow_passwords() -> CheckResult:
    lines = read_lines("/etc/shadow")
    if lines is None:
        return CheckResult(
            Status.NOT_APPLICABLE,
            "/etc/shadow could not be read (requires root) - cannot verify password fields.",
        )
    empty_accounts = []
    for line in lines:
        fields = line.split(":")
        if len(fields) < 2:
            continue
        username, pwd_field = fields[0], fields[1]
        if pwd_field == "":
            empty_accounts.append(username)
    if not empty_accounts:
        return CheckResult(Status.PASS, f"Checked {len(lines)} /etc/shadow entries; no empty password fields.")
    return CheckResult(
        Status.FAIL,
        f"{len(empty_accounts)} account(s) with an empty password field: " + ", ".join(empty_accounts),
    )


@register(
    id="CIS-6.2.2",
    title="No duplicate UID 0 (root-equivalent) accounts exist besides root",
    category=CATEGORY,
    rationale="Any account sharing UID 0 has full root privileges regardless "
    "of its username - this is a classic backdoor technique and should never "
    "occur outside of 'root' itself.",
    remediation="Investigate any extra UID-0 account immediately; usually: "
    "usermod -u <new-unique-uid> <account>  or delete it with userdel if unauthorized.",
)
def check_no_duplicate_uid_zero() -> CheckResult:
    lines = read_lines("/etc/passwd")
    if lines is None:
        return CheckResult(Status.NOT_APPLICABLE, "/etc/passwd could not be read.")
    uid_zero_accounts = []
    for line in lines:
        fields = line.split(":")
        if len(fields) < 3:
            continue
        username, _, uid_s = fields[0], fields[1], fields[2]
        if uid_s == "0":
            uid_zero_accounts.append(username)
    extra = [u for u in uid_zero_accounts if u != "root"]
    evidence = f"UID 0 accounts: {', '.join(uid_zero_accounts)}"
    if not extra:
        return CheckResult(Status.PASS, evidence)
    return CheckResult(Status.FAIL, evidence + f" (unexpected UID-0 account(s): {', '.join(extra)})")


@register(
    id="CIS-5.4.2",
    title="Root account's default group is GID 0",
    category=CATEGORY,
    rationale="root's primary group should be the root group (GID 0), matching "
    "standard system convention; a different primary group is unusual and "
    "worth investigating (could indicate tampering or a broken account "
    "migration).",
    remediation="usermod -g 0 root",
)
def check_root_default_group() -> CheckResult:
    lines = read_lines("/etc/passwd")
    if lines is None:
        return CheckResult(Status.NOT_APPLICABLE, "/etc/passwd could not be read.")
    for line in lines:
        fields = line.split(":")
        if len(fields) < 4:
            continue
        if fields[0] == "root":
            gid = fields[3]
            evidence = f"root:x:{fields[2]}:{gid}"
            if gid == "0":
                return CheckResult(Status.PASS, evidence)
            return CheckResult(Status.FAIL, evidence + " (expected root's primary GID to be 0)")
    return CheckResult(Status.NOT_APPLICABLE, "No 'root' entry found in /etc/passwd.")
