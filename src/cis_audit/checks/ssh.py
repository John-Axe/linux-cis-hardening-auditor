"""SSH server configuration checks (CIS section 5.2.x).

Prefers `sshd -T` (sshd's own dump of its *effective* config, including
built-in defaults for anything not set explicitly) since that's the
authoritative source recommended by the CIS benchmark itself. `sshd -T`
normally needs to read the host keys, which usually requires root, so this
falls back to parsing /etc/ssh/sshd_config directly (OpenSSH's
first-occurrence-wins semantics) when `sshd -T` isn't usable. If neither the
sshd binary nor a config file exists at all, every check here reports
NOT_APPLICABLE - an unattended CI runner or minimal container legitimately
has no SSH server installed.
"""

from __future__ import annotations

import os

from cis_audit.models import CheckResult, Status
from cis_audit.registry import register
from cis_audit.utils import read_lines, run_cmd, which

CATEGORY = "ssh"
SSHD_CONFIG = "/etc/ssh/sshd_config"


def _parse_sshd_config_file() -> dict[str, str] | None:
    lines = read_lines(SSHD_CONFIG)
    if lines is None:
        return None
    cfg: dict[str, str] = {}
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split(None, 1)
        if len(parts) == 2:
            key = parts[0].lower()
            cfg.setdefault(key, parts[1])  # first occurrence wins, like sshd
    return cfg


def _effective_sshd_config() -> tuple[dict[str, str] | None, str]:
    """Returns (config-dict-or-None, source-description)."""
    sshd_path = which("sshd") or (
        "/usr/sbin/sshd" if os.path.exists("/usr/sbin/sshd") else None
    )
    if sshd_path:
        rc, out, err = run_cmd([sshd_path, "-T"])
        if rc == 0 and out:
            cfg: dict[str, str] = {}
            for line in out.splitlines():
                parts = line.split(None, 1)
                if len(parts) == 2:
                    cfg.setdefault(parts[0].lower(), parts[1])
            return cfg, "`sshd -T` (effective running configuration)"

    cfg = _parse_sshd_config_file()
    if cfg is not None:
        return cfg, f"parsed {SSHD_CONFIG} directly (sshd -T unavailable, likely unprivileged)"

    return None, "no sshd binary or sshd_config found"


def _na_no_sshd() -> CheckResult:
    return CheckResult(
        Status.NOT_APPLICABLE,
        "openssh-server is not installed and no sshd_config exists on this host "
        f"(checked `sshd -T` and {SSHD_CONFIG}) - SSH hardening does not apply.",
    )


def _sshd_directive_check(
    key: str, expected: str, default_if_unset: str, comparator=None
) -> CheckResult:
    cfg, source = _effective_sshd_config()
    if cfg is None:
        return _na_no_sshd()
    value = cfg.get(key, default_if_unset)
    ok = (comparator or (lambda v: v.lower() == expected.lower()))(value)
    evidence = f"{source}: {key} {value}"
    if ok:
        return CheckResult(Status.PASS, evidence)
    return CheckResult(Status.FAIL, evidence + f" (expected {key} {expected})")


@register(
    id="CIS-5.2.4",
    title="SSH root login is disabled (PermitRootLogin no)",
    category=CATEGORY,
    rationale="Allowing SSH login directly as root removes the audit trail of "
    "which named account escalated, and gives a brute-forced/leaked root "
    "password or key immediate full access.",
    remediation="In /etc/ssh/sshd_config set 'PermitRootLogin no' then "
    "systemctl reload sshd",
)
def check_ssh_root_login() -> CheckResult:
    return _sshd_directive_check("permitrootlogin", "no", "prohibit-password")


@register(
    id="CIS-5.2.5",
    title="SSH PermitEmptyPasswords is disabled",
    category=CATEGORY,
    rationale="If empty passwords are permitted, any account with a blank "
    "password field could log in over SSH with no credential at all.",
    remediation="In /etc/ssh/sshd_config set 'PermitEmptyPasswords no' then "
    "systemctl reload sshd",
)
def check_ssh_empty_passwords() -> CheckResult:
    return _sshd_directive_check("permitemptypasswords", "no", "no")


@register(
    id="CIS-5.2.10",
    title="SSH password authentication is disabled (key-based auth only)",
    category=CATEGORY,
    rationale="Password authentication over SSH is subject to brute-force and "
    "credential-stuffing attacks; disabling it in favor of key-based auth "
    "removes that entire attack surface.",
    remediation="In /etc/ssh/sshd_config set 'PasswordAuthentication no', "
    "ensure your SSH key is deployed and working first, then systemctl reload sshd",
)
def check_ssh_password_auth() -> CheckResult:
    return _sshd_directive_check("passwordauthentication", "no", "yes")


@register(
    id="CIS-5.2.11",
    title="SSH MaxAuthTries is 4 or less",
    category=CATEGORY,
    rationale="A high MaxAuthTries lets an attacker attempt many password/key "
    "guesses within a single connection, speeding up brute-force attacks.",
    remediation="In /etc/ssh/sshd_config set 'MaxAuthTries 4' then systemctl reload sshd",
)
def check_ssh_max_auth_tries() -> CheckResult:
    def comparator(value: str) -> bool:
        try:
            return int(value) <= 4
        except ValueError:
            return False

    return _sshd_directive_check("maxauthtries", "<= 4", "6", comparator)


@register(
    id="CIS-5.2.16",
    title="SSH X11Forwarding is disabled",
    category=CATEGORY,
    rationale="X11 forwarding over SSH is rarely needed on a server and "
    "expands attack surface (X11 has a long history of privilege-escalation "
    "and information-disclosure issues).",
    remediation="In /etc/ssh/sshd_config set 'X11Forwarding no' then systemctl reload sshd",
)
def check_ssh_x11_forwarding() -> CheckResult:
    return _sshd_directive_check("x11forwarding", "no", "no")


@register(
    id="CIS-5.2.20",
    title="SSH warning banner is configured",
    category=CATEGORY,
    rationale="A pre-authentication banner (e.g. an authorized-use warning) "
    "is often a legal prerequisite for prosecuting unauthorized access and "
    "signals that the system is monitored.",
    remediation="Create /etc/issue.net with a warning banner, then in "
    "/etc/ssh/sshd_config set 'Banner /etc/issue.net' and systemctl reload sshd",
)
def check_ssh_banner() -> CheckResult:
    cfg, source = _effective_sshd_config()
    if cfg is None:
        return _na_no_sshd()
    value = cfg.get("banner", "none")
    evidence = f"{source}: Banner {value}"
    if value.lower() not in ("none", ""):
        return CheckResult(Status.PASS, evidence)
    return CheckResult(Status.FAIL, evidence + " (expected Banner to point at a warning-banner file)")
