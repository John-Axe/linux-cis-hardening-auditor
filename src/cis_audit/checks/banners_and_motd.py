"""Warning-banner checks (CIS sections 1.8.x local/remote login banners,
1.9.x GDM banner).

/etc/issue is shown for local (console) logins, /etc/issue.net for remote
logins (when Banner is configured in sshd_config - see checks/ssh.py's
CIS-5.2.20 for that side), /etc/motd after a successful login. CIS also
requires these not leak OS/version info via the traditional \\m \\r \\s \\v
escape sequences, since that hands a would-be attacker free reconnaissance.
"""

from __future__ import annotations

import os

from cis_audit.models import CheckResult, Status
from cis_audit.registry import register
from cis_audit.utils import path_mode_octal, path_owner, read_text, run_cmd, which

CATEGORY = "banners"

_OS_INFO_ESCAPES = ("\\m", "\\r", "\\s", "\\v")


def _perms_check(path: str, max_mode: int) -> CheckResult:
    mode = path_mode_octal(path)
    if mode is None:
        return CheckResult(Status.FAIL, f"{path} does not exist.")
    owner_group = path_owner(path)
    owner, group = owner_group if owner_group else ("?", "?")
    mode_int = int(mode, 8)
    evidence = f"{path}: mode={mode} owner={owner} group={group}"
    if mode_int <= max_mode and owner == "root":
        return CheckResult(Status.PASS, evidence)
    return CheckResult(Status.FAIL, evidence + f" (expected mode <= {oct(max_mode)[2:].zfill(3)}, owner root)")


def _no_os_info_check(path: str) -> CheckResult:
    text = read_text(path)
    if text is None:
        return CheckResult(Status.FAIL, f"{path} does not exist.")
    found = [esc for esc in _OS_INFO_ESCAPES if esc in text]
    evidence = f"{path} content: {text[:200]!r}"
    if not found:
        return CheckResult(Status.PASS, evidence)
    return CheckResult(Status.FAIL, evidence + f" (contains OS-identifying escape sequence(s): {', '.join(found)})")


@register(
    id="CIS-1.8.1",
    title="/etc/motd permissions are 644 or more restrictive, owned by root",
    category=CATEGORY,
    rationale="The message-of-the-day file should not be writable by "
    "non-root users, or a local user could plant misleading/malicious "
    "content shown to every other user who logs in.",
    remediation="chown root:root /etc/motd && chmod 644 /etc/motd",
)
def check_motd_perms() -> CheckResult:
    return _perms_check("/etc/motd", 0o644)


@register(
    id="CIS-1.8.2",
    title="/etc/issue permissions are 644 or more restrictive, owned by root",
    category=CATEGORY,
    rationale="/etc/issue is shown before local console login; if writable "
    "by non-root it could be tampered with to display misleading prompts.",
    remediation="chown root:root /etc/issue && chmod 644 /etc/issue",
)
def check_issue_perms() -> CheckResult:
    return _perms_check("/etc/issue", 0o644)


@register(
    id="CIS-1.8.3",
    title="/etc/issue.net permissions are 644 or more restrictive, owned by root",
    category=CATEGORY,
    rationale="/etc/issue.net is shown before remote (SSH) login when "
    "configured as the sshd Banner; if writable by non-root it could be "
    "tampered with.",
    remediation="chown root:root /etc/issue.net && chmod 644 /etc/issue.net",
)
def check_issue_net_perms() -> CheckResult:
    return _perms_check("/etc/issue.net", 0o644)


@register(
    id="CIS-1.8.4",
    title="/etc/issue does not reveal OS or version information",
    category=CATEGORY,
    rationale="A login banner that prints the OS name/kernel version/host "
    "info (via \\m \\r \\s \\v escapes) hands an attacker free reconnaissance "
    "before they've even authenticated.",
    remediation="Replace /etc/issue with a generic authorized-access-only warning, "
    "removing any \\m \\r \\s \\v escape sequences.",
)
def check_issue_no_os_info() -> CheckResult:
    return _no_os_info_check("/etc/issue")


@register(
    id="CIS-1.8.5",
    title="/etc/issue.net does not reveal OS or version information",
    category=CATEGORY,
    rationale="Same rationale as /etc/issue: the remote-login banner "
    "shouldn't hand out OS/version reconnaissance before authentication.",
    remediation="Replace /etc/issue.net with a generic authorized-access-only warning, "
    "removing any \\m \\r \\s \\v escape sequences.",
)
def check_issue_net_no_os_info() -> CheckResult:
    return _no_os_info_check("/etc/issue.net")


@register(
    id="CIS-1.8.6",
    title="/etc/motd does not reveal OS or version information",
    category=CATEGORY,
    rationale="Many distributions auto-populate /etc/motd (or update-motd.d "
    "scripts) with kernel/OS version banners at login; that's useful "
    "reconnaissance for an attacker who's already gained a shell and "
    "shouldn't be handed out unnecessarily either.",
    remediation="Remove OS/version-revealing content from /etc/motd and any "
    "/etc/update-motd.d/ scripts that generate it.",
)
def check_motd_no_os_info() -> CheckResult:
    return _no_os_info_check("/etc/motd")


@register(
    id="CIS-1.9.1",
    title="GDM displays a login warning banner (if GDM is installed)",
    category=CATEGORY,
    rationale="On a system with a graphical login manager, the text-console "
    "banners in /etc/issue don't apply to GDM's own login screen - it needs "
    "its own banner-message setting to carry the same legal/monitoring "
    "notice.",
    remediation="gsettings set org.gnome.login-screen banner-message-enable true && "
    "gsettings set org.gnome.login-screen banner-message-text 'Authorized uses only.'  "
    "(via a dconf profile/db for the gdm user, not interactively)",
)
def check_gdm_banner_configured() -> CheckResult:
    if which("gdm3") is None and which("gdm") is None and not os.path.isdir("/etc/gdm3"):
        return CheckResult(
            Status.NOT_APPLICABLE,
            "GDM is not installed on this host (checked for gdm3/gdm binaries and /etc/gdm3) - "
            "this is a headless/server system, so a GDM login banner does not apply.",
        )
    rc, out, err = run_cmd(["gsettings", "get", "org.gnome.login-screen", "banner-message-enable"])
    evidence = f"`gsettings get org.gnome.login-screen banner-message-enable`: {out or err}"
    if rc == 0 and out.strip() == "true":
        return CheckResult(Status.PASS, evidence)
    return CheckResult(Status.FAIL, evidence + " (expected banner-message-enable true)")
