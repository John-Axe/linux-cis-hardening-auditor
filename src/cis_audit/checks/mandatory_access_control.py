"""Mandatory access control checks (CIS section 1.5: AppArmor on Debian/Ubuntu,
or SELinux on RHEL-family systems). Honestly reports NOT_APPLICABLE when
neither is installed rather than guessing which one "should" be there -
which MAC system applies is a distribution choice this tool doesn't assume.
"""

from __future__ import annotations

import os

from cis_audit.models import CheckResult, Status
from cis_audit.registry import register
from cis_audit.utils import read_text, run_cmd, which

CATEGORY = "mac"


def _apparmor_installed() -> bool:
    return which("apparmor_status") is not None or which("aa-status") is not None or os.path.isdir("/etc/apparmor.d")


def _selinux_installed() -> bool:
    return which("getenforce") is not None or os.path.exists("/etc/selinux/config")


@register(
    id="CIS-1.5.1",
    title="A mandatory access control system (AppArmor) is installed",
    category=CATEGORY,
    rationale="Discretionary Unix permissions alone don't confine what a "
    "compromised process can do; a MAC system like AppArmor restricts "
    "processes to a defined profile even if they're running as root.",
    remediation="apt install apparmor apparmor-utils && systemctl --now enable apparmor",
)
def check_mac_installed() -> CheckResult:
    apparmor = _apparmor_installed()
    selinux = _selinux_installed()
    evidence = f"AppArmor installed: {apparmor}; SELinux installed: {selinux}"
    if apparmor or selinux:
        return CheckResult(Status.PASS, evidence)
    return CheckResult(Status.FAIL, evidence + " (no mandatory access control system found)")


@register(
    id="CIS-1.5.2",
    title="AppArmor is enabled at boot",
    category=CATEGORY,
    rationale="Installing AppArmor without it being active at boot provides "
    "no protection - the kernel needs apparmor=1 security=apparmor (or the "
    "distro default) to actually load and enforce profiles.",
    remediation="Ensure the running kernel was booted with apparmor enabled "
    "(Ubuntu kernels default to this; verify with 'cat /sys/module/apparmor/parameters/enabled').",
)
def check_apparmor_enabled_at_boot() -> CheckResult:
    if not _apparmor_installed():
        return CheckResult(Status.NOT_APPLICABLE, "AppArmor is not installed on this host.")
    text = read_text("/sys/module/apparmor/parameters/enabled")
    if text is None:
        return CheckResult(
            Status.FAIL,
            "/sys/module/apparmor/parameters/enabled could not be read - AppArmor does not appear to be loaded.",
        )
    evidence = f"/sys/module/apparmor/parameters/enabled = {text.strip()!r}"
    if text.strip() == "Y":
        return CheckResult(Status.PASS, evidence)
    return CheckResult(Status.FAIL, evidence)


@register(
    id="CIS-1.5.3",
    title="AppArmor profiles are loaded",
    category=CATEGORY,
    rationale="An enabled but empty AppArmor install (no profiles loaded) "
    "provides no actual confinement - profiles have to be loaded for the "
    "framework to do anything.",
    remediation="apt install apparmor-profiles apparmor-profiles-extra && systemctl reload apparmor",
)
def check_apparmor_profiles_loaded() -> CheckResult:
    if not _apparmor_installed():
        return CheckResult(Status.NOT_APPLICABLE, "AppArmor is not installed on this host.")
    aa_status = which("aa-status") or which("apparmor_status")
    if aa_status is None:
        return CheckResult(Status.NOT_APPLICABLE, "aa-status/apparmor_status binary not found (likely needs root).")
    rc, out, err = run_cmd([aa_status, "--enabled"] if "aa-status" in aa_status else [aa_status])
    # --enabled exits 0 if aa is enabled with >=1 profile; fall back to parsing full status text.
    rc2, out2, err2 = run_cmd([aa_status])
    evidence = f"`aa-status`: {out2 or err2}"
    if "0 profiles are loaded" in out2:
        return CheckResult(Status.FAIL, evidence)
    if rc2 == 0 and "profiles are loaded" in out2:
        return CheckResult(Status.PASS, evidence)
    return CheckResult(Status.NOT_APPLICABLE, evidence + " (could not determine profile count, likely needs root)")


@register(
    id="CIS-1.5.4",
    title="No AppArmor profiles are running in complain (non-enforcing) mode",
    category=CATEGORY,
    rationale="A profile in complain mode only logs policy violations "
    "instead of blocking them - useful while tuning a new profile, but any "
    "profile left in complain mode long-term provides no actual confinement.",
    remediation="aa-enforce /etc/apparmor.d/<profile>  # for each profile reported still in complain mode",
)
def check_no_apparmor_complain_profiles() -> CheckResult:
    if not _apparmor_installed():
        return CheckResult(Status.NOT_APPLICABLE, "AppArmor is not installed on this host.")
    aa_status = which("aa-status") or which("apparmor_status")
    if aa_status is None:
        return CheckResult(Status.NOT_APPLICABLE, "aa-status/apparmor_status binary not found (likely needs root).")
    rc, out, err = run_cmd([aa_status])
    if rc != 0:
        return CheckResult(Status.NOT_APPLICABLE, f"`aa-status` failed: {err} (likely needs root).")
    evidence = f"`aa-status`: {out}"
    if "0 profiles are in complain mode" in out:
        return CheckResult(Status.PASS, evidence)
    return CheckResult(Status.FAIL, evidence)


@register(
    id="CIS-1.5.5",
    title="SELinux and AppArmor are not both installed",
    category=CATEGORY,
    rationale="Running two mandatory access control frameworks side by side "
    "is unsupported and typically means one was installed by accident "
    "(e.g. as a stray dependency) - it doesn't add protection and can cause "
    "confusing policy conflicts.",
    remediation="Remove whichever MAC system your distribution doesn't use by default "
    "(apt purge selinux-basics on Ubuntu, or the AppArmor packages on RHEL-family systems).",
)
def check_only_one_mac_system() -> CheckResult:
    apparmor = _apparmor_installed()
    selinux = _selinux_installed()
    evidence = f"AppArmor installed: {apparmor}; SELinux installed: {selinux}"
    if apparmor and selinux:
        return CheckResult(Status.FAIL, evidence + " (both installed simultaneously)")
    return CheckResult(Status.PASS, evidence)


@register(
    id="CIS-1.5.6",
    title="SELinux is not set to disabled (on systems where it is installed)",
    category=CATEGORY,
    rationale="On a distribution that ships SELinux, having it present but "
    "explicitly disabled is worse than not having it at all - it gives a "
    "false sense of protection while providing none.",
    remediation="Set SELINUX=enforcing (or at minimum permissive) in /etc/selinux/config, then reboot.",
)
def check_selinux_not_disabled() -> CheckResult:
    if not _selinux_installed():
        return CheckResult(
            Status.NOT_APPLICABLE, "SELinux is not installed on this host (this is an AppArmor-based distribution)."
        )
    getenforce = which("getenforce")
    if getenforce:
        rc, out, err = run_cmd([getenforce])
        evidence = f"`getenforce`: {out or err}"
        if rc == 0 and out.strip() in ("Enforcing", "Permissive"):
            return CheckResult(Status.PASS, evidence)
        return CheckResult(Status.FAIL, evidence)
    text = read_text("/etc/selinux/config")
    if text is None:
        return CheckResult(Status.NOT_APPLICABLE, "/etc/selinux/config could not be read.")
    evidence = f"/etc/selinux/config content: {text[:200]!r}"
    if "SELINUX=disabled" in text.replace(" ", ""):
        return CheckResult(Status.FAIL, evidence)
    return CheckResult(Status.PASS, evidence)
