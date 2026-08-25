"""Package manager integrity and system-integrity-tooling checks (CIS
sections 1.2.x package manager configuration, 1.3.x filesystem integrity
checking, 1.4.x bootloader, and 1.7.x extends the automatic-updates check in
services.py with a couple of unattended-upgrades detail settings).
"""

from __future__ import annotations

import glob
import os

from cis_audit.models import CheckResult, Status
from cis_audit.registry import register
from cis_audit.utils import path_mode_octal, path_owner, read_lines, read_text, run_cmd, which

CATEGORY = "package_management"


@register(
    id="CIS-1.2.1",
    title="APT is not configured to allow unauthenticated (unsigned) packages",
    category=CATEGORY,
    rationale="Disabling GPG signature verification lets APT install packages "
    "that weren't signed by a trusted repository key - a direct path for a "
    "compromised mirror or MITM to plant malicious packages.",
    remediation="Remove any 'APT::Get::AllowUnauthenticated \"true\";' lines from "
    "/etc/apt/apt.conf.d/*, GPG checking is on by default otherwise.",
)
def check_apt_gpg_check_enabled() -> CheckResult:
    conf_files = sorted(glob.glob("/etc/apt/apt.conf.d/*"))
    offending = []
    for f in conf_files:
        text = read_text(f)
        if text is None:
            continue
        for line in text.splitlines():
            stripped = line.strip()
            if "allowunauthenticated" in stripped.lower().replace(" ", "") and '"true"' in stripped.lower():
                offending.append(f"{f}: {stripped}")
    if offending:
        return CheckResult(Status.FAIL, "AllowUnauthenticated is enabled: " + " | ".join(offending))
    return CheckResult(
        Status.PASS,
        f"No AllowUnauthenticated override found in {len(conf_files)} file(s) under /etc/apt/apt.conf.d "
        "(GPG signature checking is on by default).",
    )


@register(
    id="CIS-1.2.2",
    title="No plain-HTTP (unencrypted) APT repository sources are configured",
    category=CATEGORY,
    rationale="An http:// (not https://) repository source lets a network "
    "attacker tamper with package downloads in transit; APT's GPG check "
    "mitigates but does not fully eliminate the risk of an unauthenticated "
    "transport, so both matter.",
    remediation="Edit /etc/apt/sources.list and /etc/apt/sources.list.d/* to use https:// mirror URLs.",
)
def check_apt_sources_use_https() -> CheckResult:
    files = ["/etc/apt/sources.list"] + sorted(glob.glob("/etc/apt/sources.list.d/*"))
    http_lines = []
    any_readable = False
    for f in files:
        text = read_text(f)
        if text is None:
            continue
        any_readable = True
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if "http://" in stripped:
                http_lines.append(f"{f}: {stripped}")
    if not any_readable:
        return CheckResult(Status.NOT_APPLICABLE, "No readable APT source list files found.")
    if not http_lines:
        return CheckResult(Status.PASS, f"Checked {len(files)} APT source file(s); no plain-http:// entries.")
    shown = http_lines[:5]
    return CheckResult(Status.FAIL, f"{len(http_lines)} plain-http:// source line(s) found: " + " | ".join(shown))


@register(
    id="CIS-1.2.3",
    title="dpkg reports no broken or half-configured packages",
    category=CATEGORY,
    rationale="Packages stuck in a broken/half-installed state can leave "
    "security-relevant files (e.g. a postinst hardening script) partially "
    "applied, and often indicate a previous update was interrupted.",
    remediation="dpkg --configure -a  # then investigate/resolve any package that still fails",
)
def check_dpkg_no_broken_packages() -> CheckResult:
    dpkg = which("dpkg")
    if dpkg is None:
        return CheckResult(Status.NOT_APPLICABLE, "dpkg is not installed on this host (not a Debian/Ubuntu system).")
    rc, out, err = run_cmd([dpkg, "--audit"])
    evidence = f"`dpkg --audit`: {out or '(no output)'}"
    if rc == 0 and not out.strip():
        return CheckResult(Status.PASS, evidence)
    return CheckResult(Status.FAIL, evidence)


@register(
    id="CIS-1.3.1",
    title="A file integrity checking tool (AIDE) is installed",
    category=CATEGORY,
    rationale="A file-integrity tool creates a baseline of cryptographic "
    "hashes for system files and detects unauthorized changes - without it, "
    "an intruder who plants a trojaned binary can persist undetected "
    "indefinitely.",
    remediation="apt install aide aide-common && aideinit",
)
def check_aide_installed() -> CheckResult:
    if which("aide") or os.path.exists("/usr/sbin/aide"):
        return CheckResult(Status.PASS, f"aide binary found at {which('aide') or '/usr/sbin/aide'}.")
    return CheckResult(Status.FAIL, "No aide binary found on PATH or at /usr/sbin/aide.")


@register(
    id="CIS-1.3.2",
    title="Filesystem integrity checks are scheduled regularly",
    category=CATEGORY,
    rationale="Installing AIDE without scheduling regular checks means "
    "nothing actually compares the live filesystem against the baseline - "
    "the tool only provides protection if it's actually run periodically.",
    remediation="Enable the aide systemd timer (systemctl --now enable aidecheck.timer) "
    "or add a cron.d entry that runs 'aide --check' daily.",
)
def check_aide_scheduled() -> CheckResult:
    cron_paths = ["/etc/cron.d/aide", "/etc/cron.daily/aide"]
    for p in cron_paths:
        if os.path.exists(p):
            return CheckResult(Status.PASS, f"Found AIDE cron schedule at {p}.")
    rc, out, err = run_cmd(["systemctl", "is-enabled", "aidecheck.timer"])
    if out.strip() == "enabled":
        return CheckResult(Status.PASS, "systemd timer aidecheck.timer is enabled.")
    return CheckResult(
        Status.FAIL,
        "No AIDE cron job (checked /etc/cron.d/aide, /etc/cron.daily/aide) and "
        f"aidecheck.timer is not enabled (systemctl is-enabled: {out or err}).",
    )


@register(
    id="CIS-1.4.1",
    title="Bootloader configuration file permissions are restrictive",
    category=CATEGORY,
    rationale="The bootloader config can contain a plaintext password hash "
    "and controls what kernel/parameters are booted; if it's readable or "
    "writable by non-root users, boot-time security settings could be "
    "tampered with or a hash could be cracked offline.",
    remediation="chown root:root /boot/grub/grub.cfg && chmod 600 /boot/grub/grub.cfg",
)
def check_bootloader_config_perms() -> CheckResult:
    for candidate in ("/boot/grub/grub.cfg", "/boot/grub2/grub.cfg"):
        mode = path_mode_octal(candidate)
        if mode is None:
            continue
        owner_group = path_owner(candidate)
        owner, group = owner_group if owner_group else ("?", "?")
        mode_int = int(mode, 8)
        evidence = f"{candidate}: mode={mode} owner={owner} group={group}"
        if mode_int <= 0o600 and owner == "root":
            return CheckResult(Status.PASS, evidence)
        return CheckResult(Status.FAIL, evidence + " (expected mode <= 600, owner root)")
    return CheckResult(
        Status.NOT_APPLICABLE,
        "Neither /boot/grub/grub.cfg nor /boot/grub2/grub.cfg exists (no GRUB bootloader found).",
    )


@register(
    id="CIS-1.4.2",
    title="Bootloader is password protected",
    category=CATEGORY,
    rationale="Without a bootloader password, anyone with physical/console "
    "access can edit boot parameters (e.g. append init=/bin/sh) to bypass "
    "authentication entirely.",
    remediation="Run 'grub-mkpasswd-pbkdf2' and add a 'set superusers' / "
    "'password_pbkdf2' block to /etc/grub.d/40_custom, then update-grub.",
)
def check_bootloader_password_set() -> CheckResult:
    for candidate in ("/boot/grub/grub.cfg", "/boot/grub2/grub.cfg"):
        text = read_text(candidate)
        if text is None:
            continue
        has_password = "password_pbkdf2" in text or "password " in text
        evidence = f"{candidate}: {'password directive found' if has_password else 'no password directive found'}"
        if has_password:
            return CheckResult(Status.PASS, evidence)
        return CheckResult(Status.FAIL, evidence)
    return CheckResult(
        Status.NOT_APPLICABLE,
        "Neither /boot/grub/grub.cfg nor /boot/grub2/grub.cfg exists (no GRUB bootloader found).",
    )


@register(
    id="CIS-1.7.1",
    title="Unattended-upgrades is configured to automatically reboot when required",
    category=CATEGORY,
    rationale="Some security updates (kernel, glibc) only take effect after a "
    "reboot; without automatic reboots, a host can silently run vulnerable "
    "code for months after being 'patched' on disk.",
    remediation="Set 'Unattended-Upgrade::Automatic-Reboot \"true\";' in "
    "/etc/apt/apt.conf.d/50unattended-upgrades",
)
def check_unattended_upgrades_auto_reboot() -> CheckResult:
    text = read_text("/etc/apt/apt.conf.d/50unattended-upgrades")
    if text is None:
        return CheckResult(
            Status.FAIL,
            "/etc/apt/apt.conf.d/50unattended-upgrades does not exist - unattended-upgrades is not configured.",
        )
    enabled = 'Unattended-Upgrade::Automatic-Reboot "true"' in text
    evidence = f"Automatic-Reboot setting present and true: {enabled}"
    if enabled:
        return CheckResult(Status.PASS, evidence)
    return CheckResult(Status.FAIL, evidence)


@register(
    id="CIS-1.7.2",
    title="Unattended-upgrades removes unused dependencies after upgrading",
    category=CATEGORY,
    rationale="Leaving unused package dependencies installed after an "
    "upgrade grows the attack surface with software nothing on the system "
    "actually needs anymore.",
    remediation="Set 'Unattended-Upgrade::Remove-Unused-Dependencies \"true\";' in "
    "/etc/apt/apt.conf.d/50unattended-upgrades",
)
def check_unattended_upgrades_remove_unused() -> CheckResult:
    text = read_text("/etc/apt/apt.conf.d/50unattended-upgrades")
    if text is None:
        return CheckResult(
            Status.FAIL,
            "/etc/apt/apt.conf.d/50unattended-upgrades does not exist - unattended-upgrades is not configured.",
        )
    enabled = 'Unattended-Upgrade::Remove-Unused-Dependencies "true"' in text
    evidence = f"Remove-Unused-Dependencies setting present and true: {enabled}"
    if enabled:
        return CheckResult(Status.PASS, evidence)
    return CheckResult(Status.FAIL, evidence)
