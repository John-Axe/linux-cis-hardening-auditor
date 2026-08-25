"""Kernel module blacklisting checks (CIS section 1.1.1: filesystem and
uncommon network-protocol kernel modules that shouldn't load on a hardened
server).

Loaded-module state is read straight from /proc/modules (always readable, no
subprocess needed - same "/proc first" philosophy as utils.sysctl_value).
Whether a module is *prevented* from loading in the future is checked by
scanning /etc/modprobe.d/*.conf for either an `install <module> /bin/true`
override or a `blacklist <module>` line - both real, standard ways to disable
a module on Debian/Ubuntu.
"""

from __future__ import annotations

import glob

from cis_audit.models import CheckResult, Status
from cis_audit.registry import register
from cis_audit.utils import read_lines, read_text

CATEGORY = "kernel_modules"

_MODPROBE_D_GLOB = "/etc/modprobe.d/*.conf"


def _is_loaded(module: str) -> bool:
    lines = read_lines("/proc/modules")
    if lines is None:
        return False
    normalized = module.replace("-", "_")
    for line in lines:
        parts = line.split()
        if parts and parts[0].replace("-", "_") == normalized:
            return True
    return False


def _is_denylisted(module: str) -> tuple[bool, str]:
    """Returns (denylisted, evidence). Scans every /etc/modprobe.d/*.conf for
    an 'install <module> /bin/true|/bin/false' override or a
    'blacklist <module>' line."""
    found_files = sorted(glob.glob(_MODPROBE_D_GLOB))
    if not found_files:
        return False, "no /etc/modprobe.d/*.conf files found"
    for conf_file in found_files:
        text = read_text(conf_file)
        if text is None:
            continue
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if stripped.startswith(f"install {module} ") and (
                "/bin/true" in stripped or "/bin/false" in stripped
            ):
                return True, f"{conf_file}: {stripped}"
            if stripped == f"blacklist {module}" or stripped.startswith(f"blacklist {module} "):
                return True, f"{conf_file}: {stripped}"
    return False, f"no install/blacklist directive for '{module}' found in {', '.join(found_files)}"


def _module_disabled_check(module: str, purpose: str) -> CheckResult:
    loaded = _is_loaded(module)
    denylisted, conf_evidence = _is_denylisted(module)
    evidence = f"module '{module}' ({purpose}): currently loaded={loaded}; {conf_evidence}"
    if not loaded and denylisted:
        return CheckResult(Status.PASS, evidence)
    if loaded:
        return CheckResult(Status.FAIL, evidence + " - module is currently loaded")
    return CheckResult(Status.FAIL, evidence + " - not blocked for future loads")


def _register_module_check(id: str, module: str, purpose: str) -> None:
    @register(
        id=id,
        title=f"Kernel module '{module}' ({purpose}) is disabled",
        category=CATEGORY,
        rationale=f"The {module} kernel module ({purpose}) is rarely needed on a "
        "hardened server; leaving it loadable widens kernel attack surface for "
        "no operational benefit, especially for filesystem modules parsing "
        "untrusted removable media.",
        remediation=f"echo 'install {module} /bin/true' >> /etc/modprobe.d/cis-hardening.conf && "
        f"echo 'blacklist {module}' >> /etc/modprobe.d/cis-hardening.conf && rmmod {module} 2>/dev/null || true",
    )
    def _check() -> CheckResult:
        return _module_disabled_check(module, purpose)

    _check.__name__ = f"check_module_{module.replace('-', '_')}_disabled"


_register_module_check("CIS-1.1.1.1", "cramfs", "obsolete compressed ROM filesystem")
_register_module_check("CIS-1.1.1.2", "freevxfs", "legacy Veritas filesystem")
_register_module_check("CIS-1.1.1.3", "hfs", "legacy Apple HFS filesystem")
_register_module_check("CIS-1.1.1.4", "hfsplus", "legacy Apple HFS+ filesystem")
_register_module_check("CIS-1.1.1.5", "jffs2", "flash filesystem, unneeded on non-flash media")
_register_module_check("CIS-1.1.1.6", "squashfs", "read-only compressed filesystem, mainly used by snap/live media")
_register_module_check("CIS-1.1.1.7", "udf", "Universal Disk Format filesystem used by optical media")
_register_module_check("CIS-1.1.1.8", "usb-storage", "USB mass-storage driver, a common exfiltration/malware vector")
_register_module_check("CIS-1.1.1.9", "dccp", "Datagram Congestion Control Protocol, rarely used")
_register_module_check("CIS-1.1.1.10", "sctp", "Stream Control Transmission Protocol, rarely used")
_register_module_check("CIS-1.1.1.11", "rds", "Reliable Datagram Sockets protocol, rarely used")
_register_module_check("CIS-1.1.1.12", "tipc", "Transparent Inter-Process Communication protocol, rarely used")
_register_module_check("CIS-1.1.1.13", "firewire-core", "FireWire core driver, historically a DMA-attack vector")
_register_module_check("CIS-1.1.1.14", "bluetooth", "Bluetooth stack, unneeded on a headless server")
