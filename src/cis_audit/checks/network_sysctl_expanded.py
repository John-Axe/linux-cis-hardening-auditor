"""Additional network-hardening sysctl checks (CIS section 3.2, extending the
handful already covered in checks/network.py) - source routing, secure/
default-scope ICMP redirects, martian packet logging, broadcast/bogus ICMP
handling, default-scope reverse-path filtering, and IPv6 router-advertisement/
source-route equivalents.

Same "read straight from /proc/sys" approach as network.py - see
utils.sysctl_value.
"""

from __future__ import annotations

from cis_audit.models import CheckResult, Status
from cis_audit.registry import register
from cis_audit.utils import sysctl_value

CATEGORY = "network"


def _sysctl_check(key: str, expected: str, comparator=None) -> CheckResult:
    value = sysctl_value(key)
    if value is None:
        return CheckResult(Status.NOT_APPLICABLE, f"sysctl key {key} is not readable on this host/kernel.")
    ok = (comparator or (lambda v: v == expected))(value)
    evidence = f"{key} = {value}"
    if ok:
        return CheckResult(Status.PASS, evidence)
    return CheckResult(Status.FAIL, evidence + f" (expected {key} = {expected})")


def _register_sysctl_check(id: str, key: str, expected: str, title: str, rationale: str, comparator=None) -> None:
    @register(
        id=id,
        title=title,
        category=CATEGORY,
        rationale=rationale,
        remediation=f"sysctl -w {key}={expected} && echo '{key}={expected}' >> /etc/sysctl.d/60-cis-hardening.conf",
    )
    def _check() -> CheckResult:
        return _sysctl_check(key, expected, comparator)

    _check.__name__ = f"check_{key.replace('.', '_')}"


_register_sysctl_check(
    "CIS-3.2.3", "net.ipv4.conf.all.accept_source_route", "0",
    "Source-routed IPv4 packets are not accepted (all interfaces)",
    "Source routing lets the packet's sender dictate its path through the "
    "network, bypassing normal routing decisions - a classic technique for "
    "evading network-path-based security controls.",
)
_register_sysctl_check(
    "CIS-3.2.5", "net.ipv4.conf.default.accept_source_route", "0",
    "Source-routed IPv4 packets are not accepted (default for new interfaces)",
    "Same rationale as the 'all' variant, applied to the default template "
    "new interfaces inherit, so a hot-plugged interface doesn't silently "
    "revert to accepting source-routed packets.",
)
_register_sysctl_check(
    "CIS-3.2.6", "net.ipv4.conf.default.accept_redirects", "0",
    "ICMP redirects are not accepted (default for new interfaces)",
    "Same MITM rationale as the 'all' variant (CIS-3.2.1), applied to the "
    "default template new interfaces inherit.",
)
_register_sysctl_check(
    "CIS-3.2.7", "net.ipv4.conf.default.send_redirects", "0",
    "Sending ICMP redirects is disabed (default for new interfaces)",
    "Same rationale as the 'all' variant (CIS-3.2.2), applied to the "
    "default template new interfaces inherit.",
)
_register_sysctl_check(
    "CIS-3.2.8", "net.ipv4.conf.all.secure_redirects", "0",
    "Secure ICMP redirects are not accepted (all interfaces)",
    "'Secure' redirects (from hosts already listed as gateways) are still "
    "redirects an attacker on-path could spoof; disabling them removes that "
    "residual MITM surface entirely.",
)
_register_sysctl_check(
    "CIS-3.2.9", "net.ipv4.conf.default.secure_redirects", "0",
    "Secure ICMP redirects are not accepted (default for new interfaces)",
    "Same rationale as the 'all' variant, applied to the default template "
    "new interfaces inherit.",
)
_register_sysctl_check(
    "CIS-3.2.10", "net.ipv4.conf.all.log_martians", "1",
    "Suspicious (martian) packets are logged (all interfaces)",
    "Martian packets - ones with impossible source addresses for the "
    "interface they arrived on - are a strong spoofing/misconfiguration "
    "signal; logging them gives visibility that's otherwise silently "
    "dropped and forgotten.",
)
_register_sysctl_check(
    "CIS-3.2.11", "net.ipv4.conf.default.log_martians", "1",
    "Suspicious (martian) packets are logged (default for new interfaces)",
    "Same rationale as the 'all' variant, applied to the default template "
    "new interfaces inherit.",
)
_register_sysctl_check(
    "CIS-3.2.12", "net.ipv4.icmp_echo_ignore_broadcasts", "1",
    "Broadcast ICMP requests are ignored",
    "Responding to broadcast ICMP echo requests lets this host be used as "
    "an amplifier in a Smurf-style DDoS attack against a spoofed victim "
    "address.",
)
_register_sysctl_check(
    "CIS-3.2.13", "net.ipv4.icmp_ignore_bogus_error_responses", "1",
    "Bogus ICMP error responses are ignored",
    "Some routers send non-RFC-compliant ICMP error responses that would "
    "otherwise flood the kernel log with unnecessary warnings.",
)
_register_sysctl_check(
    "CIS-3.2.14", "net.ipv4.conf.default.rp_filter", "1 or 2",
    "Reverse path filtering is enabled (default for new interfaces)",
    "Same spoofing-mitigation rationale as CIS-3.2.4, applied to the "
    "default template new interfaces inherit.",
    comparator=lambda v: v in ("1", "2"),
)
_register_sysctl_check(
    "CIS-3.2.15", "net.ipv6.conf.all.accept_ra", "0",
    "IPv6 router advertisements are not accepted (all interfaces)",
    "Accepting router advertisements lets any host on the local network "
    "silently reconfigure this host's IPv6 default route and DNS servers - "
    "a MITM/traffic-redirection technique analogous to rogue DHCP.",
)
_register_sysctl_check(
    "CIS-3.2.16", "net.ipv6.conf.default.accept_ra", "0",
    "IPv6 router advertisements are not accepted (default for new interfaces)",
    "Same rationale as the 'all' variant, applied to the default template "
    "new interfaces inherit.",
)
_register_sysctl_check(
    "CIS-3.2.17", "net.ipv6.conf.all.accept_source_route", "0",
    "Source-routed IPv6 packets are not accepted (all interfaces)",
    "Same source-routing rationale as the IPv4 checks, for IPv6.",
)
_register_sysctl_check(
    "CIS-3.2.18", "net.ipv6.conf.default.accept_source_route", "0",
    "Source-routed IPv6 packets are not accepted (default for new interfaces)",
    "Same rationale as the 'all' variant, applied to the default template "
    "new interfaces inherit.",
)
