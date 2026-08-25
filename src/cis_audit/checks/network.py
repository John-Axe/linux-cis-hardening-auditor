"""Network / firewall checks (CIS sections 3.x, 4.1).

sysctl checks read straight from /proc/sys (always readable, no root or
subprocess needed) via utils.sysctl_value. The firewall check shells out to
whichever of ufw/nft/iptables is actually installed.
"""

from __future__ import annotations

from cis_audit.models import CheckResult, Status
from cis_audit.registry import register
from cis_audit.utils import run_cmd, sysctl_value, which

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


@register(
    id="CIS-3.1.1",
    title="IP forwarding is disabled",
    category=CATEGORY,
    rationale="A host that isn't meant to be a router shouldn't forward "
    "packets between interfaces - leaving it enabled widens the blast "
    "radius if the host is compromised and could be abused to pivot traffic.",
    remediation="sysctl -w net.ipv4.ip_forward=0 && echo 'net.ipv4.ip_forward=0' >> /etc/sysctl.d/60-cis-hardening.conf",
)
def check_ip_forward_disabled() -> CheckResult:
    return _sysctl_check("net.ipv4.ip_forward", "0")


@register(
    id="CIS-3.2.1",
    title="ICMP redirects are not accepted",
    category=CATEGORY,
    rationale="Accepting ICMP redirects lets another host on the local "
    "network silently alter this host's routing table, a classic MITM "
    "technique.",
    remediation="sysctl -w net.ipv4.conf.all.accept_redirects=0 && echo 'net.ipv4.conf.all.accept_redirects=0' >> /etc/sysctl.d/60-cis-hardening.conf",
)
def check_icmp_redirects_disabled() -> CheckResult:
    return _sysctl_check("net.ipv4.conf.all.accept_redirects", "0")


@register(
    id="CIS-3.2.2",
    title="Sending ICMP redirects is disabled",
    category=CATEGORY,
    rationale="A host that isn't a router shouldn't send ICMP redirects "
    "either - doing so can leak internal topology information and isn't "
    "needed for a non-routing host.",
    remediation="sysctl -w net.ipv4.conf.all.send_redirects=0 && echo 'net.ipv4.conf.all.send_redirects=0' >> /etc/sysctl.d/60-cis-hardening.conf",
)
def check_send_redirects_disabled() -> CheckResult:
    return _sysctl_check("net.ipv4.conf.all.send_redirects", "0")


@register(
    id="CIS-3.2.4",
    title="Reverse path filtering is enabled",
    category=CATEGORY,
    rationale="Reverse path filtering drops packets whose source address "
    "couldn't have legitimately arrived on the interface they came in on, "
    "which mitigates IP spoofing used in many DoS and MITM attacks.",
    remediation="sysctl -w net.ipv4.conf.all.rp_filter=1 && echo 'net.ipv4.conf.all.rp_filter=1' >> /etc/sysctl.d/60-cis-hardening.conf",
)
def check_rp_filter_enabled() -> CheckResult:
    return _sysctl_check("net.ipv4.conf.all.rp_filter", "1 or 2", comparator=lambda v: v in ("1", "2"))


@register(
    id="CIS-3.3.1",
    title="TCP SYN cookies are enabled",
    category=CATEGORY,
    rationale="SYN cookies let the kernel keep accepting legitimate "
    "connections under a SYN-flood DoS attack instead of exhausting its "
    "backlog queue.",
    remediation="sysctl -w net.ipv4.tcp_syncookies=1 && echo 'net.ipv4.tcp_syncookies=1' >> /etc/sysctl.d/60-cis-hardening.conf",
)
def check_syncookies_enabled() -> CheckResult:
    return _sysctl_check("net.ipv4.tcp_syncookies", "1")


@register(
    id="CIS-4.1",
    title="A host-based firewall (ufw/nftables/iptables) is installed and active",
    category=CATEGORY,
    rationale="A host-based firewall is a baseline defense-in-depth control "
    "even behind network firewalls/security groups - without one, every "
    "listening service on the host is directly reachable from anything that "
    "can route to it.",
    remediation="Install and enable one firewall: 'apt install ufw && ufw default deny incoming && ufw enable' "
    "is the simplest option for a single host.",
)
def check_firewall_active() -> CheckResult:
    ufw = which("ufw")
    if ufw:
        rc, out, err = run_cmd([ufw, "status"])
        evidence = f"`ufw status`: {out or err}"
        if rc == 0 and out.lower().startswith("status: active"):
            return CheckResult(Status.PASS, evidence)
        if rc == 0:
            return CheckResult(Status.FAIL, evidence + " (ufw installed but not active)")
        # ufw present but status needs root - can't tell either way
        return CheckResult(Status.NOT_APPLICABLE, evidence + " (could not query ufw status, likely needs root)")

    nft = which("nft")
    if nft:
        rc, out, err = run_cmd([nft, "list", "ruleset"])
        if rc == 0:
            evidence = f"`nft list ruleset`: {'non-empty' if out else 'empty'} ruleset"
            if out.strip():
                return CheckResult(Status.PASS, evidence)
            return CheckResult(Status.FAIL, evidence + " (nftables installed but no rules loaded)")
        return CheckResult(Status.NOT_APPLICABLE, f"`nft list ruleset` failed: {err} (likely needs root)")

    iptables = which("iptables")
    if iptables:
        rc, out, err = run_cmd([iptables, "-S"])
        if rc == 0:
            rule_count = len([l for l in out.splitlines() if l.startswith("-A")])
            evidence = f"`iptables -S`: {rule_count} rule(s) beyond default chain policies"
            if rule_count > 0:
                return CheckResult(Status.PASS, evidence)
            return CheckResult(Status.FAIL, evidence + " (iptables installed but no filtering rules)")
        return CheckResult(Status.NOT_APPLICABLE, f"`iptables -S` failed: {err} (likely needs root)")

    return CheckResult(
        Status.FAIL,
        "No firewall tool found on PATH (checked ufw, nft, iptables) - no host-based firewall is installed.",
    )
