""""Service X is not installed/active" checks (CIS section 2.2: network
services a hardened, single-purpose server generally shouldn't run).

Each check is deliberately simple and honest: does dpkg know about the
package, and if so, is its systemd unit active? A package can be installed
but its service stopped/masked (common after "apt install" without enabling
it) - that's still a PASS, since nothing is actually listening.
"""

from __future__ import annotations

from cis_audit.models import CheckResult, Status
from cis_audit.registry import register
from cis_audit.utils import read_text, run_cmd, which

CATEGORY = "network_services"


def _dpkg_installed(package: str) -> bool:
    rc, out, err = run_cmd(["dpkg-query", "-W", "-f=${Status}", package])
    return rc == 0 and "install ok installed" in out


def _service_active(unit: str) -> bool:
    rc, out, err = run_cmd(["systemctl", "is-active", unit])
    return out.strip() == "active"


def _service_absent_check(id_suffix: str, package: str, unit: str, label: str) -> CheckResult:
    installed = _dpkg_installed(package)
    active = _service_active(unit) if installed else False
    evidence = f"package '{package}' installed={installed}; unit '{unit}' active={active}"
    if not installed:
        return CheckResult(Status.PASS, evidence)
    if not active:
        return CheckResult(Status.PASS, evidence + " (installed but not active - not currently a listening risk)")
    return CheckResult(Status.FAIL, evidence + f" ({label} is installed and running)")


def _register_service_check(id: str, title: str, package: str, unit: str, label: str, rationale: str) -> None:
    @register(
        id=id,
        title=title,
        category=CATEGORY,
        rationale=rationale,
        remediation=f"systemctl disable --now {unit}; apt purge {package}",
    )
    def _check() -> CheckResult:
        return _service_absent_check(id, package, unit, label)

    _check.__name__ = f"check_{package.replace('-', '_')}_absent"


_register_service_check(
    "CIS-2.2.1", "autofs is not installed or active", "autofs", "autofs", "autofs",
    "autofs automatically mounts removable/network filesystems on access - "
    "convenient but rarely needed on a hardened server and expands the set "
    "of filesystems that can be attached without explicit administrator action.",
)
_register_service_check(
    "CIS-2.2.2", "avahi-daemon is not installed or active", "avahi-daemon", "avahi-daemon",
    "the Avahi mDNS/DNS-SD daemon",
    "Avahi advertises this host and its services on the local network via "
    "mDNS (zero-config networking) - useful on a desktop, unnecessary "
    "network exposure on a server.",
)
_register_service_check(
    "CIS-2.2.3", "A DHCP server (isc-dhcp-server) is not installed or active", "isc-dhcp-server",
    "isc-dhcp-server", "the ISC DHCP server",
    "Running a DHCP server on a host that isn't meant to be one can hand out "
    "conflicting or malicious network configuration to every other host on "
    "the segment.",
)
_register_service_check(
    "CIS-2.2.4", "A DNS server (bind9) is not installed or active", "bind9", "bind9", "the BIND9 DNS server",
    "An unintended authoritative/recursive DNS server is a common "
    "misconfiguration that can be abused for DNS amplification DDoS or "
    "cache poisoning if it's not the host's actual job.",
)
_register_service_check(
    "CIS-2.2.5", "dnsmasq is not installed or active", "dnsmasq", "dnsmasq", "dnsmasq",
    "dnsmasq provides combined DHCP/DNS services - unnecessary attack "
    "surface unless this host is specifically deployed as a network "
    "gateway/router.",
)
_register_service_check(
    "CIS-2.2.6", "Samba (smbd) is not installed or active", "samba", "smbd", "the Samba SMB/CIFS file server",
    "SMB file sharing has a long history of remote-exploitable "
    "vulnerabilities (e.g. EternalBlue); it shouldn't run unless this host "
    "is specifically a file server.",
)
_register_service_check(
    "CIS-2.2.7", "An FTP server (vsftpd) is not installed or active", "vsftpd", "vsftpd", "the vsftpd FTP server",
    "FTP transmits credentials in cleartext by default and has a long-"
    "available encrypted replacement (SFTP over SSH) - an FTP server "
    "shouldn't be running unless there's a specific legacy requirement.",
)
_register_service_check(
    "CIS-2.2.8", "An IMAP/POP3 server (dovecot) is not installed or active", "dovecot-core", "dovecot",
    "the Dovecot IMAP/POP3 server",
    "A mail retrieval server is a common target for credential-stuffing and "
    "shouldn't be running on a host that isn't specifically a mail server.",
)
_register_service_check(
    "CIS-2.2.9", "An NFS server is not installed or active", "nfs-kernel-server", "nfs-server",
    "the NFS kernel server",
    "NFS shares filesystem access over the network, often with weak "
    "host-based trust; it shouldn't run unless this host is specifically a "
    "file server.",
)
_register_service_check(
    "CIS-2.2.10", "rpcbind is not installed or active", "rpcbind", "rpcbind", "rpcbind",
    "rpcbind (the RPC portmapper) is required by NFS/NIS and has "
    "historically been abused for DDoS amplification; it has no reason to "
    "run on a host that isn't serving RPC-based services.",
)
_register_service_check(
    "CIS-2.2.11", "A print server (CUPS) is not installed or active", "cups", "cups", "the CUPS print server",
    "A network print server is unnecessary attack surface on a system that "
    "isn't specifically a print server, and CUPS has had multiple remote "
    "vulnerabilities historically.",
)
_register_service_check(
    "CIS-2.2.12", "The rsync service (daemon mode) is not installed or active", "rsync", "rsync",
    "the rsync daemon",
    "Running rsync in standalone daemon mode (rather than over SSH) can "
    "expose file transfer with weak or no authentication if misconfigured.",
)
_register_service_check(
    "CIS-2.2.13", "An SNMP server (snmpd) is not installed or active", "snmpd", "snmpd", "the SNMP daemon",
    "SNMP, especially with default/weak community strings, can leak "
    "detailed system information or allow remote configuration changes; it "
    "shouldn't run unless network monitoring specifically requires it.",
)
_register_service_check(
    "CIS-2.2.14", "A web proxy server (squid) is not installed or active", "squid", "squid",
    "the Squid proxy server",
    "An unintended open or misconfigured proxy can be abused to relay "
    "traffic and obscure an attacker's origin, or to bypass network egress "
    "controls.",
)
_register_service_check(
    "CIS-2.2.15", "A web server (apache2) is not installed or active", "apache2", "apache2", "Apache HTTP Server",
    "A web server is a large, frequently-targeted attack surface that "
    "shouldn't run unless this host is specifically deployed to serve web "
    "traffic.",
)
_register_service_check(
    "CIS-2.2.16", "A web server (nginx) is not installed or active", "nginx", "nginx", "nginx",
    "Same rationale as Apache: an unintended web server is unnecessary "
    "attack surface on a non-web-serving host.",
)
_register_service_check(
    "CIS-2.2.17", "xinetd is not installed or active", "xinetd", "xinetd", "the xinetd super-server",
    "xinetd exists to launch legacy inetd-style services on demand; its "
    "presence usually means one of those legacy services is also present, "
    "widening attack surface for no benefit on a modern host.",
)


@register(
    id="CIS-2.2.18",
    title="The X Window System is not installed",
    category=CATEGORY,
    rationale="A headless server has no legitimate need for a graphical "
    "display server; its presence increases the local attack surface "
    "(X has a long history of local privilege-escalation issues) for no "
    "operational benefit.",
    remediation="apt purge xserver-xorg*",
)
def check_x_window_system_not_installed() -> CheckResult:
    installed = _dpkg_installed("xserver-xorg-core") or which("Xorg") is not None
    evidence = f"xserver-xorg-core installed or Xorg binary present: {installed}"
    if installed:
        return CheckResult(Status.FAIL, evidence)
    return CheckResult(Status.PASS, evidence)


@register(
    id="CIS-2.3.1",
    title="The mail transfer agent is configured for local-only mail delivery",
    category=CATEGORY,
    rationale="A general-purpose host usually only needs to send mail "
    "locally (e.g. cron job output) and receive none from the network; an "
    "MTA listening on external interfaces is unnecessary attack surface and "
    "a potential open-relay risk if misconfigured.",
    remediation="Set 'inet_interfaces = loopback-only' in /etc/postfix/main.cf and systemctl restart postfix",
)
def check_mta_local_only() -> CheckResult:
    postconf = which("postconf")
    if postconf is None:
        text = read_text("/etc/postfix/main.cf")
        if text is None:
            return CheckResult(Status.NOT_APPLICABLE, "postfix is not installed on this host.")
        loopback_only = "inet_interfaces = loopback-only" in text or "inet_interfaces=loopback-only" in text
        evidence = f"/etc/postfix/main.cf: {'loopback-only found' if loopback_only else 'loopback-only not set'}"
        if loopback_only:
            return CheckResult(Status.PASS, evidence)
        return CheckResult(Status.FAIL, evidence)
    rc, out, err = run_cmd([postconf, "-h", "inet_interfaces"])
    if rc != 0:
        return CheckResult(Status.NOT_APPLICABLE, f"`postconf -h inet_interfaces` failed: {err}")
    evidence = f"`postconf -h inet_interfaces`: {out}"
    if out.strip() in ("loopback-only", "localhost"):
        return CheckResult(Status.PASS, evidence)
    return CheckResult(Status.FAIL, evidence + " (expected loopback-only)")


@register(
    id="CIS-2.4.1",
    title="A NIS client (ypbind) is not installed",
    category=CATEGORY,
    rationale="NIS (Network Information Service) transmits authentication "
    "data, including password hashes, in cleartext across the network - "
    "even acting only as a client exposes the host to a rogue NIS server on "
    "the same segment.",
    remediation="apt purge nis",
)
def check_nis_client_not_installed() -> CheckResult:
    installed = _dpkg_installed("nis") or which("ypbind") is not None
    evidence = f"nis package installed or ypbind binary present: {installed}"
    if installed:
        return CheckResult(Status.FAIL, evidence)
    return CheckResult(Status.PASS, evidence)
