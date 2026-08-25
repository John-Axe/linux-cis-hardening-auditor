"""Additional sshd_config directive checks (CIS section 5.2, extending
checks/ssh.py) - session limits, idle timeout, forwarding/environment/
host-based-auth hardening, log verbosity, and approved crypto algorithms.

Reuses ssh.py's _effective_sshd_config()/_na_no_sshd() helpers directly so
every check here follows the exact same sshd -T-preferred, config-file-
fallback, NOT_APPLICABLE-when-no-sshd behavior as the original module.
"""

from __future__ import annotations

from cis_audit.checks.ssh import _effective_sshd_config, _na_no_sshd
from cis_audit.models import CheckResult, Status
from cis_audit.registry import register

CATEGORY = "ssh"

# Algorithms CIS considers weak/deprecated - if any of these appear in the
# effective Ciphers/MACs/KexAlgorithms lists, the check fails.
_WEAK_CIPHERS = ("3des-cbc", "aes128-cbc", "aes192-cbc", "aes256-cbc", "arcfour", "blowfish-cbc", "cast128-cbc")
_WEAK_MACS = ("hmac-md5", "hmac-sha1-96", "hmac-md5-96", "umac-64")
_WEAK_KEX = ("diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1", "diffie-hellman-group-exchange-sha1")


def _directive_check(key: str, expected: str, default_if_unset: str, comparator=None) -> CheckResult:
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
    id="CIS-5.2.12",
    title="SSH LoginGraceTime is 60 seconds or less",
    category=CATEGORY,
    rationale="A long login grace period lets an attacker hold open many "
    "half-authenticated connections simultaneously, tying up server "
    "resources in a slow-loris-style denial of service.",
    remediation="In /etc/ssh/sshd_config set 'LoginGraceTime 60' then systemctl reload sshd",
)
def check_ssh_login_grace_time() -> CheckResult:
    def comparator(value: str) -> bool:
        try:
            return int(value.rstrip("s")) <= 60
        except ValueError:
            return False

    return _directive_check("logingracetime", "<= 60", "120", comparator)


@register(
    id="CIS-5.2.13",
    title="SSH MaxSessions is 10 or less",
    category=CATEGORY,
    rationale="A high MaxSessions lets a single authenticated connection "
    "multiplex an excessive number of shell/forwarding sessions, "
    "amplifying the impact of one compromised credential.",
    remediation="In /etc/ssh/sshd_config set 'MaxSessions 10' then systemctl reload sshd",
)
def check_ssh_max_sessions() -> CheckResult:
    def comparator(value: str) -> bool:
        try:
            return int(value) <= 10
        except ValueError:
            return False

    return _directive_check("maxsessions", "<= 10", "10", comparator)


@register(
    id="CIS-5.2.14",
    title="SSH ClientAliveInterval is configured (nonzero, at most 900 seconds)",
    category=CATEGORY,
    rationale="Without a ClientAliveInterval, a dropped or abandoned "
    "connection can leave an authenticated session open indefinitely - this "
    "setting makes sshd probe and eventually close idle/dead sessions.",
    remediation="In /etc/ssh/sshd_config set 'ClientAliveInterval 300' then systemctl reload sshd",
)
def check_ssh_client_alive_interval() -> CheckResult:
    def comparator(value: str) -> bool:
        try:
            v = int(value)
        except ValueError:
            return False
        return 0 < v <= 900

    return _directive_check("clientaliveinterval", "0 < value <= 900", "0", comparator)


@register(
    id="CIS-5.2.15",
    title="SSH ClientAliveCountMax is 3 or less",
    category=CATEGORY,
    rationale="Combined with ClientAliveInterval, a low CountMax bounds how "
    "long an unresponsive session is kept open before sshd disconnects it.",
    remediation="In /etc/ssh/sshd_config set 'ClientAliveCountMax 3' then systemctl reload sshd",
)
def check_ssh_client_alive_count_max() -> CheckResult:
    def comparator(value: str) -> bool:
        try:
            return int(value) <= 3
        except ValueError:
            return False

    return _directive_check("clientalivecountmax", "<= 3", "3", comparator)


@register(
    id="CIS-5.2.17",
    title="SSH AllowTcpForwarding is disabled",
    category=CATEGORY,
    rationale="TCP forwarding lets an SSH session tunnel arbitrary "
    "additional traffic through the server - useful for legitimate "
    "tunneling, but it also lets a compromised account pivot into networks "
    "the server can reach.",
    remediation="In /etc/ssh/sshd_config set 'AllowTcpForwarding no' then systemctl reload sshd",
)
def check_ssh_allow_tcp_forwarding() -> CheckResult:
    return _directive_check("allowtcpforwarding", "no", "yes")


@register(
    id="CIS-5.2.18",
    title="SSH PermitUserEnvironment is disabled",
    category=CATEGORY,
    rationale="Allowing users to set arbitrary environment variables at "
    "login (via ~/.ssh/environment) can be abused to override LD_PRELOAD "
    "or PATH for subsequently-invoked privileged helper programs.",
    remediation="In /etc/ssh/sshd_config set 'PermitUserEnvironment no' then systemctl reload sshd",
)
def check_ssh_permit_user_environment() -> CheckResult:
    return _directive_check("permituserenvironment", "no", "no")


@register(
    id="CIS-5.2.19",
    title="SSH IgnoreRhosts is enabled",
    category=CATEGORY,
    rationale="rhosts-based trust has no cryptographic authentication at "
    "all; IgnoreRhosts ensures sshd never honors ~/.rhosts or "
    "/etc/hosts.equiv even if one is somehow present.",
    remediation="In /etc/ssh/sshd_config set 'IgnoreRhosts yes' then systemctl reload sshd",
)
def check_ssh_ignore_rhosts() -> CheckResult:
    return _directive_check("ignorerhosts", "yes", "yes")


@register(
    id="CIS-5.2.21",
    title="SSH HostbasedAuthentication is disabled",
    category=CATEGORY,
    rationale="Host-based authentication trusts the connecting client "
    "machine's identity instead of a per-user credential - if any host in "
    "the trust list is compromised, every account on this server becomes "
    "reachable from it.",
    remediation="In /etc/ssh/sshd_config set 'HostbasedAuthentication no' then systemctl reload sshd",
)
def check_ssh_hostbased_auth() -> CheckResult:
    return _directive_check("hostbasedauthentication", "no", "no")


@register(
    id="CIS-5.2.22",
    title="SSH LogLevel is INFO or more verbose",
    category=CATEGORY,
    rationale="The default LogLevel doesn't record which key was used to "
    "authenticate a session; INFO (or VERBOSE) is needed to attribute a "
    "login to a specific key during an investigation.",
    remediation="In /etc/ssh/sshd_config set 'LogLevel INFO' then systemctl reload sshd",
)
def check_ssh_log_level() -> CheckResult:
    def comparator(value: str) -> bool:
        return value.upper() in ("INFO", "VERBOSE", "DEBUG", "DEBUG1", "DEBUG2", "DEBUG3")

    return _directive_check("loglevel", "INFO or more verbose", "INFO", comparator)


@register(
    id="CIS-5.2.23",
    title="SSH Ciphers are limited to strong, approved algorithms",
    category=CATEGORY,
    rationale="Weak ciphers (CBC-mode, RC4/arcfour, 3DES) have known "
    "cryptographic weaknesses (e.g. padding-oracle or biased-keystream "
    "attacks); an attacker who can negotiate a weak cipher gets a much "
    "easier target than a modern AEAD cipher.",
    remediation="In /etc/ssh/sshd_config set "
    "'Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com' "
    "then systemctl reload sshd",
)
def check_ssh_ciphers() -> CheckResult:
    cfg, source = _effective_sshd_config()
    if cfg is None:
        return _na_no_sshd()
    value = cfg.get("ciphers", "")
    configured = [c.strip().lower() for c in value.split(",") if c.strip()]
    weak_present = [c for c in configured if c in _WEAK_CIPHERS]
    evidence = f"{source}: Ciphers {value or '(unset, using sshd default list)'}"
    if not configured:
        # sshd's own compiled-in default list excludes the weak ciphers already.
        return CheckResult(Status.PASS, evidence)
    if weak_present:
        return CheckResult(Status.FAIL, evidence + f" (weak cipher(s) present: {', '.join(weak_present)})")
    return CheckResult(Status.PASS, evidence)


@register(
    id="CIS-5.2.24",
    title="SSH MACs are limited to strong, approved algorithms",
    category=CATEGORY,
    rationale="MD5- and truncated-SHA1-based MACs are weaker than modern "
    "ETM (encrypt-then-MAC) constructions and shouldn't be offered even if "
    "a client would accept the downgrade.",
    remediation="In /etc/ssh/sshd_config set "
    "'MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com' then systemctl reload sshd",
)
def check_ssh_macs() -> CheckResult:
    cfg, source = _effective_sshd_config()
    if cfg is None:
        return _na_no_sshd()
    value = cfg.get("macs", "")
    configured = [c.strip().lower() for c in value.split(",") if c.strip()]
    weak_present = [c for c in configured if c in _WEAK_MACS]
    evidence = f"{source}: MACs {value or '(unset, using sshd default list)'}"
    if not configured:
        return CheckResult(Status.PASS, evidence)
    if weak_present:
        return CheckResult(Status.FAIL, evidence + f" (weak MAC(s) present: {', '.join(weak_present)})")
    return CheckResult(Status.PASS, evidence)


@register(
    id="CIS-5.2.25",
    title="SSH KexAlgorithms are limited to strong, approved algorithms",
    category=CATEGORY,
    rationale="SHA-1-based key exchange methods are weaker than modern "
    "curve/group-14+ SHA-2 based exchanges and shouldn't be offered.",
    remediation="In /etc/ssh/sshd_config set "
    "'KexAlgorithms curve25519-sha256,diffie-hellman-group16-sha512' then systemctl reload sshd",
)
def check_ssh_kex_algorithms() -> CheckResult:
    cfg, source = _effective_sshd_config()
    if cfg is None:
        return _na_no_sshd()
    value = cfg.get("kexalgorithms", "")
    configured = [c.strip().lower() for c in value.split(",") if c.strip()]
    weak_present = [c for c in configured if c in _WEAK_KEX]
    evidence = f"{source}: KexAlgorithms {value or '(unset, using sshd default list)'}"
    if not configured:
        return CheckResult(Status.PASS, evidence)
    if weak_present:
        return CheckResult(Status.FAIL, evidence + f" (weak KEX algorithm(s) present: {', '.join(weak_present)})")
    return CheckResult(Status.PASS, evidence)


@register(
    id="CIS-5.2.26",
    title="SSH compression is disabled or delayed until after authentication",
    category=CATEGORY,
    rationale="Pre-authentication compression has historically enabled "
    "information-leak attacks (e.g. CVE-2016-0777 style); delaying "
    "compression until after auth or disabling it removes that surface.",
    remediation="In /etc/ssh/sshd_config set 'Compression no' then systemctl reload sshd",
)
def check_ssh_compression() -> CheckResult:
    def comparator(value: str) -> bool:
        return value.lower() in ("no", "delayed")

    return _directive_check("compression", "no or delayed", "no", comparator)


@register(
    id="CIS-5.2.27",
    title="SSH UsePAM is enabled",
    category=CATEGORY,
    rationale="UsePAM integrates sshd with the system's PAM stack, which is "
    "what actually enforces account lockout (faillock), password quality, "
    "and login restrictions configured elsewhere in this audit - without "
    "it, those controls don't apply to SSH logins at all.",
    remediation="In /etc/ssh/sshd_config set 'UsePAM yes' then systemctl reload sshd",
)
def check_ssh_use_pam() -> CheckResult:
    return _directive_check("usepam", "yes", "yes")
