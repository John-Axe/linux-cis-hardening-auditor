"""Time synchronization checks (CIS section 2.5).

An accurate system clock matters for security in ways that are easy to
overlook: log correlation across hosts, TLS certificate validity windows,
Kerberos ticket lifetimes, and time-based one-time-password (TOTP) MFA all
depend on it.
"""

from __future__ import annotations

from cis_audit.models import CheckResult, Status
from cis_audit.registry import register
from cis_audit.utils import read_text, run_cmd, which

CATEGORY = "time_sync"


def _chrony_installed() -> bool:
    return which("chronyd") is not None


def _timesyncd_installed() -> bool:
    return which("timedatectl") is not None


@register(
    id="CIS-2.5.1",
    title="A time synchronization daemon (chrony or systemd-timesyncd) is installed",
    category=CATEGORY,
    rationale="Without an active time sync daemon, the system clock drifts "
    "over time (sometimes minutes to hours per week), breaking TLS "
    "certificate validation, log correlation across hosts, and TOTP-based "
    "MFA.",
    remediation="apt install chrony && systemctl --now enable chrony",
)
def check_time_sync_daemon_installed() -> CheckResult:
    chrony = _chrony_installed()
    timesyncd = _timesyncd_installed()
    evidence = f"chronyd present: {chrony}; timedatectl present: {timesyncd}"
    if chrony or timesyncd:
        return CheckResult(Status.PASS, evidence)
    return CheckResult(Status.FAIL, evidence + " (no time sync daemon found)")


@register(
    id="CIS-2.5.2",
    title="The time synchronization service is active and enabled",
    category=CATEGORY,
    rationale="Installing a time sync daemon without it actually running "
    "provides no protection - the clock will still drift.",
    remediation="systemctl --now enable chrony  (or systemd-timesyncd, whichever is installed)",
)
def check_time_sync_service_active() -> CheckResult:
    if not (_chrony_installed() or _timesyncd_installed()):
        return CheckResult(Status.NOT_APPLICABLE, "No time sync daemon is installed on this host.")
    results = {}
    for unit in ("chrony", "chronyd", "systemd-timesyncd"):
        rc, out, err = run_cmd(["systemctl", "is-active", unit])
        results[unit] = out.strip() or err.strip()
    evidence = "; ".join(f"{u}: {s}" for u, s in results.items())
    if any(s == "active" for s in results.values()):
        return CheckResult(Status.PASS, evidence)
    return CheckResult(Status.FAIL, evidence)


@register(
    id="CIS-2.5.3",
    title="chrony is configured with at least one explicit time source",
    category=CATEGORY,
    rationale="chrony ships with no default servers on some distributions; "
    "without an explicit 'server'/'pool' directive it has nothing to "
    "synchronize against even though the daemon itself is running.",
    remediation="Add at least one 'pool <ntp-pool> iburst' or 'server <ntp-server> iburst' "
    "line to /etc/chrony/chrony.conf, then systemctl restart chrony",
)
def check_chrony_has_time_source() -> CheckResult:
    if not _chrony_installed():
        return CheckResult(Status.NOT_APPLICABLE, "chrony is not installed on this host.")
    text = read_text("/etc/chrony/chrony.conf") or read_text("/etc/chrony.conf")
    if text is None:
        return CheckResult(Status.FAIL, "chrony is installed but its config file could not be found/read.")
    sources = [
        line.strip()
        for line in text.splitlines()
        if line.strip().startswith(("server ", "pool ", "peer "))
    ]
    evidence = f"chrony.conf time source directives: {sources or '(none)'}"
    if sources:
        return CheckResult(Status.PASS, evidence)
    return CheckResult(Status.FAIL, evidence)


@register(
    id="CIS-2.5.4",
    title="systemd-timesyncd has an NTP server configured (if in use as the sync daemon)",
    category=CATEGORY,
    rationale="Like chrony, systemd-timesyncd needs at least one NTP server "
    "configured (or falls back to distro-default servers, which is fine, "
    "but a config with an empty NTP= that overrides the default with "
    "nothing is a real misconfiguration).",
    remediation="Set 'NTP=<server>' in /etc/systemd/timesyncd.conf, then systemctl restart systemd-timesyncd",
)
def check_timesyncd_has_ntp_server() -> CheckResult:
    text = read_text("/etc/systemd/timesyncd.conf")
    if text is None:
        return CheckResult(Status.NOT_APPLICABLE, "/etc/systemd/timesyncd.conf does not exist on this host.")
    ntp_line = None
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("NTP="):
            ntp_line = stripped
            break
    evidence = f"timesyncd.conf NTP= line: {ntp_line!r}"
    if ntp_line is None:
        return CheckResult(
            Status.PASS, evidence + " (unset - falls back to distro-default NTP servers, which is acceptable)"
        )
    if ntp_line == "NTP=":
        return CheckResult(Status.FAIL, evidence + " (explicitly set to empty, overriding defaults with nothing)")
    return CheckResult(Status.PASS, evidence)


@register(
    id="CIS-2.5.5",
    title="The system clock is currently synchronized",
    category=CATEGORY,
    rationale="A time sync daemon can be installed and 'active' yet still "
    "not have successfully synchronized (e.g. no network route to any "
    "configured server) - checking the live synchronized state catches "
    "that gap.",
    remediation="Verify network connectivity to the configured NTP server(s); "
    "check `chronyc tracking` or `timedatectl show` for the specific failure.",
)
def check_clock_is_synchronized() -> CheckResult:
    timedatectl = which("timedatectl")
    if timedatectl is None:
        return CheckResult(Status.NOT_APPLICABLE, "timedatectl is not available on this host.")
    rc, out, err = run_cmd([timedatectl, "show", "-p", "NTPSynchronized", "--value"])
    if rc != 0:
        return CheckResult(Status.NOT_APPLICABLE, f"`timedatectl show` failed: {err} (likely no systemd or no root).")
    evidence = f"`timedatectl show -p NTPSynchronized --value`: {out}"
    if out.strip() == "yes":
        return CheckResult(Status.PASS, evidence)
    return CheckResult(Status.FAIL, evidence)


@register(
    id="CIS-2.5.6",
    title="Only one time synchronization daemon is active",
    category=CATEGORY,
    rationale="Running both chrony and systemd-timesyncd simultaneously "
    "means two daemons compete to adjust the same clock, which can cause "
    "erratic time jumps instead of smooth synchronization.",
    remediation="systemctl disable --now systemd-timesyncd  # if chrony is the intended daemon, or vice versa",
)
def check_only_one_time_sync_daemon_active() -> CheckResult:
    rc1, out1, err1 = run_cmd(["systemctl", "is-active", "chrony"])
    rc1b, out1b, err1b = run_cmd(["systemctl", "is-active", "chronyd"])
    rc2, out2, err2 = run_cmd(["systemctl", "is-active", "systemd-timesyncd"])
    chrony_active = out1.strip() == "active" or out1b.strip() == "active"
    timesyncd_active = out2.strip() == "active"
    evidence = f"chrony active: {chrony_active}; systemd-timesyncd active: {timesyncd_active}"
    if chrony_active and timesyncd_active:
        return CheckResult(Status.FAIL, evidence + " (both active simultaneously)")
    if not chrony_active and not timesyncd_active:
        return CheckResult(Status.NOT_APPLICABLE, evidence + " (neither is active - see CIS-2.5.2)")
    return CheckResult(Status.PASS, evidence)
