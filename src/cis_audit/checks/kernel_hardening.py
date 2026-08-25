"""General kernel-hardening sysctl checks (CIS section 1.6, extending the
ASLR/SUID-dumpable checks already in checks/services.py) - kernel pointer/
dmesg exposure, ptrace scope, hardlink/symlink/fifo/regular-file protections,
unprivileged BPF, and perf event access.
"""

from __future__ import annotations

from cis_audit.models import CheckResult, Status
from cis_audit.registry import register
from cis_audit.utils import sysctl_value

CATEGORY = "kernel_hardening"


def _sysctl_check(key: str, expected_desc: str, comparator) -> CheckResult:
    value = sysctl_value(key)
    if value is None:
        return CheckResult(Status.NOT_APPLICABLE, f"sysctl key {key} is not readable on this host/kernel.")
    evidence = f"{key} = {value}"
    if comparator(value):
        return CheckResult(Status.PASS, evidence)
    return CheckResult(Status.FAIL, evidence + f" (expected {expected_desc})")


@register(
    id="CIS-1.6.3",
    title="Kernel pointers are restricted from unprivileged reads (kernel.kptr_restrict)",
    category=CATEGORY,
    rationale="Leaking kernel pointer addresses to unprivileged users "
    "defeats kernel-space ASLR, making kernel exploits significantly easier "
    "to develop and reliably trigger.",
    remediation="sysctl -w kernel.kptr_restrict=1 && echo 'kernel.kptr_restrict=1' >> /etc/sysctl.d/60-cis-hardening.conf",
)
def check_kptr_restrict() -> CheckResult:
    return _sysctl_check("kernel.kptr_restrict", "kernel.kptr_restrict >= 1", lambda v: v.isdigit() and int(v) >= 1)


@register(
    id="CIS-1.6.4",
    title="dmesg output is restricted to privileged users (kernel.dmesg_restrict)",
    category=CATEGORY,
    rationale="The kernel ring buffer can contain kernel addresses and "
    "hardware details useful for building an exploit; restricting dmesg to "
    "root denies that reconnaissance to an unprivileged local user.",
    remediation="sysctl -w kernel.dmesg_restrict=1 && echo 'kernel.dmesg_restrict=1' >> /etc/sysctl.d/60-cis-hardening.conf",
)
def check_dmesg_restrict() -> CheckResult:
    return _sysctl_check("kernel.dmesg_restrict", "kernel.dmesg_restrict = 1", lambda v: v == "1")


@register(
    id="CIS-1.6.5",
    title="ptrace scope is restricted (kernel.yama.ptrace_scope)",
    category=CATEGORY,
    rationale="Unrestricted ptrace lets any process attach to and inspect "
    "the memory of any other process owned by the same user - including "
    "one holding decrypted secrets in memory - which Yama's ptrace_scope "
    "setting restricts to direct parent/child relationships by default.",
    remediation="sysctl -w kernel.yama.ptrace_scope=1 && echo 'kernel.yama.ptrace_scope=1' >> /etc/sysctl.d/60-cis-hardening.conf",
)
def check_ptrace_scope() -> CheckResult:
    return _sysctl_check(
        "kernel.yama.ptrace_scope", "kernel.yama.ptrace_scope >= 1", lambda v: v.isdigit() and int(v) >= 1
    )


@register(
    id="CIS-1.6.6",
    title="Hardlink creation restrictions are enabled (fs.protected_hardlinks)",
    category=CATEGORY,
    rationale="Without this protection, a user can create a hardlink to a "
    "file they don't own (e.g. a SUID binary), which has historically "
    "enabled several local privilege-escalation and TOCTOU exploits.",
    remediation="sysctl -w fs.protected_hardlinks=1 && echo 'fs.protected_hardlinks=1' >> /etc/sysctl.d/60-cis-hardening.conf",
)
def check_protected_hardlinks() -> CheckResult:
    return _sysctl_check("fs.protected_hardlinks", "fs.protected_hardlinks = 1", lambda v: v == "1")


@register(
    id="CIS-1.6.7",
    title="Symlink-following restrictions are enabled (fs.protected_symlinks)",
    category=CATEGORY,
    rationale="Without this protection, a privileged process following a "
    "symlink in a world-writable directory (e.g. /tmp) can be tricked into "
    "operating on a file the attacker chose - a classic symlink-attack "
    "privilege-escalation vector.",
    remediation="sysctl -w fs.protected_symlinks=1 && echo 'fs.protected_symlinks=1' >> /etc/sysctl.d/60-cis-hardening.conf",
)
def check_protected_symlinks() -> CheckResult:
    return _sysctl_check("fs.protected_symlinks", "fs.protected_symlinks = 1", lambda v: v == "1")


@register(
    id="CIS-1.6.8",
    title="FIFO write restrictions are enabled (fs.protected_fifos)",
    category=CATEGORY,
    rationale="Without this protection, writing to a FIFO in a world-"
    "writable sticky directory that the process doesn't own can be abused "
    "similarly to the symlink attack this same kernel feature family "
    "closes off.",
    remediation="sysctl -w fs.protected_fifos=2 && echo 'fs.protected_fifos=2' >> /etc/sysctl.d/60-cis-hardening.conf",
)
def check_protected_fifos() -> CheckResult:
    return _sysctl_check("fs.protected_fifos", "fs.protected_fifos >= 1", lambda v: v.isdigit() and int(v) >= 1)


@register(
    id="CIS-1.6.9",
    title="Regular-file write restrictions are enabled (fs.protected_regular)",
    category=CATEGORY,
    rationale="Same class of protection as protected_fifos, extended to "
    "regular files opened for writing in a world-writable sticky "
    "directory by a process that isn't the file's owner.",
    remediation="sysctl -w fs.protected_regular=2 && echo 'fs.protected_regular=2' >> /etc/sysctl.d/60-cis-hardening.conf",
)
def check_protected_regular() -> CheckResult:
    return _sysctl_check("fs.protected_regular", "fs.protected_regular >= 1", lambda v: v.isdigit() and int(v) >= 1)


@register(
    id="CIS-1.6.10",
    title="Unprivileged BPF is disabled (kernel.unprivileged_bpf_disabled)",
    category=CATEGORY,
    rationale="The eBPF verifier has repeatedly been a source of local "
    "privilege-escalation bugs; disabling unprivileged access to bpf() "
    "removes that entire class of attack from unprivileged local users.",
    remediation="sysctl -w kernel.unprivileged_bpf_disabled=1 && echo 'kernel.unprivileged_bpf_disabled=1' >> /etc/sysctl.d/60-cis-hardening.conf",
)
def check_unprivileged_bpf_disabled() -> CheckResult:
    return _sysctl_check(
        "kernel.unprivileged_bpf_disabled", "kernel.unprivileged_bpf_disabled >= 1",
        lambda v: v.isdigit() and int(v) >= 1,
    )


@register(
    id="CIS-1.6.11",
    title="JIT hardening is enabled for the BPF just-in-time compiler (net.core.bpf_jit_harden)",
    category=CATEGORY,
    rationale="Without JIT hardening, BPF-JIT-compiled code is more "
    "predictable and easier to use as a building block in a kernel "
    "exploit; hardening randomizes/constant-blinds the generated code.",
    remediation="sysctl -w net.core.bpf_jit_harden=2 && echo 'net.core.bpf_jit_harden=2' >> /etc/sysctl.d/60-cis-hardening.conf",
)
def check_bpf_jit_harden() -> CheckResult:
    return _sysctl_check(
        "net.core.bpf_jit_harden", "net.core.bpf_jit_harden >= 1", lambda v: v.isdigit() and int(v) >= 1
    )


@register(
    id="CIS-1.6.12",
    title="Performance event access is restricted (kernel.perf_event_paranoid)",
    category=CATEGORY,
    rationale="The perf_event subsystem has been used in multiple published "
    "local privilege-escalation exploits; restricting it to privileged "
    "users closes off that surface for unprivileged local accounts.",
    remediation="sysctl -w kernel.perf_event_paranoid=2 && echo 'kernel.perf_event_paranoid=2' >> /etc/sysctl.d/60-cis-hardening.conf",
)
def check_perf_event_paranoid() -> CheckResult:
    return _sysctl_check(
        "kernel.perf_event_paranoid", "kernel.perf_event_paranoid >= 2", lambda v: v.lstrip("-").isdigit() and int(v) >= 2
    )
