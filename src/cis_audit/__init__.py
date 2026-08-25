"""cis_audit - a stdlib-only CIS Ubuntu/Debian Linux Benchmark-style hardening auditor.

Offline, read-only by default. Every check inspects real system state
(files, sysctl values, command output) and reports PASS / FAIL / NOT_APPLICABLE
with the actual evidence it looked at, plus a concrete remediation.
"""

__version__ = "0.1.0"
