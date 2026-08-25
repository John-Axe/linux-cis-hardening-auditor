"""Importing this package registers every check module's checks.

Each submodule uses @register(...) at import time to add itself to the
global registry in cis_audit.registry - so simply importing this package
(which cis_audit.engine does) is enough to make every check available.
"""

from cis_audit.checks import (  # noqa: F401
    auth,
    auth_expanded,
    banners_and_motd,
    cron_and_pam,
    filesystem,
    filesystem_expanded,
    kernel_hardening,
    kernel_modules,
    logging_audit,
    mandatory_access_control,
    network,
    network_services,
    network_sysctl_expanded,
    ntp_and_time,
    package_management,
    services,
    ssh,
    ssh_expanded,
)

__all__ = [
    "auth",
    "auth_expanded",
    "banners_and_motd",
    "cron_and_pam",
    "filesystem",
    "filesystem_expanded",
    "kernel_hardening",
    "kernel_modules",
    "logging_audit",
    "mandatory_access_control",
    "network",
    "network_services",
    "network_sysctl_expanded",
    "ntp_and_time",
    "package_management",
    "services",
    "ssh",
    "ssh_expanded",
]
