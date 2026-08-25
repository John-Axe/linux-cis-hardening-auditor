"""Importing this package registers every check module's checks.

Each submodule uses @register(...) at import time to add itself to the
global registry in cis_audit.registry - so simply importing this package
(which cis_audit.engine does) is enough to make every check available.
"""

from cis_audit.checks import (  # noqa: F401
    auth,
    filesystem,
    kernel_hardening,
    kernel_modules,
    logging_audit,
    network,
    services,
    ssh,
)

__all__ = [
    "auth",
    "filesystem",
    "kernel_hardening",
    "kernel_modules",
    "logging_audit",
    "network",
    "services",
    "ssh",
]
