"""Unit tests for checks/network_services.py - dpkg/systemctl/postconf calls
are all mocked so these are deterministic regardless of what's actually
installed on the machine running pytest. The per-service "not installed or
active" checks are produced by a factory function and only registered in the
global registry, so they're exercised here via the registry."""

from cis_audit.checks import network_services as ns
from cis_audit.models import Status
from cis_audit.registry import all_checks

CHECKS = {c.id: c for c in all_checks()}


def test_service_pass_when_not_installed(monkeypatch):
    monkeypatch.setattr(ns, "run_cmd", lambda args, timeout=5.0: (1, "", "no packages found"))
    result = CHECKS["CIS-2.2.2"].run()  # avahi-daemon
    assert result.status == Status.PASS


def test_service_pass_when_installed_but_inactive(monkeypatch):
    def fake_run_cmd(args, timeout=5.0):
        if "dpkg-query" in args:
            return 0, "install ok installed", ""
        return 3, "inactive", ""

    monkeypatch.setattr(ns, "run_cmd", fake_run_cmd)
    result = CHECKS["CIS-2.2.6"].run()  # samba
    assert result.status == Status.PASS
    assert "not currently a listening risk" in result.evidence


def test_service_fail_when_installed_and_active(monkeypatch):
    def fake_run_cmd(args, timeout=5.0):
        if "dpkg-query" in args:
            return 0, "install ok installed", ""
        return 0, "active", ""

    monkeypatch.setattr(ns, "run_cmd", fake_run_cmd)
    result = CHECKS["CIS-2.2.15"].run()  # apache2
    assert result.status == Status.FAIL
    assert "installed and running" in result.evidence


def test_x_window_system_pass_when_absent(monkeypatch):
    monkeypatch.setattr(ns, "run_cmd", lambda args, timeout=5.0: (1, "", ""))
    monkeypatch.setattr(ns, "which", lambda b: None)
    result = ns.check_x_window_system_not_installed()
    assert result.status == Status.PASS


def test_x_window_system_fail_when_present(monkeypatch):
    monkeypatch.setattr(ns, "which", lambda b: "/usr/bin/Xorg" if b == "Xorg" else None)
    monkeypatch.setattr(ns, "run_cmd", lambda args, timeout=5.0: (1, "", ""))
    result = ns.check_x_window_system_not_installed()
    assert result.status == Status.FAIL


def test_mta_local_only_na_when_not_installed(monkeypatch):
    monkeypatch.setattr(ns, "which", lambda b: None)
    monkeypatch.setattr(ns, "read_text", lambda p: None)
    result = ns.check_mta_local_only()
    assert result.status == Status.NOT_APPLICABLE


def test_mta_local_only_pass_via_postconf(monkeypatch):
    monkeypatch.setattr(ns, "which", lambda b: "/usr/sbin/postconf" if b == "postconf" else None)
    monkeypatch.setattr(ns, "run_cmd", lambda args, timeout=5.0: (0, "loopback-only", ""))
    result = ns.check_mta_local_only()
    assert result.status == Status.PASS


def test_mta_local_only_fail_via_config_file(monkeypatch):
    monkeypatch.setattr(ns, "which", lambda b: None)
    monkeypatch.setattr(ns, "read_text", lambda p: "inet_interfaces = all\n")
    result = ns.check_mta_local_only()
    assert result.status == Status.FAIL


def test_nis_client_pass_when_absent(monkeypatch):
    monkeypatch.setattr(ns, "run_cmd", lambda args, timeout=5.0: (1, "", ""))
    monkeypatch.setattr(ns, "which", lambda b: None)
    result = ns.check_nis_client_not_installed()
    assert result.status == Status.PASS


def test_nis_client_fail_when_present(monkeypatch):
    monkeypatch.setattr(ns, "run_cmd", lambda args, timeout=5.0: (0, "install ok installed", ""))
    monkeypatch.setattr(ns, "which", lambda b: None)
    result = ns.check_nis_client_not_installed()
    assert result.status == Status.FAIL


def test_all_eighteen_service_checks_registered():
    for n in range(1, 18):
        cid = f"CIS-2.2.{n}"
        assert cid in CHECKS, f"missing {cid}"
