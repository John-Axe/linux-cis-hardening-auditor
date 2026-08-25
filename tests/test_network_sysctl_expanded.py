"""Unit tests for checks/network_sysctl_expanded.py - sysctl reads are
mocked so these are deterministic regardless of the kernel running pytest.
Every check here is produced by a factory function and only registered in
the global registry (never bound to a module-level name), so they're all
exercised via the registry rather than by attribute access."""

from cis_audit.checks import network_sysctl_expanded as nse
from cis_audit.models import Status
from cis_audit.registry import all_checks

CHECKS = {c.id: c for c in all_checks()}


def test_source_route_all_pass(monkeypatch):
    monkeypatch.setattr(nse, "sysctl_value", lambda k: "0")
    result = CHECKS["CIS-3.2.3"].run()
    assert result.status == Status.PASS


def test_source_route_default_fail(monkeypatch):
    monkeypatch.setattr(nse, "sysctl_value", lambda k: "1")
    result = CHECKS["CIS-3.2.5"].run()
    assert result.status == Status.FAIL


def test_redirects_default_na_when_unreadable(monkeypatch):
    monkeypatch.setattr(nse, "sysctl_value", lambda k: None)
    result = CHECKS["CIS-3.2.6"].run()
    assert result.status == Status.NOT_APPLICABLE


def test_send_redirects_default_pass(monkeypatch):
    monkeypatch.setattr(nse, "sysctl_value", lambda k: "0")
    result = CHECKS["CIS-3.2.7"].run()
    assert result.status == Status.PASS


def test_secure_redirects_all_fail(monkeypatch):
    monkeypatch.setattr(nse, "sysctl_value", lambda k: "1")
    result = CHECKS["CIS-3.2.8"].run()
    assert result.status == Status.FAIL


def test_secure_redirects_default_pass(monkeypatch):
    monkeypatch.setattr(nse, "sysctl_value", lambda k: "0")
    result = CHECKS["CIS-3.2.9"].run()
    assert result.status == Status.PASS


def test_log_martians_all_pass_when_enabled(monkeypatch):
    monkeypatch.setattr(nse, "sysctl_value", lambda k: "1")
    result = CHECKS["CIS-3.2.10"].run()
    assert result.status == Status.PASS


def test_log_martians_default_fail_when_disabled(monkeypatch):
    monkeypatch.setattr(nse, "sysctl_value", lambda k: "0")
    result = CHECKS["CIS-3.2.11"].run()
    assert result.status == Status.FAIL


def test_ignore_broadcasts_pass(monkeypatch):
    monkeypatch.setattr(nse, "sysctl_value", lambda k: "1")
    result = CHECKS["CIS-3.2.12"].run()
    assert result.status == Status.PASS


def test_ignore_bogus_errors_fail(monkeypatch):
    monkeypatch.setattr(nse, "sysctl_value", lambda k: "0")
    result = CHECKS["CIS-3.2.13"].run()
    assert result.status == Status.FAIL


def test_rp_filter_default_accepts_1_or_2(monkeypatch):
    monkeypatch.setattr(nse, "sysctl_value", lambda k: "2")
    assert CHECKS["CIS-3.2.14"].run().status == Status.PASS
    monkeypatch.setattr(nse, "sysctl_value", lambda k: "0")
    assert CHECKS["CIS-3.2.14"].run().status == Status.FAIL


def test_ipv6_accept_ra_all_fail_when_enabled(monkeypatch):
    monkeypatch.setattr(nse, "sysctl_value", lambda k: "1")
    result = CHECKS["CIS-3.2.15"].run()
    assert result.status == Status.FAIL


def test_ipv6_accept_ra_default_pass(monkeypatch):
    monkeypatch.setattr(nse, "sysctl_value", lambda k: "0")
    result = CHECKS["CIS-3.2.16"].run()
    assert result.status == Status.PASS


def test_ipv6_source_route_all_pass(monkeypatch):
    monkeypatch.setattr(nse, "sysctl_value", lambda k: "0")
    result = CHECKS["CIS-3.2.17"].run()
    assert result.status == Status.PASS


def test_ipv6_source_route_default_fail(monkeypatch):
    monkeypatch.setattr(nse, "sysctl_value", lambda k: "1")
    result = CHECKS["CIS-3.2.18"].run()
    assert result.status == Status.FAIL


def test_all_eighteen_sysctl_checks_registered():
    expected_ids = [f"CIS-3.2.{n}" for n in (3, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18)]
    for cid in expected_ids:
        assert cid in CHECKS, f"missing {cid}"
        assert CHECKS[cid].category == "network"
