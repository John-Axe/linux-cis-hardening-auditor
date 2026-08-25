from cis_audit.checks import network
from cis_audit.models import Status


def test_ip_forward_pass(monkeypatch):
    monkeypatch.setattr(network, "sysctl_value", lambda k: "0")
    result = network.check_ip_forward_disabled()
    assert result.status == Status.PASS


def test_ip_forward_fail(monkeypatch):
    monkeypatch.setattr(network, "sysctl_value", lambda k: "1")
    result = network.check_ip_forward_disabled()
    assert result.status == Status.FAIL


def test_ip_forward_na_when_unreadable(monkeypatch):
    monkeypatch.setattr(network, "sysctl_value", lambda k: None)
    result = network.check_ip_forward_disabled()
    assert result.status == Status.NOT_APPLICABLE


def test_rp_filter_accepts_1_or_2(monkeypatch):
    monkeypatch.setattr(network, "sysctl_value", lambda k: "2")
    assert network.check_rp_filter_enabled().status == Status.PASS
    monkeypatch.setattr(network, "sysctl_value", lambda k: "1")
    assert network.check_rp_filter_enabled().status == Status.PASS
    monkeypatch.setattr(network, "sysctl_value", lambda k: "0")
    assert network.check_rp_filter_enabled().status == Status.FAIL


def test_firewall_ufw_active(monkeypatch):
    monkeypatch.setattr(network, "which", lambda b: "/usr/sbin/ufw" if b == "ufw" else None)
    monkeypatch.setattr(network, "run_cmd", lambda args, timeout=5.0: (0, "Status: active", ""))
    result = network.check_firewall_active()
    assert result.status == Status.PASS


def test_firewall_ufw_inactive(monkeypatch):
    monkeypatch.setattr(network, "which", lambda b: "/usr/sbin/ufw" if b == "ufw" else None)
    monkeypatch.setattr(network, "run_cmd", lambda args, timeout=5.0: (0, "Status: inactive", ""))
    result = network.check_firewall_active()
    assert result.status == Status.FAIL


def test_firewall_none_installed(monkeypatch):
    monkeypatch.setattr(network, "which", lambda b: None)
    result = network.check_firewall_active()
    assert result.status == Status.FAIL
    assert "No firewall tool found" in result.evidence


def test_firewall_iptables_with_rules(monkeypatch):
    def fake_which(b):
        return "/usr/sbin/iptables" if b == "iptables" else None

    monkeypatch.setattr(network, "which", fake_which)
    monkeypatch.setattr(
        network,
        "run_cmd",
        lambda args, timeout=5.0: (0, "-P INPUT DROP\n-A INPUT -i lo -j ACCEPT", ""),
    )
    result = network.check_firewall_active()
    assert result.status == Status.PASS
