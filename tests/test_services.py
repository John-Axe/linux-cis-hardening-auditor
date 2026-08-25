import os

from cis_audit.checks import services
from cis_audit.models import Status


def test_legacy_services_pass_when_none_found(monkeypatch):
    monkeypatch.setattr(services, "which", lambda b: None)
    result = services.check_legacy_services_absent()
    assert result.status == Status.PASS


def test_legacy_services_fail_when_telnetd_found(monkeypatch):
    monkeypatch.setattr(services, "which", lambda b: "/usr/sbin/in.telnetd" if b == "in.telnetd" else None)
    result = services.check_legacy_services_absent()
    assert result.status == Status.FAIL
    assert "telnet" in result.evidence.lower()


def test_automatic_updates_pass(monkeypatch):
    monkeypatch.setattr(
        services,
        "read_lines",
        lambda p: ['APT::Periodic::Update-Package-Lists "1";', 'APT::Periodic::Unattended-Upgrade "1";'],
    )
    result = services.check_automatic_updates_configured()
    assert result.status == Status.PASS


def test_automatic_updates_fail_when_disabled(monkeypatch):
    monkeypatch.setattr(services, "read_lines", lambda p: ['APT::Periodic::Unattended-Upgrade "0";'])
    result = services.check_automatic_updates_configured()
    assert result.status == Status.FAIL


def test_automatic_updates_fail_when_file_missing(monkeypatch):
    monkeypatch.setattr(services, "read_lines", lambda p: None)
    result = services.check_automatic_updates_configured()
    assert result.status == Status.FAIL


def test_aslr_pass(monkeypatch):
    monkeypatch.setattr(services, "sysctl_value", lambda k: "2")
    result = services.check_aslr_enabled()
    assert result.status == Status.PASS


def test_aslr_fail(monkeypatch):
    monkeypatch.setattr(services, "sysctl_value", lambda k: "0")
    result = services.check_aslr_enabled()
    assert result.status == Status.FAIL


def test_suid_dumpable_pass(monkeypatch):
    monkeypatch.setattr(services, "sysctl_value", lambda k: "0")
    result = services.check_suid_dumpable_disabled()
    assert result.status == Status.PASS


def test_passwordless_sudo_na_when_no_sudoers(monkeypatch):
    monkeypatch.setattr(services, "_sudoers_files", lambda: [])
    result = services.check_no_passwordless_sudo()
    assert result.status == Status.NOT_APPLICABLE


def test_passwordless_sudo_na_when_unreadable(monkeypatch):
    monkeypatch.setattr(services, "_sudoers_files", lambda: ["/etc/sudoers"])
    monkeypatch.setattr(services, "read_lines", lambda p: None)
    result = services.check_no_passwordless_sudo()
    assert result.status == Status.NOT_APPLICABLE


def test_passwordless_sudo_fail_when_nopasswd_found(monkeypatch):
    monkeypatch.setattr(services, "_sudoers_files", lambda: ["/etc/sudoers.d/90-deploy"])
    monkeypatch.setattr(
        services,
        "read_lines",
        lambda p: ["deploy ALL=(ALL) NOPASSWD: ALL"],
    )
    result = services.check_no_passwordless_sudo()
    assert result.status == Status.FAIL
    assert "deploy" in result.evidence


def test_passwordless_sudo_pass_when_clean(monkeypatch):
    monkeypatch.setattr(services, "_sudoers_files", lambda: ["/etc/sudoers"])
    monkeypatch.setattr(
        services,
        "read_lines",
        lambda p: ["%sudo   ALL=(ALL:ALL) ALL"],
    )
    result = services.check_no_passwordless_sudo()
    assert result.status == Status.PASS


def test_sudoers_files_lists_sudoers_d(tmp_path, monkeypatch):
    sudoers_d = tmp_path / "sudoers.d"
    sudoers_d.mkdir()
    (sudoers_d / "README").write_text("ignored")
    (sudoers_d / "90-app").write_text("app ALL=(ALL) ALL")
    real_listdir = os.listdir
    monkeypatch.setattr(os.path, "exists", lambda p: p == "/etc/sudoers")
    monkeypatch.setattr(os.path, "isdir", lambda p: p == "/etc/sudoers.d")
    monkeypatch.setattr(os, "listdir", lambda p: real_listdir(sudoers_d))
    files = services._sudoers_files()
    assert files == ["/etc/sudoers", "/etc/sudoers.d/90-app"]
