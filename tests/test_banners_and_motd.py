"""Unit tests for checks/banners_and_motd.py - all filesystem/subprocess
access is mocked so these are deterministic regardless of the machine
running pytest."""

from cis_audit.checks import banners_and_motd as banners
from cis_audit.models import Status


def test_motd_perms_pass(monkeypatch):
    monkeypatch.setattr(banners, "path_mode_octal", lambda p: "644")
    monkeypatch.setattr(banners, "path_owner", lambda p: ("root", "root"))
    result = banners.check_motd_perms()
    assert result.status == Status.PASS


def test_motd_perms_fail_too_permissive(monkeypatch):
    monkeypatch.setattr(banners, "path_mode_octal", lambda p: "666")
    monkeypatch.setattr(banners, "path_owner", lambda p: ("root", "root"))
    result = banners.check_motd_perms()
    assert result.status == Status.FAIL


def test_motd_perms_fail_wrong_owner(monkeypatch):
    monkeypatch.setattr(banners, "path_mode_octal", lambda p: "644")
    monkeypatch.setattr(banners, "path_owner", lambda p: ("alice", "alice"))
    result = banners.check_motd_perms()
    assert result.status == Status.FAIL


def test_issue_perms_fail_when_missing(monkeypatch):
    monkeypatch.setattr(banners, "path_mode_octal", lambda p: None)
    result = banners.check_issue_perms()
    assert result.status == Status.FAIL
    assert "does not exist" in result.evidence


def test_issue_net_perms_pass(monkeypatch):
    monkeypatch.setattr(banners, "path_mode_octal", lambda p: "600")
    monkeypatch.setattr(banners, "path_owner", lambda p: ("root", "root"))
    result = banners.check_issue_net_perms()
    assert result.status == Status.PASS


def test_issue_no_os_info_pass(monkeypatch):
    monkeypatch.setattr(banners, "read_text", lambda p: "Authorized uses only. All activity is monitored.\n")
    result = banners.check_issue_no_os_info()
    assert result.status == Status.PASS


def test_issue_no_os_info_fail_leaks_version(monkeypatch):
    monkeypatch.setattr(banners, "read_text", lambda p: "Welcome to \\s \\r \\v \\m\n")
    result = banners.check_issue_no_os_info()
    assert result.status == Status.FAIL
    assert "\\s" in result.evidence


def test_issue_net_no_os_info_fail_when_missing(monkeypatch):
    monkeypatch.setattr(banners, "read_text", lambda p: None)
    result = banners.check_issue_net_no_os_info()
    assert result.status == Status.FAIL


def test_motd_no_os_info_pass(monkeypatch):
    monkeypatch.setattr(banners, "read_text", lambda p: "Authorized use only.\n")
    result = banners.check_motd_no_os_info()
    assert result.status == Status.PASS


def test_gdm_banner_na_when_not_installed(monkeypatch):
    monkeypatch.setattr(banners, "which", lambda b: None)
    monkeypatch.setattr("os.path.isdir", lambda p: False)
    result = banners.check_gdm_banner_configured()
    assert result.status == Status.NOT_APPLICABLE


def test_gdm_banner_pass_when_enabled(monkeypatch):
    monkeypatch.setattr(banners, "which", lambda b: "/usr/sbin/gdm3" if b == "gdm3" else None)
    monkeypatch.setattr(banners, "run_cmd", lambda args, timeout=5.0: (0, "true", ""))
    result = banners.check_gdm_banner_configured()
    assert result.status == Status.PASS


def test_gdm_banner_fail_when_disabled(monkeypatch):
    monkeypatch.setattr(banners, "which", lambda b: "/usr/sbin/gdm3" if b == "gdm3" else None)
    monkeypatch.setattr(banners, "run_cmd", lambda args, timeout=5.0: (0, "false", ""))
    result = banners.check_gdm_banner_configured()
    assert result.status == Status.FAIL
