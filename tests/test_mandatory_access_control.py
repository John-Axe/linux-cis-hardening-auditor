"""Unit tests for checks/mandatory_access_control.py - all filesystem/
subprocess access is mocked so these are deterministic regardless of whether
the machine running pytest actually has AppArmor or SELinux installed."""

from cis_audit.checks import mandatory_access_control as mac
from cis_audit.models import Status


def _no_mac(monkeypatch):
    monkeypatch.setattr(mac, "which", lambda b: None)
    monkeypatch.setattr("os.path.isdir", lambda p: False)
    monkeypatch.setattr("os.path.exists", lambda p: False)


def _apparmor_only(monkeypatch):
    monkeypatch.setattr(mac, "which", lambda b: "/usr/sbin/aa-status" if b == "aa-status" else None)
    monkeypatch.setattr("os.path.isdir", lambda p: p == "/etc/apparmor.d")
    monkeypatch.setattr("os.path.exists", lambda p: False)


def test_mac_installed_fail_when_neither_present(monkeypatch):
    _no_mac(monkeypatch)
    result = mac.check_mac_installed()
    assert result.status == Status.FAIL


def test_mac_installed_pass_with_apparmor(monkeypatch):
    _apparmor_only(monkeypatch)
    result = mac.check_mac_installed()
    assert result.status == Status.PASS


def test_apparmor_enabled_at_boot_na_when_not_installed(monkeypatch):
    _no_mac(monkeypatch)
    result = mac.check_apparmor_enabled_at_boot()
    assert result.status == Status.NOT_APPLICABLE


def test_apparmor_enabled_at_boot_pass(monkeypatch):
    _apparmor_only(monkeypatch)
    monkeypatch.setattr(mac, "read_text", lambda p: "Y\n")
    result = mac.check_apparmor_enabled_at_boot()
    assert result.status == Status.PASS


def test_apparmor_enabled_at_boot_fail(monkeypatch):
    _apparmor_only(monkeypatch)
    monkeypatch.setattr(mac, "read_text", lambda p: "N\n")
    result = mac.check_apparmor_enabled_at_boot()
    assert result.status == Status.FAIL


def test_apparmor_profiles_loaded_pass(monkeypatch):
    _apparmor_only(monkeypatch)
    monkeypatch.setattr(
        mac, "run_cmd",
        lambda args, timeout=5.0: (0, "apparmor module is loaded.\n12 profiles are loaded.", ""),
    )
    result = mac.check_apparmor_profiles_loaded()
    assert result.status == Status.PASS


def test_apparmor_profiles_loaded_fail_when_zero(monkeypatch):
    _apparmor_only(monkeypatch)
    monkeypatch.setattr(
        mac, "run_cmd",
        lambda args, timeout=5.0: (0, "apparmor module is loaded.\n0 profiles are loaded.", ""),
    )
    result = mac.check_apparmor_profiles_loaded()
    assert result.status == Status.FAIL


def test_no_complain_profiles_pass(monkeypatch):
    _apparmor_only(monkeypatch)
    monkeypatch.setattr(mac, "run_cmd", lambda args, timeout=5.0: (0, "0 profiles are in complain mode.", ""))
    result = mac.check_no_apparmor_complain_profiles()
    assert result.status == Status.PASS


def test_no_complain_profiles_fail(monkeypatch):
    _apparmor_only(monkeypatch)
    monkeypatch.setattr(mac, "run_cmd", lambda args, timeout=5.0: (0, "2 profiles are in complain mode.", ""))
    result = mac.check_no_apparmor_complain_profiles()
    assert result.status == Status.FAIL


def test_only_one_mac_system_pass_with_only_apparmor(monkeypatch):
    _apparmor_only(monkeypatch)
    result = mac.check_only_one_mac_system()
    assert result.status == Status.PASS


def test_only_one_mac_system_fail_when_both_present(monkeypatch):
    monkeypatch.setattr(mac, "which", lambda b: "/usr/bin/x")
    monkeypatch.setattr("os.path.isdir", lambda p: True)
    monkeypatch.setattr("os.path.exists", lambda p: True)
    result = mac.check_only_one_mac_system()
    assert result.status == Status.FAIL


def test_selinux_not_disabled_na_when_absent(monkeypatch):
    _no_mac(monkeypatch)
    result = mac.check_selinux_not_disabled()
    assert result.status == Status.NOT_APPLICABLE


def test_selinux_not_disabled_pass_via_getenforce(monkeypatch):
    monkeypatch.setattr(mac, "which", lambda b: "/usr/sbin/getenforce" if b == "getenforce" else None)
    monkeypatch.setattr("os.path.exists", lambda p: True)
    monkeypatch.setattr(mac, "run_cmd", lambda args, timeout=5.0: (0, "Enforcing", ""))
    result = mac.check_selinux_not_disabled()
    assert result.status == Status.PASS


def test_selinux_not_disabled_fail_via_config_file(monkeypatch):
    monkeypatch.setattr(mac, "which", lambda b: None)
    monkeypatch.setattr("os.path.exists", lambda p: p == "/etc/selinux/config")
    monkeypatch.setattr(mac, "read_text", lambda p: "SELINUX=disabled\n")
    result = mac.check_selinux_not_disabled()
    assert result.status == Status.FAIL
