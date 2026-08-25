"""Unit tests for checks/package_management.py - all filesystem/subprocess
access (including glob.glob for /etc/apt/apt.conf.d/*) is mocked so these
are deterministic regardless of the machine running pytest."""

from cis_audit.checks import package_management as pm
from cis_audit.models import Status


def test_apt_gpg_check_pass_when_no_override(monkeypatch):
    monkeypatch.setattr(pm.glob, "glob", lambda pattern: ["/etc/apt/apt.conf.d/01-vendor"])
    monkeypatch.setattr(pm, "read_text", lambda p: 'APT::Install-Recommends "false";\n')
    result = pm.check_apt_gpg_check_enabled()
    assert result.status == Status.PASS


def test_apt_gpg_check_fail_when_unauthenticated_allowed(monkeypatch):
    monkeypatch.setattr(pm.glob, "glob", lambda pattern: ["/etc/apt/apt.conf.d/99insecure"])
    monkeypatch.setattr(pm, "read_text", lambda p: 'APT::Get::AllowUnauthenticated "true";\n')
    result = pm.check_apt_gpg_check_enabled()
    assert result.status == Status.FAIL


def test_apt_sources_https_pass(monkeypatch):
    monkeypatch.setattr(pm.glob, "glob", lambda pattern: [])
    monkeypatch.setattr(pm, "read_text", lambda p: "deb https://archive.ubuntu.com/ubuntu jammy main\n")
    result = pm.check_apt_sources_use_https()
    assert result.status == Status.PASS


def test_apt_sources_https_fail_when_plain_http(monkeypatch):
    monkeypatch.setattr(pm.glob, "glob", lambda pattern: [])
    monkeypatch.setattr(pm, "read_text", lambda p: "deb http://archive.ubuntu.com/ubuntu jammy main\n")
    result = pm.check_apt_sources_use_https()
    assert result.status == Status.FAIL


def test_apt_sources_https_na_when_nothing_readable(monkeypatch):
    monkeypatch.setattr(pm.glob, "glob", lambda pattern: [])
    monkeypatch.setattr(pm, "read_text", lambda p: None)
    result = pm.check_apt_sources_use_https()
    assert result.status == Status.NOT_APPLICABLE


def test_dpkg_no_broken_packages_pass(monkeypatch):
    monkeypatch.setattr(pm, "which", lambda b: "/usr/bin/dpkg")
    monkeypatch.setattr(pm, "run_cmd", lambda args, timeout=5.0: (0, "", ""))
    result = pm.check_dpkg_no_broken_packages()
    assert result.status == Status.PASS


def test_dpkg_no_broken_packages_fail(monkeypatch):
    monkeypatch.setattr(pm, "which", lambda b: "/usr/bin/dpkg")
    monkeypatch.setattr(pm, "run_cmd", lambda args, timeout=5.0: (0, "iF broken-pkg 1.0", ""))
    result = pm.check_dpkg_no_broken_packages()
    assert result.status == Status.FAIL


def test_dpkg_no_broken_packages_na_when_not_debian(monkeypatch):
    monkeypatch.setattr(pm, "which", lambda b: None)
    result = pm.check_dpkg_no_broken_packages()
    assert result.status == Status.NOT_APPLICABLE


def test_aide_installed_pass(monkeypatch):
    monkeypatch.setattr(pm, "which", lambda b: "/usr/bin/aide" if b == "aide" else None)
    result = pm.check_aide_installed()
    assert result.status == Status.PASS


def test_aide_installed_fail(monkeypatch):
    monkeypatch.setattr(pm, "which", lambda b: None)
    monkeypatch.setattr("os.path.exists", lambda p: False)
    result = pm.check_aide_installed()
    assert result.status == Status.FAIL


def test_aide_scheduled_pass_via_cron(monkeypatch):
    monkeypatch.setattr("os.path.exists", lambda p: p == "/etc/cron.daily/aide")
    result = pm.check_aide_scheduled()
    assert result.status == Status.PASS


def test_aide_scheduled_pass_via_timer(monkeypatch):
    monkeypatch.setattr("os.path.exists", lambda p: False)
    monkeypatch.setattr(pm, "run_cmd", lambda args, timeout=5.0: (0, "enabled", ""))
    result = pm.check_aide_scheduled()
    assert result.status == Status.PASS


def test_aide_scheduled_fail(monkeypatch):
    monkeypatch.setattr("os.path.exists", lambda p: False)
    monkeypatch.setattr(pm, "run_cmd", lambda args, timeout=5.0: (1, "disabled", ""))
    result = pm.check_aide_scheduled()
    assert result.status == Status.FAIL


def test_bootloader_config_perms_pass(monkeypatch):
    monkeypatch.setattr(pm, "path_mode_octal", lambda p: "600" if p == "/boot/grub/grub.cfg" else None)
    monkeypatch.setattr(pm, "path_owner", lambda p: ("root", "root"))
    result = pm.check_bootloader_config_perms()
    assert result.status == Status.PASS


def test_bootloader_config_perms_fail(monkeypatch):
    monkeypatch.setattr(pm, "path_mode_octal", lambda p: "644" if p == "/boot/grub/grub.cfg" else None)
    monkeypatch.setattr(pm, "path_owner", lambda p: ("root", "root"))
    result = pm.check_bootloader_config_perms()
    assert result.status == Status.FAIL


def test_bootloader_config_perms_na_when_no_grub(monkeypatch):
    monkeypatch.setattr(pm, "path_mode_octal", lambda p: None)
    result = pm.check_bootloader_config_perms()
    assert result.status == Status.NOT_APPLICABLE


def test_bootloader_password_set_pass(monkeypatch):
    monkeypatch.setattr(
        pm, "read_text",
        lambda p: "password_pbkdf2 root grub.pbkdf2.sha512...\n" if p == "/boot/grub/grub.cfg" else None,
    )
    result = pm.check_bootloader_password_set()
    assert result.status == Status.PASS


def test_bootloader_password_set_fail(monkeypatch):
    monkeypatch.setattr(pm, "read_text", lambda p: "set default=0\n" if p == "/boot/grub/grub.cfg" else None)
    result = pm.check_bootloader_password_set()
    assert result.status == Status.FAIL


def test_unattended_upgrades_auto_reboot_pass(monkeypatch):
    monkeypatch.setattr(pm, "read_text", lambda p: 'Unattended-Upgrade::Automatic-Reboot "true";\n')
    result = pm.check_unattended_upgrades_auto_reboot()
    assert result.status == Status.PASS


def test_unattended_upgrades_auto_reboot_fail_when_missing_file(monkeypatch):
    monkeypatch.setattr(pm, "read_text", lambda p: None)
    result = pm.check_unattended_upgrades_auto_reboot()
    assert result.status == Status.FAIL


def test_unattended_upgrades_remove_unused_pass(monkeypatch):
    monkeypatch.setattr(pm, "read_text", lambda p: 'Unattended-Upgrade::Remove-Unused-Dependencies "true";\n')
    result = pm.check_unattended_upgrades_remove_unused()
    assert result.status == Status.PASS


def test_unattended_upgrades_remove_unused_fail(monkeypatch):
    monkeypatch.setattr(pm, "read_text", lambda p: 'Unattended-Upgrade::Automatic-Reboot "true";\n')
    result = pm.check_unattended_upgrades_remove_unused()
    assert result.status == Status.FAIL
