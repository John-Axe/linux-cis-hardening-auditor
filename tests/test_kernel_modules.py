"""Unit tests for checks/kernel_modules.py - /proc/modules and
/etc/modprobe.d/*.conf access are both mocked so these are deterministic
regardless of the machine running pytest. The per-module checks are produced
by a factory function and only registered in the global registry (never
bound to a module-level name), so they're exercised here via the registry,
and the underlying _is_loaded/_is_denylisted helpers are also tested
directly since they carry the actual logic.
"""

from cis_audit.checks import kernel_modules as km
from cis_audit.models import Status
from cis_audit.registry import all_checks

CHECKS = {c.id: c for c in all_checks()}


def test_is_loaded_true_when_present(monkeypatch):
    monkeypatch.setattr(km, "read_lines", lambda p: ["cramfs 16384 0 - Live 0x0000000000000000"])
    assert km._is_loaded("cramfs") is True


def test_is_loaded_false_when_absent(monkeypatch):
    monkeypatch.setattr(km, "read_lines", lambda p: ["ext4 000000 0 - Live 0x0"])
    assert km._is_loaded("cramfs") is False


def test_is_loaded_false_when_proc_modules_unreadable(monkeypatch):
    monkeypatch.setattr(km, "read_lines", lambda p: None)
    assert km._is_loaded("cramfs") is False


def test_is_loaded_normalizes_hyphens(monkeypatch):
    monkeypatch.setattr(km, "read_lines", lambda p: ["usb_storage 000 0 - Live 0x0"])
    assert km._is_loaded("usb-storage") is True


def test_is_denylisted_true_via_install_true(monkeypatch):
    monkeypatch.setattr(km.glob, "glob", lambda pattern: ["/etc/modprobe.d/cis.conf"])
    monkeypatch.setattr(km, "read_text", lambda p: "install cramfs /bin/true\n")
    denylisted, evidence = km._is_denylisted("cramfs")
    assert denylisted is True
    assert "cis.conf" in evidence


def test_is_denylisted_true_via_blacklist(monkeypatch):
    monkeypatch.setattr(km.glob, "glob", lambda pattern: ["/etc/modprobe.d/cis.conf"])
    monkeypatch.setattr(km, "read_text", lambda p: "blacklist cramfs\n")
    denylisted, evidence = km._is_denylisted("cramfs")
    assert denylisted is True


def test_is_denylisted_false_when_no_directive(monkeypatch):
    monkeypatch.setattr(km.glob, "glob", lambda pattern: ["/etc/modprobe.d/cis.conf"])
    monkeypatch.setattr(km, "read_text", lambda p: "# nothing relevant here\n")
    denylisted, evidence = km._is_denylisted("cramfs")
    assert denylisted is False


def test_is_denylisted_false_when_no_conf_files(monkeypatch):
    monkeypatch.setattr(km.glob, "glob", lambda pattern: [])
    denylisted, evidence = km._is_denylisted("cramfs")
    assert denylisted is False
    assert "no /etc/modprobe.d" in evidence


def test_module_check_pass_when_unloaded_and_denylisted(monkeypatch):
    monkeypatch.setattr(km, "read_lines", lambda p: ["ext4 000 0 - Live 0x0"])
    monkeypatch.setattr(km.glob, "glob", lambda pattern: ["/etc/modprobe.d/cis.conf"])
    monkeypatch.setattr(km, "read_text", lambda p: "blacklist cramfs\ninstall cramfs /bin/true\n")
    result = CHECKS["CIS-1.1.1.1"].run()
    assert result.status == Status.PASS


def test_module_check_fail_when_loaded(monkeypatch):
    monkeypatch.setattr(km, "read_lines", lambda p: ["cramfs 16384 0 - Live 0x0"])
    monkeypatch.setattr(km.glob, "glob", lambda pattern: ["/etc/modprobe.d/cis.conf"])
    monkeypatch.setattr(km, "read_text", lambda p: "blacklist cramfs\n")
    result = CHECKS["CIS-1.1.1.1"].run()
    assert result.status == Status.FAIL
    assert "currently loaded" in result.evidence


def test_module_check_fail_when_not_blocked(monkeypatch):
    monkeypatch.setattr(km, "read_lines", lambda p: ["ext4 000 0 - Live 0x0"])
    monkeypatch.setattr(km.glob, "glob", lambda pattern: [])
    result = CHECKS["CIS-1.1.1.8"].run()  # usb-storage
    assert result.status == Status.FAIL
    assert "not blocked" in result.evidence


def test_all_fourteen_module_checks_registered():
    module_ids = [f"CIS-1.1.1.{n}" for n in range(1, 15)]
    for mid in module_ids:
        assert mid in CHECKS, f"missing {mid}"
        assert CHECKS[mid].category == "kernel_modules"
