"""Unit tests for checks/ntp_and_time.py - subprocess/filesystem access is
mocked so these are deterministic regardless of what's actually installed on
the machine running pytest."""

from cis_audit.checks import ntp_and_time as ntp
from cis_audit.models import Status


def test_time_sync_daemon_installed_pass_with_chrony(monkeypatch):
    monkeypatch.setattr(ntp, "which", lambda b: "/usr/sbin/chronyd" if b == "chronyd" else None)
    result = ntp.check_time_sync_daemon_installed()
    assert result.status == Status.PASS


def test_time_sync_daemon_installed_fail_when_neither(monkeypatch):
    monkeypatch.setattr(ntp, "which", lambda b: None)
    result = ntp.check_time_sync_daemon_installed()
    assert result.status == Status.FAIL


def test_time_sync_service_active_na_when_not_installed(monkeypatch):
    monkeypatch.setattr(ntp, "which", lambda b: None)
    result = ntp.check_time_sync_service_active()
    assert result.status == Status.NOT_APPLICABLE


def test_time_sync_service_active_pass(monkeypatch):
    monkeypatch.setattr(ntp, "which", lambda b: "/usr/sbin/chronyd" if b == "chronyd" else None)
    monkeypatch.setattr(
        ntp, "run_cmd",
        lambda args, timeout=5.0: (0, "active", "") if "chrony" in args else (3, "inactive", ""),
    )
    result = ntp.check_time_sync_service_active()
    assert result.status == Status.PASS


def test_time_sync_service_active_fail_when_installed_but_stopped(monkeypatch):
    monkeypatch.setattr(ntp, "which", lambda b: "/usr/sbin/chronyd" if b == "chronyd" else None)
    monkeypatch.setattr(ntp, "run_cmd", lambda args, timeout=5.0: (3, "inactive", ""))
    result = ntp.check_time_sync_service_active()
    assert result.status == Status.FAIL


def test_chrony_has_time_source_na_when_not_installed(monkeypatch):
    monkeypatch.setattr(ntp, "which", lambda b: None)
    result = ntp.check_chrony_has_time_source()
    assert result.status == Status.NOT_APPLICABLE


def test_chrony_has_time_source_pass(monkeypatch):
    monkeypatch.setattr(ntp, "which", lambda b: "/usr/sbin/chronyd" if b == "chronyd" else None)
    monkeypatch.setattr(ntp, "read_text", lambda p: "pool ntp.ubuntu.com iburst\n")
    result = ntp.check_chrony_has_time_source()
    assert result.status == Status.PASS


def test_chrony_has_time_source_fail_when_empty(monkeypatch):
    monkeypatch.setattr(ntp, "which", lambda b: "/usr/sbin/chronyd" if b == "chronyd" else None)
    monkeypatch.setattr(ntp, "read_text", lambda p: "driftfile /var/lib/chrony/drift\n")
    result = ntp.check_chrony_has_time_source()
    assert result.status == Status.FAIL


def test_timesyncd_ntp_server_pass_when_unset(monkeypatch):
    monkeypatch.setattr(ntp, "read_text", lambda p: "[Time]\n#NTP=\n")
    result = ntp.check_timesyncd_has_ntp_server()
    assert result.status == Status.PASS


def test_timesyncd_ntp_server_fail_when_explicitly_empty(monkeypatch):
    monkeypatch.setattr(ntp, "read_text", lambda p: "[Time]\nNTP=\n")
    result = ntp.check_timesyncd_has_ntp_server()
    assert result.status == Status.FAIL


def test_timesyncd_ntp_server_na_when_no_config(monkeypatch):
    monkeypatch.setattr(ntp, "read_text", lambda p: None)
    result = ntp.check_timesyncd_has_ntp_server()
    assert result.status == Status.NOT_APPLICABLE


def test_clock_synchronized_na_when_no_timedatectl(monkeypatch):
    monkeypatch.setattr(ntp, "which", lambda b: None)
    result = ntp.check_clock_is_synchronized()
    assert result.status == Status.NOT_APPLICABLE


def test_clock_synchronized_pass(monkeypatch):
    monkeypatch.setattr(ntp, "which", lambda b: "/usr/bin/timedatectl")
    monkeypatch.setattr(ntp, "run_cmd", lambda args, timeout=5.0: (0, "yes", ""))
    result = ntp.check_clock_is_synchronized()
    assert result.status == Status.PASS


def test_clock_synchronized_fail(monkeypatch):
    monkeypatch.setattr(ntp, "which", lambda b: "/usr/bin/timedatectl")
    monkeypatch.setattr(ntp, "run_cmd", lambda args, timeout=5.0: (0, "no", ""))
    result = ntp.check_clock_is_synchronized()
    assert result.status == Status.FAIL


def test_only_one_daemon_active_pass(monkeypatch):
    def fake_run_cmd(args, timeout=5.0):
        if "chrony" in args or "chronyd" in args:
            return 0, "active", ""
        return 3, "inactive", ""

    monkeypatch.setattr(ntp, "run_cmd", fake_run_cmd)
    result = ntp.check_only_one_time_sync_daemon_active()
    assert result.status == Status.PASS


def test_only_one_daemon_active_fail_when_both(monkeypatch):
    monkeypatch.setattr(ntp, "run_cmd", lambda args, timeout=5.0: (0, "active", ""))
    result = ntp.check_only_one_time_sync_daemon_active()
    assert result.status == Status.FAIL


def test_only_one_daemon_active_na_when_neither(monkeypatch):
    monkeypatch.setattr(ntp, "run_cmd", lambda args, timeout=5.0: (3, "inactive", ""))
    result = ntp.check_only_one_time_sync_daemon_active()
    assert result.status == Status.NOT_APPLICABLE
