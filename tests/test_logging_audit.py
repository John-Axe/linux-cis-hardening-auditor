from cis_audit.checks import logging_audit as la
from cis_audit.models import Status


def test_auditd_not_installed(monkeypatch):
    monkeypatch.setattr(la, "which", lambda b: None)
    monkeypatch.setattr("os.path.exists", lambda p: False)
    result = la.check_auditd_enabled()
    assert result.status == Status.FAIL
    assert "not installed" in result.evidence


def test_auditd_installed_and_active(monkeypatch):
    monkeypatch.setattr(la, "which", lambda b: "/sbin/auditctl" if b == "auditctl" else None)

    def fake_run_cmd(args, timeout=5.0):
        if "is-enabled" in args:
            return 0, "enabled", ""
        return 0, "active", ""

    monkeypatch.setattr(la, "run_cmd", fake_run_cmd)
    result = la.check_auditd_enabled()
    assert result.status == Status.PASS


def test_logging_service_active_via_rsyslog(monkeypatch):
    monkeypatch.setattr(
        la, "run_cmd", lambda args, timeout=5.0: (0, "active", "") if "rsyslog" in args else (3, "inactive", "")
    )
    result = la.check_logging_service_active()
    assert result.status == Status.PASS


def test_logging_service_fail_when_none_active(monkeypatch):
    monkeypatch.setattr(la, "run_cmd", lambda args, timeout=5.0: (3, "inactive", ""))
    result = la.check_logging_service_active()
    assert result.status == Status.FAIL


def test_auth_log_perms_pass(monkeypatch):
    monkeypatch.setattr(la, "path_mode_octal", lambda p: "640" if p == "/var/log/auth.log" else None)
    monkeypatch.setattr(la, "path_owner", lambda p: ("syslog", "adm"))
    result = la.check_auth_log_perms()
    assert result.status == Status.PASS


def test_auth_log_perms_fail_world_readable(monkeypatch):
    monkeypatch.setattr(la, "path_mode_octal", lambda p: "644" if p == "/var/log/auth.log" else None)
    monkeypatch.setattr(la, "path_owner", lambda p: ("syslog", "adm"))
    result = la.check_auth_log_perms()
    assert result.status == Status.FAIL


def test_auth_log_na_when_neither_file_exists(monkeypatch):
    monkeypatch.setattr(la, "path_mode_octal", lambda p: None)
    result = la.check_auth_log_perms()
    assert result.status == Status.NOT_APPLICABLE


def test_cron_restricted_pass(monkeypatch):
    monkeypatch.setattr("os.path.exists", lambda p: p == "/etc/cron.allow")
    result = la.check_cron_restricted()
    assert result.status == Status.PASS


def test_cron_restricted_fail_when_both_missing(monkeypatch):
    monkeypatch.setattr("os.path.exists", lambda p: False)
    result = la.check_cron_restricted()
    assert result.status == Status.FAIL
