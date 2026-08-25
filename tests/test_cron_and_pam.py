"""Unit tests for checks/cron_and_pam.py - all filesystem/subprocess access
is mocked so these are deterministic regardless of the machine running
pytest. Per-directive checks (cron.hourly/daily/weekly/monthly/cron.d, and
the pwquality/faillock value checks) are produced by factory functions and
only registered in the global registry (same pattern as the pre-existing
checks/filesystem.py mount-option factories) - exercised here via the
registry rather than by module attribute access.
"""

from cis_audit.checks import cron_and_pam as cp
from cis_audit.models import Status
from cis_audit.registry import all_checks

CHECKS = {c.id: c for c in all_checks()}


def test_cron_daemon_active_pass(monkeypatch):
    monkeypatch.setattr(
        cp, "run_cmd",
        lambda args, timeout=5.0: (0, "active", "") if "is-active" in args else (0, "enabled", ""),
    )
    result = cp.check_cron_daemon_active()
    assert result.status == Status.PASS


def test_cron_daemon_active_fail_when_stopped(monkeypatch):
    monkeypatch.setattr(
        cp, "run_cmd",
        lambda args, timeout=5.0: (3, "inactive", "") if "is-active" in args else (1, "disabled", ""),
    )
    result = cp.check_cron_daemon_active()
    assert result.status == Status.FAIL


def test_crontab_perms_pass(monkeypatch):
    monkeypatch.setattr(cp, "path_mode_octal", lambda p: "600")
    monkeypatch.setattr(cp, "path_owner", lambda p: ("root", "root"))
    result = CHECKS["CIS-5.1.2"].run()
    assert result.status == Status.PASS


def test_crontab_perms_fail_too_permissive(monkeypatch):
    monkeypatch.setattr(cp, "path_mode_octal", lambda p: "644")
    monkeypatch.setattr(cp, "path_owner", lambda p: ("root", "root"))
    result = CHECKS["CIS-5.1.2"].run()
    assert result.status == Status.FAIL


def test_cron_dir_perms_na_when_missing(monkeypatch):
    monkeypatch.setattr(cp, "path_mode_octal", lambda p: None)
    result = CHECKS["CIS-5.1.4"].run()
    assert result.status == Status.NOT_APPLICABLE


def test_at_restricted_pass(monkeypatch):
    monkeypatch.setattr("os.path.exists", lambda p: p == "/etc/at.allow")
    result = cp.check_at_restricted()
    assert result.status == Status.PASS


def test_at_restricted_fail_when_deny_present(monkeypatch):
    monkeypatch.setattr("os.path.exists", lambda p: True)
    result = cp.check_at_restricted()
    assert result.status == Status.FAIL


def test_su_restricted_pass(monkeypatch):
    monkeypatch.setattr(cp, "read_text", lambda p: "auth required pam_wheel.so use_uid group=sudo\n")
    result = cp.check_su_restricted()
    assert result.status == Status.PASS


def test_su_restricted_fail(monkeypatch):
    monkeypatch.setattr(cp, "read_text", lambda p: "auth sufficient pam_rootok.so\n")
    result = cp.check_su_restricted()
    assert result.status == Status.FAIL


def test_su_restricted_na_when_missing(monkeypatch):
    monkeypatch.setattr(cp, "read_text", lambda p: None)
    result = cp.check_su_restricted()
    assert result.status == Status.NOT_APPLICABLE


def test_pwquality_minlen_pass(monkeypatch):
    monkeypatch.setattr(cp, "read_lines", lambda p: ["minlen = 14"])
    result = CHECKS["CIS-5.5.1.1"].run()
    assert result.status == Status.PASS


def test_pwquality_minlen_fail_too_short(monkeypatch):
    monkeypatch.setattr(cp, "read_lines", lambda p: ["minlen = 8"])
    result = CHECKS["CIS-5.5.1.1"].run()
    assert result.status == Status.FAIL


def test_pwquality_dcredit_fail_when_unset(monkeypatch):
    monkeypatch.setattr(cp, "read_lines", lambda p: ["minlen = 14"])
    result = CHECKS["CIS-5.5.1.2"].run()
    assert result.status == Status.FAIL
    assert "not set" in result.evidence


def test_pwquality_maxrepeat_boundary(monkeypatch):
    monkeypatch.setattr(cp, "read_lines", lambda p: ["maxrepeat = 3"])
    assert CHECKS["CIS-5.5.1.6"].run().status == Status.PASS
    monkeypatch.setattr(cp, "read_lines", lambda p: ["maxrepeat = 0"])
    assert CHECKS["CIS-5.5.1.6"].run().status == Status.FAIL


def test_pwquality_non_integer_is_na(monkeypatch):
    monkeypatch.setattr(cp, "read_lines", lambda p: ["minlen = abc"])
    result = CHECKS["CIS-5.5.1.1"].run()
    assert result.status == Status.NOT_APPLICABLE


def test_faillock_deny_pass(monkeypatch):
    monkeypatch.setattr(cp, "read_lines", lambda p: ["deny = 5"])
    result = CHECKS["CIS-5.5.2.1"].run()
    assert result.status == Status.PASS


def test_faillock_deny_fail_too_high(monkeypatch):
    monkeypatch.setattr(cp, "read_lines", lambda p: ["deny = 20"])
    result = CHECKS["CIS-5.5.2.1"].run()
    assert result.status == Status.FAIL


def test_faillock_unlock_time_fail_when_unset(monkeypatch):
    monkeypatch.setattr(cp, "read_lines", lambda p: ["deny = 5"])
    result = CHECKS["CIS-5.5.2.2"].run()
    assert result.status == Status.FAIL


def test_faillock_even_deny_root_pass_when_present(monkeypatch):
    monkeypatch.setattr(cp, "read_lines", lambda p: ["deny = 5", "even_deny_root"])
    result = CHECKS["CIS-5.5.2.3"].run()
    assert result.status == Status.PASS


def test_pwhistory_remember_pass(monkeypatch):
    monkeypatch.setattr(
        cp, "read_text",
        lambda p: "password required pam_pwhistory.so remember=24 use_authtok\n",
    )
    result = cp.check_pwhistory_remember()
    assert result.status == Status.PASS


def test_pwhistory_remember_fail_too_low(monkeypatch):
    monkeypatch.setattr(
        cp, "read_text",
        lambda p: "password required pam_pwhistory.so remember=3 use_authtok\n",
    )
    result = cp.check_pwhistory_remember()
    assert result.status == Status.FAIL


def test_pwhistory_remember_na_when_missing(monkeypatch):
    monkeypatch.setattr(cp, "read_text", lambda p: None)
    result = cp.check_pwhistory_remember()
    assert result.status == Status.NOT_APPLICABLE
