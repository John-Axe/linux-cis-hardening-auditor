from cis_audit.checks import auth
from cis_audit.models import Status


def test_pass_max_days_pass(monkeypatch):
    monkeypatch.setattr(auth, "read_lines", lambda p: ["PASS_MAX_DAYS   90"])
    result = auth.check_pass_max_days()
    assert result.status == Status.PASS


def test_pass_max_days_fail_too_high(monkeypatch):
    monkeypatch.setattr(auth, "read_lines", lambda p: ["PASS_MAX_DAYS   99999"])
    result = auth.check_pass_max_days()
    assert result.status == Status.FAIL


def test_pass_min_days_na_when_missing(monkeypatch):
    monkeypatch.setattr(auth, "read_lines", lambda p: None)
    result = auth.check_pass_min_days()
    assert result.status == Status.NOT_APPLICABLE


def test_empty_shadow_password_detected(monkeypatch):
    monkeypatch.setattr(
        auth,
        "read_lines",
        lambda p: ["root:$6$abc:19000:0:99999:7:::", "guest::19000:0:99999:7:::"],
    )
    result = auth.check_no_empty_shadow_passwords()
    assert result.status == Status.FAIL
    assert "guest" in result.evidence
    # must never leak the real hash into evidence
    assert "$6$abc" not in result.evidence


def test_no_empty_shadow_passwords_pass(monkeypatch):
    monkeypatch.setattr(auth, "read_lines", lambda p: ["root:$6$abc:19000:0:99999:7:::"])
    result = auth.check_no_empty_shadow_passwords()
    assert result.status == Status.PASS


def test_shadow_unreadable_is_na_not_fail(monkeypatch):
    monkeypatch.setattr(auth, "read_lines", lambda p: None)
    result = auth.check_no_empty_shadow_passwords()
    assert result.status == Status.NOT_APPLICABLE


def test_duplicate_uid_zero_detected(monkeypatch):
    monkeypatch.setattr(
        auth,
        "read_lines",
        lambda p: ["root:x:0:0:root:/root:/bin/bash", "backdoor:x:0:1000:evil:/home/x:/bin/bash"],
    )
    result = auth.check_no_duplicate_uid_zero()
    assert result.status == Status.FAIL
    assert "backdoor" in result.evidence


def test_no_duplicate_uid_zero_pass(monkeypatch):
    monkeypatch.setattr(auth, "read_lines", lambda p: ["root:x:0:0:root:/root:/bin/bash"])
    result = auth.check_no_duplicate_uid_zero()
    assert result.status == Status.PASS


def test_root_default_group_pass(monkeypatch):
    monkeypatch.setattr(auth, "read_lines", lambda p: ["root:x:0:0:root:/root:/bin/bash"])
    result = auth.check_root_default_group()
    assert result.status == Status.PASS


def test_root_default_group_fail(monkeypatch):
    monkeypatch.setattr(auth, "read_lines", lambda p: ["root:x:0:100:root:/root:/bin/bash"])
    result = auth.check_root_default_group()
    assert result.status == Status.FAIL
