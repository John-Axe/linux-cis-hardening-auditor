from cis_audit.checks import ssh
from cis_audit.models import Status


def test_na_when_no_sshd_and_no_config(monkeypatch):
    monkeypatch.setattr(ssh, "which", lambda b: None)
    monkeypatch.setattr("os.path.exists", lambda p: False)
    monkeypatch.setattr(ssh, "read_lines", lambda p: None)
    result = ssh.check_ssh_root_login()
    assert result.status == Status.NOT_APPLICABLE


def test_root_login_fail_via_config_file(monkeypatch):
    monkeypatch.setattr(ssh, "which", lambda b: None)
    monkeypatch.setattr("os.path.exists", lambda p: False)
    monkeypatch.setattr(ssh, "read_lines", lambda p: ["PermitRootLogin yes"])
    result = ssh.check_ssh_root_login()
    assert result.status == Status.FAIL
    assert "yes" in result.evidence


def test_root_login_pass_via_config_file(monkeypatch):
    monkeypatch.setattr(ssh, "which", lambda b: None)
    monkeypatch.setattr("os.path.exists", lambda p: False)
    monkeypatch.setattr(ssh, "read_lines", lambda p: ["PermitRootLogin no"])
    result = ssh.check_ssh_root_login()
    assert result.status == Status.PASS


def test_root_login_uses_sshd_dash_t_when_available(monkeypatch):
    monkeypatch.setattr(ssh, "which", lambda b: "/usr/sbin/sshd" if b == "sshd" else None)
    monkeypatch.setattr(ssh, "run_cmd", lambda args, timeout=5.0: (0, "permitrootlogin no\nmaxauthtries 3", ""))
    result = ssh.check_ssh_root_login()
    assert result.status == Status.PASS
    assert "sshd -T" in result.evidence


def test_max_auth_tries_fail_when_too_high(monkeypatch):
    monkeypatch.setattr(ssh, "which", lambda b: "/usr/sbin/sshd" if b == "sshd" else None)
    monkeypatch.setattr(ssh, "run_cmd", lambda args, timeout=5.0: (0, "maxauthtries 6", ""))
    result = ssh.check_ssh_max_auth_tries()
    assert result.status == Status.FAIL


def test_max_auth_tries_pass_default_from_config(monkeypatch):
    # No maxauthtries directive present in the config file: falls back to the
    # OpenSSH documented default of 6, so this should FAIL not crash.
    monkeypatch.setattr(ssh, "which", lambda b: None)
    monkeypatch.setattr("os.path.exists", lambda p: False)
    monkeypatch.setattr(ssh, "read_lines", lambda p: ["PermitRootLogin no"])
    result = ssh.check_ssh_max_auth_tries()
    assert result.status == Status.FAIL


def test_banner_fail_when_none(monkeypatch):
    monkeypatch.setattr(ssh, "which", lambda b: None)
    monkeypatch.setattr("os.path.exists", lambda p: False)
    monkeypatch.setattr(ssh, "read_lines", lambda p: ["Banner none"])
    result = ssh.check_ssh_banner()
    assert result.status == Status.FAIL


def test_banner_pass_when_set(monkeypatch):
    monkeypatch.setattr(ssh, "which", lambda b: None)
    monkeypatch.setattr("os.path.exists", lambda p: False)
    monkeypatch.setattr(ssh, "read_lines", lambda p: ["Banner /etc/issue.net"])
    result = ssh.check_ssh_banner()
    assert result.status == Status.PASS


def test_config_file_first_occurrence_wins(monkeypatch):
    monkeypatch.setattr(ssh, "which", lambda b: None)
    monkeypatch.setattr("os.path.exists", lambda p: False)
    monkeypatch.setattr(
        ssh, "read_lines", lambda p: ["PermitRootLogin no", "PermitRootLogin yes"]
    )
    result = ssh.check_ssh_root_login()
    assert result.status == Status.PASS  # first line (no) wins, matching real sshd behavior
