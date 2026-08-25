"""Unit tests for checks/ssh_expanded.py - reuses checks/ssh.py's
_effective_sshd_config(), so mocking follows the exact same pattern as
tests/test_ssh.py: mock ssh.which/ssh.run_cmd/os.path.exists/ssh.read_lines
(the module the helper actually lives in), not ssh_expanded's own names."""

from cis_audit.checks import ssh
from cis_audit.checks import ssh_expanded as sshx
from cis_audit.models import Status


def _use_config_file(monkeypatch, lines):
    monkeypatch.setattr(ssh, "which", lambda b: None)
    monkeypatch.setattr("os.path.exists", lambda p: False)
    monkeypatch.setattr(ssh, "read_lines", lambda p: lines)


def test_na_when_no_sshd(monkeypatch):
    _use_config_file(monkeypatch, None)
    result = sshx.check_ssh_login_grace_time()
    assert result.status == Status.NOT_APPLICABLE


def test_login_grace_time_pass(monkeypatch):
    _use_config_file(monkeypatch, ["LoginGraceTime 30"])
    result = sshx.check_ssh_login_grace_time()
    assert result.status == Status.PASS


def test_login_grace_time_fail_too_long(monkeypatch):
    _use_config_file(monkeypatch, ["LoginGraceTime 300"])
    result = sshx.check_ssh_login_grace_time()
    assert result.status == Status.FAIL


def test_max_sessions_pass(monkeypatch):
    _use_config_file(monkeypatch, ["MaxSessions 5"])
    result = sshx.check_ssh_max_sessions()
    assert result.status == Status.PASS


def test_max_sessions_fail(monkeypatch):
    _use_config_file(monkeypatch, ["MaxSessions 50"])
    result = sshx.check_ssh_max_sessions()
    assert result.status == Status.FAIL


def test_client_alive_interval_pass(monkeypatch):
    _use_config_file(monkeypatch, ["ClientAliveInterval 300"])
    result = sshx.check_ssh_client_alive_interval()
    assert result.status == Status.PASS


def test_client_alive_interval_fail_when_disabled(monkeypatch):
    _use_config_file(monkeypatch, ["ClientAliveInterval 0"])
    result = sshx.check_ssh_client_alive_interval()
    assert result.status == Status.FAIL


def test_client_alive_count_max_pass(monkeypatch):
    _use_config_file(monkeypatch, ["ClientAliveCountMax 3"])
    result = sshx.check_ssh_client_alive_count_max()
    assert result.status == Status.PASS


def test_client_alive_count_max_fail(monkeypatch):
    _use_config_file(monkeypatch, ["ClientAliveCountMax 10"])
    result = sshx.check_ssh_client_alive_count_max()
    assert result.status == Status.FAIL


def test_allow_tcp_forwarding_pass(monkeypatch):
    _use_config_file(monkeypatch, ["AllowTcpForwarding no"])
    result = sshx.check_ssh_allow_tcp_forwarding()
    assert result.status == Status.PASS


def test_allow_tcp_forwarding_fail_default_is_yes(monkeypatch):
    _use_config_file(monkeypatch, ["PermitRootLogin no"])
    result = sshx.check_ssh_allow_tcp_forwarding()
    assert result.status == Status.FAIL


def test_permit_user_environment_pass_by_default(monkeypatch):
    _use_config_file(monkeypatch, ["PermitRootLogin no"])
    result = sshx.check_ssh_permit_user_environment()
    assert result.status == Status.PASS


def test_ignore_rhosts_pass_by_default(monkeypatch):
    _use_config_file(monkeypatch, ["PermitRootLogin no"])
    result = sshx.check_ssh_ignore_rhosts()
    assert result.status == Status.PASS


def test_hostbased_auth_fail_when_enabled(monkeypatch):
    _use_config_file(monkeypatch, ["HostbasedAuthentication yes"])
    result = sshx.check_ssh_hostbased_auth()
    assert result.status == Status.FAIL


def test_log_level_pass_at_info(monkeypatch):
    _use_config_file(monkeypatch, ["LogLevel VERBOSE"])
    result = sshx.check_ssh_log_level()
    assert result.status == Status.PASS


def test_log_level_fail_at_quiet(monkeypatch):
    _use_config_file(monkeypatch, ["LogLevel QUIET"])
    result = sshx.check_ssh_log_level()
    assert result.status == Status.FAIL


def test_ciphers_pass_when_unset(monkeypatch):
    _use_config_file(monkeypatch, ["PermitRootLogin no"])
    result = sshx.check_ssh_ciphers()
    assert result.status == Status.PASS


def test_ciphers_pass_when_strong(monkeypatch):
    _use_config_file(monkeypatch, ["Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com"])
    result = sshx.check_ssh_ciphers()
    assert result.status == Status.PASS


def test_ciphers_fail_when_weak_cipher_present(monkeypatch):
    _use_config_file(monkeypatch, ["Ciphers chacha20-poly1305@openssh.com,3des-cbc"])
    result = sshx.check_ssh_ciphers()
    assert result.status == Status.FAIL
    assert "3des-cbc" in result.evidence


def test_macs_fail_when_weak(monkeypatch):
    _use_config_file(monkeypatch, ["MACs hmac-sha2-256-etm@openssh.com,hmac-md5"])
    result = sshx.check_ssh_macs()
    assert result.status == Status.FAIL
    assert "hmac-md5" in result.evidence


def test_macs_pass_when_strong(monkeypatch):
    _use_config_file(monkeypatch, ["MACs hmac-sha2-512-etm@openssh.com"])
    result = sshx.check_ssh_macs()
    assert result.status == Status.PASS


def test_kex_algorithms_fail_when_weak(monkeypatch):
    _use_config_file(monkeypatch, ["KexAlgorithms diffie-hellman-group1-sha1"])
    result = sshx.check_ssh_kex_algorithms()
    assert result.status == Status.FAIL


def test_kex_algorithms_pass_when_strong(monkeypatch):
    _use_config_file(monkeypatch, ["KexAlgorithms curve25519-sha256"])
    result = sshx.check_ssh_kex_algorithms()
    assert result.status == Status.PASS


def test_compression_pass_no(monkeypatch):
    _use_config_file(monkeypatch, ["Compression no"])
    result = sshx.check_ssh_compression()
    assert result.status == Status.PASS


def test_compression_pass_delayed(monkeypatch):
    _use_config_file(monkeypatch, ["Compression delayed"])
    result = sshx.check_ssh_compression()
    assert result.status == Status.PASS


def test_compression_fail_yes(monkeypatch):
    _use_config_file(monkeypatch, ["Compression yes"])
    result = sshx.check_ssh_compression()
    assert result.status == Status.FAIL


def test_use_pam_pass_by_default(monkeypatch):
    _use_config_file(monkeypatch, ["PermitRootLogin no"])
    result = sshx.check_ssh_use_pam()
    assert result.status == Status.PASS


def test_use_pam_fail_when_disabled(monkeypatch):
    _use_config_file(monkeypatch, ["UsePAM no"])
    result = sshx.check_ssh_use_pam()
    assert result.status == Status.FAIL


def test_uses_sshd_dash_t_when_available(monkeypatch):
    monkeypatch.setattr(ssh, "which", lambda b: "/usr/sbin/sshd" if b == "sshd" else None)
    monkeypatch.setattr(ssh, "run_cmd", lambda args, timeout=5.0: (0, "usepam yes\nloginGraceTime 60", ""))
    result = sshx.check_ssh_use_pam()
    assert result.status == Status.PASS
    assert "sshd -T" in result.evidence
