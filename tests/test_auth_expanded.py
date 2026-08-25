"""Unit tests for checks/auth_expanded.py - all filesystem access is mocked.

Some checks here (duplicate UID/GID/name, dangerous dotfiles, legacy '+'
entries) are produced by factory functions and never bound to a module-level
name (only registered in the global registry) - the same pattern already
used, and already verified, for the equivalent checks in the pre-existing
checks/filesystem.py/auth.py modules' sibling factories. Those are exercised
here via the registry rather than by attribute access.
"""

import os

from cis_audit.checks import auth_expanded as ae
from cis_audit.models import Status
from cis_audit.registry import all_checks

CHECKS = {c.id: c for c in all_checks()}


def test_duplicate_uids_detected(monkeypatch):
    monkeypatch.setattr(
        ae, "read_lines",
        lambda p: [
            "root:x:0:0:root:/root:/bin/bash",
            "alice:x:1000:1000:Alice:/home/alice:/bin/bash",
            "mallory:x:1000:1001:Mallory:/home/mallory:/bin/bash",
        ] if p == "/etc/passwd" else None,
    )
    result = CHECKS["CIS-6.2.3"].run()
    assert result.status == Status.FAIL
    assert "1000" in result.evidence


def test_no_duplicate_uids_pass(monkeypatch):
    monkeypatch.setattr(
        ae, "read_lines",
        lambda p: ["root:x:0:0:root:/root:/bin/bash", "alice:x:1000:1000:Alice:/home/alice:/bin/bash"]
        if p == "/etc/passwd" else None,
    )
    result = CHECKS["CIS-6.2.3"].run()
    assert result.status == Status.PASS


def test_duplicate_gids_detected(monkeypatch):
    monkeypatch.setattr(
        ae, "read_lines",
        lambda p: ["sudo:x:27:alice", "admin:x:27:bob"] if p == "/etc/group" else None,
    )
    result = CHECKS["CIS-6.2.4"].run()
    assert result.status == Status.FAIL


def test_duplicate_check_na_when_file_missing(monkeypatch):
    monkeypatch.setattr(ae, "read_lines", lambda p: None)
    result = CHECKS["CIS-6.2.5"].run()
    assert result.status == Status.NOT_APPLICABLE


def test_root_path_integrity_pass(monkeypatch):
    monkeypatch.setenv("PATH", "/usr/local/sbin:/usr/sbin")
    result = ae.check_root_path_integrity()
    assert result.status == Status.PASS


def test_root_path_integrity_fail_relative_entry(monkeypatch):
    monkeypatch.setenv("PATH", "/usr/sbin:.")
    result = ae.check_root_path_integrity()
    assert result.status == Status.FAIL
    assert "relative to cwd" in result.evidence


def test_root_path_integrity_fail_world_writable(monkeypatch, tmp_path):
    writable_dir = tmp_path / "wwdir"
    writable_dir.mkdir()
    os.chmod(writable_dir, 0o777)
    monkeypatch.setenv("PATH", f"/usr/sbin:{writable_dir}")
    result = ae.check_root_path_integrity()
    assert result.status == Status.FAIL
    assert "world-writable" in result.evidence


def test_dangerous_dotfile_detected(monkeypatch, tmp_path):
    home = tmp_path / "alice"
    home.mkdir()
    (home / ".netrc").write_text("machine example.com login x password y\n")
    monkeypatch.setattr(
        ae, "read_lines",
        lambda p: [f"alice:x:1001:1001:Alice:{home}:/bin/bash"] if p == "/etc/passwd" else None,
    )
    result = CHECKS["CIS-6.2.8"].run()
    assert result.status == Status.FAIL
    assert ".netrc" in result.evidence


def test_dangerous_dotfile_pass_when_absent(monkeypatch, tmp_path):
    home = tmp_path / "alice"
    home.mkdir()
    monkeypatch.setattr(
        ae, "read_lines",
        lambda p: [f"alice:x:1001:1001:Alice:{home}:/bin/bash"] if p == "/etc/passwd" else None,
    )
    result = CHECKS["CIS-6.2.11"].run()
    assert result.status == Status.PASS


def test_home_dirs_exist_pass(monkeypatch, tmp_path):
    home = tmp_path / "alice"
    home.mkdir()
    monkeypatch.setattr(
        ae, "read_lines",
        lambda p: [f"alice:x:1001:1001:Alice:{home}:/bin/bash"] if p == "/etc/passwd" else None,
    )
    result = ae.check_home_dirs_exist()
    assert result.status == Status.PASS


def test_home_dirs_exist_fail_when_missing(monkeypatch, tmp_path):
    missing = tmp_path / "nope"
    monkeypatch.setattr(
        ae, "read_lines",
        lambda p: [f"alice:x:1001:1001:Alice:{missing}:/bin/bash"] if p == "/etc/passwd" else None,
    )
    result = ae.check_home_dirs_exist()
    assert result.status == Status.FAIL
    assert "alice" in result.evidence


def test_home_dirs_owned_by_user_pass(monkeypatch, tmp_path):
    home = tmp_path / str(os.getuid())
    home.mkdir()
    import pwd

    my_name = pwd.getpwuid(os.getuid()).pw_name
    monkeypatch.setattr(
        ae, "read_lines",
        lambda p: [f"{my_name}:x:1001:1001:Me:{home}:/bin/bash"] if p == "/etc/passwd" else None,
    )
    result = ae.check_home_dirs_owned_by_user()
    assert result.status == Status.PASS


def test_shadow_group_empty_pass(monkeypatch):
    monkeypatch.setattr(ae, "read_lines", lambda p: ["shadow:x:42:"] if p == "/etc/group" else None)
    result = ae.check_shadow_group_empty()
    assert result.status == Status.PASS


def test_shadow_group_has_members_fail(monkeypatch):
    monkeypatch.setattr(ae, "read_lines", lambda p: ["shadow:x:42:alice,bob"] if p == "/etc/group" else None)
    result = ae.check_shadow_group_empty()
    assert result.status == Status.FAIL
    assert "alice" in result.evidence


def test_shadow_group_missing_is_na(monkeypatch):
    monkeypatch.setattr(ae, "read_lines", lambda p: ["sudo:x:27:"] if p == "/etc/group" else None)
    result = ae.check_shadow_group_empty()
    assert result.status == Status.NOT_APPLICABLE


def test_passwd_gids_exist_pass(monkeypatch):
    def fake_read_lines(p):
        if p == "/etc/passwd":
            return ["root:x:0:0:root:/root:/bin/bash"]
        if p == "/etc/group":
            return ["root:x:0:"]
        return None

    monkeypatch.setattr(ae, "read_lines", fake_read_lines)
    result = ae.check_passwd_gids_exist_in_group()
    assert result.status == Status.PASS


def test_passwd_gids_orphaned_fail(monkeypatch):
    def fake_read_lines(p):
        if p == "/etc/passwd":
            return ["ghost:x:1002:9999:Ghost:/home/ghost:/bin/bash"]
        if p == "/etc/group":
            return ["root:x:0:"]
        return None

    monkeypatch.setattr(ae, "read_lines", fake_read_lines)
    result = ae.check_passwd_gids_exist_in_group()
    assert result.status == Status.FAIL
    assert "ghost" in result.evidence


def test_legacy_plus_entry_detected(monkeypatch):
    monkeypatch.setattr(ae, "read_lines", lambda p: ["root:x:0:0:root:/root:/bin/bash", "+"] if p == "/etc/passwd" else None)
    result = CHECKS["CIS-6.2.16"].run()
    assert result.status == Status.FAIL


def test_legacy_plus_entry_pass(monkeypatch):
    monkeypatch.setattr(ae, "read_lines", lambda p: ["root:x:0:0:root:/root:/bin/bash"] if p == "/etc/group" else None)
    result = CHECKS["CIS-6.2.18"].run()
    assert result.status == Status.PASS


def test_password_hash_algorithm_pass_via_login_defs(monkeypatch):
    monkeypatch.setattr(ae, "read_lines", lambda p: ["ENCRYPT_METHOD SHA512"])
    result = ae.check_password_hash_algorithm()
    assert result.status == Status.PASS


def test_password_hash_algorithm_fail_weak(monkeypatch):
    monkeypatch.setattr(ae, "read_lines", lambda p: ["ENCRYPT_METHOD MD5"])
    result = ae.check_password_hash_algorithm()
    assert result.status == Status.FAIL


def test_password_hash_algorithm_falls_back_to_pam(monkeypatch):
    monkeypatch.setattr(ae, "read_lines", lambda p: None)
    monkeypatch.setattr(ae, "read_text", lambda p: "password [success=1 default=ignore] pam_unix.so obscure sha512")
    result = ae.check_password_hash_algorithm()
    assert result.status == Status.PASS


def test_password_hash_algorithm_na_when_unknown(monkeypatch):
    monkeypatch.setattr(ae, "read_lines", lambda p: None)
    monkeypatch.setattr(ae, "read_text", lambda p: None)
    result = ae.check_password_hash_algorithm()
    assert result.status == Status.NOT_APPLICABLE


def test_default_inactive_lock_pass(monkeypatch):
    monkeypatch.setattr(ae, "read_text", lambda p: "INACTIVE=30\n")
    result = ae.check_default_inactive_lock()
    assert result.status == Status.PASS


def test_default_inactive_lock_fail_when_disabled(monkeypatch):
    monkeypatch.setattr(ae, "read_text", lambda p: "INACTIVE=-1\n")
    result = ae.check_default_inactive_lock()
    assert result.status == Status.FAIL


def test_default_inactive_lock_na_when_missing(monkeypatch):
    monkeypatch.setattr(ae, "read_text", lambda p: None)
    result = ae.check_default_inactive_lock()
    assert result.status == Status.NOT_APPLICABLE
