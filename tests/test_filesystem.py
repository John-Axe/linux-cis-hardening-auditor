"""Unit tests for checks/filesystem.py - all subprocess/filesystem access is
mocked so these are deterministic regardless of the machine running pytest."""

from cis_audit.checks import filesystem as fs
from cis_audit.models import Status


def test_etc_passwd_perms_pass(monkeypatch):
    monkeypatch.setattr(fs, "path_mode_octal", lambda p: "644")
    monkeypatch.setattr(fs, "path_owner", lambda p: ("root", "root"))
    result = fs.check_etc_passwd_perms()
    assert result.status == Status.PASS


def test_etc_passwd_perms_fail_too_permissive(monkeypatch):
    monkeypatch.setattr(fs, "path_mode_octal", lambda p: "666")
    monkeypatch.setattr(fs, "path_owner", lambda p: ("root", "root"))
    result = fs.check_etc_passwd_perms()
    assert result.status == Status.FAIL
    assert "666" in result.evidence


def test_etc_passwd_perms_na_when_missing(monkeypatch):
    monkeypatch.setattr(fs, "path_mode_octal", lambda p: None)
    monkeypatch.setattr(fs, "path_owner", lambda p: None)
    result = fs.check_etc_passwd_perms()
    assert result.status == Status.NOT_APPLICABLE


def test_etc_shadow_perms_fail_wrong_group(monkeypatch):
    monkeypatch.setattr(fs, "path_mode_octal", lambda p: "640")
    monkeypatch.setattr(fs, "path_owner", lambda p: ("root", "root"))
    result = fs.check_etc_shadow_perms()
    assert result.status == Status.FAIL
    assert "shadow" in result.evidence


def test_world_writable_files_pass_when_none_found(monkeypatch):
    monkeypatch.setattr(fs, "_scan_dirs_for", lambda predicate: ([], 100, False))
    result = fs.check_world_writable_files()
    assert result.status == Status.PASS


def test_world_writable_files_fail_when_found(monkeypatch):
    monkeypatch.setattr(fs, "_scan_dirs_for", lambda predicate: (["/tmp/bad"], 100, False))
    result = fs.check_world_writable_files()
    assert result.status == Status.FAIL
    assert "/tmp/bad" in result.evidence


def test_unowned_files_pass(monkeypatch):
    monkeypatch.setattr(fs, "_known_uids", lambda: {0, 1000})
    monkeypatch.setattr(fs, "_known_gids", lambda: {0, 1000})
    monkeypatch.setattr(fs, "_scan_dirs_for", lambda predicate: ([], 50, False))
    result = fs.check_unowned_files()
    assert result.status == Status.PASS


def test_home_dir_perms_fail_for_group_writable(monkeypatch, tmp_path):
    home = tmp_path / "alice"
    home.mkdir()
    monkeypatch.setattr(
        fs,
        "read_lines",
        lambda p: [f"alice:x:1001:1001:Alice:{home}:/bin/bash"],
    )
    monkeypatch.setattr(fs, "path_mode_octal", lambda p: "770")
    result = fs.check_home_dir_perms()
    assert result.status == Status.FAIL
    assert "alice" in result.evidence


def test_home_dir_perms_pass(monkeypatch, tmp_path):
    home = tmp_path / "alice"
    home.mkdir()
    monkeypatch.setattr(
        fs,
        "read_lines",
        lambda p: [f"alice:x:1001:1001:Alice:{home}:/bin/bash"],
    )
    monkeypatch.setattr(fs, "path_mode_octal", lambda p: "750")
    result = fs.check_home_dir_perms()
    assert result.status == Status.PASS


def test_home_dir_perms_na_when_no_interactive_users(monkeypatch):
    monkeypatch.setattr(
        fs,
        "read_lines",
        lambda p: ["daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin"],
    )
    result = fs.check_home_dir_perms()
    assert result.status == Status.NOT_APPLICABLE


def test_default_umask_pass(monkeypatch):
    monkeypatch.setattr(fs, "read_lines", lambda p: ["UMASK\t027"])
    result = fs.check_default_umask()
    assert result.status == Status.PASS


def test_default_umask_fail_too_permissive(monkeypatch):
    monkeypatch.setattr(fs, "read_lines", lambda p: ["UMASK\t022"])
    result = fs.check_default_umask()
    assert result.status == Status.FAIL


def test_default_umask_fail_when_unset(monkeypatch):
    monkeypatch.setattr(fs, "read_lines", lambda p: ["# no umask here"])
    result = fs.check_default_umask()
    assert result.status == Status.FAIL


def test_default_umask_na_when_file_missing(monkeypatch):
    monkeypatch.setattr(fs, "read_lines", lambda p: None)
    result = fs.check_default_umask()
    assert result.status == Status.NOT_APPLICABLE
