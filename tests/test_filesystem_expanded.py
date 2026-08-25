"""Unit tests for checks/filesystem_expanded.py - /proc/mounts parsing and
the sticky-bit directory scan are both mocked so these are deterministic
regardless of the machine running pytest."""

from cis_audit.checks import filesystem_expanded as fse
from cis_audit.models import Status


_MOUNTS_WITH_HARDENED_TMP = "\n".join(
    [
        "/dev/sda1 / ext4 rw,relatime 0 0",
        "tmpfs /tmp tmpfs rw,nosuid,nodev,noexec,relatime 0 0",
        "/dev/sda2 /home ext4 rw,nodev,relatime 0 0",
    ]
)

_MOUNTS_ROOT_ONLY = "/dev/sda1 / ext4 rw,relatime 0 0"


def test_tmp_separate_partition_pass(monkeypatch):
    monkeypatch.setattr(fse, "read_lines", lambda p: _MOUNTS_WITH_HARDENED_TMP.splitlines())
    result = fse.check_tmp_separate_partition()
    assert result.status == Status.PASS


def test_tmp_separate_partition_fail_when_on_root(monkeypatch):
    monkeypatch.setattr(fse, "read_lines", lambda p: _MOUNTS_ROOT_ONLY.splitlines())
    result = fse.check_tmp_separate_partition()
    assert result.status == Status.FAIL


def test_tmp_separate_partition_na_when_proc_mounts_unreadable(monkeypatch):
    monkeypatch.setattr(fse, "read_lines", lambda p: None)
    result = fse.check_tmp_separate_partition()
    assert result.status == Status.NOT_APPLICABLE


def test_tmp_nodev_pass_when_option_present(monkeypatch):
    monkeypatch.setattr(fse, "read_lines", lambda p: _MOUNTS_WITH_HARDENED_TMP.splitlines())
    result = fse.check_tmp_nodev()
    assert result.status == Status.PASS


def test_tmp_nosuid_na_when_not_a_mount_point(monkeypatch):
    monkeypatch.setattr(fse, "read_lines", lambda p: _MOUNTS_ROOT_ONLY.splitlines())
    result = fse.check_tmp_nosuid()
    assert result.status == Status.NOT_APPLICABLE


def test_tmp_noexec_fail_when_option_missing(monkeypatch):
    mounts = "tmpfs /tmp tmpfs rw,nosuid,nodev,relatime 0 0"
    monkeypatch.setattr(fse, "read_lines", lambda p: mounts.splitlines())
    result = fse.check_tmp_noexec()
    assert result.status == Status.FAIL


def test_var_separate_partition_pass(monkeypatch):
    mounts = "/dev/sda3 /var ext4 rw,relatime 0 0"
    monkeypatch.setattr(fse, "read_lines", lambda p: mounts.splitlines())
    result = fse.check_var_separate_partition()
    assert result.status == Status.PASS


def test_home_nodev_fail_when_missing(monkeypatch):
    mounts = "/dev/sda2 /home ext4 rw,relatime 0 0"
    monkeypatch.setattr(fse, "read_lines", lambda p: mounts.splitlines())
    result = fse.check_home_nodev()
    assert result.status == Status.FAIL


def test_dev_shm_noexec_pass(monkeypatch):
    mounts = "tmpfs /dev/shm tmpfs rw,nosuid,nodev,noexec,relatime 0 0"
    monkeypatch.setattr(fse, "read_lines", lambda p: mounts.splitlines())
    result = fse.check_dev_shm_noexec()
    assert result.status == Status.PASS


def test_sticky_bit_scan_pass_when_none_found(monkeypatch):
    monkeypatch.setattr("os.path.isdir", lambda p: False)
    result = fse.check_sticky_bit_on_world_writable_dirs()
    assert result.status == Status.PASS


def test_sticky_bit_scan_fail_when_world_writable_no_sticky(monkeypatch, tmp_path):
    bad_dir = tmp_path / "shared"
    bad_dir.mkdir()
    import os
    import stat as stat_mod

    os.chmod(bad_dir, 0o777)  # world-writable, no sticky bit

    monkeypatch.setattr(fse, "_SCAN_DIRS_FOR_STICKY", [str(tmp_path)])
    result = fse.check_sticky_bit_on_world_writable_dirs()
    assert result.status == Status.FAIL
    assert "shared" in result.evidence


def test_sticky_bit_scan_pass_when_sticky_set(monkeypatch, tmp_path):
    import os

    good_dir = tmp_path / "shared"
    good_dir.mkdir()
    os.chmod(good_dir, 0o777 | stat_ISVTX())
    monkeypatch.setattr(fse, "_SCAN_DIRS_FOR_STICKY", [str(tmp_path)])
    result = fse.check_sticky_bit_on_world_writable_dirs()
    assert result.status == Status.PASS


def stat_ISVTX():
    import stat as stat_mod

    return stat_mod.S_ISVTX
