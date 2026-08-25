"""Unit tests for remediation/remediate.py.

remediate.py is a standalone script (deliberately outside the installed
cis_audit package, since it's a privileged operational tool, not a library
import), so it's loaded here via importlib from its file path. All fixer
logic that touches "system" files is redirected at the module's path
constants to tmp_path files - nothing here ever touches a real system file,
and _run (which shells out to chown/chmod/sysctl/systemctl) is monkeypatched
to a no-op recorder so no subprocess is ever actually invoked either.
"""

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path

import pytest

_REMEDIATE_PATH = Path(__file__).parent.parent / "remediation" / "remediate.py"
_spec = importlib.util.spec_from_file_location("remediate", _REMEDIATE_PATH)
remediate = importlib.util.module_from_spec(_spec)
sys.modules["remediate"] = remediate
_spec.loader.exec_module(remediate)


@pytest.fixture(autouse=True)
def no_real_subprocess(monkeypatch):
    """Every test in this file gets _run replaced with a recorder, so a
    fixer's chown/chmod/sysctl/systemctl call is captured, never executed."""
    calls = []
    monkeypatch.setattr(remediate, "_run", lambda cmd: calls.append(cmd))
    return calls


def test_check_and_all_are_mutually_exclusive():
    with pytest.raises(SystemExit):
        remediate.main(["--check", "CIS-6.1.3", "--all"])


def test_list_ignores_apply_flag_and_never_applies(capsys):
    # --list short-circuits before any fixer runs, even if --apply is also
    # passed - listing available fixers must never itself make changes.
    rc = remediate.main(["--list", "--apply"])
    assert rc == 0
    assert "CIS-6.1.3" in capsys.readouterr().out


def test_unknown_check_id_returns_error(capsys):
    rc = remediate.main(["--check", "CIS-DOES-NOT-EXIST"])
    assert rc == 1
    assert "No fixer registered" in capsys.readouterr().err


def test_dry_run_touches_nothing(tmp_path, monkeypatch, capsys):
    shadow = tmp_path / "shadow"
    shadow.write_text("root:x:...\n")
    monkeypatch.setattr(remediate, "SHADOW_PATH", str(shadow))
    before = shadow.read_text()

    rc = remediate.main(["--check", "CIS-6.1.3"])  # no --apply

    assert rc == 0
    assert shadow.read_text() == before  # untouched
    out = capsys.readouterr().out
    assert "DRY RUN" in out
    assert "chown root:shadow" in out


def test_apply_without_root_is_skipped_not_silently_ignored(monkeypatch, capsys):
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    rc = remediate.main(["--check", "CIS-6.1.3", "--apply"])
    assert rc == 3  # reported as a failure, not swallowed
    assert "requires root" in capsys.readouterr().err


def test_apply_as_root_runs_chown_and_chmod(monkeypatch, no_real_subprocess):
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    rc = remediate.main(["--check", "CIS-6.1.3", "--apply"])
    assert rc == 0
    assert ["chown", "root:shadow", remediate.SHADOW_PATH] in no_real_subprocess
    assert ["chmod", "640", remediate.SHADOW_PATH] in no_real_subprocess


def test_set_login_defs_key_updates_existing_line(tmp_path, monkeypatch):
    login_defs = tmp_path / "login.defs"
    login_defs.write_text("UMASK\t022\nPASS_MAX_DAYS\t99999\n")
    monkeypatch.setattr(remediate, "LOGIN_DEFS_PATH", str(login_defs))
    remediate._set_login_defs_key("UMASK", "027")
    content = login_defs.read_text()
    assert "UMASK\t027" in content
    assert "PASS_MAX_DAYS\t99999" in content  # untouched


def test_set_login_defs_key_appends_when_missing(tmp_path, monkeypatch):
    login_defs = tmp_path / "login.defs"
    login_defs.write_text("# just a comment\n")
    monkeypatch.setattr(remediate, "LOGIN_DEFS_PATH", str(login_defs))
    remediate._set_login_defs_key("PASS_WARN_AGE", "7")
    assert "PASS_WARN_AGE\t7" in login_defs.read_text()


def test_set_sshd_directive_updates_existing(tmp_path, monkeypatch, no_real_subprocess):
    sshd_config = tmp_path / "sshd_config"
    sshd_config.write_text("PermitRootLogin yes\nPort 22\n")
    monkeypatch.setattr(remediate, "SSHD_CONFIG_PATH", str(sshd_config))
    remediate._set_sshd_directive("PermitRootLogin", "no")
    content = sshd_config.read_text()
    assert "PermitRootLogin no" in content
    assert "Port 22" in content
    assert ["sshd", "-t"] in no_real_subprocess
    assert ["systemctl", "reload", "sshd"] in no_real_subprocess


def test_append_sysctl_conf_is_idempotent(tmp_path, monkeypatch):
    conf = tmp_path / "60-cis-hardening.conf"
    monkeypatch.setattr(remediate, "SYSCTL_CONF_PATH", str(conf))
    remediate._append_sysctl_conf("net.ipv4.ip_forward", "0")
    remediate._append_sysctl_conf("net.ipv4.ip_forward", "0")  # run twice
    lines = conf.read_text().splitlines()
    assert lines.count("net.ipv4.ip_forward=0") == 1  # not duplicated


def test_cron_fixer_creates_allow_and_removes_deny(tmp_path, monkeypatch):
    allow = tmp_path / "cron.allow"
    deny = tmp_path / "cron.deny"
    deny.write_text("someuser\n")
    monkeypatch.setattr(remediate, "CRON_ALLOW_PATH", str(allow))
    monkeypatch.setattr(remediate, "CRON_DENY_PATH", str(deny))
    remediate.fix_cron_restricted()
    assert allow.exists()
    assert oct(allow.stat().st_mode)[-3:] == "600"
    assert not deny.exists()


def test_every_fixer_has_at_least_one_action_description():
    for f in remediate.FIXERS:
        assert f.actions
        assert all(a.strip() for a in f.actions)


def test_no_fixer_covers_password_authentication_directive():
    # This is deliberate (see the comment in remediate.py): flipping
    # PasswordAuthentication automatically could lock an operator out if a
    # working SSH key isn't already confirmed - it's a judgment call, not a
    # safe blind fix. Assert the guardrail stays in place.
    ssh_password_auth_fixers = [f for f in remediate.FIXERS if "PasswordAuthentication" in f.description]
    assert ssh_password_auth_fixers == []
