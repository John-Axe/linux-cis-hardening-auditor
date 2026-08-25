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


# --- tests for the 75 fixers added for the expanded (191-check) check set -------------


def test_ninety_five_fixers_registered_no_duplicates():
    ids = [f.check_id for f in remediate.FIXERS]
    assert len(ids) == 95
    assert len(ids) == len(set(ids))


def test_kernel_hardening_sysctl_fixer(tmp_path, monkeypatch, no_real_subprocess):
    conf = tmp_path / "60-cis-hardening.conf"
    monkeypatch.setattr(remediate, "SYSCTL_CONF_PATH", str(conf))
    f = next(f for f in remediate.FIXERS if f.check_id == "CIS-1.6.3")
    f.apply()
    assert "kernel.kptr_restrict=1" in conf.read_text()
    assert ["sysctl", "-w", "kernel.kptr_restrict=1"] in no_real_subprocess


def test_network_sysctl_expanded_fixer(tmp_path, monkeypatch, no_real_subprocess):
    conf = tmp_path / "60-cis-hardening.conf"
    monkeypatch.setattr(remediate, "SYSCTL_CONF_PATH", str(conf))
    f = next(f for f in remediate.FIXERS if f.check_id == "CIS-3.2.15")
    f.apply()
    assert "net.ipv6.conf.all.accept_ra=0" in conf.read_text()


def test_kernel_module_blacklist_fixer_writes_conf_and_rmmods(tmp_path, monkeypatch, no_real_subprocess):
    conf = tmp_path / "modprobe-cis.conf"
    monkeypatch.setattr(remediate, "MODPROBE_CONF_PATH", str(conf))
    f = next(f for f in remediate.FIXERS if f.check_id == "CIS-1.1.1.1")  # cramfs
    f.apply()
    content = conf.read_text()
    assert "install cramfs /bin/true" in content
    assert "blacklist cramfs" in content
    assert ["rmmod", "cramfs"] in no_real_subprocess


def test_kernel_module_blacklist_fixer_is_idempotent(tmp_path, monkeypatch, no_real_subprocess):
    conf = tmp_path / "modprobe-cis.conf"
    monkeypatch.setattr(remediate, "MODPROBE_CONF_PATH", str(conf))
    f = next(f for f in remediate.FIXERS if f.check_id == "CIS-1.1.1.1")
    f.apply()
    f.apply()
    lines = conf.read_text().splitlines()
    assert lines.count("blacklist cramfs") == 1


def test_kernel_module_blacklist_fixer_tolerates_rmmod_failure(tmp_path, monkeypatch):
    conf = tmp_path / "modprobe-cis.conf"
    monkeypatch.setattr(remediate, "MODPROBE_CONF_PATH", str(conf))

    def failing_run(cmd):
        raise __import__("subprocess").CalledProcessError(1, cmd)

    monkeypatch.setattr(remediate, "_run", failing_run)
    f = next(f for f in remediate.FIXERS if f.check_id == "CIS-1.1.1.8")  # usb-storage
    f.apply()  # must not raise even though rmmod "fails" (module wasn't loaded)
    assert "blacklist usb-storage" in conf.read_text()


def test_banner_perms_fixer(monkeypatch, tmp_path, no_real_subprocess):
    motd = tmp_path / "motd"
    motd.write_text("hello\n")
    monkeypatch.setattr(remediate, "MOTD_PATH", str(motd))
    f = next(f for f in remediate.FIXERS if f.check_id == "CIS-1.8.1")
    f.apply()
    assert ["chown", "root:root", str(motd)] in no_real_subprocess
    assert ["chmod", "644", str(motd)] in no_real_subprocess


def test_cron_dir_perms_fixer(monkeypatch, tmp_path, no_real_subprocess):
    cron_daily = tmp_path / "cron.daily"
    monkeypatch.setattr(remediate, "CRON_DAILY_PATH", str(cron_daily))
    f = next(f for f in remediate.FIXERS if f.check_id == "CIS-5.1.4")
    f.apply()
    assert ["chmod", "700", str(cron_daily)] in no_real_subprocess


def test_at_restricted_fixer_creates_allow_removes_deny(tmp_path, monkeypatch):
    allow = tmp_path / "at.allow"
    deny = tmp_path / "at.deny"
    deny.write_text("someuser\n")
    monkeypatch.setattr(remediate, "AT_ALLOW_PATH", str(allow))
    monkeypatch.setattr(remediate, "AT_DENY_PATH", str(deny))
    remediate.fix_at_restricted()
    assert allow.exists()
    assert oct(allow.stat().st_mode)[-3:] == "600"
    assert not deny.exists()


def test_pwquality_fixer_sets_new_value(tmp_path, monkeypatch):
    conf = tmp_path / "pwquality.conf"
    conf.write_text("# defaults\n")
    monkeypatch.setattr(remediate, "PWQUALITY_CONF_PATH", str(conf))
    f = next(f for f in remediate.FIXERS if f.check_id == "CIS-5.5.1.1")
    f.apply()
    assert "minlen = 14" in conf.read_text()


def test_pwquality_fixer_updates_existing_value_in_place(tmp_path, monkeypatch):
    conf = tmp_path / "pwquality.conf"
    conf.write_text("minlen = 8\nretry = 5\n")
    monkeypatch.setattr(remediate, "PWQUALITY_CONF_PATH", str(conf))
    f = next(f for f in remediate.FIXERS if f.check_id == "CIS-5.5.1.1")
    f.apply()
    content = conf.read_text()
    assert "minlen = 14" in content
    assert "retry = 5" in content  # untouched


def test_faillock_deny_fixer(tmp_path, monkeypatch):
    conf = tmp_path / "faillock.conf"
    monkeypatch.setattr(remediate, "FAILLOCK_CONF_PATH", str(conf))
    remediate.fix_faillock_deny()
    assert "deny = 5" in conf.read_text()


def test_faillock_even_deny_root_fixer_is_idempotent(tmp_path, monkeypatch):
    conf = tmp_path / "faillock.conf"
    monkeypatch.setattr(remediate, "FAILLOCK_CONF_PATH", str(conf))
    remediate.fix_faillock_even_deny_root()
    remediate.fix_faillock_even_deny_root()
    assert conf.read_text().splitlines().count("even_deny_root") == 1


def test_sshd_expanded_fixer_updates_directive(tmp_path, monkeypatch, no_real_subprocess):
    sshd_config = tmp_path / "sshd_config"
    sshd_config.write_text("Port 22\n")
    monkeypatch.setattr(remediate, "SSHD_CONFIG_PATH", str(sshd_config))
    f = next(f for f in remediate.FIXERS if f.check_id == "CIS-5.2.27")  # UsePAM
    f.apply()
    content = sshd_config.read_text()
    assert "UsePAM yes" in content
    assert "Port 22" in content
    assert ["sshd", "-t"] in no_real_subprocess


def test_password_hash_algorithm_fixer(tmp_path, monkeypatch):
    login_defs = tmp_path / "login.defs"
    login_defs.write_text("PASS_MAX_DAYS\t365\n")
    monkeypatch.setattr(remediate, "LOGIN_DEFS_PATH", str(login_defs))
    remediate.fix_password_hash_algorithm()
    assert "ENCRYPT_METHOD\tSHA512" in login_defs.read_text()


def test_default_inactive_lock_fixer_updates_existing(tmp_path, monkeypatch):
    useradd = tmp_path / "useradd"
    useradd.write_text("INACTIVE=-1\nEXPIRE=\n")
    monkeypatch.setattr(remediate, "DEFAULT_USERADD_PATH", str(useradd))
    remediate.fix_default_inactive_lock()
    content = useradd.read_text()
    assert "INACTIVE=30" in content
    assert "EXPIRE=" in content


def test_default_inactive_lock_fixer_appends_when_missing(tmp_path, monkeypatch):
    useradd = tmp_path / "useradd"
    useradd.write_text("GROUP=100\n")
    monkeypatch.setattr(remediate, "DEFAULT_USERADD_PATH", str(useradd))
    remediate.fix_default_inactive_lock()
    assert "INACTIVE=30" in useradd.read_text()


def test_unattended_upgrades_auto_reboot_fixer_sets_new(tmp_path, monkeypatch):
    conf = tmp_path / "50unattended-upgrades"
    conf.write_text("// comment\n")
    monkeypatch.setattr(remediate, "UNATTENDED_UPGRADES_PATH", str(conf))
    remediate.fix_unattended_upgrades_auto_reboot()
    assert 'Unattended-Upgrade::Automatic-Reboot "true";' in conf.read_text()


def test_unattended_upgrades_remove_unused_fixer_updates_existing(tmp_path, monkeypatch):
    conf = tmp_path / "50unattended-upgrades"
    conf.write_text('Unattended-Upgrade::Remove-Unused-Dependencies "false";\n')
    monkeypatch.setattr(remediate, "UNATTENDED_UPGRADES_PATH", str(conf))
    remediate.fix_unattended_upgrades_remove_unused()
    content = conf.read_text()
    assert 'Unattended-Upgrade::Remove-Unused-Dependencies "true";' in content
    assert content.count("Remove-Unused-Dependencies") == 1
