"""Unit tests for checks/kernel_hardening.py - sysctl reads are mocked so
these are deterministic regardless of the kernel running pytest."""

from cis_audit.checks import kernel_hardening as kh
from cis_audit.models import Status


def test_kptr_restrict_pass(monkeypatch):
    monkeypatch.setattr(kh, "sysctl_value", lambda k: "1")
    result = kh.check_kptr_restrict()
    assert result.status == Status.PASS


def test_kptr_restrict_fail(monkeypatch):
    monkeypatch.setattr(kh, "sysctl_value", lambda k: "0")
    result = kh.check_kptr_restrict()
    assert result.status == Status.FAIL


def test_kptr_restrict_na_when_unreadable(monkeypatch):
    monkeypatch.setattr(kh, "sysctl_value", lambda k: None)
    result = kh.check_kptr_restrict()
    assert result.status == Status.NOT_APPLICABLE


def test_dmesg_restrict_pass(monkeypatch):
    monkeypatch.setattr(kh, "sysctl_value", lambda k: "1")
    result = kh.check_dmesg_restrict()
    assert result.status == Status.PASS


def test_dmesg_restrict_fail(monkeypatch):
    monkeypatch.setattr(kh, "sysctl_value", lambda k: "0")
    result = kh.check_dmesg_restrict()
    assert result.status == Status.FAIL


def test_ptrace_scope_pass_at_max(monkeypatch):
    monkeypatch.setattr(kh, "sysctl_value", lambda k: "3")
    result = kh.check_ptrace_scope()
    assert result.status == Status.PASS


def test_protected_hardlinks_pass(monkeypatch):
    monkeypatch.setattr(kh, "sysctl_value", lambda k: "1")
    result = kh.check_protected_hardlinks()
    assert result.status == Status.PASS


def test_protected_symlinks_fail(monkeypatch):
    monkeypatch.setattr(kh, "sysctl_value", lambda k: "0")
    result = kh.check_protected_symlinks()
    assert result.status == Status.FAIL


def test_protected_fifos_pass_at_2(monkeypatch):
    monkeypatch.setattr(kh, "sysctl_value", lambda k: "2")
    result = kh.check_protected_fifos()
    assert result.status == Status.PASS


def test_protected_regular_fail_at_0(monkeypatch):
    monkeypatch.setattr(kh, "sysctl_value", lambda k: "0")
    result = kh.check_protected_regular()
    assert result.status == Status.FAIL


def test_unprivileged_bpf_disabled_pass(monkeypatch):
    monkeypatch.setattr(kh, "sysctl_value", lambda k: "1")
    result = kh.check_unprivileged_bpf_disabled()
    assert result.status == Status.PASS


def test_bpf_jit_harden_pass(monkeypatch):
    monkeypatch.setattr(kh, "sysctl_value", lambda k: "2")
    result = kh.check_bpf_jit_harden()
    assert result.status == Status.PASS


def test_perf_event_paranoid_pass_at_boundary(monkeypatch):
    monkeypatch.setattr(kh, "sysctl_value", lambda k: "2")
    result = kh.check_perf_event_paranoid()
    assert result.status == Status.PASS


def test_perf_event_paranoid_fail_below_boundary(monkeypatch):
    monkeypatch.setattr(kh, "sysctl_value", lambda k: "1")
    result = kh.check_perf_event_paranoid()
    assert result.status == Status.FAIL


def test_perf_event_paranoid_handles_negative_value(monkeypatch):
    # kernel.perf_event_paranoid can legitimately be -1 (no restriction at
    # all) - must not crash on the leading '-' when checking .isdigit().
    monkeypatch.setattr(kh, "sysctl_value", lambda k: "-1")
    result = kh.check_perf_event_paranoid()
    assert result.status == Status.FAIL
