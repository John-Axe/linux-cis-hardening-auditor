from cis_audit.engine import available_categories, run_audit
from cis_audit.models import Status
from cis_audit.registry import all_checks


def test_all_check_ids_are_unique():
    ids = [c.id for c in all_checks()]
    assert len(ids) == len(set(ids))


def test_registry_has_meaningful_breadth():
    # This project's brief: a real subset of CIS checks, aiming for 20-30+,
    # spread across multiple hardening categories - not a token handful.
    checks = all_checks()
    assert len(checks) >= 20
    assert len(available_categories()) >= 5


def test_every_check_has_nonempty_metadata():
    for check in all_checks():
        assert check.id.strip()
        assert check.title.strip()
        assert check.category.strip()
        assert check.rationale.strip()
        assert check.remediation.strip()


def test_run_audit_runs_every_registered_check():
    report = run_audit()
    assert len(report.outcomes) == len(all_checks())
    for outcome in report.outcomes:
        assert outcome.status in (Status.PASS, Status.FAIL, Status.NOT_APPLICABLE)


def test_run_audit_only_filters_by_category():
    report = run_audit(only="ssh")
    assert report.outcomes
    assert all(o.category == "ssh" for o in report.outcomes)


def test_run_audit_counts_add_up():
    report = run_audit()
    counts = report.counts
    assert sum(counts.values()) == len(report.outcomes)
