import json

from cis_audit.engine import AuditReport
from cis_audit.models import CheckOutcome, Status
from cis_audit.report import format_json, format_text


def _sample_report() -> AuditReport:
    outcomes = [
        CheckOutcome(
            id="CIS-1", title="pass check", category="cat-a", rationale="r",
            status=Status.PASS, evidence="ev1", remediation="rem1",
        ),
        CheckOutcome(
            id="CIS-2", title="fail check", category="cat-a", rationale="r",
            status=Status.FAIL, evidence="ev2", remediation="rem2",
        ),
        CheckOutcome(
            id="CIS-3", title="na check", category="cat-b", rationale="r",
            status=Status.NOT_APPLICABLE, evidence="ev3", remediation="rem3",
        ),
    ]
    return AuditReport(outcomes=outcomes)


def test_format_json_is_valid_and_complete():
    report = _sample_report()
    data = json.loads(format_json(report))
    assert data["summary"]["total_checks"] == 3
    assert data["summary"]["PASS"] == 1
    assert data["summary"]["FAIL"] == 1
    assert data["summary"]["NOT_APPLICABLE"] == 1
    assert len(data["checks"]) == 3
    assert data["checks"][0]["id"] == "CIS-1"


def test_format_text_includes_remediation_only_for_failures():
    text = format_text(_sample_report())
    assert "CIS-1" in text
    assert "CIS-2" in text
    assert "rem2" in text  # remediation shown for the FAIL
    assert "rem1" not in text  # not shown for the PASS
    assert "Summary: 3 checks" in text


def test_format_text_groups_by_category():
    text = format_text(_sample_report())
    assert "== cat-a ==" in text
    assert "== cat-b ==" in text
