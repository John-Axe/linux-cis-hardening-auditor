from cis_audit.models import Check, CheckResult, Status


def test_check_execute_happy_path():
    check = Check(
        id="TEST-1",
        title="a test check",
        category="test",
        rationale="because",
        remediation="do the thing",
        run=lambda: CheckResult(Status.PASS, "evidence here"),
    )
    outcome = check.execute()
    assert outcome.id == "TEST-1"
    assert outcome.status == Status.PASS
    assert outcome.evidence == "evidence here"
    assert outcome.remediation == "do the thing"


def test_check_execute_catches_exceptions():
    def boom() -> CheckResult:
        raise RuntimeError("kaboom")

    check = Check(
        id="TEST-2",
        title="a check that blows up",
        category="test",
        rationale="because",
        remediation="n/a",
        run=boom,
    )
    outcome = check.execute()
    assert outcome.status == Status.NOT_APPLICABLE
    assert "kaboom" in outcome.evidence
    assert "RuntimeError" in outcome.evidence


def test_check_outcome_to_dict_roundtrip():
    check = Check(
        id="TEST-3",
        title="title",
        category="cat",
        rationale="rat",
        remediation="rem",
        run=lambda: CheckResult(Status.FAIL, "ev"),
    )
    d = check.execute().to_dict()
    assert d == {
        "id": "TEST-3",
        "title": "title",
        "category": "cat",
        "status": "FAIL",
        "rationale": "rat",
        "evidence": "ev",
        "remediation": "rem",
    }
