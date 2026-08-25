"""Core data model: a Check is a self-contained unit of audit logic.

A Check never raises out of ``execute()`` - any unexpected exception (a
permission error the check's own code didn't anticipate, a missing binary,
whatever) is caught and turned into a NOT_APPLICABLE result carrying the
exception text as evidence, so one broken check can never take down a whole
audit run.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Callable


class Status(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    NOT_APPLICABLE = "NOT_APPLICABLE"


@dataclass(frozen=True)
class CheckResult:
    """What a check's run() function returns: a status plus the real evidence
    it inspected to reach that status (an actual file mode, an actual sshd -T
    line, an actual sysctl value - never a canned string)."""

    status: Status
    evidence: str


@dataclass(frozen=True)
class CheckOutcome:
    """A fully-resolved check result, ready to serialize/print."""

    id: str
    title: str
    category: str
    rationale: str
    status: Status
    evidence: str
    remediation: str

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "category": self.category,
            "status": self.status.value,
            "rationale": self.rationale,
            "evidence": self.evidence,
            "remediation": self.remediation,
        }


@dataclass(frozen=True)
class Check:
    id: str
    title: str
    category: str
    rationale: str
    remediation: str
    run: Callable[[], CheckResult]

    def execute(self) -> CheckOutcome:
        try:
            result = self.run()
        except Exception as exc:  # defensive: a single bad check must never
            # crash the whole audit run - report it as NOT_APPLICABLE with the
            # exception as evidence instead.
            result = CheckResult(
                Status.NOT_APPLICABLE,
                f"check raised an unexpected error and could not be evaluated: "
                f"{exc.__class__.__name__}: {exc}",
            )
        return CheckOutcome(
            id=self.id,
            title=self.title,
            category=self.category,
            rationale=self.rationale,
            status=result.status,
            evidence=result.evidence,
            remediation=self.remediation,
        )
