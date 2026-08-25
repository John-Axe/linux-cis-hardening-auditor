"""Runs the registered checks and produces a summary + list of outcomes."""

from __future__ import annotations

from dataclasses import dataclass

# Importing cis_audit.checks populates the registry as a side effect.
import cis_audit.checks  # noqa: F401
from cis_audit.models import CheckOutcome, Status
from cis_audit.registry import all_checks, categories


@dataclass(frozen=True)
class AuditReport:
    outcomes: list[CheckOutcome]

    @property
    def counts(self) -> dict[str, int]:
        counts = {status.value: 0 for status in Status}
        for outcome in self.outcomes:
            counts[outcome.status.value] += 1
        return counts

    def to_dict(self) -> dict:
        return {
            "summary": {
                "total_checks": len(self.outcomes),
                **self.counts,
            },
            "checks": [o.to_dict() for o in self.outcomes],
        }


def available_categories() -> list[str]:
    return categories()


def run_audit(only: str | None = None) -> AuditReport:
    """Run every registered check (optionally filtered to one category) and
    return an AuditReport. Never raises - individual check failures are
    already contained by Check.execute()."""
    checks = all_checks()
    if only is not None:
        checks = [c for c in checks if c.category == only]
    outcomes = [c.execute() for c in checks]
    return AuditReport(outcomes=outcomes)
