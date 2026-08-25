"""Text and JSON report formatters."""

from __future__ import annotations

import json

from cis_audit.engine import AuditReport
from cis_audit.models import Status

_STATUS_MARK = {
    Status.PASS: "PASS",
    Status.FAIL: "FAIL",
    Status.NOT_APPLICABLE: "N/A ",
}


def format_json(report: AuditReport) -> str:
    return json.dumps(report.to_dict(), indent=2)


def format_text(report: AuditReport) -> str:
    lines: list[str] = []
    current_category = None
    for outcome in report.outcomes:
        if outcome.category != current_category:
            current_category = outcome.category
            lines.append("")
            lines.append(f"== {current_category} ==")
        mark = _STATUS_MARK[outcome.status]
        lines.append(f"[{mark}] {outcome.id}  {outcome.title}")
        lines.append(f"       evidence: {outcome.evidence}")
        if outcome.status == Status.FAIL:
            lines.append(f"       remediation: {outcome.remediation}")

    counts = report.counts
    total = len(report.outcomes)
    lines.append("")
    lines.append("-" * 60)
    lines.append(
        f"Summary: {total} checks | "
        f"{counts[Status.PASS.value]} pass, "
        f"{counts[Status.FAIL.value]} fail, "
        f"{counts[Status.NOT_APPLICABLE.value]} n/a"
    )
    return "\n".join(lines).lstrip("\n")
