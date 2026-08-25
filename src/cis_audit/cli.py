"""cis-audit CLI entry point."""

from __future__ import annotations

import argparse
import sys

from cis_audit import __version__
from cis_audit.engine import available_categories, run_audit
from cis_audit.report import format_json, format_text


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cis-audit",
        description="Offline CIS Ubuntu/Debian Linux Benchmark-style hardening auditor. "
        "Read-only: inspects local system state, makes no changes.",
    )
    parser.add_argument("--version", action="version", version=f"cis-audit {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    run_parser = subparsers.add_parser("run", help="Run the audit and print a report.")
    run_parser.add_argument(
        "--only",
        choices=available_categories(),
        default=None,
        help="Only run checks in this category.",
    )
    run_parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Report format printed to stdout (default: text).",
    )
    run_parser.add_argument(
        "--output",
        metavar="FILE",
        default=None,
        help="Also write a full JSON report to this file, regardless of --format.",
    )
    run_parser.add_argument(
        "--fail-on-findings",
        action="store_true",
        help="Exit with status 1 if any check FAILed (useful in CI). Default: always exit 0.",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "run":
        report = run_audit(only=args.only)

        if args.format == "json":
            print(format_json(report))
        else:
            print(format_text(report))

        if args.output:
            with open(args.output, "w") as f:
                f.write(format_json(report))

        if args.fail_on_findings and report.counts["FAIL"] > 0:
            return 1
        return 0

    parser.error(f"unknown command: {args.command}")
    return 2


if __name__ == "__main__":
    sys.exit(main())
