"""Command-line entry point: ``python -m scanner.cli``."""

from __future__ import annotations

import argparse
import logging
import sys
from collections.abc import Sequence

from botocore.exceptions import (
    BotoCoreError,
    ClientError,
    NoCredentialsError,
    PartialCredentialsError,
)

from scanner.config import build_session, get_settings
from scanner.models import ScanResult, Severity
from scanner.runner import run_scan

_FAIL_RANK = {Severity.LOW: 0, Severity.MEDIUM: 1, Severity.HIGH: 2}
logger = logging.getLogger("scanner.cli")


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    """Parse CLI flags."""

    settings = get_settings()
    parser = argparse.ArgumentParser(
        description="Scan an AWS account for waste and misconfigurations."
    )
    parser.add_argument("--region", default=settings.aws_region, help="AWS region to scan")
    parser.add_argument("--profile", default=settings.aws_profile, help="Local AWS CLI profile")
    parser.add_argument("--output", default=settings.report_path, help="JSON report path")
    parser.add_argument(
        "--fail-on",
        default="none",
        choices=("none", "low", "medium", "high"),
        help="Exit 1 if any finding is at or above this severity",
    )
    parser.add_argument("--verbose", action="store_true", help="Print stack traces on errors")
    return parser.parse_args(argv)


def _print_table(result: ScanResult) -> None:
    if not result.findings:
        print("No findings.")
    else:
        headers = ("SEVERITY", "RULE", "RESOURCE", "USD/MO")
        rows = [
            (
                finding.severity.value.upper(),
                finding.rule,
                finding.resource_id,
                f"{finding.est_monthly_cost_usd:.2f}",
            )
            for finding in result.findings
        ]
        widths = [max(len(headers[i]), max(len(row[i]) for row in rows)) for i in range(4)]
        fmt = "  ".join(f"{{:<{w}}}" for w in widths)
        print(fmt.format(*headers))
        print(fmt.format(*("-" * w for w in widths)))
        for row in rows:
            print(fmt.format(*row))
    print(
        f"Summary: {result.summary.total_findings} findings, "
        f"estimated monthly savings ${result.summary.total_est_monthly_savings_usd:.2f}."
    )
    if result.errors:
        print(f"Rule errors: {len(result.errors)} (see JSON report).")


def _should_fail(result: ScanResult, fail_on: str) -> bool:
    if fail_on == "none":
        return False
    threshold = _FAIL_RANK[Severity(fail_on)]
    return any(_FAIL_RANK[finding.severity] >= threshold for finding in result.findings)


def main(argv: Sequence[str] | None = None) -> int:
    """Run a scan, print a table, write JSON, and return an exit code."""

    args = parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, format="%(message)s")
    try:
        session = build_session(profile=args.profile, region=args.region)
        result = run_scan(session, args.region)
    except (NoCredentialsError, PartialCredentialsError) as exc:
        print(f"Error: AWS credentials are missing or incomplete. {exc}", file=sys.stderr)
        if args.verbose:
            logger.exception("Credential error")
        return 2
    except (BotoCoreError, ClientError, OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        if args.verbose:
            logger.exception("Scan failed")
        return 2

    _print_table(result)
    try:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(result.model_dump_json(indent=2))
    except OSError as exc:
        print(f"Error: could not write {args.output}: {exc}", file=sys.stderr)
        return 2
    print(f"Wrote {args.output}")
    return 1 if _should_fail(result, args.fail_on) else 0


if __name__ == "__main__":
    sys.exit(main())
