"""Run all scanner rules and build a ScanResult."""

import logging
import uuid
from datetime import UTC, datetime

import boto3

from scanner.models import Finding, ScanResult, ScanSummary, Severity
from scanner.pricing import PRICING_NOTE
from scanner.rules import ALL_RULES

logger = logging.getLogger(__name__)

_SEVERITY_ORDER = {Severity.HIGH: 0, Severity.MEDIUM: 1, Severity.LOW: 2}
_RULE_KEYS = (
    "unattached_volume",
    "idle_elastic_ip",
    "open_security_group",
    "missing_tags",
)


def _summarize(findings: list[Finding]) -> ScanSummary:
    by_severity = {item.value: 0 for item in Severity}
    by_rule = dict.fromkeys(_RULE_KEYS, 0)
    total_cost = 0.0
    for finding in findings:
        by_severity[finding.severity.value] += 1
        by_rule[finding.rule] = by_rule.get(finding.rule, 0) + 1
        total_cost += finding.est_monthly_cost_usd
    return ScanSummary(
        total_findings=len(findings),
        by_severity=by_severity,
        by_rule=by_rule,
        total_est_monthly_savings_usd=round(total_cost, 2),
    )


def run_scan(session: boto3.Session, region: str) -> ScanResult:
    """Execute every rule, isolate failures, and return a sorted ScanResult."""

    started_at = datetime.now(UTC)
    sts = session.client("sts", region_name=region)
    account_id = sts.get_caller_identity()["Account"]

    findings: list[Finding] = []
    errors: list[str] = []
    for rule in ALL_RULES:
        try:
            findings.extend(rule(session, region))
        except Exception as exc:  # noqa: BLE001 — isolate a single rule failure
            message = f"Rule {rule.__name__} failed: {exc}"
            logger.exception(message)
            errors.append(message)

    findings.sort(
        key=lambda item: (
            _SEVERITY_ORDER.get(item.severity, 99),
            -item.est_monthly_cost_usd,
            item.resource_id,
        )
    )
    finished_at = datetime.now(UTC)
    return ScanResult(
        scan_id=str(uuid.uuid4()),
        account_id=account_id,
        region=region,
        started_at=started_at,
        finished_at=finished_at,
        findings=findings,
        summary=_summarize(findings),
        pricing_note=PRICING_NOTE,
        errors=errors,
    )
