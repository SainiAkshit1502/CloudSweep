"""Runner summary, sort order, and isolated rule failures."""

from __future__ import annotations

from scanner.models import Finding, Severity
from scanner.pricing import eip_monthly_cost
from scanner.runner import run_scan
from tests.conftest import REGION, create_volume


def test_summary_math_and_sort(session, monkeypatch):
    ec2 = session.client("ec2", region_name=REGION)
    create_volume(ec2, size=1, volume_type="gp3")
    ec2.allocate_address(Domain="vpc")

    result = run_scan(session, REGION)
    assert result.summary.total_findings >= 2
    assert result.summary.by_severity["medium"] >= 2
    assert result.summary.total_est_monthly_savings_usd >= eip_monthly_cost()
    ranks = {"high": 0, "medium": 1, "low": 2}
    order = [ranks[item.severity.value] for item in result.findings]
    assert order == sorted(order)
    medium = [item for item in result.findings if item.severity == Severity.MEDIUM]
    costs = [item.est_monthly_cost_usd for item in medium]
    assert costs == sorted(costs, reverse=True)


def test_rule_exception_does_not_crash(session, monkeypatch):
    from scanner import runner as runner_mod
    from scanner.rules import (
        idle_elastic_ips,
        missing_tags,
        open_security_groups,
        unattached_volumes,
    )

    def boom(_session, _region):
        raise RuntimeError("simulated rule failure")

    monkeypatch.setattr(
        runner_mod,
        "ALL_RULES",
        [unattached_volumes, boom, idle_elastic_ips, open_security_groups, missing_tags],
    )
    result = run_scan(session, REGION)
    assert result.errors
    assert "simulated rule failure" in result.errors[0]
    assert isinstance(result.findings, list)


def test_empty_scan_summary(session):
    result = run_scan(session, REGION)
    assert (
        result.summary.total_findings
        == result.summary.by_severity["high"]
        + result.summary.by_severity["medium"]
        + result.summary.by_severity["low"]
    )
    assert result.pricing_note
    assert result.account_id
    Finding.model_validate(result.findings[0].model_dump()) if result.findings else None
