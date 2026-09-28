"""CLI exit codes, JSON report, and summary line."""

from __future__ import annotations

import json
from pathlib import Path

from botocore.exceptions import ClientError, NoCredentialsError

from scanner.cli import main
from tests.conftest import REGION, create_volume


def test_cli_writes_json_and_summary(session, tmp_path, capsys, monkeypatch, aws):
    ec2 = session.client("ec2", region_name=REGION)
    create_volume(ec2)
    report = tmp_path / "report.json"
    monkeypatch.setattr("scanner.cli.build_session", lambda profile=None, region=None: session)
    code = main(["--region", REGION, "--output", str(report), "--fail-on", "none"])
    assert code == 0
    captured = capsys.readouterr()
    assert "estimated monthly savings" in captured.out
    payload = json.loads(report.read_text(encoding="utf-8"))
    assert payload["summary"]["total_findings"] >= 1
    assert Path(report).exists()


def test_cli_fail_on_medium(session, tmp_path, monkeypatch, aws):
    ec2 = session.client("ec2", region_name=REGION)
    create_volume(ec2)
    report = tmp_path / "report.json"
    monkeypatch.setattr("scanner.cli.build_session", lambda profile=None, region=None: session)
    code = main(["--region", REGION, "--output", str(report), "--fail-on", "medium"])
    assert code == 1


def test_cli_fail_on_high_with_only_medium(session, tmp_path, monkeypatch, aws):
    ec2 = session.client("ec2", region_name=REGION)
    create_volume(ec2)
    report = tmp_path / "report.json"
    monkeypatch.setattr("scanner.cli.build_session", lambda profile=None, region=None: session)
    code = main(["--region", REGION, "--output", str(report), "--fail-on", "high"])
    assert code == 0


def test_cli_exit_2_on_missing_credentials(tmp_path, monkeypatch):
    def raise_creds(**_kwargs):
        raise NoCredentialsError()

    monkeypatch.setattr("scanner.cli.build_session", raise_creds)
    code = main(["--output", str(tmp_path / "report.json")])
    assert code == 2


def test_cli_verbose_credentials(tmp_path, monkeypatch):
    def raise_creds(**_kwargs):
        raise NoCredentialsError()

    monkeypatch.setattr("scanner.cli.build_session", raise_creds)
    code = main(["--verbose", "--output", str(tmp_path / "report.json")])
    assert code == 2


def test_cli_client_error(tmp_path, monkeypatch):
    def raise_client(**_kwargs):
        raise ClientError(
            {"Error": {"Code": "AuthFailure", "Message": "nope"}},
            "GetCallerIdentity",
        )

    monkeypatch.setattr("scanner.cli.build_session", raise_client)
    code = main(["--verbose", "--output", str(tmp_path / "report.json")])
    assert code == 2


def test_cli_empty_account(session, tmp_path, capsys, monkeypatch, aws):
    report = tmp_path / "report.json"
    monkeypatch.setattr("scanner.cli.build_session", lambda profile=None, region=None: session)
    code = main(["--region", REGION, "--output", str(report), "--fail-on", "none"])
    assert code == 0
    assert "No findings." in capsys.readouterr().out


def test_cli_write_failure(session, tmp_path, monkeypatch, aws):
    monkeypatch.setattr("scanner.cli.build_session", lambda profile=None, region=None: session)
    code = main(["--region", REGION, "--output", str(tmp_path)])
    assert code == 2


def test_cli_prints_rule_errors(session, tmp_path, capsys, monkeypatch, aws):
    from datetime import UTC, datetime

    from scanner.models import ScanResult, ScanSummary
    from scanner.pricing import PRICING_NOTE

    def fake_scan(_session, _region):
        return ScanResult(
            scan_id="x",
            account_id="1",
            region=REGION,
            started_at=datetime.now(UTC),
            finished_at=datetime.now(UTC),
            findings=[],
            summary=ScanSummary(
                total_findings=0,
                by_severity={"high": 0, "medium": 0, "low": 0},
                by_rule={},
                total_est_monthly_savings_usd=0.0,
            ),
            pricing_note=PRICING_NOTE,
            errors=["Rule boom failed"],
        )

    monkeypatch.setattr("scanner.cli.build_session", lambda profile=None, region=None: session)
    monkeypatch.setattr("scanner.cli.run_scan", fake_scan)
    code = main(["--output", str(tmp_path / "report.json")])
    assert code == 0
    assert "Rule errors" in capsys.readouterr().out
