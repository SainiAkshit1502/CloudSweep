"""API tests with a moto-backed get_session override."""

from __future__ import annotations

import re
from datetime import UTC, datetime

from fastapi.testclient import TestClient

from api.main import _store, app, get_session, reset_store
from scanner.models import ScanResult, ScanSummary
from tests.conftest import REGION, create_volume


def test_health():
    reset_store()
    client = TestClient(app)
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_findings_404_before_scan():
    reset_store()
    client = TestClient(app)
    response = client.get("/findings")
    assert response.status_code == 404
    assert response.json()["detail"] == "No scan has been run yet"


def test_scan_then_findings_and_filters(session, tmp_path, monkeypatch, aws):
    reset_store()
    monkeypatch.setenv("REPORT_PATH", str(tmp_path / "report.json"))
    from scanner.config import get_settings

    get_settings.cache_clear()
    ec2 = session.client("ec2", region_name=REGION)
    create_volume(ec2)

    app.dependency_overrides[get_session] = lambda: session
    client = TestClient(app)
    try:
        posted = client.post("/scan")
        assert posted.status_code == 200
        body = posted.json()
        assert body["summary"]["total_findings"] >= 1

        findings = client.get("/findings")
        assert findings.status_code == 200
        assert len(findings.json()) >= 1

        medium = client.get("/findings", params={"severity": "medium"})
        assert medium.status_code == 200
        assert all(item["severity"] == "medium" for item in medium.json())

        by_rule = client.get("/findings", params={"rule": "unattached_volume"})
        assert by_rule.status_code == 200
        assert all(item["rule"] == "unattached_volume" for item in by_rule.json())

        summary = client.get("/summary")
        assert summary.status_code == 200
        assert "total_findings" in summary.json()
    finally:
        app.dependency_overrides.clear()
        reset_store()


def test_dashboard_html(session, aws):
    reset_store()
    app.dependency_overrides[get_session] = lambda: session
    client = TestClient(app)
    try:
        response = client.get("/")
        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]
        assert "CloudSweep" in response.text
    finally:
        app.dependency_overrides.clear()
        reset_store()


def test_dashboard_rule_errors_shows_banner_and_suppresses_no_issues(tmp_path, monkeypatch):
    reset_store()
    monkeypatch.setenv("REPORT_PATH", str(tmp_path / "report.json"))
    from scanner.config import get_settings

    get_settings.cache_clear()
    now = datetime(2026, 9, 28, 14, 30, 45, 123456, tzinfo=UTC)
    result = ScanResult(
        scan_id="test-scan-err",
        account_id="123456789012",
        region="ap-south-1",
        started_at=now,
        finished_at=now,
        findings=[],
        summary=ScanSummary(
            total_findings=0,
            by_severity={"high": 0, "medium": 0, "low": 0},
            by_rule={},
            total_est_monthly_savings_usd=0.0,
        ),
        pricing_note="note",
        errors=["Rule missing_tags failed: AccessDenied"],
    )
    _store(result)
    client = TestClient(app)
    try:
        response = client.get("/")
        assert response.status_code == 200
        assert "Some rules failed, results may be incomplete" in response.text
        assert "Rule missing_tags failed: AccessDenied" in response.text
        assert "No issues found." not in response.text
    finally:
        reset_store()


def test_dashboard_formatted_timestamp(tmp_path, monkeypatch):
    reset_store()
    monkeypatch.setenv("REPORT_PATH", str(tmp_path / "report.json"))
    from scanner.config import get_settings

    get_settings.cache_clear()
    stamp = datetime(2026, 9, 28, 14, 30, 45, 987654, tzinfo=UTC)
    result = ScanResult(
        scan_id="test-scan-time",
        account_id="999888777666",
        region="ap-south-1",
        started_at=stamp,
        finished_at=stamp,
        findings=[],
        summary=ScanSummary(
            total_findings=0,
            by_severity={"high": 0, "medium": 0, "low": 0},
            by_rule={},
            total_est_monthly_savings_usd=0.0,
        ),
        pricing_note="note",
        errors=[],
    )
    _store(result)
    client = TestClient(app)
    try:
        response = client.get("/")
        assert response.status_code == 200
        assert re.search(r"Last scan:\s*2026-09-28 14:30 UTC", response.text)
        assert "+00:00" not in response.text
        assert "987654" not in response.text
    finally:
        reset_store()
