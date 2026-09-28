"""API tests with a moto-backed get_session override."""

from __future__ import annotations

from fastapi.testclient import TestClient

from api.main import app, get_session, reset_store
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
