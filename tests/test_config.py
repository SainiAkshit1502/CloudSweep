"""Settings and session construction."""

from types import SimpleNamespace

from scanner.config import build_session, get_settings


def test_build_session_without_profile(monkeypatch):
    captured: dict = {}

    def fake_session(**kwargs):
        captured.update(kwargs)
        return SimpleNamespace()

    monkeypatch.setattr("scanner.config.boto3.Session", fake_session)
    get_settings.cache_clear()
    build_session(profile="", region="ap-south-1")
    assert captured["region_name"] == "ap-south-1"
    assert "profile_name" not in captured


def test_build_session_with_profile(monkeypatch):
    captured: dict = {}

    def fake_session(**kwargs):
        captured.update(kwargs)
        return SimpleNamespace()

    monkeypatch.setattr("scanner.config.boto3.Session", fake_session)
    build_session(profile="cloudsweep-scanner", region="eu-west-1")
    assert captured == {"region_name": "eu-west-1", "profile_name": "cloudsweep-scanner"}
