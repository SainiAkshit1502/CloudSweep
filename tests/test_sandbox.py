"""Sandbox create/destroy behaviour, tag-only deletion, and account guard."""

from __future__ import annotations

import pytest

from sandbox.common import SANDBOX_TAGS, assert_safe_account
from sandbox.create_waste import create_waste
from sandbox.destroy_waste import destroy_waste
from scanner.config import get_settings
from scanner.runner import run_scan
from tests.conftest import REGION, create_volume


def _align_account(session, monkeypatch: pytest.MonkeyPatch) -> str:
    account = session.client("sts").get_caller_identity()["Account"]
    monkeypatch.setenv("CLOUDSWEEP_ALLOWED_ACCOUNT_ID", account)
    get_settings.cache_clear()
    return account


def test_create_then_scan_finds_five(session, monkeypatch):
    _align_account(session, monkeypatch)
    assert create_waste(session, REGION, yes=True, dry_run=False) == 0
    result = run_scan(session, REGION)
    by_rule = result.summary.by_rule
    assert by_rule["unattached_volume"] == 1
    assert by_rule["idle_elastic_ip"] == 1
    assert by_rule["open_security_group"] == 1
    assert by_rule["missing_tags"] == 2
    assert result.summary.total_findings == 5


def test_destroy_then_scan_finds_zero_sandbox_waste(session, monkeypatch):
    _align_account(session, monkeypatch)
    create_waste(session, REGION, yes=True, dry_run=False)
    assert destroy_waste(session, REGION, yes=True, dry_run=False) == 0
    result = run_scan(session, REGION)
    assert result.summary.by_rule["unattached_volume"] == 0
    assert result.summary.by_rule["idle_elastic_ip"] == 0
    assert result.summary.by_rule["open_security_group"] == 0
    assert result.summary.by_rule["missing_tags"] == 0


def test_destroy_does_not_delete_untagged_volume(session, monkeypatch):
    _align_account(session, monkeypatch)
    create_waste(session, REGION, yes=True, dry_run=False)
    ec2 = session.client("ec2", region_name=REGION)
    extra_id = create_volume(ec2, tags=[{"Key": "keep", "Value": "me"}])
    destroy_waste(session, REGION, yes=True, dry_run=False)
    remaining = {item["VolumeId"] for item in ec2.describe_volumes()["Volumes"]}
    assert extra_id in remaining


def test_safety_guard_wrong_account(session, monkeypatch):
    monkeypatch.setenv("CLOUDSWEEP_ALLOWED_ACCOUNT_ID", "000000000000")
    get_settings.cache_clear()
    with pytest.raises(SystemExit, match="does not match"):
        assert_safe_account(session)


def test_safety_guard_missing_account(session, monkeypatch):
    monkeypatch.delenv("CLOUDSWEEP_ALLOWED_ACCOUNT_ID", raising=False)
    get_settings.cache_clear()
    with pytest.raises(SystemExit, match="is not set"):
        assert_safe_account(session)


def test_dry_run_creates_nothing(session, monkeypatch):
    _align_account(session, monkeypatch)
    assert create_waste(session, REGION, yes=True, dry_run=True) == 0
    result = run_scan(session, REGION)
    assert result.summary.by_rule["unattached_volume"] == 0
    assert result.summary.by_rule["idle_elastic_ip"] == 0


def test_create_without_yes_creates_nothing(session, monkeypatch):
    _align_account(session, monkeypatch)
    assert create_waste(session, REGION, yes=False, dry_run=False) == 0
    result = run_scan(session, REGION)
    assert result.summary.total_findings == 0


def test_second_create_requires_destroy(session, monkeypatch):
    _align_account(session, monkeypatch)
    assert create_waste(session, REGION, yes=True, dry_run=False) == 0
    assert create_waste(session, REGION, yes=True, dry_run=False) == 1


def test_sandbox_tags_constant():
    assert SANDBOX_TAGS == [{"Key": "sandbox", "Value": "cloudsweep"}]
