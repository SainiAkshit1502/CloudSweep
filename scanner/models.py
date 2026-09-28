"""Pydantic models for scan findings and results."""

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field


class Severity(str, Enum):
    """Relative urgency of a finding."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Finding(BaseModel):
    """A single wasted resource or misconfiguration."""

    rule: str
    resource_type: str
    resource_id: str
    region: str
    severity: Severity
    est_monthly_cost_usd: float
    detail: str
    recommendation: str


class ScanSummary(BaseModel):
    """Aggregated counts and estimated savings for a scan."""

    total_findings: int
    by_severity: dict[str, int]
    by_rule: dict[str, int]
    total_est_monthly_savings_usd: float


class ScanResult(BaseModel):
    """Complete output of one account/region scan."""

    scan_id: str
    account_id: str
    region: str
    started_at: datetime
    finished_at: datetime
    findings: list[Finding]
    summary: ScanSummary
    pricing_note: str
    errors: list[str] = Field(default_factory=list)
