"""FastAPI service wrapping ``run_scan`` plus a Jinja2 dashboard."""

from __future__ import annotations

import threading
from datetime import datetime
from pathlib import Path
from typing import Annotated

from botocore.exceptions import (
    BotoCoreError,
    ClientError,
    NoCredentialsError,
    PartialCredentialsError,
)
from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from scanner.config import build_session, get_settings
from scanner.models import Finding, ScanResult, ScanSummary
from scanner.runner import run_scan

app = FastAPI(title="CloudSweep", description="Scan AWS for wasted spend and risky firewall rules.")
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))


def format_datetime(value: datetime | str | None) -> str:
    """Format a datetime or ISO string as 'YYYY-MM-DD HH:MM UTC'."""
    if not value:
        return ""
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value)
        except ValueError:
            return value
    return value.strftime("%Y-%m-%d %H:%M UTC")


templates.env.filters["format_datetime"] = format_datetime

_lock = threading.Lock()
_latest: ScanResult | None = None


def reset_store() -> None:
    """Clear the in-memory latest scan (used by tests)."""

    global _latest
    with _lock:
        _latest = None


def get_session():
    """FastAPI dependency that builds a boto3 session from settings."""

    return build_session()


def _store(result: ScanResult) -> None:
    global _latest
    with _lock:
        _latest = result
    path = get_settings().report_path
    Path(path).write_text(result.model_dump_json(indent=2), encoding="utf-8")


def _require_latest() -> ScanResult:
    with _lock:
        if _latest is None:
            raise HTTPException(status_code=404, detail="No scan has been run yet")
        return _latest


def _is_credential_error(exc: Exception) -> bool:
    if isinstance(exc, (NoCredentialsError, PartialCredentialsError)):
        return True
    if isinstance(exc, ClientError):
        code = exc.response.get("Error", {}).get("Code", "")
        return code in {
            "InvalidClientTokenId",
            "AuthFailure",
            "ExpiredToken",
            "UnrecognizedClientException",
            "InvalidUserID.NotFound",
        }
    return False


@app.get("/health")
def health() -> dict[str, str]:
    """Liveness probe."""

    return {"status": "ok"}


@app.post("/scan", response_model=ScanResult)
def scan(session: Annotated[object, Depends(get_session)]) -> ScanResult:
    """Run a synchronous scan and store it as the latest result."""

    settings = get_settings()
    try:
        result = run_scan(session, settings.aws_region)  # type: ignore[arg-type]
    except Exception as exc:
        if _is_credential_error(exc) or isinstance(exc, BotoCoreError):
            raise HTTPException(
                status_code=503,
                detail=(
                    "AWS credentials are missing or invalid. "
                    "Configure a profile or environment variables."
                ),
            ) from exc
        raise
    _store(result)
    return result


@app.get("/findings", response_model=list[Finding])
def findings(
    severity: Annotated[str | None, Query()] = None,
    rule: Annotated[str | None, Query()] = None,
) -> list[Finding]:
    """Return the latest findings, optionally filtered."""

    result = _require_latest()
    items = result.findings
    if severity:
        items = [item for item in items if item.severity.value == severity]
    if rule:
        items = [item for item in items if item.rule == rule]
    return items


@app.get("/summary", response_model=ScanSummary)
def summary() -> ScanSummary:
    """Return the latest scan summary."""

    return _require_latest().summary


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request) -> HTMLResponse:
    """Server-rendered dashboard for the latest scan."""

    settings = get_settings()
    with _lock:
        latest = _latest
    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={
            "result": latest,
            "region": latest.region if latest else settings.aws_region,
        },
    )
