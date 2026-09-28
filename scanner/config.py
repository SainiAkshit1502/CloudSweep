"""Environment-driven settings and boto3 session construction."""

from dataclasses import dataclass
from functools import lru_cache
from os import getenv

import boto3


@dataclass(frozen=True)
class Settings:
    """Runtime configuration loaded from environment variables."""

    aws_region: str
    aws_profile: str | None
    required_tags: tuple[str, ...]
    sensitive_ports: tuple[int, ...]
    report_path: str
    allowed_account_id: str | None


def _split_csv(value: str) -> tuple[str, ...]:
    return tuple(part.strip() for part in value.split(",") if part.strip())


@lru_cache
def get_settings() -> Settings:
    """Return cached settings. Call ``cache_clear()`` in tests after env changes."""

    profile = getenv("AWS_PROFILE")
    allowed = getenv("CLOUDSWEEP_ALLOWED_ACCOUNT_ID")
    return Settings(
        aws_region=getenv("AWS_REGION", "ap-south-1"),
        aws_profile=profile or None,
        required_tags=_split_csv(getenv("REQUIRED_TAGS", "owner,env")),
        sensitive_ports=tuple(int(p) for p in _split_csv(getenv("SENSITIVE_PORTS", "22,3389"))),
        report_path=getenv("REPORT_PATH", "report.json"),
        allowed_account_id=allowed.strip() if allowed else None,
    )


def build_session(profile: str | None = None, region: str | None = None) -> boto3.Session:
    """Create a boto3 session from an optional profile and region.

    When no profile is set, boto3 uses the default credential chain (env vars, instance role).
    """

    settings = get_settings()
    chosen_profile = profile if profile is not None else settings.aws_profile
    chosen_region = region or settings.aws_region
    kwargs: dict[str, str] = {"region_name": chosen_region}
    if chosen_profile:
        kwargs["profile_name"] = chosen_profile
    return boto3.Session(**kwargs)
