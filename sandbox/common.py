"""Shared sandbox constants, account guard, and tagged-resource discovery."""

from __future__ import annotations

from dataclasses import dataclass, field

import boto3
from botocore.exceptions import ClientError

from scanner.config import get_settings

SANDBOX_TAG_KEY = "sandbox"
SANDBOX_TAG_VALUE = "cloudsweep"
SANDBOX_TAGS = [{"Key": SANDBOX_TAG_KEY, "Value": SANDBOX_TAG_VALUE}]
TAG_FILTER = [{"Name": f"tag:{SANDBOX_TAG_KEY}", "Values": [SANDBOX_TAG_VALUE]}]


@dataclass
class SandboxInventory:
    """Resources tagged sandbox=cloudsweep in one region."""

    volumes: list[dict] = field(default_factory=list)
    addresses: list[dict] = field(default_factory=list)
    security_groups: list[dict] = field(default_factory=list)
    buckets: list[str] = field(default_factory=list)

    def is_empty(self) -> bool:
        """Return True when nothing tagged as sandbox exists."""

        return not (self.volumes or self.addresses or self.security_groups or self.buckets)

    def describe(self) -> list[str]:
        """Human-readable IDs for logging."""

        lines: list[str] = []
        for volume in self.volumes:
            lines.append(f"volume {volume['VolumeId']}")
        for address in self.addresses:
            lines.append(f"elastic-ip {address.get('AllocationId') or address.get('PublicIp')}")
        for group in self.security_groups:
            lines.append(f"security-group {group['GroupId']}")
        for bucket in self.buckets:
            lines.append(f"bucket {bucket}")
        return lines


def assert_safe_account(session: boto3.Session) -> str:
    """Abort unless CLOUDSWEEP_ALLOWED_ACCOUNT_ID matches the caller's account."""

    allowed = get_settings().allowed_account_id
    identity = session.client("sts").get_caller_identity()
    account_id = identity["Account"]
    if not allowed:
        raise SystemExit(
            "Refusing to run: CLOUDSWEEP_ALLOWED_ACCOUNT_ID is not set. "
            "Set it to your 12-digit AWS account ID."
        )
    if allowed != account_id:
        raise SystemExit(
            f"Refusing to run: configured account {allowed} does not match caller {account_id}."
        )
    return account_id


def _pages(client: object, operation: str, **kwargs: object) -> list[dict]:
    """Collect pages for a boto3 operation."""

    if client.can_paginate(operation):  # type: ignore[union-attr]
        return list(client.get_paginator(operation).paginate(**kwargs))  # type: ignore[union-attr]
    return [getattr(client, operation)(**kwargs)]


def _bucket_has_sandbox_tag(s3: object, bucket: str) -> bool:
    try:
        response = s3.get_bucket_tagging(Bucket=bucket)  # type: ignore[union-attr]
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code in {"NoSuchTagSet", "NoSuchTagSetError"}:
            return False
        raise
    tags = {item["Key"]: item["Value"] for item in response.get("TagSet") or []}
    return tags.get(SANDBOX_TAG_KEY) == SANDBOX_TAG_VALUE


def discover_sandbox_resources(session: boto3.Session, region: str) -> SandboxInventory:
    """Find only resources tagged sandbox=cloudsweep."""

    ec2 = session.client("ec2", region_name=region)
    s3 = session.client("s3", region_name=region)
    inventory = SandboxInventory()
    for page in _pages(ec2, "describe_volumes", Filters=TAG_FILTER):
        inventory.volumes.extend(page.get("Volumes", []))
    for page in _pages(ec2, "describe_addresses", Filters=TAG_FILTER):
        inventory.addresses.extend(page.get("Addresses", []))
    for page in _pages(ec2, "describe_security_groups", Filters=TAG_FILTER):
        inventory.security_groups.extend(page.get("SecurityGroups", []))
    for page in _pages(s3, "list_buckets"):
        for bucket in page.get("Buckets", []):
            name = bucket["Name"]
            if _bucket_has_sandbox_tag(s3, name):
                inventory.buckets.append(name)
    return inventory
