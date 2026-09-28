"""Delete only resources tagged sandbox=cloudsweep.

Run: python -m sandbox.destroy_waste --yes
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

import boto3
from botocore.exceptions import ClientError

from sandbox.common import assert_safe_account, discover_sandbox_resources
from scanner.config import build_session, get_settings


def _empty_bucket(s3: object, bucket: str) -> None:
    paginator = s3.get_paginator("list_objects_v2")  # type: ignore[union-attr]
    for page in paginator.paginate(Bucket=bucket):
        for obj in page.get("Contents") or []:
            s3.delete_object(Bucket=bucket, Key=obj["Key"])  # type: ignore[union-attr]


def destroy_waste(session: boto3.Session, region: str, *, yes: bool, dry_run: bool) -> int:
    """Delete sandbox-tagged security groups, EIPs, volumes, then buckets."""

    assert_safe_account(session)
    inventory = discover_sandbox_resources(session, region)
    if inventory.is_empty():
        print("No sandbox=cloudsweep resources found.")
        return 0

    print("Would delete:" if (dry_run or not yes) else "Deleting:")
    for line in inventory.describe():
        print(f"  - {line}")

    if dry_run:
        print("Dry run: nothing deleted.")
        return 0
    if not yes:
        print("Pass --yes to delete these resources.")
        return 0

    ec2 = session.client("ec2", region_name=region)
    s3 = session.client("s3", region_name=region)
    failures: list[str] = []

    for group in inventory.security_groups:
        group_id = group["GroupId"]
        try:
            ec2.delete_security_group(GroupId=group_id)
            print(f"Deleted security group {group_id}")
        except ClientError as exc:
            failures.append(f"{group_id}: {exc}")
            print(f"Failed to delete security group {group_id}: {exc}")

    for address in inventory.addresses:
        allocation_id = address.get("AllocationId")
        try:
            if not allocation_id:
                raise RuntimeError("missing AllocationId")
            ec2.release_address(AllocationId=allocation_id)
            print(f"Released Elastic IP {allocation_id}")
        except (ClientError, RuntimeError) as exc:
            failures.append(f"{allocation_id}: {exc}")
            print(f"Failed to release Elastic IP {allocation_id}: {exc}")

    for volume in inventory.volumes:
        volume_id = volume["VolumeId"]
        state = volume.get("State")
        if state != "available":
            warning = f"Skipped volume {volume_id}: state is {state}, expected available"
            print(warning)
            failures.append(warning)
            continue
        try:
            ec2.delete_volume(VolumeId=volume_id)
            print(f"Deleted volume {volume_id}")
        except ClientError as exc:
            failures.append(f"{volume_id}: {exc}")
            print(f"Failed to delete volume {volume_id}: {exc}")

    for bucket in inventory.buckets:
        try:
            _empty_bucket(s3, bucket)
            s3.delete_bucket(Bucket=bucket)
            print(f"Deleted bucket {bucket}")
        except ClientError as exc:
            failures.append(f"{bucket}: {exc}")
            print(f"Failed to delete bucket {bucket}: {exc}")

    if failures:
        print("Some deletions failed:")
        for item in failures:
            print(f"  - {item}")
        return 1
    print("Sandbox cleanup finished.")
    return 0


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    """Parse destroy_waste CLI flags."""

    settings = get_settings()
    parser = argparse.ArgumentParser(description="Destroy tagged CloudSweep demo waste.")
    parser.add_argument("--region", default=settings.aws_region)
    parser.add_argument("--profile", default="cloudsweep-sandbox")
    parser.add_argument("--yes", action="store_true", help="Actually delete resources")
    parser.add_argument("--dry-run", action="store_true", help="Print the plan and exit")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    """CLI wrapper around destroy_waste."""

    args = parse_args(argv)
    try:
        session = build_session(profile=args.profile, region=args.region)
        return destroy_waste(session, args.region, yes=args.yes, dry_run=args.dry_run)
    except SystemExit as exc:
        if exc.code is None or exc.code == 0:
            return 0
        if isinstance(exc.code, str):
            print(exc.code, file=sys.stderr)
            return 1
        return int(exc.code)


if __name__ == "__main__":
    sys.exit(main())
