"""Create cheap, tagged waste so the scanner has something to find.

Run: python -m sandbox.create_waste --yes
"""

from __future__ import annotations

import argparse
import random
import string
import sys
from collections.abc import Sequence

import boto3

from sandbox.common import (
    SANDBOX_TAGS,
    assert_safe_account,
    discover_sandbox_resources,
)
from scanner.config import build_session, get_settings


def _random_suffix(length: int = 6) -> str:
    return "".join(random.choices(string.ascii_lowercase, k=length))


def _default_vpc_id(ec2: object) -> str:
    response = ec2.describe_vpcs(Filters=[{"Name": "isDefault", "Values": ["true"]}])  # type: ignore[union-attr]
    vpcs = response.get("Vpcs") or []
    if not vpcs:
        raise SystemExit("No default VPC in this region. Create one or pick another region.")
    return vpcs[0]["VpcId"]


def _create_bucket(s3: object, name: str, region: str) -> None:
    if region == "us-east-1":
        s3.create_bucket(Bucket=name)  # type: ignore[union-attr]
    else:
        s3.create_bucket(  # type: ignore[union-attr]
            Bucket=name,
            CreateBucketConfiguration={"LocationConstraint": region},
        )
    s3.put_bucket_tagging(  # type: ignore[union-attr]
        Bucket=name,
        Tagging={"TagSet": SANDBOX_TAGS},
    )


def create_waste(session: boto3.Session, region: str, *, yes: bool, dry_run: bool) -> int:
    """Plant orphan volume, idle EIP, open SSH SG, and untagged-except-sandbox bucket."""

    account_id = assert_safe_account(session)
    existing = discover_sandbox_resources(session, region)
    if not existing.is_empty():
        print("Sandbox resources already exist. Run destroy_waste first:")
        for line in existing.describe():
            print(f"  - {line}")
        return 1

    az = f"{region}a"
    bucket_name = f"cloudsweep-sandbox-{account_id}-{_random_suffix()}"
    plan = [
        f"1 GB gp3 EBS volume in {az} (unattached)",
        "Idle Elastic IP (VPC)",
        "Security group cloudsweep-open-ssh with TCP 22 from 0.0.0.0/0",
        f"S3 bucket {bucket_name} tagged sandbox=cloudsweep only",
    ]
    print("Would create:" if (dry_run or not yes) else "Creating:")
    for item in plan:
        print(f"  - {item}")

    if dry_run:
        print("Dry run: nothing created.")
        return 0
    if not yes:
        print("Pass --yes to create these resources.")
        return 0

    ec2 = session.client("ec2", region_name=region)
    s3 = session.client("s3", region_name=region)

    volume = ec2.create_volume(
        AvailabilityZone=az,
        Size=1,
        VolumeType="gp3",
        TagSpecifications=[{"ResourceType": "volume", "Tags": SANDBOX_TAGS}],
    )
    print(f"Created volume {volume['VolumeId']}")

    address = ec2.allocate_address(
        Domain="vpc",
        TagSpecifications=[{"ResourceType": "elastic-ip", "Tags": SANDBOX_TAGS}],
    )
    print(f"Created Elastic IP {address.get('PublicIp')} ({address.get('AllocationId')})")

    vpc_id = _default_vpc_id(ec2)
    group = ec2.create_security_group(
        GroupName="cloudsweep-open-ssh",
        Description="CloudSweep demo: SSH open to the world (delete after demo)",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": SANDBOX_TAGS}],
    )
    group_id = group["GroupId"]
    ec2.authorize_security_group_ingress(
        GroupId=group_id,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0", "Description": "demo-only"}],
            }
        ],
    )
    print(f"Created security group {group_id} (cloudsweep-open-ssh)")

    _create_bucket(s3, bucket_name, region)
    print(f"Created bucket {bucket_name}")
    print("Run destroy_waste when you're done.")
    return 0


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    """Parse create_waste CLI flags."""

    settings = get_settings()
    parser = argparse.ArgumentParser(description="Create tagged CloudSweep demo waste.")
    parser.add_argument("--region", default=settings.aws_region)
    parser.add_argument("--profile", default="cloudsweep-sandbox")
    parser.add_argument("--yes", action="store_true", help="Actually create resources")
    parser.add_argument("--dry-run", action="store_true", help="Print the plan and exit")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    """CLI wrapper around create_waste."""

    args = parse_args(argv)
    try:
        session = build_session(profile=args.profile, region=args.region)
        return create_waste(session, args.region, yes=args.yes, dry_run=args.dry_run)
    except SystemExit as exc:
        if exc.code is None or exc.code == 0:
            return 0
        if isinstance(exc.code, str):
            print(exc.code, file=sys.stderr)
            return 1
        return int(exc.code)


if __name__ == "__main__":
    sys.exit(main())
