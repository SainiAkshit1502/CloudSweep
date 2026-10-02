"""Run CloudSweep in demo mode using moto mock data (no AWS credentials needed).

Usage:
    python -m scripts.demo_dashboard
    # or: python scripts/demo_dashboard.py
"""

from __future__ import annotations

import os

# Set dummy credentials before boto3 imports
os.environ["AWS_ACCESS_KEY_ID"] = "testing"
os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
os.environ["AWS_SECURITY_TOKEN"] = "testing"
os.environ["AWS_SESSION_TOKEN"] = "testing"
os.environ["AWS_DEFAULT_REGION"] = "ap-south-1"
os.environ["AWS_REGION"] = "ap-south-1"
os.environ["CLOUDSWEEP_ALLOWED_ACCOUNT_ID"] = "123456789012"
os.environ["REQUIRED_TAGS"] = "owner,env"
os.environ["SENSITIVE_PORTS"] = "22,3389"

import boto3  # noqa: E402
import uvicorn  # noqa: E402
from moto import mock_aws  # noqa: E402

from api.main import _store, app, get_session  # noqa: E402
from scanner.config import get_settings  # noqa: E402
from scanner.runner import run_scan  # noqa: E402

REGION = "ap-south-1"
SANDBOX_TAGS = [{"Key": "sandbox", "Value": "cloudsweep"}]


def _populate_mock_waste(session: boto3.Session) -> None:
    """Create 5 sandbox-style demo resources inside the moto mock."""

    ec2 = session.client("ec2", region_name=REGION)
    s3 = session.client("s3", region_name=REGION)

    # 1. Orphan 1 GB gp3 volume (unattached + untagged for owner/env -> 2 findings)
    ec2.create_volume(
        AvailabilityZone=f"{REGION}a",
        Size=1,
        VolumeType="gp3",
        TagSpecifications=[{"ResourceType": "volume", "Tags": SANDBOX_TAGS}],
    )

    # 2. Idle Elastic IP (1 finding)
    ec2.allocate_address(
        Domain="vpc",
        TagSpecifications=[{"ResourceType": "elastic-ip", "Tags": SANDBOX_TAGS}],
    )

    # 3. Open SSH Security Group (1 finding)
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "isDefault", "Values": ["true"]}])["Vpcs"]
    vpc_id = vpcs[0]["VpcId"]
    group = ec2.create_security_group(
        GroupName="cloudsweep-open-ssh",
        Description="CloudSweep demo: SSH open to 0.0.0.0/0",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": SANDBOX_TAGS}],
    )
    ec2.authorize_security_group_ingress(
        GroupId=group["GroupId"],
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }
        ],
    )

    # 4. Untagged S3 bucket (missing owner/env -> 1 finding)
    bucket_name = "cloudsweep-sandbox-demo-waste-123456"
    s3.create_bucket(
        Bucket=bucket_name,
        CreateBucketConfiguration={"LocationConstraint": REGION},
    )
    s3.put_bucket_tagging(
        Bucket=bucket_name,
        Tagging={"TagSet": SANDBOX_TAGS},
    )


def main() -> None:
    """Start the mock environment, populate waste, run scan, and serve dashboard."""

    get_settings.cache_clear()
    with mock_aws():
        session = boto3.Session(region_name=REGION)
        _populate_mock_waste(session)

        # Pre-seed the initial scan so dashboard displays findings immediately
        scan_result = run_scan(session, REGION)
        _store(scan_result)

        # Ensure "Run scan" in the web UI re-scans the active mock session
        app.dependency_overrides[get_session] = lambda: session

        banner = (
            "\n"
            + "=" * 70
            + "\n"
            + "  DEMO MODE: mock data, not a real AWS account\n"
            + "  CloudSweep Dashboard: http://localhost:8000\n"
            + f"  Pre-loaded {scan_result.summary.total_findings} findings "
            + f"(est. monthly savings ${scan_result.summary.total_est_monthly_savings_usd:.2f})\n"
            + "  Press Ctrl+C to stop.\n"
            + "=" * 70
            + "\n"
        )
        print(banner)
        uvicorn.run(app, host="127.0.0.1", port=8000, log_level="info")


if __name__ == "__main__":
    main()
