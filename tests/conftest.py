"""Shared pytest fixtures. Fake credentials only — never real AWS."""

from __future__ import annotations

import boto3
import pytest
from moto import mock_aws

from scanner.config import get_settings

REGION = "ap-south-1"


@pytest.fixture(autouse=True)
def fake_aws_credentials(monkeypatch: pytest.MonkeyPatch):
    """Point boto3 at dummy keys so tests cannot use a real account."""

    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)
    monkeypatch.setenv("AWS_REGION", REGION)
    monkeypatch.setenv("REQUIRED_TAGS", "owner,env")
    monkeypatch.setenv("SENSITIVE_PORTS", "22,3389")
    monkeypatch.setenv("CLOUDSWEEP_ALLOWED_ACCOUNT_ID", "123456789012")
    monkeypatch.delenv("AWS_PROFILE", raising=False)
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture
def aws():
    """Moto backend for EC2, S3 and STS."""

    with mock_aws():
        yield


@pytest.fixture
def session(aws) -> boto3.Session:
    """boto3 session bound to the mocked region."""

    return boto3.Session(region_name=REGION)


def create_volume(
    ec2, *, size: int = 1, volume_type: str = "gp3", tags: list[dict] | None = None
) -> str:
    """Create an EBS volume in the mock account."""

    kwargs: dict = {
        "AvailabilityZone": f"{REGION}a",
        "Size": size,
        "VolumeType": volume_type,
    }
    if tags:
        kwargs["TagSpecifications"] = [{"ResourceType": "volume", "Tags": tags}]
    return ec2.create_volume(**kwargs)["VolumeId"]


def first_image_id(ec2) -> str:
    """Return any AMI moto provides."""

    images = ec2.describe_images()["Images"]
    return images[0]["ImageId"]


def run_instance(ec2, *, tags: list[dict] | None = None) -> str:
    """Launch a tiny mock instance."""

    kwargs: dict = {
        "ImageId": first_image_id(ec2),
        "MinCount": 1,
        "MaxCount": 1,
    }
    if tags:
        kwargs["TagSpecifications"] = [{"ResourceType": "instance", "Tags": tags}]
    return ec2.run_instances(**kwargs)["Instances"][0]["InstanceId"]


def default_vpc_id(ec2) -> str:
    """Return the default VPC id."""

    vpcs = ec2.describe_vpcs(Filters=[{"Name": "isDefault", "Values": ["true"]}])["Vpcs"]
    return vpcs[0]["VpcId"]
