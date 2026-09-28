"""Rule tests against moto. No real AWS calls."""

from __future__ import annotations

import pytest
from botocore.exceptions import ClientError

from scanner.rules import (
    idle_elastic_ips,
    missing_tags,
    open_security_groups,
    unattached_volumes,
)
from tests.conftest import REGION, create_volume, default_vpc_id, first_image_id, run_instance

REQUIRED = [{"Key": "owner", "Value": "ada"}, {"Key": "env", "Value": "test"}]


def test_unattached_volume_found(session):
    ec2 = session.client("ec2", region_name=REGION)
    volume_id = create_volume(ec2)
    findings = unattached_volumes(session, REGION)
    assert len(findings) == 1
    assert findings[0].resource_id == volume_id
    assert findings[0].rule == "unattached_volume"
    assert findings[0].severity.value == "medium"


def test_unattached_volume_ignores_attached(session):
    ec2 = session.client("ec2", region_name=REGION)
    instance_id = run_instance(ec2)
    volume_id = create_volume(ec2)
    ec2.attach_volume(VolumeId=volume_id, InstanceId=instance_id, Device="/dev/sdf")
    assert unattached_volumes(session, REGION) == []


def test_unattached_volume_empty_account(session):
    assert unattached_volumes(session, REGION) == []


def test_unattached_volume_pagination(session):
    ec2 = session.client("ec2", region_name=REGION)
    create_volume(ec2)
    create_volume(ec2)
    findings = unattached_volumes(session, REGION)
    assert len(findings) == 2


def test_idle_eip_found(session):
    ec2 = session.client("ec2", region_name=REGION)
    allocation = ec2.allocate_address(Domain="vpc")
    findings = idle_elastic_ips(session, REGION)
    assert len(findings) == 1
    assert findings[0].resource_id == allocation["AllocationId"]
    assert findings[0].rule == "idle_elastic_ip"


def test_idle_eip_ignores_associated(session):
    ec2 = session.client("ec2", region_name=REGION)
    instance_id = run_instance(ec2)
    allocation = ec2.allocate_address(Domain="vpc")
    ec2.associate_address(AllocationId=allocation["AllocationId"], InstanceId=instance_id)
    assert idle_elastic_ips(session, REGION) == []


def test_idle_eip_empty_account(session):
    assert idle_elastic_ips(session, REGION) == []


def _create_sg(ec2, name: str, ip_permissions: list[dict]) -> str:
    group_id = ec2.create_security_group(
        GroupName=name,
        Description="test",
        VpcId=default_vpc_id(ec2),
    )["GroupId"]
    if ip_permissions:
        ec2.authorize_security_group_ingress(GroupId=group_id, IpPermissions=ip_permissions)
    return group_id


def test_open_sg_ssh(session):
    ec2 = session.client("ec2", region_name=REGION)
    group_id = _create_sg(
        ec2,
        "open-ssh",
        [
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }
        ],
    )
    findings = open_security_groups(session, REGION)
    assert any(item.resource_id == group_id and "port 22" in item.detail for item in findings)
    assert all(item.severity.value == "high" for item in findings if item.resource_id == group_id)


def test_open_sg_ignores_private_cidr(session):
    ec2 = session.client("ec2", region_name=REGION)
    _create_sg(
        ec2,
        "private-ssh",
        [
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "10.0.0.0/8"}],
            }
        ],
    )
    assert open_security_groups(session, REGION) == []


def test_open_sg_empty_account(session):
    assert open_security_groups(session, REGION) == []


def test_open_sg_all_traffic(session):
    ec2 = session.client("ec2", region_name=REGION)
    group_id = _create_sg(
        ec2,
        "open-all",
        [{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}],
    )
    findings = open_security_groups(session, REGION)
    assert any(item.resource_id == group_id and "all traffic" in item.detail for item in findings)


def test_open_sg_port_range_covers_22(session):
    ec2 = session.client("ec2", region_name=REGION)
    group_id = _create_sg(
        ec2,
        "range-ssh",
        [
            {
                "IpProtocol": "tcp",
                "FromPort": 20,
                "ToPort": 30,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }
        ],
    )
    findings = open_security_groups(session, REGION)
    assert any(item.resource_id == group_id and "port 22" in item.detail for item in findings)


def test_open_sg_ipv6_and_udp_ignored(session):
    ec2 = session.client("ec2", region_name=REGION)
    ssh_v6 = _create_sg(
        ec2,
        "open-ssh-v6",
        [
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
            }
        ],
    )
    _create_sg(
        ec2,
        "open-udp",
        [
            {
                "IpProtocol": "udp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }
        ],
    )
    findings = open_security_groups(session, REGION)
    assert any(item.resource_id == ssh_v6 for item in findings)
    assert all("open-udp" not in item.detail for item in findings)


def test_tagged_s3_bucket_not_flagged(session):
    s3 = session.client("s3", region_name=REGION)
    s3.create_bucket(
        Bucket="cloudsweep-tagged-ok",
        CreateBucketConfiguration={"LocationConstraint": REGION},
    )
    s3.put_bucket_tagging(
        Bucket="cloudsweep-tagged-ok",
        Tagging={"TagSet": REQUIRED},
    )
    findings = missing_tags(session, REGION)
    assert all(item.resource_id != "cloudsweep-tagged-ok" for item in findings)


def test_open_sg_port_80_not_flagged(session):
    ec2 = session.client("ec2", region_name=REGION)
    _create_sg(
        ec2,
        "open-http",
        [
            {
                "IpProtocol": "tcp",
                "FromPort": 80,
                "ToPort": 80,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }
        ],
    )
    assert open_security_groups(session, REGION) == []


def test_missing_tags_volume(session):
    ec2 = session.client("ec2", region_name=REGION)
    volume_id = create_volume(ec2)
    findings = missing_tags(session, REGION)
    assert any(item.resource_id == volume_id and item.rule == "missing_tags" for item in findings)


def test_missing_tags_ignores_fully_tagged_volume(session):
    ec2 = session.client("ec2", region_name=REGION)
    create_volume(ec2, tags=REQUIRED)
    volume_findings = [
        item for item in missing_tags(session, REGION) if item.resource_type == "ebs_volume"
    ]
    assert volume_findings == []


def test_missing_tags_empty_account(session):
    assert missing_tags(session, REGION) == []


def test_missing_tags_s3_no_tag_set(session):
    s3 = session.client("s3", region_name=REGION)
    s3.create_bucket(
        Bucket="cloudsweep-notags-abc123",
        CreateBucketConfiguration={"LocationConstraint": REGION},
    )
    with pytest.raises(ClientError) as exc:
        s3.get_bucket_tagging(Bucket="cloudsweep-notags-abc123")
    assert exc.value.response["Error"]["Code"] in {"NoSuchTagSet", "NoSuchTagSetError"}
    findings = missing_tags(session, REGION)
    assert any(item.resource_id == "cloudsweep-notags-abc123" for item in findings)


def test_missing_tags_skips_terminated_instance(session):
    ec2 = session.client("ec2", region_name=REGION)
    instance_id = run_instance(ec2)
    ec2.terminate_instances(InstanceIds=[instance_id])
    findings = missing_tags(session, REGION)
    assert all(item.resource_id != instance_id for item in findings)


def test_missing_tags_flags_running_instance(session):
    ec2 = session.client("ec2", region_name=REGION)
    instance_id = run_instance(ec2)
    findings = missing_tags(session, REGION)
    assert any(
        item.resource_id == instance_id and item.resource_type == "ec2_instance"
        for item in findings
    )


def test_missing_tags_ignores_bucket_in_other_region(session):
    s3 = session.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="cloudsweep-useast-notags")
    findings = missing_tags(session, REGION)
    assert all(item.resource_id != "cloudsweep-useast-notags" for item in findings)


def test_first_image_exists(session):
    ec2 = session.client("ec2", region_name=REGION)
    assert first_image_id(ec2)
