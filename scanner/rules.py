"""Read-only scanner rules. Each rule is (session, region) -> list[Finding]."""

from collections.abc import Callable

import boto3
from botocore.exceptions import ClientError

from scanner.config import get_settings
from scanner.models import Finding, Severity
from scanner.pricing import ebs_monthly_cost, eip_monthly_cost

RuleFn = Callable[[boto3.Session, str], list[Finding]]

WORLD_IPV4 = "0.0.0.0/0"
WORLD_IPV6 = "::/0"


def _pages(client: object, operation: str, **kwargs: object) -> list[dict]:
    """Yield operation pages using a paginator when boto3 provides one."""

    pages: list[dict] = []
    if client.can_paginate(operation):  # type: ignore[union-attr]
        paginator = client.get_paginator(operation)  # type: ignore[union-attr]
        for page in paginator.paginate(**kwargs):
            pages.append(page)
    else:
        pages.append(getattr(client, operation)(**kwargs))
    return pages


def _tag_map(tags: list[dict] | None) -> dict[str, str]:
    if not tags:
        return {}
    return {item["Key"]: item["Value"] for item in tags}


def unattached_volumes(session: boto3.Session, region: str) -> list[Finding]:
    """Flag EBS volumes in available (unattached) state."""

    ec2 = session.client("ec2", region_name=region)
    findings: list[Finding] = []
    for page in _pages(
        ec2,
        "describe_volumes",
        Filters=[{"Name": "status", "Values": ["available"]}],
    ):
        for volume in page.get("Volumes", []):
            volume_id = volume["VolumeId"]
            volume_type = volume.get("VolumeType", "gp2")
            size_gb = int(volume.get("Size", 0))
            cost = ebs_monthly_cost(volume_type, size_gb)
            findings.append(
                Finding(
                    rule="unattached_volume",
                    resource_type="ebs_volume",
                    resource_id=volume_id,
                    region=region,
                    severity=Severity.MEDIUM,
                    est_monthly_cost_usd=cost,
                    detail=(
                        f"Volume {volume_id} ({size_gb} GB, {volume_type}) "
                        "is not attached to any instance."
                    ),
                    recommendation="Snapshot if the data matters, then delete the volume.",
                )
            )
    return findings


def idle_elastic_ips(session: boto3.Session, region: str) -> list[Finding]:
    """Flag Elastic IPs that are not associated with a resource."""

    ec2 = session.client("ec2", region_name=region)
    findings: list[Finding] = []
    cost = eip_monthly_cost()
    for page in _pages(ec2, "describe_addresses"):
        for address in page.get("Addresses", []):
            if address.get("AssociationId"):
                continue
            allocation_id = address.get("AllocationId") or address.get("PublicIp", "unknown")
            public_ip = address.get("PublicIp", "unknown")
            findings.append(
                Finding(
                    rule="idle_elastic_ip",
                    resource_type="elastic_ip",
                    resource_id=allocation_id,
                    region=region,
                    severity=Severity.MEDIUM,
                    est_monthly_cost_usd=cost,
                    detail=(
                        f"Elastic IP {public_ip} ({allocation_id}) "
                        "is not associated with any instance."
                    ),
                    recommendation="Release the Elastic IP if it is not needed.",
                )
            )
    return findings


def _permission_world_sources(permission: dict) -> set[str]:
    sources: set[str] = set()
    for ip_range in permission.get("IpRanges") or []:
        if ip_range.get("CidrIp") == WORLD_IPV4:
            sources.add(WORLD_IPV4)
    for ipv6_range in permission.get("Ipv6Ranges") or []:
        if ipv6_range.get("CidrIpv6") == WORLD_IPV6:
            sources.add(WORLD_IPV6)
    return sources


def open_security_groups(session: boto3.Session, region: str) -> list[Finding]:
    """Flag security groups that expose SSH, RDP, or all traffic to the world."""

    settings = get_settings()
    sensitive = set(settings.sensitive_ports)
    ec2 = session.client("ec2", region_name=region)
    findings: list[Finding] = []
    recommendation = "Restrict the source to a known IP range or use SSM Session Manager."
    seen: set[tuple[str, int | str]] = set()

    for page in _pages(ec2, "describe_security_groups"):
        for group in page.get("SecurityGroups", []):
            group_id = group["GroupId"]
            group_name = group.get("GroupName", "")
            exposed: dict[int | str, set[str]] = {}

            for permission in group.get("IpPermissions") or []:
                sources = _permission_world_sources(permission)
                if not sources:
                    continue
                protocol = permission.get("IpProtocol", "")
                if protocol == "-1":
                    exposed.setdefault("all traffic", set()).update(sources)
                    continue
                if protocol != "tcp":
                    continue
                from_port = permission.get("FromPort")
                to_port = permission.get("ToPort")
                if from_port is None or to_port is None:
                    continue
                for port in sorted(sensitive):
                    if from_port <= port <= to_port:
                        exposed.setdefault(port, set()).update(sources)

            targets: list[int | str] = []
            if "all traffic" in exposed:
                targets.append("all traffic")
            targets.extend(sorted(p for p in exposed if isinstance(p, int)))

            for target in targets:
                key = (group_id, target)
                if key in seen:
                    continue
                seen.add(key)
                sources = exposed[target]
                if WORLD_IPV4 in sources and WORLD_IPV6 in sources:
                    src_str = f"{WORLD_IPV4} and {WORLD_IPV6}"
                elif WORLD_IPV4 in sources:
                    src_str = WORLD_IPV4
                else:
                    src_str = WORLD_IPV6

                if target == "all traffic":
                    detail = (
                        f"Security group {group_id} ({group_name}) allows {src_str} on all traffic."
                    )
                else:
                    detail = (
                        f"Security group {group_id} ({group_name}) allows "
                        f"{src_str} on port {target}."
                    )

                findings.append(
                    Finding(
                        rule="open_security_group",
                        resource_type="security_group",
                        resource_id=group_id,
                        region=region,
                        severity=Severity.HIGH,
                        est_monthly_cost_usd=0.0,
                        detail=detail,
                        recommendation=recommendation,
                    )
                )
    return findings


def _missing_required(tags: dict[str, str], required: tuple[str, ...]) -> list[str]:
    return [key for key in required if key not in tags]


def _tag_finding(
    resource_type: str,
    resource_id: str,
    region: str,
    missing: list[str],
    label: str,
) -> Finding:
    missing_csv = ", ".join(missing)
    return Finding(
        rule="missing_tags",
        resource_type=resource_type,
        resource_id=resource_id,
        region=region,
        severity=Severity.LOW,
        est_monthly_cost_usd=0.0,
        detail=f"{label} {resource_id} is missing required tags: {missing_csv}.",
        recommendation="Add the missing tags so cost and ownership can be traced.",
    )


def _s3_bucket_region(s3: object, bucket: str) -> str:
    response = s3.get_bucket_location(Bucket=bucket)  # type: ignore[union-attr]
    constraint = response.get("LocationConstraint") or ""
    if constraint in ("", None):
        return "us-east-1"
    if constraint == "EU":
        return "eu-west-1"
    return constraint


def _s3_bucket_tags(s3: object, bucket: str) -> dict[str, str]:
    try:
        response = s3.get_bucket_tagging(Bucket=bucket)  # type: ignore[union-attr]
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code in {"NoSuchTagSet", "NoSuchTagSetError"}:
            return {}
        raise
    return _tag_map(response.get("TagSet"))


def missing_tags(session: boto3.Session, region: str) -> list[Finding]:
    """Flag EC2 instances, EBS volumes and in-region S3 buckets missing required tags."""

    required = get_settings().required_tags
    findings: list[Finding] = []
    ec2 = session.client("ec2", region_name=region)
    s3 = session.client("s3", region_name=region)

    for page in _pages(ec2, "describe_instances"):
        for reservation in page.get("Reservations", []):
            for instance in reservation.get("Instances", []):
                if instance.get("State", {}).get("Name") == "terminated":
                    continue
                instance_id = instance["InstanceId"]
                missing = _missing_required(_tag_map(instance.get("Tags")), required)
                if missing:
                    findings.append(
                        _tag_finding("ec2_instance", instance_id, region, missing, "Instance")
                    )

    for page in _pages(ec2, "describe_volumes"):
        for volume in page.get("Volumes", []):
            volume_id = volume["VolumeId"]
            missing = _missing_required(_tag_map(volume.get("Tags")), required)
            if missing:
                findings.append(_tag_finding("ebs_volume", volume_id, region, missing, "Volume"))

    for page in _pages(s3, "list_buckets"):
        for bucket in page.get("Buckets", []):
            name = bucket["Name"]
            if _s3_bucket_region(s3, name) != region:
                continue
            missing = _missing_required(_s3_bucket_tags(s3, name), required)
            if missing:
                findings.append(_tag_finding("s3_bucket", name, region, missing, "Bucket"))

    return findings


ALL_RULES: list[RuleFn] = [
    unattached_volumes,
    idle_elastic_ips,
    open_security_groups,
    missing_tags,
]
