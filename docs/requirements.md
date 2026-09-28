# CloudSweep requirements

## Problem statement

Teams leave unused AWS resources running and accidentally open administrative ports to the internet. Finding those issues in the console is slow. CloudSweep scans one AWS account and region, reports wasted spend and risky firewall rules, and never changes anything.

## Users

- Cloud or platform engineers who want a cheap, repeatable waste/security check.
- Students and interview candidates demonstrating AWS + Python automation.
- A CI job that runs a read-only nightly scan.

## Functional requirements

| ID | Requirement |
|---|---|
| F1 | Detect unattached EBS volumes (`status=available`) and estimate monthly storage cost. |
| F2 | Detect idle Elastic IPs (no `AssociationId`) and estimate monthly public IPv4 cost. |
| F3 | Detect security groups with world-open (`0.0.0.0/0` or `::/0`) SSH (22), RDP (3389), or all traffic. |
| F4 | Detect EC2 instances, EBS volumes, and in-region S3 buckets missing required tags (`owner`, `env` by default). Skip terminated instances. Treat `NoSuchTagSet` as empty tags. |
| F5 | Produce a `ScanResult` with findings, severity, summary counts, and total estimated monthly savings. |
| F6 | CLI (`python -m scanner.cli`) prints a table, writes JSON, and supports `--fail-on` exit codes. |
| F7 | FastAPI service: `/health`, `POST /scan`, `GET /findings`, `GET /summary`, HTML dashboard at `/`. |
| F8 | Sandbox scripts create and destroy tagged demo waste (`sandbox=cloudsweep`) behind an account-ID guard. |
| F9 | Scanner uses only read-only AWS APIs (`Describe*`, `List*`, `Get*`). |

## Non-functional requirements

- **Security:** scanner identity is read-only; sandbox identity is separate; no credentials in Git or the Docker image.
- **Cost safety:** sandbox resources are tiny (1 GB volume, one EIP, one SG, one empty bucket); destroy only tagged resources.
- **Testability:** unit tests use moto and dummy credentials; no test may call real AWS.
- **Operability:** default region `ap-south-1`; configuration via environment variables.
- **Quality:** ruff-clean Python 3.12; ≥ 85% coverage on `scanner/`.

## Assumptions

- A default VPC exists in the scanned region (required for the sandbox security group).
- Approximate list prices in `scanner/pricing.py` are good enough for demos; they are not a bill.
- One account and one region per run.

## Out of scope

Auto-remediation, multi-account/multi-region scanning, databases, authentication, frontend frameworks, Terraform/CloudFormation, idle-EC2 CPU detection.
