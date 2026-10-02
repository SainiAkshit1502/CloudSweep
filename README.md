# CloudSweep

Python tool that scans **one AWS account and region** for wasted spend and risky firewall rules, then reports estimated monthly savings. It never modifies or deletes anything except the optional tagged sandbox.

It looks for:

1. Unattached EBS volumes
2. Idle Elastic IPs
3. Security groups open to the world on SSH, RDP, or all traffic
4. Missing `owner` / `env` tags on instances, volumes, and S3 buckets

## Two-minute quickstart

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements-dev.txt
pytest
```

## Demo mode (no AWS account needed)

Run CloudSweep with pre-seeded mock resources using moto without requiring real AWS credentials:

```bash
python -m scripts.demo_dashboard
```

Open http://localhost:8000 to view the dashboard pre-loaded with 5 demo findings.

## Real AWS usage

Against a real account (after the IAM setup in [docs/runbook.md](docs/runbook.md)):

```bash
python -m sandbox.create_waste --profile cloudsweep-sandbox --yes
python -m scanner.cli --profile cloudsweep-scanner
uvicorn api.main:app --port 8000
python -m sandbox.destroy_waste --profile cloudsweep-sandbox --yes
```

API: http://127.0.0.1:8000 — OpenAPI at `/docs`.

```bash
docker build -t cloudsweep .
docker run --rm -p 8000:8000 -e AWS_ACCESS_KEY_ID -e AWS_SECRET_ACCESS_KEY -e AWS_REGION=ap-south-1 cloudsweep
```

## Configuration

Copy [.env.example](.env.example) to `.env`:

```bash
cp .env.example .env
```

Key environment variables:
- `AWS_REGION`: Target AWS region (default: `ap-south-1`).
- `CLOUDSWEEP_ALLOWED_ACCOUNT_ID`: 12-digit AWS account ID guard required by sandbox scripts.
- `AWS_PROFILE`: Optional local AWS CLI profile name.
- `REQUIRED_TAGS`: Comma-separated tag keys every resource should have (default: `owner,env`).
- `SENSITIVE_PORTS`: Comma-separated ports monitored for open access (default: `22,3389`).

## Architecture

```mermaid
flowchart LR
  CLI[CLI] --> Runner
  API[FastAPI] --> Runner
  Runner --> Rules[Four read-only rules]
  Rules --> AWS[Describe / List / Get]
  Sandbox[sandbox scripts] --> TaggedAWS[Tagged demo resources]
```

## Dashboard

Dashboard (demo data)
![CloudSweep Dashboard](docs/images/dashboard.png)

## Docs

- [Project spec](docs/PROJECT_SPEC.md)
- [Requirements](docs/requirements.md)
- [Design](docs/design.md)
- [Test plan](docs/test_plan.md)
- [Runbook](docs/runbook.md)
- [IAM policies](docs/iam/README.md)

## Safety

- Scanner identity: read-only.
- Sandbox identity: separate, and it will not run unless `CLOUDSWEEP_ALLOWED_ACCOUNT_ID` matches the caller.
- Destroy only deletes resources tagged `sandbox=cloudsweep`.
