# CloudSweep test plan

## Strategy

- **Unit / service tests** use pytest and moto `mock_aws` with dummy credentials from `tests/conftest.py`. They must never call a real AWS account.
- **Manual integration** (optional, on your laptop): `create_waste` → CLI scan → dashboard → `destroy_waste` → re-scan.

## How to run

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements-dev.txt
ruff check .
ruff format --check .
pytest --cov=scanner --cov-report=term-missing
```

Coverage target: **≥ 85%** on `scanner/`.

## Test cases

| ID | Description | Expected |
|---|---|---|
| R1 | Unattached volume | One medium `unattached_volume` finding |
| R2 | Attached volume | No unattached finding |
| R3 | Empty account, each rule | `[]` |
| R4 | Idle EIP | One medium `idle_elastic_ip` finding |
| R5 | Associated EIP | Ignored |
| R6 | SG SSH 0.0.0.0/0 | High finding on port 22 |
| R7 | SG private CIDR | Ignored |
| R8 | SG protocol `-1` world-open | High “all traffic” finding |
| R9 | SG TCP 20–30 world-open | Finding for port 22 |
| R10 | SG TCP 80 only | Not flagged |
| R11 | Volume missing tags | Low finding |
| R12 | Fully tagged volume | Not flagged for tags |
| R13 | S3 `NoSuchTagSet` | Flagged |
| R14 | Terminated instance | Skipped |
| R15 | Two unattached volumes | Both found (pagination path) |
| U1 | Runner summary math and sort | High first; cost descending within severity |
| U2 | Rule raises | Scan continues; `errors` populated |
| C1 | CLI `--fail-on none` | Exit 0; JSON written; summary line printed |
| C2 | CLI `--fail-on medium` with volume | Exit 1 |
| C3 | Missing credentials | Exit 2 |
| A1 | `GET /health` | `{"status":"ok"}` |
| A2 | `GET /findings` before scan | 404 |
| A3 | `POST /scan` then filters | Findings and summary returned |
| A4 | `GET /` | 200 HTML containing CloudSweep |
| S1 | `create_waste` then scan | 5 findings (1+1+1+2) |
| S2 | `destroy_waste` then scan | Those four rules return 0 |
| S3 | Untagged volume survives destroy | Volume still present |
| S4 | Wrong/missing account ID | `SystemExit` |
| S5 | `--dry-run` / no `--yes` | No resources created |

## Integration (manual)

On a real account with budgets and IAM from the spec: create → scan (5 findings) → destroy → scan (0 from those resources). Then confirm Billing and the EC2/S3 consoles are clean.
