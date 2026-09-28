# CloudSweep runbook

Step-by-step operations for someone new to the repo. Manual AWS setup is yours; the tool will not create IAM users for you.

## 1. Set up AWS (once)

1. Create an AWS account. Enable MFA on the root user. Do not create root access keys.
2. Billing → Budgets → monthly **$2** budget with email alerts at 50% and 100%.
3. Create IAM users `cloudsweep-scanner` and `cloudsweep-sandbox` with the policies in `docs/PROJECT_SPEC.md` Appendix B. Create access keys for each.
4. Configure profiles:
   ```bash
   aws configure --profile cloudsweep-scanner
   aws configure --profile cloudsweep-sandbox
   ```
   Region: `ap-south-1`.
5. Read your account ID:
   ```bash
   aws sts get-caller-identity --profile cloudsweep-scanner
   ```
6. Copy `.env.example` to `.env` and set `CLOUDSWEEP_ALLOWED_ACCOUNT_ID` to that 12-digit ID.

Never commit `.env` or access keys.

## 2. Install locally

Python 3.12:

```bash
cd CloudSweep
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements-dev.txt
```

## 3. Run the CLI (read-only)

```bash
python -m scanner.cli --profile cloudsweep-scanner --region ap-south-1 --output report.json
```

Exit codes: `0` ok, `1` findings at or above `--fail-on`, `2` credentials/runtime error.

## 4. Run the API and dashboard

```bash
set AWS_PROFILE=cloudsweep-scanner
uvicorn api.main:app --reload --port 8000
```

Open http://127.0.0.1:8000 — click **Run scan**. OpenAPI docs: http://127.0.0.1:8000/docs

## 5. Sandbox demo (write path, laptop only)

```bash
python -m sandbox.create_waste --profile cloudsweep-sandbox --yes
python -m scanner.cli --profile cloudsweep-scanner
python -m sandbox.destroy_waste --profile cloudsweep-sandbox --yes
python -m scanner.cli --profile cloudsweep-scanner
```

Expected: 5 findings after create (unattached volume, idle EIP, open SSH SG, missing tags on the volume and bucket). After destroy, those planted issues are gone.

`--dry-run` prints the plan and changes nothing. Without `--yes`, scripts also refuse to mutate.

If the account id guard fires, your `.env` / environment does not match the caller identity.

## 6. Read the report

`report.json` is a `ScanResult`: account, region, timestamps, findings, summary, pricing note. Costs are approximate list prices, not your bill.

## 7. Docker

```bash
docker build -t cloudsweep .
docker run --rm -p 8000:8000 -e AWS_ACCESS_KEY_ID -e AWS_SECRET_ACCESS_KEY -e AWS_REGION=ap-south-1 cloudsweep
```

Do not bake keys into the image.

## 8. Troubleshoot

| Symptom | What to check |
|---|---|
| `NoCredentialsError` | Profile or `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` |
| `InvalidClientTokenId` | Deactivated or mistyped key |
| `AccessDenied` | IAM policy missing an action from Appendix B |
| Sandbox refuses to run | `CLOUDSWEEP_ALLOWED_ACCOUNT_ID` vs `get-caller-identity` |
| `IllegalLocationConstraintException` | Bucket create must set `LocationConstraint` outside `us-east-1` |
| `VolumeInUse` on destroy | Volume not `available`; wait or detach |
| `DependencyViolation` on SG delete | Another resource still references the group |
| Tests hitting real AWS | `tests/conftest.py` dummy credentials fixture missing |

## 9. Clean up

Always finish with:

```bash
python -m sandbox.destroy_waste --profile cloudsweep-sandbox --yes
```

Then check the EC2 (volumes, EIPs, security groups), S3, and Billing consoles for leftovers.
