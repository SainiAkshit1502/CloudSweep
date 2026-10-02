# CloudSweep: Project Specification (AWS, Python, boto3)

## 1. Project summary

**CloudSweep** is a Python tool that scans an AWS account for **wasted spend and security misconfigurations** and produces a report with estimated monthly savings.

It detects four kinds of problems:

1. **Unattached EBS volumes** (paying for storage nobody uses)
2. **Idle Elastic IPs** (public IPv4 addresses attached to nothing)
3. **Security groups open to the world** (0.0.0.0/0 on SSH 22, RDP 3389, or all traffic)
4. **Missing ownership tags** (`owner` / `env`) on EC2 instances, EBS volumes and S3 buckets

It ships as:

- a **scanner library** (`scanner/`)
- a **CLI** (`python -m scanner.cli`)
- a **FastAPI service** with a JSON API and a small HTML dashboard (`api/`)
- **sandbox scripts** that safely create and destroy deliberately wasteful resources for testing and demos (`sandbox/`)
- a **Docker image**, **pytest + moto tests**, and **GitHub Actions** (CI plus a nightly scan)

### Why this project exists (real-world problem)

Teams and students routinely pay for forgotten cloud resources, and leave firewall rules open by accident. Finding them manually in the console is slow and error-prone. CloudSweep automates the check and reports the potential savings and risks.

### Target role alignment (Deloitte Analyst, EAD Engineering, HCE)

| JD line | How the project shows it |
|---|---|
| Provision and manage cloud resources on AWS | Sandbox scripts create and delete EC2/EBS/S3 resources with boto3 |
| Monitor, troubleshoot and optimize cloud environments | The scanner and its cost report |
| Python and automation scripting | Entire codebase is Python |
| DevOps tools and CI/CD | GitHub Actions: CI on push, scheduled nightly scan |
| Docker | Containerized API |
| Identity and Access Management | Two least-privilege IAM identities (read-only scanner, separate sandbox) |
| Networking fundamentals, firewalls | Security group analysis, public IP analysis |
| Identify risks and escalate | Severity levels on every finding |
| Requirement doc, design doc, test plan, training manual | Docs deliverables (Section 14) |

---

## 2. Goals and non-goals

**Goals**
- A working scanner with four rules, tested without touching real AWS (moto).
- Safe demo: create waste, scan, clean up, re-scan and get zero findings.
- Clear, small, readable code that the author can explain line by line in an interview.

**Non-goals (do not build these)**
- No auto-remediation. The scanner **never** modifies or deletes anything.
- No multi-account or multi-region scanning (single account, single region per run).
- No database, authentication or user management. Results live in memory and in `report.json`.
- No frontend framework. The dashboard is one server-rendered HTML page.
- No Terraform or CloudFormation. Infrastructure for the sandbox is created with boto3.

---

## 3. Tech stack

| Area | Choice |
|---|---|
| Language | Python 3.12 |
| AWS SDK | boto3 |
| API | FastAPI + Uvicorn |
| Models/validation | Pydantic v2 |
| Dashboard | Jinja2 template (single page, no JS framework) |
| Tests | pytest, moto (`mock_aws`), httpx (FastAPI TestClient) |
| Lint/format | ruff |
| Container | Docker (python:3.12-slim, non-root user) |
| CI/CD | GitHub Actions |
| Default region | `ap-south-1` (Mumbai), configurable |

`requirements.txt` (runtime): `boto3`, `fastapi`, `uvicorn[standard]`, `pydantic>=2`, `jinja2`
`requirements-dev.txt`: `-r requirements.txt`, `pytest`, `pytest-cov`, `moto[ec2,s3]`, `httpx`, `ruff`

After the first successful install, pin exact versions with `pip freeze` so builds are reproducible.

---

## 4. Prerequisites: AWS account setup (do this manually, step by step)

1. **Create an AWS account** and enable MFA on the root user. Never use root keys.
2. **Create a budget alert first**: Billing > Budgets > Create budget > monthly cost budget of **$2** with email alerts at 50% and 100%.
3. **Create two IAM users** (or roles) with access keys, each with a custom policy from Appendix B:
   - `cloudsweep-scanner`: read-only, used by the scanner, API and nightly GitHub Action.
   - `cloudsweep-sandbox`: can create and delete the sandbox resources, used only by `sandbox/` scripts on your laptop.
4. **Configure two local AWS CLI profiles**:
   ```
   aws configure --profile cloudsweep-scanner
   aws configure --profile cloudsweep-sandbox
   ```
5. Find your **12-digit AWS account ID** (`aws sts get-caller-identity --profile cloudsweep-scanner`). It's needed for the sandbox safety guard.
6. Make a `.env.example` (committed) and `.env` (git-ignored) with:
   ```
   AWS_REGION=ap-south-1
   CLOUDSWEEP_ALLOWED_ACCOUNT_ID=123456789012
   ```
7. Confirm `.gitignore` contains `.env`, `report.json`, `__pycache__/`, `.venv/`, `.pytest_cache/`, `.ruff_cache/`, `htmlcov/`.

> **Never commit access keys.** Never bake credentials into the Docker image. Pass them at runtime via environment variables or profiles.

---

## 5. Repository structure

```
cloudsweep/
├── .cursor/rules/project.mdc
├── .github/workflows/
│   ├── ci.yml
│   └── nightly-scan.yml
├── api/
│   ├── __init__.py
│   ├── main.py                 # FastAPI app
│   └── templates/
│       └── dashboard.html
├── scanner/
│   ├── __init__.py
│   ├── models.py               # Pydantic models
│   ├── config.py               # settings from env vars
│   ├── pricing.py              # approximate cost constants
│   ├── rules.py                # the four rule functions
│   ├── runner.py               # runs all rules, builds ScanResult
│   └── cli.py                  # command-line entry point
├── sandbox/
│   ├── __init__.py
│   ├── common.py               # shared: safety guard, tag constants
│   ├── create_waste.py
│   └── destroy_waste.py
├── tests/
│   ├── conftest.py
│   ├── test_rules.py
│   ├── test_runner.py
│   ├── test_cli.py
│   ├── test_api.py
│   └── test_sandbox.py
├── docs/
│   ├── PROJECT_SPEC.md         # this file
│   ├── requirements.md         # requirement document
│   ├── design.md               # system design document + diagram
│   ├── test_plan.md
│   └── runbook.md              # training manual / how to operate
├── Dockerfile
├── .dockerignore
├── .env.example
├── .gitignore
├── pyproject.toml              # ruff + pytest config
├── requirements.txt
├── requirements-dev.txt
└── README.md
```

---

## 6. Data models (`scanner/models.py`)

Use Pydantic v2.

```python
class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Finding(BaseModel):
    rule: str  # "unattached_volume" | "idle_elastic_ip" | "open_security_group" | "missing_tags"
    resource_type: (
        str  # "ebs_volume" | "elastic_ip" | "security_group" | "ec2_instance" | "s3_bucket"
    )
    resource_id: str  # vol-..., eipalloc-..., sg-..., i-..., bucket name
    region: str
    severity: Severity
    est_monthly_cost_usd: float  # 0.0 for pure security or tagging findings
    detail: str  # human-readable explanation
    recommendation: str  # what a human should do (never automated)


class ScanSummary(BaseModel):
    total_findings: int
    by_severity: dict[str, int]  # {"high": 1, "medium": 2, "low": 2}
    by_rule: dict[str, int]
    total_est_monthly_savings_usd: float


class ScanResult(BaseModel):
    scan_id: str  # uuid4
    account_id: str
    region: str
    started_at: datetime  # timezone-aware UTC
    finished_at: datetime
    findings: list[Finding]
    summary: ScanSummary
    pricing_note: str  # "Costs are approximate list prices, not a bill."
```

`total_est_monthly_savings_usd` = sum of `est_monthly_cost_usd`, rounded to 2 decimals.

---

## 7. Configuration (`scanner/config.py`)

Read from environment variables with defaults. No hardcoded secrets.

| Variable | Default | Meaning |
|---|---|---|
| `AWS_REGION` | `ap-south-1` | Region to scan |
| `AWS_PROFILE` | unset | Optional local profile (not used in CI or Docker) |
| `REQUIRED_TAGS` | `owner,env` | Comma-separated tag keys every resource should have |
| `SENSITIVE_PORTS` | `22,3389` | Ports that must not be open to the world |

Expose a `get_settings()` function returning a small dataclass. Build the boto3 session with `boto3.Session(profile_name=..., region_name=...)` and let boto3 fall back to env-var credentials when no profile is set.

---

## 8. Pricing (`scanner/pricing.py`)

Hardcoded **approximate** constants with a comment linking to the AWS pricing page. State in the docs that these are estimates and that regional differences are not modelled.

```python
HOURS_PER_MONTH = 730
EIP_HOURLY_USD = 0.005  # public IPv4 address, in-use or idle
EBS_GB_MONTH_USD = {  # approximate list prices per GB-month
    "gp3": 0.08,
    "gp2": 0.10,
    "io1": 0.125,
    "io2": 0.125,
    "st1": 0.045,
    "sc1": 0.015,
    "standard": 0.05,
}
EBS_DEFAULT_GB_MONTH_USD = 0.10


def ebs_monthly_cost(volume_type: str, size_gb: int) -> float: ...
def eip_monthly_cost() -> float: ...  # EIP_HOURLY_USD * HOURS_PER_MONTH
```

---

## 9. Scanner rules (`scanner/rules.py`)

Every rule is a **pure function** with this signature, so it can be tested in isolation:

```python
def rule_name(session: boto3.Session, region: str) -> list[Finding]
```

Rules create their own clients from the session. They only call `Describe*`, `List*` and `Get*` APIs. Use **paginators** wherever boto3 provides them (`describe_volumes`, `describe_security_groups`, `describe_instances`, `list_buckets` if paginated).

### Rule 1: `unattached_volumes`
- **API:** `ec2.describe_volumes` with filter `status = available`.
- **Logic:** every returned volume is unattached.
- **Finding:** `resource_type="ebs_volume"`, `severity=MEDIUM`, cost from `ebs_monthly_cost(VolumeType, Size)`.
- **Detail:** e.g. `"Volume vol-0abc (1 GB, gp3) is not attached to any instance."`
- **Recommendation:** "Snapshot if the data matters, then delete the volume."

### Rule 2: `idle_elastic_ips`
- **API:** `ec2.describe_addresses`.
- **Logic:** an address with no `AssociationId` is idle.
- **Finding:** `resource_type="elastic_ip"`, `resource_id=AllocationId`, `severity=MEDIUM`, cost from `eip_monthly_cost()`.
- **Recommendation:** "Release the Elastic IP if it is not needed."

### Rule 3: `open_security_groups`
- **API:** `ec2.describe_security_groups`.
- **Logic:** for each ingress permission in `IpPermissions`:
  - The rule is world-open if any `IpRanges[].CidrIp == "0.0.0.0/0"` or any `Ipv6Ranges[].CidrIpv6 == "::/0"`.
  - If world-open **and** `IpProtocol == "-1"` (all traffic): finding, `severity=HIGH`.
  - If world-open **and** `IpProtocol == "tcp"` and any sensitive port `p` satisfies `FromPort <= p <= ToPort`: finding, `severity=HIGH`.
  - `FromPort` / `ToPort` may be absent when protocol is `-1`; handle it without a KeyError.
- **One finding per (security group, exposed port or "all traffic")**, not one per CIDR.
- **Cost:** `0.0`.
- **Detail:** `"Security group sg-0abc (cloudsweep-open-ssh) allows 0.0.0.0/0 on port 22."`
- **Recommendation:** "Restrict the source to a known IP range or use SSM Session Manager."

### Rule 4: `missing_tags`
- **Scope:** EC2 instances (`describe_instances`), EBS volumes (`describe_volumes`), S3 buckets in the scanned region.
- **Logic:** a resource is flagged if it lacks **any** key in `REQUIRED_TAGS` (case-sensitive match).
- **S3 details:**
  - `list_buckets`, then `get_bucket_location` per bucket (`None` or empty `LocationConstraint` means `us-east-1`). Only check buckets in the scanned region.
  - `get_bucket_tagging` raises `ClientError` with code `NoSuchTagSet` when the bucket has no tags. Catch it and treat it as an empty tag set. Let other errors propagate.
- **Finding:** `severity=LOW`, cost `0.0`.
- **Detail:** `"Volume vol-0abc is missing required tags: owner, env."`
- **Recommendation:** "Add the missing tags so cost and ownership can be traced."
- Skip EC2 instances in `terminated` state.

### Registry
In `rules.py` expose:
```python
ALL_RULES: list[Callable[[boto3.Session, str], list[Finding]]] = [
    unattached_volumes,
    idle_elastic_ips,
    open_security_groups,
    missing_tags,
]
```

---

## 10. Runner and CLI

### `scanner/runner.py`
```python
def run_scan(session: boto3.Session, region: str) -> ScanResult
```
1. Get `account_id` via `sts.get_caller_identity()["Account"]`.
2. Record `started_at` (UTC).
3. Run every rule in `ALL_RULES`. If a rule raises, **do not crash the whole scan**: log the error and record it. (Simple approach: log it and continue with the other rules. Optional: add an `errors: list[str]` field to `ScanResult`.)
4. Build the summary and return a `ScanResult`.
5. Sort findings by severity (high, medium, low), then by `est_monthly_cost_usd` descending.

### `scanner/cli.py` (run as `python -m scanner.cli`)

| Flag | Default | Meaning |
|---|---|---|
| `--region` | from settings | Region to scan |
| `--profile` | from settings | Local AWS profile |
| `--output` | `report.json` | Where to write the JSON report |
| `--fail-on` | `none` | `none`, `low`, `medium` or `high`: exit code 1 if any finding is at or above this severity |

- Print a readable table to stdout: severity, rule, resource, monthly cost. Then a one-line summary with the total savings.
- Write the full `ScanResult` as JSON to `--output`.
- **Exit codes:** `0` OK, `1` findings at or above `--fail-on`, `2` runtime or credential error (with a clear message, no stack trace unless `--verbose`).

---

## 11. Sandbox scripts (safe test data)

Purpose: create small, cheap, deliberately wasteful resources so the scanner has something to find and the demo works. **Everything the sandbox creates is tagged `sandbox=cloudsweep`.** The destroy script only ever touches resources carrying that tag.

### `sandbox/common.py`
- Constants: `SANDBOX_TAG_KEY = "sandbox"`, `SANDBOX_TAG_VALUE = "cloudsweep"`, `SANDBOX_TAGS = [{"Key": ..., "Value": ...}]`.
- `assert_safe_account(session)`: read `CLOUDSWEEP_ALLOWED_ACCOUNT_ID`, compare it with `sts.get_caller_identity()["Account"]`, and **abort with a clear error if the variable is missing or does not match**. Called at the start of both scripts.

> The sandbox tag is deliberately **not** `owner` or `env`, so sandbox resources are still flagged by the missing-tags rule.

### `sandbox/create_waste.py` (run with `python -m sandbox.create_waste --yes`)
Flags: `--region`, `--profile` (default `cloudsweep-sandbox`), `--yes` (required, otherwise print what would be created and exit), `--dry-run`.

Steps:
1. `assert_safe_account`.
2. If any resource tagged `sandbox=cloudsweep` already exists, print them and exit ("Run destroy_waste first"). This keeps the script idempotent.
3. Create, all with `TagSpecifications` containing `SANDBOX_TAGS`:
   - **Orphan EBS volume:** 1 GB, `gp3`, in `<region>a`.
   - **Idle Elastic IP:** `allocate_address(Domain="vpc")` with `TagSpecifications` (`ResourceType="elastic-ip"`).
   - **Open security group:** name `cloudsweep-open-ssh`, in the default VPC, with an ingress rule TCP 22 from `0.0.0.0/0`. (Look up the default VPC with `describe_vpcs` filter `isDefault=true`. If none exists, exit with a clear message.)
   - **S3 bucket** named `cloudsweep-sandbox-<account_id>-<6 random lowercase chars>`, created with the correct `LocationConstraint` for non-us-east-1 regions, then tagged with `sandbox=cloudsweep` only (no `owner` or `env`).
4. Print each created resource ID and a reminder: "Run destroy_waste when you're done."

Expected findings on an otherwise clean account: **5**
- unattached_volume: 1
- idle_elastic_ip: 1
- open_security_group: 1
- missing_tags: 2 (the volume and the bucket)

### `sandbox/destroy_waste.py` (run with `python -m sandbox.destroy_waste --yes`)
Flags: `--region`, `--profile`, `--yes`, `--dry-run`.

1. `assert_safe_account`.
2. Discover **only** resources with tag `sandbox=cloudsweep` (`describe_volumes`, `describe_addresses`, `describe_security_groups` with `tag:sandbox` filter; for S3, list buckets and check `get_bucket_tagging`).
3. Delete in this order:
   - Security groups (`delete_security_group`)
   - Elastic IPs (`release_address` by `AllocationId`)
   - Volumes (`delete_volume`; only if `State == "available"`, otherwise skip with a warning)
   - S3 buckets (empty them first, then `delete_bucket`)
4. Print what was deleted. Continue past individual failures and report them at the end. Exit non-zero if anything failed.
5. `--dry-run` prints what would be deleted and changes nothing.

---

## 12. API and dashboard (`api/main.py`)

FastAPI app. The API is a thin wrapper around `run_scan`.

| Method | Path | Behaviour |
|---|---|---|
| `GET` | `/health` | `{"status": "ok"}` |
| `POST` | `/scan` | Runs a scan (synchronously), stores it as the latest result, returns the `ScanResult`. Returns 503 with a clear JSON error if AWS credentials are missing or invalid. |
| `GET` | `/findings` | Returns the latest result's findings. Optional query params `severity` and `rule` to filter. Returns 404 `{"detail": "No scan has been run yet"}` if none exists. |
| `GET` | `/summary` | Returns the latest `ScanSummary`, same 404 rule. |
| `GET` | `/` | HTML dashboard |

Implementation notes:
- Keep the latest result in a module-level variable protected by a `threading.Lock`. No database.
- Use a FastAPI dependency `get_session()` that builds the boto3 session, so tests can override it.
- Also write each scan to `report.json` (path from env `REPORT_PATH`, default `report.json`).
- Enable auto docs at `/docs`.

### Dashboard (`api/templates/dashboard.html`)
- Header: "CloudSweep", region, account ID, last scan time.
- Summary cards: total findings, high/medium/low counts, **estimated monthly savings**.
- Findings table: severity (colour-coded badge), rule, resource ID, detail, monthly cost, recommendation.
- A "Run scan" button: JavaScript `fetch("/scan", {method: "POST"})`, then reload.
- Empty state: "No scan yet" or "No issues found".
- Plain CSS in a `<style>` block. No external CDNs. Mobile-friendly.

---

## 13. Tests (`tests/`)

Use `pytest` with `moto`'s `mock_aws`. **No test may touch real AWS.**

`conftest.py`:
- An `autouse` fixture that sets fake credentials (`AWS_ACCESS_KEY_ID=testing`, `AWS_SECRET_ACCESS_KEY=testing`, `AWS_DEFAULT_REGION=ap-south-1`) and clears `AWS_PROFILE`.
- A `session` fixture returning a `boto3.Session(region_name="ap-south-1")`.
- Helper factories to create volumes, EIPs, security groups and buckets inside the mock.

| File | What to test |
|---|---|
| `test_rules.py` | For **each rule**: (a) finds the bad resource, (b) ignores the good one (attached volume, associated EIP, SG restricted to a private CIDR, fully tagged resource), (c) returns `[]` on an empty account. Extra cases: SG with `IpProtocol="-1"`; SG with port range 20-30 that covers 22; SG open on port 80 only must **not** be flagged; S3 bucket with no tag set (`NoSuchTagSet`) is flagged; terminated EC2 instance is skipped; pagination not broken |
| `test_runner.py` | Summary math (counts and total savings); sort order; a rule raising an exception does not crash the scan |
| `test_cli.py` | Exit codes 0/1/2 with `--fail-on`; JSON file written; output contains the summary line |
| `test_api.py` | `/health`; `/findings` returns 404 before a scan; `POST /scan` then `GET /findings`; severity and rule filters; dashboard returns 200 HTML. Override `get_session` with a moto-backed session |
| `test_sandbox.py` | `create_waste` then `run_scan` finds the 5 expected findings; `destroy_waste` then `run_scan` finds 0; destroy does **not** delete an untagged resource created by the test; safety guard aborts on a wrong or missing account ID; `--dry-run` changes nothing |

Target: **≥ 85% coverage** on `scanner/` (`pytest --cov=scanner --cov-report=term-missing`).

`pyproject.toml` configures ruff (line length 100, rules `E,F,I,B`) and pytest (`testpaths = ["tests"]`).

---

## 14. Docker, CI/CD and documentation

### Dockerfile
- Base `python:3.12-slim`.
- Copy `requirements.txt` first, install with `--no-cache-dir`, then copy source (better layer caching).
- Create and switch to a **non-root user**.
- Set `PYTHONDONTWRITEBYTECODE=1` and `PYTHONUNBUFFERED=1`.
- `EXPOSE 8000`; `CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]`.
- `.dockerignore`: `.git`, `.env`, `.venv`, `tests`, `docs`, `__pycache__`, `report.json`.
- **No credentials in the image.** Run with:
  ```
  docker build -t cloudsweep .
  docker run --rm -p 8000:8000 \
    -e AWS_ACCESS_KEY_ID -e AWS_SECRET_ACCESS_KEY -e AWS_REGION=ap-south-1 cloudsweep
  ```

### `.github/workflows/ci.yml` (on push and pull_request)
Jobs / steps: checkout, set up Python 3.12 (with pip cache), install `requirements-dev.txt`, `ruff check .`, `ruff format --check .`, `pytest --cov=scanner`, `docker build`. Set `permissions: contents: read`.

### `.github/workflows/nightly-scan.yml` (cron `0 2 * * *` plus `workflow_dispatch`)
1. Checkout, set up Python, install `requirements.txt`.
2. Configure AWS credentials with `aws-actions/configure-aws-credentials` using repository secrets `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` (the **read-only scanner** user only) and region `ap-south-1`.
3. `python -m scanner.cli --output report.json`
4. Upload `report.json` with `actions/upload-artifact` (`if: always()`).
5. **Stretch:** open a GitHub Issue with the summary using `gh issue create` when findings exist (needs `permissions: issues: write`). **Stretch 2:** replace stored keys with GitHub OIDC and an IAM role.

### Documentation to write (in `docs/`)
| File | Contents |
|---|---|
| `requirements.md` | Problem statement, users, functional requirements (F1..Fn), non-functional requirements (security, cost safety, testability), assumptions, out of scope |
| `design.md` | Architecture diagram (Mermaid is fine), component descriptions, data flow (CLI, API, sandbox), data model, IAM design, security decisions, limitations (single region, approximate pricing), future work |
| `test_plan.md` | Test strategy (unit with moto, integration against sandbox), test cases table (ID, description, expected result), how to run, coverage target |
| `runbook.md` | Step-by-step: set up AWS, run the CLI, run the API, run the sandbox demo, read the report, troubleshoot common errors, clean up. Write it so a newcomer could follow it without help |
| `README.md` | What it is, 2-minute quickstart, architecture image or diagram, screenshots of the dashboard, links to docs |

---

## 15. Build order (7 days) with Cursor prompts

Each phase ends with acceptance criteria. Do not move on until they pass.

### Phase 0: Day 1: Setup
Do the manual AWS setup in Section 4. Create the repo, folders, `.gitignore`, `pyproject.toml`, requirements files and a virtualenv. Write `docs/requirements.md` yourself, with Cursor's help for wording only.

> **Cursor prompt:** "Read @docs/PROJECT_SPEC.md. Create the repository skeleton from Section 5 with empty modules and `__init__.py` files, plus `pyproject.toml` (ruff and pytest config from Section 13), `requirements.txt`, `requirements-dev.txt`, `.gitignore` and `.env.example`. Do not implement any logic yet."

**Done when:** `pip install -r requirements-dev.txt` works, `ruff check .` and `pytest` run without errors, budget alert exists.

### Phase 1: Day 2: Models, config, pricing, sandbox
> **Cursor prompt:** "Implement `scanner/models.py`, `scanner/config.py` and `scanner/pricing.py` exactly as specified in Sections 6-8. Then implement `sandbox/common.py`, `sandbox/create_waste.py` and `sandbox/destroy_waste.py` as in Section 11, including the account-ID safety guard, tag-only deletion, `--yes` and `--dry-run`. Add type hints and docstrings."

Manually run `create_waste --dry-run`, then `create_waste --yes`, and check the four resources in the AWS console. Then `destroy_waste --yes` and confirm everything is gone.

**Done when:** create then destroy leaves the account exactly as before, and the guard refuses a wrong account ID.

### Phase 2: Day 3: Scanner rules and runner
> **Cursor prompt:** "Implement the four rules in `scanner/rules.py` per Section 9, `scanner/runner.py` and `scanner/cli.py` per Section 10. Use paginators. Rules must be pure functions with the signature `(session, region) -> list[Finding]` and only call read-only AWS APIs."

Run the sandbox create, scan with the CLI, and confirm the 5 expected findings. Destroy and re-scan to get 0.

**Done when:** the before/after demo works from the terminal and `report.json` is valid.

### Phase 3: Day 4: Tests
> **Cursor prompt:** "Write `tests/conftest.py`, `test_rules.py`, `test_runner.py`, `test_cli.py` and `test_sandbox.py` per Section 13 using moto's `mock_aws`. No test may call real AWS. Then run pytest with coverage and fix failures."

Read every test yourself. Break a rule on purpose and confirm a test fails.

**Done when:** all tests pass, coverage on `scanner/` is at least 85%.

### Phase 4: Day 4-5: API, dashboard and Docker
> **Cursor prompt:** "Implement `api/main.py` and `api/templates/dashboard.html` per Section 12, with a `get_session` dependency for testability. Write `tests/test_api.py`. Then write the Dockerfile and `.dockerignore` per Section 14."

**Done when:** `docker run` serves the dashboard on port 8000 and "Run scan" shows sandbox findings and total savings.

### Phase 5: Day 5: GitHub Actions
> **Cursor prompt:** "Create `.github/workflows/ci.yml` and `nightly-scan.yml` per Section 14."

Add the repository secrets (scanner keys only). Trigger the nightly workflow manually with `workflow_dispatch` and download the artifact.

**Done when:** CI is green on push and the nightly artifact contains `report.json`.

### Phase 6: Day 6: Documentation and demo recording
Write `design.md`, `test_plan.md`, `runbook.md` and `README.md` (Cursor can draft, you must read and correct them so they match the code). Record a 2-minute before/after screen capture. **Run `destroy_waste --yes` when finished**, then check the console for leftover resources and the Billing page.

### Phase 7: Day 7: Rehearsal
Practice the 2-minute walkthrough (Section 17) and the questions in Section 18 out loud, without notes.

**If you fall behind:** cut in this order: dashboard, nightly Issue creation, the S3 part of the tags rule. Never cut the tests, the sandbox safety guard or the docs.

---

## 16. Definition of done

- [x] Four rules implemented, each tested for positive, negative and empty cases
- [ ] `create_waste` then scan gives 5 findings; `destroy_waste` then scan gives 0
- [ ] Scanner uses the read-only IAM user and never calls a write API
- [ ] Sandbox refuses to run against the wrong account and deletes only tagged resources
- [x] CLI exit codes and JSON report work
- [ ] API endpoints and dashboard work; Docker image runs with runtime credentials
- [ ] CI green; nightly scan uploads an artifact
- [ ] Docs written and consistent with the code; screenshots in README
- [ ] Sandbox destroyed; no leftover AWS resources; no secrets in Git history

---

## 17. Demo script (2 minutes)

1. "This tool finds wasted spend and risky firewall rules in an AWS account, without ever changing anything."
2. Run `python -m sandbox.create_waste --yes` and explain each of the four planted problems.
3. Run `python -m scanner.cli` and read out: "5 findings, 1 high severity (SSH open to the world), about $X per month of waste."
4. Open the dashboard in Docker and click "Run scan".
5. Run `python -m sandbox.destroy_waste --yes` and re-scan: "Zero findings."
6. Show CI green, the nightly artifact, and the least-privilege IAM policy.

---

## 18. Interview preparation

- **Why a read-only IAM user for the scanner?** Least privilege. A monitoring tool should be unable to delete anything, so a bug or leaked key can't cause damage.
- **Why separate sandbox credentials?** Only the sandbox needs write access, and keeping it separate keeps the scanner's blast radius small.
- **How does destroy avoid deleting the wrong things?** Tag-based discovery (`sandbox=cloudsweep`), an account-ID guard, a `--yes` flag and a dry-run mode.
- **Why moto?** Fast, free tests that never touch a real account.
- **Why are idle Elastic IPs a cost?** AWS charges for public IPv4 addresses, so idle ones are pure waste.
- **Why check ports 22 and 3389?** They are the most attacked admin ports; world-open access is a common breach cause.
- **What are the limits of the tool?** Single region, approximate pricing, no CPU-based idle instance detection, no remediation.
- **How would you scale it?** AWS Organizations plus a cross-account role, scheduled Lambda or ECS task, results into S3 or a database, alerts to Slack.
- **What about Terraform?** "I created the sandbox with boto3 for simplicity. I understand Terraform declares desired state with plan, apply and destroy, and I'd move the sandbox there next."
- **What would you improve?** Idle EC2 detection via CloudWatch CPU metrics, OIDC instead of stored keys, Slack alerts, an approval-based auto-remediation.

**Resume bullet (add only once it works):**
> Built CloudSweep, a Python/boto3 and FastAPI tool that scans AWS accounts for unattached EBS volumes, idle Elastic IPs, open security groups and untagged resources, reporting estimated monthly savings; used least-privilege IAM, moto-based tests, Docker, and scheduled GitHub Actions scans.

---

## Appendix A: Cursor rules (`.cursor/rules/project.mdc`)

```
---
description: CloudSweep project conventions
alwaysApply: true
---
- Project spec is in docs/PROJECT_SPEC.md. Follow it. If something is ambiguous, ask before inventing behaviour.
- Python 3.12, type hints everywhere, docstrings on public functions, ruff-clean code (line length 100).
- The scanner must ONLY call read-only AWS APIs (Describe*, List*, Get*). Never add code that modifies or deletes AWS resources outside sandbox/.
- Code in sandbox/ may only delete resources tagged sandbox=cloudsweep and must call assert_safe_account() first.
- Never hardcode or log AWS credentials. Never commit .env or report.json.
- Use boto3 paginators where available.
- Rules are pure functions: (session, region) -> list[Finding].
- All tests use moto's mock_aws. No test may call real AWS.
- Keep code simple and readable; the author must be able to explain every line in an interview. No clever abstractions, no extra dependencies beyond requirements files.
- Build only the phase requested in the prompt. Do not implement later phases.
```

## Appendix B: IAM policies

**Scanner (read-only), attach to `cloudsweep-scanner`:**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "CloudSweepReadOnly",
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeVolumes",
        "ec2:DescribeAddresses",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeInstances",
        "s3:ListAllMyBuckets",
        "s3:GetBucketLocation",
        "s3:GetBucketTagging"
      ],
      "Resource": "*"
    }
  ]
}
```
`sts:GetCallerIdentity` needs no permission. `Describe*` calls do not support resource-level restrictions, hence `"Resource": "*"`.

**Sandbox (create/delete), attach to `cloudsweep-sandbox`:**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "SandboxEC2",
      "Effect": "Allow",
      "Action": [
        "ec2:CreateVolume", "ec2:DeleteVolume",
        "ec2:AllocateAddress", "ec2:ReleaseAddress",
        "ec2:CreateSecurityGroup", "ec2:DeleteSecurityGroup",
        "ec2:AuthorizeSecurityGroupIngress",
        "ec2:CreateTags",
        "ec2:DescribeVolumes", "ec2:DescribeAddresses",
        "ec2:DescribeSecurityGroups", "ec2:DescribeVpcs"
      ],
      "Resource": "*"
    },
    {
      "Sid": "SandboxS3",
      "Effect": "Allow",
      "Action": [
        "s3:ListAllMyBuckets", "s3:CreateBucket", "s3:DeleteBucket",
        "s3:PutBucketTagging", "s3:GetBucketTagging", "s3:GetBucketLocation",
        "s3:ListBucket", "s3:DeleteObject"
      ],
      "Resource": "*"
    }
  ]
}
```
For a tighter version, restrict S3 actions to `arn:aws:s3:::cloudsweep-sandbox-*`. If Cursor's generated code hits an `AccessDenied`, add only the specific missing action, not `*`.

## Appendix C: Common problems

| Symptom | Likely cause |
|---|---|
| `NoCredentialsError` | No profile or env vars set; pass `--profile` or export the keys |
| `InvalidClientTokenId` | Wrong or deactivated access key |
| `AccessDenied` in the scanner | Policy missing an action from Appendix B |
| `BucketAlreadyOwnedByYou` / `IllegalLocationConstraintException` | Missing `LocationConstraint` for non-us-east-1 |
| `InvalidVolume.NotFound` / `VolumeInUse` in destroy | Volume attached or still deleting; retry |
| `DependencyViolation` deleting a security group | Something still references it; delete the dependant first |
| Moto test hits real AWS | Fake credentials fixture missing; check `conftest.py` |
