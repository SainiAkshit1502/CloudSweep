# CloudSweep IAM Policies

This directory contains least-privilege IAM policies for CloudSweep:

1. **`scanner-policy.json`**: Read-only permissions (`ec2:Describe*`, `s3:List*`, `s3:Get*`) used by the scanner CLI, FastAPI service, and nightly CI job.
   Attach to user: `aws iam put-user-policy --user-name cloudsweep-scanner --policy-name CloudSweepReadOnly --policy-document file://docs/iam/scanner-policy.json`
2. **`sandbox-policy.json`**: Write permissions to create and tear down tagged demo waste (`sandbox=cloudsweep`) from your local machine.
   Attach to user: `aws iam put-user-policy --user-name cloudsweep-sandbox --policy-name CloudSweepSandbox --policy-document file://docs/iam/sandbox-policy.json`

Keep scanner credentials read-only; never assign sandbox permissions to the scanner identity.
