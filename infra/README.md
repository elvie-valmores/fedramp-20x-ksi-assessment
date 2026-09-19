# infra

Three Terraform roots, each with its own state.

| Root | What it manages | State |
|---|---|---|
| `bootstrap/` | The S3 bucket that holds everyone else's state | Local |
| `aws/` | All AWS resources | S3, key `aws/` |
| `gcp/` | All GCP resources | S3, key `gcp/` |

## Why bootstrap is separate

Remote state has to live somewhere, and that somewhere has to exist before
any root can point at it. `bootstrap/` creates that bucket while keeping its
own state on local disk, which is the only way to break the circular
dependency. It is applied once and then rarely touched.

`gcp/` stores its state in the same S3 bucket rather than a GCS one. The
backend only stores a JSON file; it does not care which cloud the resources
it describes live in.

Locking uses S3 natively (`use_lockfile`, Terraform >= 1.10), so there is no
DynamoDB table to maintain.

## First-time setup

```sh
# 1. Create the state bucket
cd infra/bootstrap
terraform init
terraform apply
terraform output -raw state_bucket_name    # copy this

# 2. Point the AWS root at it
cd ../aws
cp backend.hcl.example backend.hcl         # paste the bucket name in
terraform init -backend-config=backend.hcl
terraform plan

# 3. Same for GCP
cd ../gcp
cp backend.hcl.example backend.hcl         # same bucket, different key
terraform init -backend-config=backend.hcl
terraform plan
```

## Required variables

Neither `backend.hcl` nor any `.tfvars` file is committed; both are
gitignored because they carry account-specific values.

| Variable | Roots | Notes |
|---|---|---|
| `billing_alert_email` | `aws`, `gcp` | No default. Set via `TF_VAR_billing_alert_email`. |
| `billing_account_id` | `gcp` | No default. From `gcloud billing accounts list`. |

## GCP authentication

The `gcp/` root does not use a service account key file. It authenticates as
whoever runs it, then impersonates the `terraform-admin` service account.
That requires:

```sh
gcloud auth application-default login
```

and the caller holding `roles/iam.serviceAccountTokenCreator` on
`terraform-admin@<project>.iam.gserviceaccount.com`.

## Cost posture

The state bucket and the central log store persist across sessions. Most
other resources are expected to be destroyed and rebuilt, so cost tracks
usage rather than standing infrastructure. Both clouds have a $50/month
budget alert as a tripwire — see `aws/billing.tf` and `gcp/billing.tf`.
