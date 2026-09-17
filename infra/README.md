# infra

Two Terraform roots, not one, because of a bootstrapping order problem: a remote
state backend has to exist before anything can point at it as a backend.

## `bootstrap/`

Creates the S3 bucket that holds everyone else's remote state. Runs with
**local** state — it cannot use the backend it is creating. One-time, rarely
touched again after the first apply.

## `aws/`

Everything else. Uses the bucket `bootstrap/` created, via S3-native locking
(`use_lockfile`, Terraform >= 1.10 — no DynamoDB table).

## First-time setup

```sh
cd infra/bootstrap
terraform init
terraform apply

terraform output -raw state_bucket_name   # copy this

cd ../aws
cp backend.hcl.example backend.hcl        # fill in the bucket name
terraform init -backend-config=backend.hcl
terraform plan
```

`billing_alert_email` has no default. Set it via `TF_VAR_billing_alert_email`
or a `terraform.tfvars` in `infra/aws/` — both are gitignored.

## Cost posture

Per PROJECT-CONTEXT.md, the state backend persists across sessions; it is not
part of the apply-and-destroy cycle everything built on top of it follows.
