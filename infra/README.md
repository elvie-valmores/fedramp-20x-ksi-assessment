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

## Before the first apply: the account plan

**Upgrade the AWS account to the Paid plan in the Billing console before doing
anything else, and specifically before creating an AWS Organization.**

This is not optional and the ordering is not cosmetic:

- The Free plan blocks GuardDuty, Security Hub and Inspector outright
  (`SubscriptionRequiredException`) and caps RDS backup retention below what
  this project declares.
- The Free plan expires roughly six months after account creation. If the
  account has not upgraded by then it is closed and its resources deleted —
  including the Object Locked log store and the Terraform state backend.
- **Upgrading by joining an AWS Organization, or by setting up a Control Tower
  landing zone, expires the remaining Free Tier credits immediately.** IAM
  Identity Center requires Organizations and the identity architecture
  requires Identity Center, so the Organization will be created — it just has
  to come second. Getting this backwards costs up to 200 USD and nothing in
  any error message explains why.

Upgrade first, as a deliberate standalone action. Create the Organization
after. See `docs/DECISIONS.md`, 2026-09-19.

## The domain and its certificate

The application's public certificate is issued in `infra/bootstrap` rather
than in the `aws` root, because its DNS validation records are created by
hand and a hand-validated certificate must survive teardown.

```sh
# 1. Issue the certificate (bootstrap, applied once)
cd infra/bootstrap
TF_VAR_app_domain=ksi.example.com terraform apply
terraform output certificate_validation_records

# 2. Create those records as CNAMEs at the DNS provider, by hand.
#    LEAVE THEM IN PLACE — ACM re-validates through the same records on
#    renewal, so deleting them breaks renewal ~13 months later, silently.

# 3. Wait for ACM to issue. Then the aws root can find it.
cd ../aws
TF_VAR_app_domain=ksi.example.com terraform apply
```

If the `aws` root is applied with `app_domain` set before the certificate has
been issued, it fails with `reading ACM Certificates: empty result`. That
means step 2 or 3 has not completed.

With `app_domain` unset the environment still applies: the load balancer falls
back to an imported self-signed certificate and the `security.txt` disclosure
file is not published. That fallback exists so the domain work does not block
every apply, not because it is a supported end state.

The DNS record for the domain itself must point at the load balancer and must
be **DNS-only, not proxied** — proxied mode puts the DNS provider inside the
offering boundary and disturbs three determinations. See `docs/DECISIONS.md`.

## Applying the AWS root

The AWS root applies in two phases. This is not a convenience — KSI-SVC-VRI
requires task definitions reference images by digest, and a digest cannot be
looked up for an image that does not exist yet.

```sh
# Phase 1: network, database, registry, identities. No services.
terraform apply

# Build and push both images to the repositories phase 1 created, tagged
# with the value of app_image_tag (default "v1"). Tags are immutable, so a
# rebuild needs a new tag.

# Phase 2: the ECS services, pinned to the digests those tags resolve to.
terraform apply -var deploy_services=true
```

Then run the migration once, which creates the schema and the two IAM-auth
database roles. It is idempotent, so running it again is a no-op:

```sh
aws ecs run-task \
  --cluster fedramp-20x-ksi \
  --task-definition fedramp-20x-ksi-migrate \
  --launch-type FARGATE \
  --network-configuration "awsvpcConfiguration={subnets=[<app subnet ids>],securityGroups=[<migrate sg id>],assignPublicIp=DISABLED}"
```

## Required variables

Neither `backend.hcl` nor any `.tfvars` file is committed; both are
gitignored because they carry account-specific values.

| Variable | Roots | Notes |
|---|---|---|
| `billing_alert_email` | `aws`, `gcp` | No default. Set via `TF_VAR_billing_alert_email`. |
| `billing_account_id` | `gcp` | No default. From `gcloud billing accounts list`. |
| `deploy_services` | `aws` | Defaults to `false`. See the two phases above. |
| `app_image_tag` | `aws` | Defaults to `v1`. The tag whose digest the services pin to. |
| `app_domain` | `aws`, `bootstrap` | Defaults to empty. Set to the same value in both roots. |
| `security_contact` | `aws` | Defaults to `security@<app_domain>`. |
| `security_policy_url` | `aws` | Optional. Omitted from `security.txt` when empty. |

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

The application environment is where the standing cost actually lives:
roughly 115 to 125 USD per month if left running, dominated by the load
balancer, RDS, and six interface endpoints at about 7 USD each. The endpoints
cost more than the NAT gateway they replace and are bought deliberately —
they are what makes KSI-CNA-RNT's "no internet route at all" claim true.

**Destroy it between sessions.** The residual is a few dollars, mostly KMS
keys and retained snapshots.
