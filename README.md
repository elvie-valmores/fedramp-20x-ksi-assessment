# fedramp-20x-ksi-assessment

A FedRAMP 20x Class C Key Security Indicator self-assessment, built against
real infrastructure on AWS and GCP.

The premise: a small team runs a product on AWS with an analytics pipeline on
GCP, and is assessing itself against the 46 Key Security Indicators in
FedRAMP's Consolidated Rules for 2026 ahead of a first independent
assessment. The infrastructure is real and the evidence is gathered from live
cloud APIs — nothing here is mocked or simulated.

## Repository layout

```
docs/         The assessment design. Start with PROJECT-CONTEXT.md.
infra/        Terraform for both clouds. Three roots; see infra/README.md.
app/          The application being assessed. Two services; see app/README.md.
inventory/    Generates a live inventory of every resource in both clouds.
collector/    Runs evidence checks against that infrastructure.
lambda/       Python for the AWS Lambda functions Terraform deploys.
```

### `docs/`

The design phase, completed before any code was written. All 46 indicators
were worked through one at a time and the reasoning recorded.

- `PROJECT-CONTEXT.md` — the entry point. Read this first.
- `KSI-Design-Matrix.xlsx` — the primary artifact: all 46 determinations.
- `DECISIONS.md` — a dated log of why each decision was made, including
  the ones that were later reversed.

### `app/`

Two small but real services on ECS Fargate: an API behind the load balancer
and a worker that extracts data for the GCP analytics pipeline. They exist
because several determinations need something genuine to assess — real image
digests for KSI-SVC-VRI, a real dependency manifest for KSI-SCR-MON, two
genuinely separate services for KSI-CNA-MAT's segmentation claim.

Neither holds a database password. Both authenticate to Postgres with IAM.

### `inventory/`

Answers "what actually exists right now?" by querying each cloud's own
inventory service — AWS Config and GCP Cloud Asset Inventory — live on every
run. Terraform state is deliberately not the source: state describes what was
declared, not what is running.

Both clouds are normalized to one record shape, so a single output covers
both.

### `collector/`

Gathers the evidence the assessment needs. Roughly 380 pieces of evidence
reduce to nine ways of gathering it, so the framework implements the nine
mechanisms and each individual check is a JSON file in `collector/checks/`.

Five mechanisms are implemented. The other four are registered but raise a
clear error explaining what they are waiting on.

`self_test.py` runs each assertion against input that should satisfy it and
input that should not: a good and a broken workflow, and a clean and a drifted
Terraform plan. A check that cannot fail is not a check.

### `sdr/`

Emits the Security Decision Record, the project's deliverable, in FedRAMP's
schema. It reads the determinations from the design matrix and the collector's
results, validates against the pinned schemas before writing, and renders a
Markdown copy from the same JSON. It states what it cannot claim: no
independent assessor, no FRR determinations, and one run of evidence rather
than a history.

## Running it

One virtualenv serves both Python components:

```sh
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

```sh
# What exists across both clouds, as JSON
cd inventory && ../.venv/bin/python generate_inventory.py

# Prove the inventory is accurate and live (creates and deletes real
# throwaway resources in both clouds)
cd inventory && ../.venv/bin/python self_test.py

# Run every evidence check
cd collector && ../.venv/bin/python run_checks.py

# Emit the SDR from a run's results, into sdr/out/
cd collector && ../.venv/bin/python run_checks.py --json results.json
cd sdr && ../.venv/bin/python emit.py --results ../collector/results.json --frr empty --runtime local

# Compare the pinned FedRAMP schemas against the published ones
cd sdr && ../.venv/bin/python verify_pins.py
```

All three need working cloud credentials: an AWS profile, and
`gcloud auth application-default login` for GCP. See `infra/README.md`.

The drift checks run `terraform plan` in `infra/aws` and `infra/gcp`, so both
roots must be initialised, and the `TF_VAR_` variables each check lists must be
set. A missing variable is reported as an error, never as a pass.

## Build status

| Component | State |
|---|---|
| Terraform foundations, both clouds | Done |
| Inventory generator (KSI-PIY-GIV) | Done, self-tested |
| Collector framework | 5 of 9 mechanisms implemented. 91 check definitions, each linked to the matrix rows it proves (2026-10-02). **Runs daily from GitHub Actions** (`collect.yml`, 05:30 UTC) as read-only identities in AWS and GCP, with no stored credential, and emits the SDR each run |
| SDR emitter | Emits a schema-valid record for all 46 indicators. Each evidence row names the checks behind it: of 380 rows, 49 fully automated, 25 partly ([coverage report](docs/MATRIX-COVERAGE.md)) |
| Central log store and query engine | Done |
| Log normalization and detection | Done, AWS side only. Sign-in classification fixed and tested 2026-10-01; the detection Lambda's alert path to the encrypted topic is not yet proven |
| Application environment, AWS | Phase 1 and 2 last run 2026-10-02: served requests with IAM auth to the database, and the worker's extracts landed through the S3 gateway endpoint after its policy was fixed (it had never allowed a write). Torn down after |
| Workforce identity | Google Cloud Identity federated to IAM Identity Center, authenticated end to end. Operator permission set assigned to `alex@` (2026-09-29); `aws sso login` not yet proven |
| Cross-cloud federation (GCP → AWS) | Role applied and persistent; trust pinned to the GCP service account numeric ID |
| GCP analytics pipeline | Phase 2 deployed 2026-10-02. **Data crossed end to end the same day**: four measurements written through the api reached BigQuery by way of the worker, S3, the cross-cloud federation and the Cloud Run job pinned to the signed digest. Runs every six hours |
| CI/CD pipeline | `drift` clean in CI over the full persistent set (2026-09-23). `build-and-push` has published signed images |
| Posture services (GuardDuty, Security Hub, Inspector) | Running continuously since 2026-09-23. Inspector scans the persisted images |

**Nothing expensive is standing between sessions.** 271 AWS resource instances persist,
plus the state backend: the log store, CloudTrail, the Config recorder, Athena,
both Lambdas, the CI identities, the cross-cloud role, the container registry
with its signed images, the extract bucket, the artifacts key and the posture
services. The posture services are the only ones with a real standing cost,
estimated at 3 to 8 USD a month. There is no load balancer, database, VPC or
endpoint. The
application environment is rebuilt each session with `terraform apply` and
removed with `infra/aws/teardown.sh`; see `infra/README.md`. Phase 1 was last
verified on 2026-09-22 — inventory self-test and collector checks passing on
both clouds, no internet route on the private tiers, database private and
encrypted. The evidence is in `docs/DECISIONS.md`.

The AWS account is on the Paid plan, so GuardDuty, Security Hub and Inspector
work as designed. The account was created 2026-07-31 and **must not be left on
the Free plan past roughly 2027-01-31**, which is a condition of it continuing
to exist at all rather than a service question — see `docs/DECISIONS.md`.

Scope reductions are recorded in `docs/DECISIONS.md` as they are made, rather
than discovered later by a reader.
