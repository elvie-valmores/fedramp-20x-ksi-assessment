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

Three mechanisms are implemented. The other six are registered but raise a
clear error explaining what they are waiting on.

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
```

All three need working cloud credentials: an AWS profile, and
`gcloud auth application-default login` for GCP. See `infra/README.md`.

## Build status

| Component | State |
|---|---|
| Terraform foundations, both clouds | Done |
| Inventory generator (KSI-PIY-GIV) | Done, self-tested |
| Collector framework | 3 of 9 mechanisms implemented |
| Central log store and query engine | Done |
| Log normalization and detection | Done, AWS side only |
| Application environment, AWS | Phase 1 applied and verified 2026-09-22; torn down after. Phase 2 needs images |
| GCP analytics pipeline | Written, never applied |
| Cross-cloud federation (GCP → AWS) | Written, never applied — gated on the GCP service account existing |
| CI/CD pipeline | `drift` verified working end to end 2026-09-22 (clean, exit 0). `build-and-push` not yet re-run |

**Nothing is standing between sessions** except the state backend, the log
store, CloudTrail, the Config recorder, Athena and the two Lambdas. The
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
