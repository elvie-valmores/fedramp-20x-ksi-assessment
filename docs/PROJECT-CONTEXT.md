# Project Context — FedRAMP 20x Class C KSI Self-Assessment

**Read this first.** This document is the entry point for anyone (human or AI assistant) working on
this repository. It carries its own context and does not assume you have seen prior conversations.

---

## What this project is

A FedRAMP 20x Class C Key Security Indicator self-assessment, built against real infrastructure
across AWS and GCP.

A fictional two-person security team runs a SaaS product on AWS with a separate analytics pipeline on
GCP. Commercial cloud, not FedRAMP-authorized hosting. The team is self-assessing against the 46 Key
Security Indicators in FedRAMP's Consolidated Rules for 2026 (CR26) ahead of a first independent
assessment.

The deliverable is a Security Decision Record: the artifact that replaced the System Security Plan
under CR26.

## What has already been done

The full determination pass is complete. All 46 indicators were worked one at a time against the
pinned catalog, with the reasoning recorded.

- **18 in scope** — built and satisfied
- **22 in scope, partially satisfied** — built, with stated gaps
- **6 deferred** — with recorded reasons and resulting customer risk

The design phase is closed. What remains is the build.

## Where the build has reached

The build is in progress, and `README.md` carries the current status table. As of 2026-09-23:

- **Persisting between sessions**: 58 AWS resources and 30 GCP ones. On AWS: the log store, CloudTrail,
  the Config recorder, Athena and Glue, both Lambdas, the budget guardrail, the CI identities (OIDC
  provider, drift role, build role), the cross-cloud role, the container registry, the extract bucket
  and the artifacts key. On GCP: all of phase 1. "Resume here" below has the detail.
- **Built and verified, but not standing**: the AWS application environment, both phases. It applies
  in about fifteen minutes and is torn down after each session. Phase 1 was last verified on
  2026-09-22. Phase 2 was verified on 2026-09-23, when it served a request authenticated to the
  database through IAM. **Do not assume it is running.** Check before building anything that talks
  to it.
- **Applied up to a gate**: the GCP analytics pipeline. Phase 1 is standing. The Cloud Run job waits
  behind `deploy_pipeline = false` for an image that has no way to be built yet (below).
- **Proven**: the CI/CD pipeline. `drift` runs clean in CI against the full persistent set, and
  `build-and-push` has published signed images, which survive teardown. See the 2026-09-22 and
  2026-09-23 entries in `DECISIONS.md`.
- **Not started**: the three workflows, policy-as-code, the SDR emitter, and the remaining check
  definitions. 15 of roughly 380 exist. 4 of 9 collector mechanisms are implemented and self-tested.
  The other five are registered and raise a clear error naming what they wait on. Two of those five
  have since been unblocked by later work; see the 2026-09-22 entry in `DECISIONS.md`.

**The two phase gates, both real and both the indicators working correctly.** The AWS root and the
GCP root each apply in two phases. KSI-SVC-VRI requires images referenced by digest, and a digest
cannot be looked up before the image exists. AWS phase 2 is now reachable in a single apply. GCP
phase 2 is still blocked on the analytics image.

**The analytics image has no path to existing yet.** `build-and-push.yml` builds `api` and `worker`
only, there is no GitHub-to-GCP workload identity federation, and there is no container runtime on
the workstation. `infra/README.md` says the image is "pushed by hand until then", which is not
currently possible. Resolve this before planning GCP phase 2.

The build order below is the plan; the status table in `README.md` is what has actually happened.

---

## Resume here — state at the end of 2026-09-23

Read this before inferring anything from the code or from git history. Both have been stale before,
and so has this block. The most common failure in this project is a control that is configured,
deployed and internally consistent, and still does nothing. Check against the live accounts.

### What is standing

**AWS — 58 persistent resources. Nothing ephemeral is in state and nothing expensive is running.**
Checked against the API at 21:35 UTC on 2026-09-23. No load balancer, no database, no ECS cluster,
no VPC except the default one, no endpoints. Inspector reports `DISABLED`, GuardDuty has no detector,
and the account is not subscribed to Security Hub.

What remains: the Object Locked log store (`COMPLIANCE`, 7 days), CloudTrail, the Config recorder,
Athena and Glue, both Lambdas, the budget guardrail, the GitHub OIDC provider, the drift role, the
build role, the cross-cloud role, the two ECR repositories, the extract bucket and the artifacts key.
Fifteen other customer-managed keys sit in `PendingDeletion` and clear on their own. `terraform state
list` prints 103 lines; 45 of them are data sources, which `boundary.py` leaves out.

**Signed images survived the teardown.** ECR holds 8 manifests each for `api` and `worker`. **Deploy
`git-f9f2c35f8fd1`**: it carries the `/dev/shm` certificate fix. `v1` predates that fix, and its api
task crashes on start. Phase 2 no longer needs a rebuild first.

**GCP — 30 resources, phase 1 complete, and a plan on 2026-09-23 showed no drift.** Landing bucket,
BigQuery dataset and table, Artifact Registry, two KMS keys and their ring, two service accounts, and
Data Access audit configuration on storage, BigQuery and KMS. The Cloud Run job and its schedule stay
switched off with `deploy_pipeline = false` until there is an image.

**Identity.** AWS Organization `o-yyhciflg3u` (feature set `ALL`). IAM Identity Center
`ssoins-7223046591f7f9f9` in `us-east-1`, identity store `d-90667e73f9`. The SAML identity provider is
Google Cloud Identity on `corp.elvievalmores.com` (customer ID `C01rucqxe`). Three accounts: `admin@`
(break-glass), `alex@` (Platform Engineer), `sam@` (Security Engineer).

**The offering is named Caliper**, at `caliper.elvievalmores.com`. Its ACM certificate is issued and
DNS-validated. It is valid for **197 days** and expires 2027-04-07, not the thirteen months this file
once assumed. Read certificate dates; do not assume durations.

### What is proven, and how

Nothing below is "configured". Each was exercised.

- **Inventory**: the self-test passes on both clouds, including its negative control. It seeds one
  watched and one unwatched resource and confirms only the first appears.
- **Collectors**: 15 of 15 checks pass, and 4 of 9 mechanisms are implemented. Every pipeline
  assertion has a negative control in `collector/self_test.py`, because a check that cannot fail is
  not a check.
- **Drift**: runs green in CI against the full 58-resource persistent set, including the build role
  and the cross-cloud role. The first such run was 35923874415 on 2026-09-23. Earlier green runs
  checked a smaller set; see the last 2026-09-23 entry in `DECISIONS.md`.
- **Image pipeline**: `build-and-push` has completed twice. It scans dependencies, builds, signs,
  verifies the signature and pushes by digest.
- **The application**: phase 2 served a request. `POST /measurements` returned 201 and the read-back
  returned 200. It authenticated to Postgres through IAM, and no password exists anywhere in the
  system.
- **Teardown**: 118 resources destroyed, the persistent set intact, and the images kept.
- **Federation**: a sign-in has gone through end to end, from Google to Identity Center.
- **Cross-cloud trust**: AWS accepted a policy pinning `sub` and `aud` to the GCP service account's
  numeric ID, `104894493962317106056`.

### The persistence boundary, which is now a rule

`infra/aws/boundary.py` owns the split. `teardown.sh --ephemeral` and `drift.yml --persistent` both
consume it. Implementing it twice would let the halves diverge, and both failure modes are silent: a
resource the teardown forgets bills forever, and one the drift check forgets stops being watched.

**The rule, which came up three times in one day: a persistent resource may not reference an
ephemeral one, and the seam falls between the thing and the permission to use it.** The store
persists; the grants to transient principals do not. `registry_grants.tf` and the IAM-side
authorisation for the artifacts key both follow from this.

**Moving a file across the boundary changes which variables the drift plan needs**, because
targeting decides what gets evaluated. `cross_cloud.tf` brought `GCP_PIPELINE_SA_UNIQUE_ID` with it.

`boundary.py` derives from Terraform state, so it lists what exists and cannot propose creating what
does not. Moving something onto the persistent side needs a one-time apply targeted by declaration.

### Applying

A full AWS apply needs `TF_VAR_billing_alert_email`, `TF_VAR_gcp_pipeline_sa_unique_id` and
`TF_VAR_app_domain`. The first two are repository variables. **`APP_DOMAIN` is not one**; its value is
`caliper.elvievalmores.com`. Phase 2 adds `-var deploy_services=true -var
app_image_tag=git-f9f2c35f8fd1`. Tear down with `infra/aws/teardown.sh`.

The GCP root also needs `TF_VAR_billing_account_id`. Read it with `gcloud billing projects describe
fedramp-20x-ksi-assessment`.

### The next thing to do

**First, decide whether `posture.tf` moves to the persistent side.** This is open and needs the
user's decision; do not act on it without one. The case is in `DECISIONS.md` under 2026-09-23. It
costs roughly 3 to 8 USD a month. The file is eligible, because its only outside reference is the
already-persistent SNS topic. Against it: the 3-day collector cadence limitation is an accepted
precedent of the same shape. It matters because nothing scans the persisted images between sessions,
and nine indicators consume the scanner.

**Then the collector framework, which is the bottleneck on the build order.** 4 of 9 mechanisms and
15 of roughly 380 check definitions exist, and the SDR emitter, which is the actual deliverable, has
not been started. **`declared_versus_live_comparison` is next.** Its "not yet built" note says it
waits on "a reader for Terraform state". The state has been in S3 and readable all along, so that
block is stale (2026-09-22).

### Open items

| Item | State |
|---|---|
| `posture.tf` persistence | Open question. See above |
| The analytics image has no build path at all | Blocks GCP phase 2 |
| `APP_DOMAIN` is not a repository variable | `drift.yml` passes it anyway, and it comes through empty. Harmless while only ephemeral files use it |
| Cloud Identity Premium for SCIM | Deferred until KSI-IAM-AAM's evidence is built |
| `security.txt` contact would bounce | No MX on `caliper.elvievalmores.com` |
| ACM managed renewal under apply-and-destroy | Verify before 2027-02-06 |
| Identity Center sign-ins may not reach CloudTrail | Unverified; would affect KSI-MLA-LET |
| Security Command Center Standard | Console activation outstanding |
| Passkey on `admin@corp.elvievalmores.com` | Requested, never confirmed. That account had no second factor and administers the whole workforce directory |

**On the analytics image.** `build-and-push.yml`'s matrix is `[api, worker]`, and `app/analytics/` is
not in it. There is no GitHub-to-GCP workload identity federation and no container runtime on the
workstation. `infra/README.md` says the image is "pushed by hand until then", which is not currently
possible by any route. The most likely fix is adding the federation and a third matrix entry.

**Groups, permission sets and assignments do not exist yet.** They are declared in Terraform by
decision, because SCIM does not sync groups. They can be built now up to the seam. Permission sets,
groups and account assignments can all be declared. Putting Alex and Sam *into* groups needs the
users to exist in Identity Center, which needs SCIM, which needs Premium.

## The files in `/docs`

| File | What it is |
|---|---|
| `KSI-Design-Matrix.xlsx` | **The primary artifact.** All 46 determinations, one block each |
| `DECISIONS.md` | 208 dated entries recording why each decision was made, including reversals |
| `KSI-Catalog-Reference.md` | All 46 indicator statements, mappings and defined terms |
| `SDR-Emitter-Spec.md` | How determinations map onto FedRAMP's official SDR schema |
| `fedramp-security-decision-record-schema-2026-06-24.json` | The official schema, vendored |
| `fedramp-consolidated-rules-2026.09.13.02.json` | The pinned catalog |

### Reading the design matrix

Thirteen tabs. Start with **Index** and **Responsibility Matrix**, then the cluster tabs.

- **Index** — every determination, plus the environment design, cost posture, conventions, and the
  shared components table
- **Responsibility Matrix** — all 46 sorted by cluster with determination, validation type and
  provider position
- **Cluster tabs** (IAM, SVC, CNA, MLA, CMT, SCR, RPL, PIY, INR, CED) — one block per indicator:
  requirement, design rationale, what to build, verification evidence, validation evidence,
  automation assurance, remediation, limitations
- **Assertion Coverage** — each indicator decomposed into assertions with how each is satisfied

---

## Pinned sources — verify before trusting

Both of these have already drifted once during this project. Re-verify rather than assuming.

**Catalog:** FedRAMP Consolidated Rules for 2026
- Version `2026.09.13.02`, from `github.com/FedRAMP/rules`
- sha256 `64915d88e72353c95f321ea4a9014516ac9441972cbd7f3d1abef7d1514c8fc8`
- Previously pinned at 2026.07.14.01; re-verified with no indicator text or mapping changes

**SDR schema:** `fedramp-security-decision-record-schema-2026-06-24.json`
- From `github.com/FedRAMP/schemas`
- `$schemaVersion` **1.1.1**, sha256 `94580404e8d4276ee3ced2a3c39cce5cc6565df6ae38a91f60f26cb96d833188`
- The filename is dated 2026-06-24 and has not changed, but the internal version moved from 1.0.3 to
  1.1.1 and a field-name typo was corrected after publication. **Pin the filename, the
  `$schemaVersion`, and the hash.** A filename pin alone catches neither change.

---

## The architecture

**AWS — the SaaS product**

ECS Fargate running two services, behind an Application Load Balancer with WAF and Shield Standard.
RDS PostgreSQL `db.t4g.small`, single-AZ, automated backups with point-in-time recovery. Private
subnets with **no NAT gateway and no internet route** — egress reaches AWS services through six VPC
interface endpoints plus a free S3 gateway endpoint. Secrets Manager, customer-managed KMS keys,
CloudTrail, a scoped Config recorder, GuardDuty foundational, Security Hub Essentials.

**GCP — the analytics pipeline**

BigQuery, a scheduled Cloud Run job, a GCS landing bucket, Cloud Asset Inventory, Audit Logs,
Security Command Center free tier, Cloud KMS, Artifact Registry.

**Identity**

Google Cloud Identity is the workforce identity provider. AWS IAM Identity Center trusts its SAML
assertion, with SCIM user provisioning. Groups and permission set assignments are declared in
Terraform, since SCIM group sync is not supported. AWS root and break-glass stay native by design.

**Shared**

One S3 bucket with Object Lock (compliance mode, **retention in days**) and CloudTrail log file
validation, receiving both clouds' logs as partitioned Parquet, normalized to OCSF on the way in.
Athena over that store with partition projection and workgroup scan limits. GitHub with Actions,
OIDC to both clouds, actions pinned to commit SHAs.

---

## Shared components — build these before any indicator

The cluster tabs name what each indicator relies on, not what is separately built. Twelve components
are built once and consumed by many. **A build row naming a shared component is a consumer, not an
additional build.**

| Component | Consumers |
|---|---|
| Collector framework — nine evidence mechanisms | 40 indicators |
| Inventory generator | 27 indicators |
| Consolidated resource register | 13 indicators |
| Normalized log corpus (OCSF) | 12 indicators |
| Query layer (Athena) | 12 indicators |
| Detection path | 9 indicators |
| Vulnerability scanner | 9 indicators |
| Standing-query self-test harness | 34 indicators, 65 queries |
| Deliberate test harness | 12 indicators, 23 scenarios |
| Signal report generator | 7 indicators |
| SDR emitter | 40 indicators |
| Environment (Terraform, both clouds, pipeline) | all |

380 evidence rows resolve to nine mechanism classes: cloud API config read, log query,
declared-versus-live comparison, inventory reconciliation, register read, pipeline config read,
deliberate test, record store, effective-access analysis.

**Build mechanism-first, not indicator-first.** Indicator-by-indicator means writing 380 things.
Mechanism-first means writing nine, then 380 lines of configuration.

---

## Build order

1. **Environment** — Terraform for both clouds and the pipeline
2. **Inventory generator** — 27 indicators reconcile against it
3. **Collector framework** — the nine mechanisms
4. **Normalized log corpus and query layer** — OCSF mapping, Athena, partitioning. Most likely to
   overrun; do it while there is slack
5. **The three workflows** — elevation, responder, SCIM token rotation
6. **Policy-as-code and the SDR emitter**
7. **The 380 check definitions** as configuration, in batches
8. **Test harness** — built alongside each mechanism, not bolted on at the end

**First task:** a vertical slice. AWS provider config, remote state backend, one billing alarm.
Confirm credentials and cost guardrails work before building anything on top.

---

## Cost posture

Apply and destroy per session. Persisting between sessions: Terraform state backend, evidence
storage, the central log store, database snapshots, KMS keys.

Standing continuously the stack is roughly 115 to 125 USD per month. Torn down between sessions the
residual is under 5. Realistically 15 to 25 per month at normal working cadence.

**Two cost traps already found:**

- **AWS Config bills per configuration item.** Apply-and-destroy generates items on every create,
  delete and relationship change, so this is the one meter that worsens with teardown discipline.
  The recorder is scoped to needed resource types for this reason.
- **Object Lock compliance mode cannot be shortened by anyone including root.** The only escape is
  deleting the AWS account. Retention is set in days, not months. A real provider would set months or
  years and accept the irreversibility.

Set a billing alarm before the first apply.

---

## Working rules established during the determination pass

These held across 46 determinations. Keep them.

**Read the mappings, not just the statement.** The NIST citations changed a determination nine
separate times. The statement gives the outcome; the mappings give the reach.

**Absence of a finding is only evidence if the looking was recorded.** Every zero-results query
self-tests: seed a matching event, confirm the query stops returning zero, revert. Every review run
records nil results.

**Remediate the condition, never the measurement.** Widening a declared blast radius, moving a
recovery objective to meet a measured time, or adopting drift into code all turn a finding green
while changing nothing.

**Split by subject.** Where a statement names several subjects and some are machine-based and some
are not, determine the machine-based ones and declare the rest. Defer wholesale only when the trigger
does not exist or every subject is non-machine.

**State limitations rather than narrowing scope to avoid them.** Every partial in this project is a
declared cost decision, platform limit or scope exclusion, not a gap discovered late.

**Record the session before ending it, and if one ends without a record, reconstruct it.** A session
that applies infrastructure and writes nothing leaves the repository asserting the opposite of what
is true in the account. This has happened once, on 2026-09-21. It is recoverable: S3 object-version
history on `aws/terraform.tfstate` gives a timestamped size curve of every apply and destroy, and
CloudTrail `lookup-events` on a named resource gives the matching calls. Together they date each
phase to the minute. Reconstruct first, then act — the 2026-09-22 entries in `DECISIONS.md` show the
method.

---

## Known limitations carried into the build

- **The 3-day cadence versus teardown.** The collector framework runs on a real 3-day schedule via
  EventBridge and Cloud Scheduler, which are Terraform-managed and therefore exist only while the
  environment does. A production deployment would run continuously. Record this explicitly.
- **SDR-CSX-KMT wants a year of daily metrics at Class C.** An apply-and-destroy environment cannot
  produce that. The "where available" qualifier makes it survivable; state the collection window.
- **The schema requires `fedRampRequirements`**, the ruleset half this project did not determine.
  Make it an emitter switch, not a silent empty array.
- **No assessor is engaged.** Independent verification and validation fields stay empty with a stated
  reason rather than filled with self-assessment.
- **Multi-cloud is portfolio-motivated.** A real two-person team would more likely pick one cloud. The
  honest framing is that a second cloud demonstrates cross-cloud normalization, which is harder and
  more differentiating — not that this is what the persona would organically build.
