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

The build is in progress, and `README.md` carries the current status table. As of 2026-09-22:

- **Persisting between sessions** — the state backend, the Object Locked log store, CloudTrail, the
  Config recorder, Athena and Glue, the normalization and detection Lambdas, the budget guardrails,
  and the GCP foundations (asset feed, Pub/Sub, budget). 40 AWS resources plus 7 GCP ones.
- **Built and verified, but not standing** — the AWS application environment, phase 1. It applies in
  about fifteen minutes and is torn down after each session. Last verified 2026-09-22: inventory
  self-test passing on both clouds including its negative control, 5 of 5 collector checks passing,
  no internet route on the private tiers, database private and encrypted. **Do not assume it is
  running** — check before building anything that talks to it.
- **Written, never applied** — the GCP analytics pipeline (`infra/gcp/analytics.tf`,
  `infra/gcp/pipeline.tf`), and the cross-cloud role in `infra/aws/cross_cloud.tf`, which is gated to
  zero resources until the GCP pipeline service account exists.
- **Run, and failing** — the CI/CD pipeline. `build-and-push` and `drift` have both executed and both
  failed at the same step: the GitHub OIDC trust policy pinned the legacy subject claim while the
  repository sends GitHub's newer *immutable* subject, which carries numeric owner and repository IDs.
  The fix is written in `infra/aws/pipeline.tf` and plans to two in-place trust-policy updates; it has
  not been applied, because `pipeline.tf` is in the destroyable set and the environment is down. Both
  ECR repositories are still empty as a result. See the 2026-09-22 entry in `DECISIONS.md`.
- **Not started** — the three workflows, policy-as-code, the SDR emitter, and the remaining check
  definitions. 5 of roughly 380 exist. 3 of 9 collector mechanisms are implemented; the other six are
  registered and raise a clear error naming what they wait on.

**The two phase gates, both real and both the indicators working correctly.** The AWS root and the
GCP root each apply in two phases, because KSI-SVC-VRI requires images referenced by digest and a
digest cannot be looked up before the image exists. Phase 2 on both clouds is therefore blocked on
CI, and CI is blocked on nothing but configuration — which makes it the critical path.

**The analytics image has no path to existing yet.** `build-and-push.yml` builds `api` and `worker`
only, there is no GitHub-to-GCP workload identity federation, and there is no container runtime on
the workstation. `infra/README.md` says the image is "pushed by hand until then", which is not
currently possible. Resolve this before planning GCP phase 2.

The build order below is the plan; the status table in `README.md` is what has actually happened.

---

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
