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

The build is in progress, and `README.md` carries the current status table. As of 2026-09-29:

- **Persisting between sessions**: 259 AWS resource instances (73 resources plus 186 disabled
  Security Hub controls) and 30 GCP ones. On AWS: the log store, CloudTrail,
  the Config recorder, Athena and Glue, both Lambdas, the budget guardrail, the CI identities (OIDC
  provider, drift role, build role), the cross-cloud role, the container registry, the extract bucket,
  the artifacts key, the posture services (GuardDuty, Security Hub, Inspector) and the account-level
  S3 public access block, and the operator's Identity Center permission set and assignment. On GCP: all of
  phase 1. "Resume here" below has the detail.
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
- **Built, first version**: the SDR emitter (`sdr/emit.py`). It emits a valid record for all 46
  indicators, with automated evidence for 11 of them. See the 2026-09-23 entry in `DECISIONS.md`.
- **Not started**: the three workflows, policy-as-code, and the remaining check definitions. 29 of
  roughly 380 exist. 5 of 9 collector mechanisms are implemented and self-tested.
  The other four are registered and raise a clear error naming what they wait on, and all four
  are genuinely blocked. **No collector schedule or runtime exists.** The collectors are run by
  hand.

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

## Resume here — state as of 2026-09-30

Read this before inferring anything from the code or from git history. Both have been stale before,
and so has this block. The most common failure in this project is a control that is configured,
deployed and internally consistent, and still does nothing. Five were found in one week, and every
one was found by running the thing rather than reading it. Check against the live accounts.

The build work recorded here was done on 2026-09-23. On 2026-09-25 the session was closed out: the
state below was re-verified against both clouds, the teardown was confirmed, and this block was
rewritten. On 2026-09-29 the user's items were worked through: the editor grant is gone, both
passkeys are in place, and the operator's permission set is applied. See that day's entry in
`DECISIONS.md`.

### First actions for the next session

1. **Verify, do not trust.** These four commands reproduce every claim in "What is standing":
   - `infra/aws/boundary.py --persistent | wc -l` should give 259, and `--ephemeral` should give 0.
   - The API sweep in the 2026-09-25 entry of `DECISIONS.md`.
   - `gh run list --workflow drift.yml -L 3`: the daily 07:00 UTC run should be green.
   - `cd collector && ../.venv/bin/python run_checks.py`, with the variables under "Running
     things", and `AWS_PROFILE=caliper-admin` after `aws sso login --profile caliper-admin`. Start
     the sign-in from the Google app tile as `alex@` (2026-09-30 entry). Expect 28 of 29: the
     failure is the KMS finding.
2. **Finish the move off the static key**, below, if it is still open.
3. **Then pick up the build** at "The next thing to do".

### Waiting on the user

| Item | What they do |
|---|---|
| _Nothing waiting_ | All of the user's items are closed as of 2026-09-30 |

Done on 2026-09-29: the editor grant removed (verified), and passkeys on `admin@` and `alex@` (on the
user's word). The `InterimOperatorAdmin` permission set is assigned to `alex@`, under the 2026-09-19
exception. On 2026-09-30 `aws sso login` was proven as `alex@` (profile `caliper-admin`), but only
when the sign-in starts from the Google app tile, and the static key was deactivated. See that
day's entry. The key and the `terraform-admin` user were then deleted; the account has no IAM
users. **The operator identity is `caliper-admin`, and `AWS_PROFILE=caliper-admin` is set in the
user's `~/.zshrc`.**

### What is standing

**AWS: 259 persistent resource instances. Nothing ephemeral is in state and nothing expensive is running.**
Verified 2026-09-25 against the API: no load balancer, database, ECS cluster, non-default VPC,
endpoint, NAT gateway, Elastic IP or instance. `teardown.sh` reports "already torn down".
`terraform state list` prints more lines than 259; the rest are data sources, which `boundary.py`
leaves out.

The persistent set, by file (`boundary.py --files`), is:

- **Evidence layer:** the Object Locked log store (`COMPLIANCE`, 7 days), CloudTrail, the Config
  recorder, Athena and Glue, and both Lambdas.
- **Guardrails:** the budget guardrail, the account-level S3 public access block, and the SSM
  document public-sharing block.
- **CI and cross-cloud identity:** the OIDC provider, the drift role, the build role and the
  cross-cloud role.
- **Registry:** the ECR repositories with their signed images, the extract bucket with its TLS and
  encryption denies, and the artifacts key.
- **Posture:** GuardDuty (with RDS and S3 Protection), Security Hub with CIS and FSBP, and
  Inspector on ECR. 186 Security Hub controls for undeployed services are disabled, with reasons
  (`securityhub_controls.tf`).
- **Operator access:** the `InterimOperatorAdmin` permission set, its policy attachment, and its
  assignment to `alex@`.

**The posture services are the only standing cost**, estimated at 3 to 8 USD a month and not yet
measured. The Inspector trial ends **2026-10-06** and GuardDuty's around 2026-10-22.

Of the fifteen customer keys from the 2026-09-23 teardown, three are still in `PendingDeletion` and
clear on 2026-09-30. Config had not recorded the deletion of four that cleared on 2026-09-29.

**Signed images are in ECR. Deploy `git-f9f2c35f8fd1`:** it carries the `/dev/shm` certificate fix.
`v1` predates the fix, and its api task crashes on start. Phase 2 does not need a rebuild first.

**GCP: 30 resources, phase 1, no drift.** Landing bucket, BigQuery dataset and table, Artifact
Registry, two KMS keys and their ring, two service accounts, and Data Access audit configuration.
The Cloud Run job stays off (`deploy_pipeline = false`) until there is an image. GCP has no
teardown; phase 1 is meant to stand.

**Identity.** AWS Organization `o-yyhciflg3u`, IAM Identity Center `ssoins-7223046591f7f9f9` in
`us-east-1`, identity store `d-90667e73f9`. The SAML identity provider is Google Cloud Identity on
`corp.elvievalmores.com` (customer ID `C01rucqxe`). Three directory accounts: `admin@`
(break-glass), `alex@` and `sam@`. **Identity Center has one user, `alex@`, created by hand, and
one permission set, `InterimOperatorAdmin`.** No groups yet.

**The offering is Caliper**, at `caliper.elvievalmores.com`. The ACM certificate is valid for 197 days
and expires 2027-04-07. Read certificate dates; do not assume durations.

### What is proven, and how

Nothing below is "configured". Each was exercised.

- **Collectors**: 29 checks, 28 passing on 2026-09-30. The failure is `inventory_current` on
  deleted KMS keys that Config still lists, more than a day later: a finding, not a lag.
  5 of 9 mechanisms are built, and 11 of 46 indicators have automated evidence.
  `collector/self_test.py` has negative controls for 18 assertions, each also tested against a
  deliberately broken version of itself. The older `cloud_api_config_read` handlers (Config
  recorder, asset feed), `log_query` and `inventory_reconciliation` **have none yet**.
- **Declared versus live**: drift, missing resources, and the reverse direction (every inventoried
  resource declared or excused by a rule verified with the provider). Proven by tagging the extract
  bucket out of band: the check failed, named it, and attributed it. The tag was reverted and the
  check passed again.
- **Inventory currency**: a resource the inventory lists but its service says is gone fails
  KSI-PIY-GIV's `inventory_current`. Config lagged about 70 minutes on an implicit deletion on
  2026-09-23.
- **The SDR**: `sdr/emit.py` emits a schema-valid record for all 46 indicators, and validation was
  shown to reject six kinds of broken record. `sdr/verify_pins.py` confirms both schema pins against
  FedRAMP's published copies.
- **Drift**: green in CI over all 68 persistent resources. The scheduled runs on 2026-09-24 and
  2026-09-25 passed unattended. `boundary.py --check` runs first on every run.
- **Bucket protections**: plain HTTP and writes without the KMS header are refused, tested against
  the admin user.
- **Posture**: Inspector reproduced the phase 2 image findings (4 critical, 14 high, 12 medium per
  image) against the persisted images.
- **Pipeline, application, teardown, federation, cross-cloud trust**: all exercised end to end on
  2026-09-22 and 2026-09-23. See those entries in `DECISIONS.md`.

### The persistence boundary, which is a rule

`infra/aws/boundary.py` owns the split. `teardown.sh` and `drift.yml` both consume it, and neither
keeps its own list: both now print the boundary's own list rather than a hand-written one.

- **A persistent resource may not reference an ephemeral one, and the seam falls between the thing
  and the permission to use it.** A store's own protections persist with it. Grants to transient
  principals do not. That rule, applied at file level, is how the extract bucket lost its TLS deny
  between sessions.
- **Run `boundary.py --check` before moving anything.** It fails, naming file and line, if a
  persistent file references an ephemeral resource.
- **Moving something to the persistent side needs a one-time apply targeted by declaration**,
  because the boundary is derived from state.
- **Moving a file changes which variables the drift plan needs.** `cross_cloud.tf` brought
  `GCP_PIPELINE_SA_UNIQUE_ID` with it.

### Running things

```sh
export TF_VAR_billing_alert_email=aws@elvievalmores.com
export TF_VAR_gcp_pipeline_sa_unique_id=104894493962317106056
export TF_VAR_app_domain=caliper.elvievalmores.com   # not a repository variable
export TF_VAR_billing_account_id=$(gcloud billing projects describe fedramp-20x-ksi-assessment \
  --format='value(billingAccountName)' | sed 's#billingAccounts/##')

cd collector && ../.venv/bin/python self_test.py
cd collector && ../.venv/bin/python run_checks.py --json results.json
cd sdr && ../.venv/bin/python emit.py --results ../collector/results.json --frr empty
```

- **AWS phase 1:** `terraform apply` in `infra/aws`.
- **AWS phase 2:** add `-var deploy_services=true -var app_image_tag=git-f9f2c35f8fd1`.
- **Teardown:** `infra/aws/teardown.sh`.

**Changes to IAM bindings may be refused by the session's permission controls.** Hand the user the
command. Do not route around the refusal.

### The next thing to do

**Evidence coverage is the bottleneck.** The deliverable exists, but only 11 of 46 indicators carry
automated evidence (29 of roughly 380 checks). The other four mechanisms are genuinely blocked. In
rough priority:

1. **The evidence-store encryption key.** This is SVC-SIN build row 1, and the recommended design is
   in `DECISIONS.md`, 2026-09-23, "Four open items". It is a session of its own, because a wrong
   key-policy grant stops CloudTrail or Config from logging, so confirm fresh logs arrive before
   calling it done. SVC-SIN row 39's check waits on it.
2. **Fix the AWS-started sign-in** (2026-09-30 entry). Until then, sign-in starts at the Google tile.
3. **A collector runtime and schedule.** Until one exists, the SDR's cycle statement says "run by
   hand", SDR-CSX-KMT's metrics are one run, and the emitter cannot run in CI.
4. **More check definitions** against the five built mechanisms, and **negative controls for the
   older handlers**.
5. **Link check definitions to matrix rows**, so the SDR can say which row each check proves.

**At the next phase 1:** confirm the declared default security group applied with no rules, and that
`svc-acm-cfg-aws-inventory-is-declared` passes with the environment up. **At the next phase 2:**
confirm the worker's extracts still land through the VPC endpoint, since that restriction moved to
the worker role.

### Open items

| Item | State |
|---|---|
| Posture cost: scoped, saving not yet proven | Option C applied 2026-09-30: 186 controls off. Projected about 8.70 USD a month. **Recount daily checks on 2026-10-01** and confirm `SSM.7` passes |
| Security Hub control coverage | Undeployed services' controls are off. Kept controls for declared types the Config recorder does not record still warn. Check which |
| Config and scheduled KMS key deletion | A finding, not a lag: still `OK` in Config a day after deletion. Correct Config's record or stop trusting Config for this type |
| AWS-started Identity Center sign-in fails | "Responses must contain exactly one Assertion". Lead: Entity ID versus Identity Center's issuer URL. Start from the Google tile until fixed |
| Customer-managed keys for the evidence stores | Next thing to do, item 1 |
| No collector schedule or runtime exists | Next thing to do, item 3 |
| Config lag on implicit deletions | Handled by `inventory_current`. Four AWS types and all of GCP cannot be probed, and stay unaccounted when undeclared |
| The analytics image has no build path | Blocks GCP phase 2. Needs GitHub-to-GCP federation and a third matrix entry in `build-and-push.yml` |
| `APP_DOMAIN` is not a repository variable | `drift.yml` passes it and it arrives empty. Harmless while only ephemeral files use it |
| Cloud Identity Premium for SCIM | Deferred until KSI-IAM-AAM's evidence is built |
| `security.txt` contact would bounce | No MX on `caliper.elvievalmores.com` |
| ACM managed renewal under apply-and-destroy | Verify before 2027-02-06 |
| Security Command Center Standard | Console activation outstanding |

**Groups, permission sets and assignments do not exist yet.** They are declared in Terraform by
decision, because SCIM does not sync groups. They can be built up to the seam. Putting Alex and Sam
into groups needs the users to exist in Identity Center, which needs SCIM, which needs Premium.

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
residual was under 5 until 2026-09-23. The posture services now persist, which adds an estimated 3 to
8. At normal working cadence, expect the earlier 15 to 25 per month plus that.

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

- **The 3-day cadence has no schedule behind it yet.** This bullet used to say the collector
  framework "runs on a real 3-day schedule via EventBridge and Cloud Scheduler". That was never
  built. No collector schedule, and no runtime for the collectors, exists in either root (checked
  2026-09-23). The collectors are run by hand. Until a schedule exists, the cadence column is a
  requirement, not a property. Once one is built, whether it persists is the same question
  `posture.tf` raised.
- **SDR-CSX-KMT wants a year of daily metrics at Class C.** An apply-and-destroy environment cannot
  produce that. The "where available" qualifier makes it survivable; state the collection window.
- **The schema requires `fedRampRequirements`**, the ruleset half this project did not determine.
  Make it an emitter switch, not a silent empty array.
- **No assessor is engaged.** Independent verification and validation fields stay empty with a stated
  reason rather than filled with self-assessment.
- **Multi-cloud is portfolio-motivated.** A real two-person team would more likely pick one cloud. The
  honest framing is that a second cloud demonstrates cross-cloud normalization, which is harder and
  more differentiating — not that this is what the persona would organically build.
