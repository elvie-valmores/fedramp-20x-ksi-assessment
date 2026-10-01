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

The build is in progress, and `README.md` carries the current status table. As of 2026-10-01:

- **Persisting between sessions**: 266 AWS resource instances (80 resources plus 186 disabled
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
- **Not started**: the three workflows, policy-as-code, and the remaining check definitions. 31 of
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

## Resume here — state at the end of 2026-10-01 (evening)

Read this before inferring anything from the code or from git history. Both have been stale before,
and so has this block. The most common failure in this project is a control that is configured,
deployed and internally consistent, and still does nothing. Eight have now been found, three of them
on 2026-10-01, and every one by running the thing rather than reading it. Check against the live
accounts.

Sessions 2026-09-29 to 2026-10-01 moved the operator to single sign-on, scoped Security Hub, put the
evidence stores under a customer key, fixed the normalizer's sign-in classification, and built
collector checks for SVC-SIN rows 1 and 6. The session was closed out at about 01:07 UTC on
2026-10-01. This block was rewritten then. Read `DECISIONS.md` from 2026-09-29 on for the detail.

### First actions for the next session

1. **Sign in.** Click the Identity Center tile in Google's app grid as `alex@`, then run
   `aws sso login --profile caliper-admin`. The AWS-started sign-in worked once, on 10-01, after
   failing five times, so the tile is the reliable path. Every command below needs
   `AWS_PROFILE=caliper-admin`. It is set in the user's `~/.zshrc`, but a shell started earlier may
   not have it. There are no static AWS credentials anywhere, and no IAM users.
2. **Verify, do not trust:**
   - `infra/aws/boundary.py --persistent | wc -l` gives **266**, and `--ephemeral` gives 0.
   - The API sweep in the 2026-09-25 entry of `DECISIONS.md` gives all zeros.
   - `gh run list --workflow drift.yml -L 3`: green.
   - `cd collector && ../.venv/bin/python run_checks.py` with the variables under "Running things"
     gives **30 of 32**. The failures are `piy-giv-ops-aws-inventory-current` (the KMS finding) and
     `svc-sin-cfg-aws-stores-use-declared-keys` (the RDS orphan log group).
3. **Then the build**, at "The next thing to do". The detection chain and the Security Hub recount
   were both done on 2026-10-01 evening.

### Waiting on the user

| Item | What they do |
|---|---|
| _Optional:_ Google SAML audit log | Admin console → Reporting → Audit and investigation → SAML log events, around 2026-10-01 00:42 UTC: was `admin@` issued an assertion? |

### What is standing

**AWS: 266 persistent resource instances** (80 resources plus 186 disabled Security Hub
controls). Nothing ephemeral is in state, and nothing expensive is running (verified 2026-10-01).
`terraform state list` prints more lines than 266; the rest are data sources.

The persistent set, by file (`boundary.py --files`, 15 files):

- **Evidence layer:** the Object Locked log store (`COMPLIANCE`, 7 days), CloudTrail, the Config
  recorder, Athena (the evidence workgroup, plus the built-in `primary`, governed the same way) and
  Glue, and both Lambdas with their log groups.
- **The evidence key** (`evidence_key.tf`, `alias/fedramp-20x-ksi-evidence`) encrypts the log
  store, the Config and Athena results buckets, the trail, both workgroups' results, the detection
  topic and the Lambda log groups. Only root can disable or delete it; the operator's attempt is
  denied and alerts. Objects written before 2026-09-30 stay SSE-S3 until they age out (7 days).
- **Guardrails:** the budget guardrail, the account-level S3 public access block, and the SSM
  document public-sharing block.
- **CI and cross-cloud identity:** the OIDC provider, the drift role, the build role and the
  cross-cloud role.
- **Registry:** the ECR repositories with their signed images, the extract bucket, and the
  artifacts key.
- **Posture:** GuardDuty (with RDS and S3 Protection), Security Hub with CIS and FSBP (186 controls
  for undeployed services disabled, with reasons), and Inspector on ECR.
- **Operator access:** the `InterimOperatorAdmin` permission set (4-hour sessions,
  AdministratorAccess) assigned to `alex@`, under the 2026-09-19 exception.

**Standing cost:** measured, not estimated. All three posture services are still in trial, so the
real bill is about 0.05 USD a day plus the key (1 USD a month). After the trials, the projection is
about 8.70 USD a month. Inspector's trial ends **2026-10-06**, GuardDuty's about 2026-10-21, and
Security Hub's about 2026-10-23.

**Signed images are in ECR. Deploy `git-f9f2c35f8fd1`:** it carries the `/dev/shm` certificate fix.

**GCP: 30 resources, phase 1, no drift.** The Cloud Run job stays off (`deploy_pipeline = false`)
until there is an image. GCP has no teardown; phase 1 is meant to stand.

**Identity.** AWS Organization `o-yyhciflg3u`. IAM Identity Center `ssoins-7223046591f7f9f9`, portal
`https://ssoins-7223046591f7f9f9.portal.us-east-1.app.aws`, identity store `d-90667e73f9`. The SAML
identity provider is Google Cloud Identity on `corp.elvievalmores.com` (`C01rucqxe`); its
SAML app settings are in the 2026-09-30 entry. `admin@` (break-glass) and `alex@` have passkeys,
recorded on the user's word. Identity Center has one user (`alex@`, created by hand) and one
permission set. AWS break-glass is root, with MFA. The account has **no IAM users**.

**The offering is Caliper**, at `caliper.elvievalmores.com`. The ACM certificate expires 2027-04-07.

### What is proven, and how

Nothing below is "configured". Each was exercised.

- **Collectors: 31 checks, 29 passing.** 5 of 9 mechanisms are built. `collector/self_test.py` has
  negative controls for 20 assertions, each also run against broken versions of itself. The Config
  recorder and asset feed handlers, `log_query` and `inventory_reconciliation` have none yet.
- **SVC-SIN row 1:** `svc-sin-cfg-aws-stores-use-declared-keys` lists every store from the APIs and
  compares its key with its data class's. 14 of 15 stores pass.
- **SVC-SIN row 6:** `svc-sin-cfg-aws-keys-decrypt-only-declared` resolves who can decrypt, through
  key policy, grants and IAM simulation. Both keys pass. The run takes about a minute.
- **The evidence key:** CloudTrail files and digests, normalized events, Config snapshots and
  Athena results were each seen written under it. The deny was tested by the user, and the alert
  was delivered.
- **Alert publishing to the encrypted topic:** CloudWatch alarms and EventBridge proven. **The
  detection Lambda is not yet proven** (First actions, step 3).
- **The normalizer** classifies Identity Center sign-ins as authentication and reads
  `responseElements` for failure. `lambda/normalize_events/test_handler.py` tests it against real
  records, with negative controls.
- **Single sign-on:** every operator action since 2026-09-30 is attributed to
  `alex@corp.elvievalmores.com` in CloudTrail.
- **Declared versus live, inventory currency, the SDR, drift, bucket protections, posture,
  pipeline, application, teardown, federation and cross-cloud trust:** as recorded through
  2026-09-25. Drift is green in CI over all 266.

### The persistence boundary, which is a rule

`infra/aws/boundary.py` owns the split. `teardown.sh` and `drift.yml` both consume it.

- **A persistent resource may not reference an ephemeral one, and the seam falls between the thing
  and the permission to use it.**
- **Run `boundary.py --check` before moving anything.**
- **Moving something to the persistent side needs a one-time apply targeted by declaration.**
- **Anything added persistently needs the drift role to be able to read it**, in the same apply.
  On 2026-10-01 this was proven by triggering `drift.yml` by hand rather than waiting for 07:00.
- **A key policy may only name roles that exist.** Persistent keys name persistent roles only.

### Running things

```sh
export AWS_PROFILE=caliper-admin                     # after aws sso login --profile caliper-admin
export TF_VAR_billing_alert_email=aws@elvievalmores.com
export TF_VAR_gcp_pipeline_sa_unique_id=104894493962317106056
export TF_VAR_app_domain=caliper.elvievalmores.com   # not a repository variable
export TF_VAR_billing_account_id=$(gcloud billing projects describe fedramp-20x-ksi-assessment \
  --format='value(billingAccountName)' | sed 's#billingAccounts/##')

cd collector && ../.venv/bin/python self_test.py
cd collector && ../.venv/bin/python run_checks.py --json results.json
cd lambda/normalize_events && ../../.venv/bin/python -m unittest test_handler.py
cd sdr && ../.venv/bin/python emit.py --results ../collector/results.json --frr empty --runtime local
```

- **AWS phase 1:** `terraform apply` in `infra/aws`. **Phase 2:** add `-var deploy_services=true
  -var app_image_tag=git-f9f2c35f8fd1`. **Teardown:** `infra/aws/teardown.sh`.
- **The drift-scoped plan, locally:** build a bash array from `boundary.py --persistent
  --target-flags`, as `drift.yml` does. zsh does not split an unquoted variable.
- **Hand-offs to the user** go to their own terminal, without a `!` prefix. In zsh a leading `!`
  inverts the exit status, so `! cd x && terraform apply` applies nothing.

**The session's permission controls refuse some actions. Hand the user the command; do not route
around a refusal.** Refused so far:

- IAM binding and policy changes, and applies that change key policies or grant permissions (save
  the plan, show it, hand over `terraform apply <planfile>`)
- a `kms disable-key` test on the evidence key
- once, a read-only CloudTrail and S3 check, probably misclassified

### The next thing to do

**Evidence coverage is still the bottleneck:** 11 of 46 indicators carry automated evidence, from 31
of roughly 380 checks. In rough priority:

1. **A record store for collector runs**, so SDR-CSX-KMT's 30-day and yearly metrics exist. The
   daily runs are kept as 90-day artifacts but not aggregated.
2. **Hash-pin `requirements.txt`**, now that CI installs from it, and align CI's Terraform
   (1.10.5) with local (1.16.3).
3. **The analytics image build**, now that GitHub can reach GCP: a third image and an Artifact
   Registry push identity, then GCP phase 2.
4. **More check definitions**, negative controls for the older handlers, and **links from checks
   to matrix rows**.

**At the next phase 1:**

- Confirm `aws_cloudwatch_log_group.rds["postgresql"]` was imported (its `import` block is in
  `database.tf`) and is under the logs key.
- Confirm `svc-sin-cfg-aws-stores-use-declared-keys` then passes.
- Expect `svc-sin-cfg-aws-keys-decrypt-only-declared` to fail on the three ephemeral keys (database,
  secrets, logs). They have no declared model yet, and the failure is how their models get written.
- Confirm the default security group has no rules, and that `svc-acm-cfg-aws-inventory-is-declared`
  passes.

**At the next phase 2:** confirm the worker's extracts still land through the VPC endpoint.

### Open items

| Item | State |
|---|---|
| GCP change feed notices are not retained | By decision: the audit log is the change record. Delivery is proven by `inventory/self_test.py` on every run |
| Security Hub billed checks | Recount showed about 230 findings a day (from 372), a proxy. Billed count on the console's Usage page; first real bill after about 2026-10-23 |
| api image build hung 21 minutes on 2026-10-01 | Transient: the retry built in under 2 minutes. Cause unknown, no logs kept. Jobs now time out |
| Unprovisioned directory accounts leave no CloudTrail trace | Coverage gap for KSI-IAM-SUS and KSI-MLA-LET. Google's SAML audit log is the only record, and nothing collects it |
| Normalized corpus before 2026-10-01 misclassifies sign-ins | Ages out by 2026-10-08. Read raw CloudTrail for earlier failures |
| Config and scheduled KMS key deletion | A finding: 11 deleted keys still `OK` in Config. Correct Config's record, or stop trusting Config for keys |
| AWS-started Identity Center sign-in | Failed five times on 09-29/30, worked once on 10-01. Cause unconfirmed |
| Key policy changes are not alerted, and need no JIT | The operator's standing admin can rewrite any key policy. Closes with KSI-IAM-JIT |
| Glue Data Catalog encryption | Off. Table definitions only. Left out of row 1 for now |
| The analytics image has no build path | GitHub-to-GCP federation now exists; the push identity and build entry remain. Next thing to do, item 3 |
| Cloud Identity Premium for SCIM | Deferred until KSI-IAM-AAM's evidence is built |
| `security.txt` contact would bounce | No MX on `caliper.elvievalmores.com` |
| ACM managed renewal under apply-and-destroy | Verify before 2027-02-06 |
| Security Command Center Standard | Console activation outstanding |

**Groups and further permission sets do not exist yet.** They are declared in Terraform by decision.
Putting Alex and Sam into groups needs SCIM, which needs Cloud Identity Premium.

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
