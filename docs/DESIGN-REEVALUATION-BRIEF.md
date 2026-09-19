# Design re-evaluation brief — the AWS account plan blocks three named services

**Written 2026-09-19, at the end of the build session that applied the application environment for
the first time.** This document is for taking back into the design conversation. It assumes you know
the 46 determinations and the design matrix; it does not assume you saw this build session.

**The short version:** the environment design names three AWS services that this account cannot
stand up. Two options — change the account, or change the determinations. The decision is a design
decision, not a build detail, which is why it is going back to you rather than being settled at the
keyboard.

---

## 1. Where the build actually is

| Component | State |
|---|---|
| Terraform state backend (`infra/bootstrap`) | Applied, persists |
| AWS foundations — log store, CloudTrail, Config recorder, Athena, normalization + detection Lambdas | **Applied and live** |
| GCP foundations — Cloud Asset Inventory feed, Pub/Sub, billing budget | **Applied and live** |
| Inventory generator (KSI-PIY-GIV) | Done, self-tested |
| Collector framework | 3 of 9 mechanisms implemented |
| Log normalization + detection (KSI-MLA-OSM) | Done, AWS side only |
| **AWS application environment** | **Written, applied once, torn down** |
| Application code (`app/`, two services) | Written, never built into images |
| GCP analytics pipeline | Not started |
| CI/CD pipeline | Not started |

Nothing from the application environment is running now. It was applied to prove the configuration
works, then destroyed. Residual: four customer-managed KMS keys in `PendingDeletion` for seven days.

---

## 2. What the first apply proved — the good half

This matters for the re-evaluation, because it says the architecture itself is sound. `terraform
plan` validates almost nothing about whether AWS *accepts* a configuration. These all applied on
first contact, with no errors:

- The VPC with **no internet route on the private tiers** — three tiers, distinct route tables
- All **seven VPC endpoints** (six interface + S3 gateway), each with a restrictive principal-and-
  action policy
- The **Application Load Balancer**, TLS 1.3/1.2 listener, HTTP→HTTPS redirect
- **WAF** with three managed rule groups and a rate-based rule, plus logging
- **ECS cluster**, four **customer-managed KMS keys** with rotation, two **ECR repositories** with
  immutable tags, **Secrets Manager**, the imported certificate, CloudWatch log groups, VPC flow logs

Every IAM policy document, VPC endpoint policy, KMS key policy and WAF rule set was accepted. Those
are the things that only fail at apply time, and none of them did.

**So: the network design, the segmentation model, the key model and the edge design are validated.**
What follows is not a problem with any of that.

---

## 3. What failed, and why

Four resources failed. One root cause: **the AWS account is on the new AWS free-tier plan.**

| Resource | Error |
|---|---|
| `aws_guardduty_detector` | `SubscriptionRequiredException` (HTTP 403) |
| `aws_securityhub_account` | `SubscriptionRequiredException` (HTTP 403) |
| `aws_inspector2_enabler` | `SubscriptionRequiredException` (HTTP 403) |
| `aws_db_instance` | `FreeTierRestrictionError: The specified backup retention period exceeds the maximum available to free tier customers. To remove all limitations, upgrade your account plan.` |

The RDS failure cascaded: the `api_task` and `migrate_task` inline policies reference the instance's
resource id and its RDS-managed master secret, so neither was created either.

The wording of the RDS error — *"upgrade your account plan"* — indicates the restriction is
**account-level and binary**, not a per-service opt-in. That should be verified before deciding, but
it is what the API said.

---

## 4. What depends on the blocked services

This is the part that needs your judgement, because all three are named explicitly in the design
matrix's environment table and are load-bearing for determinations.

### Inspector — the heaviest dependency

- It **is** the "Vulnerability scanner" shared component: **9 indicators** consume it.
- KSI-SVC-EIS build row 1: "Security Hub Essentials with Inspector scanning on push and on
  schedule."
- `DECISIONS.md` already contains an entry **rejecting basic ECR scanning** on the grounds that it
  covers OS packages only and "would leave application dependencies unscanned" — and application
  dependencies are precisely what KSI-SCR-MON exists to monitor. The fallback was already considered
  and already rejected on the record.
- The two services now have real pinned dependency manifests (28 and 10 packages), which is exactly
  the surface Inspector was chosen to scan.

### Security Hub

- KSI-CNA-IBP: the **entire benchmark basis**. The determination compares AWS against a named
  benchmark (CIS), and notes that the GCP benchmark mapping sits behind a paid tier and is *declared
  absent*. Losing the AWS side too would leave that indicator with no benchmark comparison at all on
  either cloud.
- KSI-SVC-EIS: supplies **two of the three finding sources** the determination names (image and
  dependency vulnerabilities, provider posture findings).

### GuardDuty

- KSI-IAM-SUS: the detection source the determination is built against.
- Named in the design matrix's audit-and-detection tier alongside CloudTrail and Config.
- Note: the *detection path* shared component (9 indicators) does not exist yet regardless — the
  2026-09-19 entry on KSI-MLA-OSM already records that alarms route to an interim SNS topic pending
  KSI-IAM-SUS being built. So this one is less immediately load-bearing than the other two.

### RDS backup retention cap — a separate, smaller problem

Free tier caps retention below the 7 days declared. This is not cosmetic:

- KSI-RPL-ABO compares backup interval and retention **against the recovery point objective declared
  in the objective register**.
- KSI-RPL-RRO's capability bound check exists to catch "an objective shorter than the backup
  interval is a number nobody can meet" — this is the same class of mismatch from the other side.
- KSI-RPL-TRC's point-in-time restore test demonstrates recovery from compromise; a one-day window
  bounds how far back "before the compromise" can be.

---

## 5. The options

### Option A — move the account off the free-tier plan

- All three services work as designed; **no determination changes**.
- The environment costs what the design already budgeted: ~115–125 USD/month standing, ~15–25/month
  at apply-and-destroy cadence.
- Security Hub, Inspector and GuardDuty add cost on top of that estimate. Security Hub Essentials is
  priced per resource unit; Inspector bills per image scan; GuardDuty per event volume. For an
  environment with no EC2 instances and few images this is small, but it is not zero and the design's
  cost table should be revisited.

### Option B — re-determine the affected indicators against what this account can evidence

- No cost change.
- Requires honest scope cuts on KSI-SVC-EIS, KSI-CNA-IBP, KSI-SCR-MON and KSI-IAM-SUS, each with the
  resulting customer risk stated.
- **This is a legitimate answer, not a defeat.** A provider whose platform cannot supply a finding
  source has a genuine limitation to declare. It is structurally identical to the GCP benchmark gap
  already recorded under KSI-CNA-IBP, and to the six deferrals already in the project.
- But it is a *large* cut: the vulnerability scanner is consumed by 9 indicators, and the project's
  own working rule is "state limitations rather than narrowing scope to avoid them." Removing the
  scanner entirely is narrowing scope, not stating a limitation — unless a substitute is named.

### Option C — Option B, with named substitutes

Worth considering rather than a straight cut:

- **Dependency scanning in CI** instead of Inspector. KSI-SVC-EIS build row 1 *already* says
  "Dependency scanning in CI" as a separate item from Inspector, so this half is in the design
  regardless. A CI scanner (e.g. `pip-audit` against the pinned manifests) covers application
  dependencies — the exact gap that caused basic ECR scanning to be rejected.
- **Basic ECR scan-on-push** covers OS packages. Already configured in `registry.tf`, and free.
- Together these cover much of Inspector's ground with a declared seam between them.
- **No good substitute for Security Hub's CIS benchmark** at zero cost. Open-source config scanning
  against a CIS profile is possible but is this project asserting a benchmark rather than a third
  party doing so — which is a materially weaker claim and would need saying.
- **No substitute for GuardDuty.** Its inputs (CloudTrail, DNS, flow logs) are all available, so
  detection content could be written as Athena queries over the existing corpus — but that is this
  project's own detection, not provider-native threat detection, and KSI-CNA-EIS's whole point is
  "assessment by managed services with the collector meta-assessing them."

---

## 6. Questions for the design conversation

1. Does the persona plausibly pay for an AWS account plan? A real two-person team running a
   production SaaS would not be on a free-tier plan — arguably Option A is the more faithful choice
   regardless of cost.
2. If Option B or C: is losing provider-native posture assessment compatible with KSI-CNA-EIS's
   reading ("assessment by managed services"), or does that determination need reopening?
3. If Option C: does a CI dependency scanner plus basic ECR scanning satisfy KSI-SVC-EIS's build row
   1, or does the earlier rejection of basic scanning still bind?
4. KSI-CNA-IBP with no benchmark on either cloud — does the determination survive, or does it move
   to deferred?
5. What backup retention can the objective register honestly declare, and does KSI-RPL-ABO's
   alignment check still have anything to compare?

---

## 7. Other design-affecting constraints found in the same build

These were hit while writing the environment and are already recorded in `DECISIONS.md` under
2026-09-19, but they are design-level and you may want to re-examine them too:

1. **The task TLS certificate is self-signed.** KSI-SVC-ASM build row 4 wants ACM-issued certificates
   with automatic renewal. ACM issues public certificates only after validating domain control, and
   this persona owns no domain; AWS Private CA is ~400 USD/month. So the internal hop has
   confidentiality but no chain of trust and no managed renewal. *Buying a domain would resolve
   this cheaply and is worth considering.*
2. **VPC flow logs cannot land in the object-locked log store.** Flow log delivery to S3 fails when
   the bucket carries a default Object Lock retention period. They go to CloudWatch Logs instead, so
   the immutability claim KSI-MLA-OSM makes for the corpus does not extend to them.
3. **ALB access logs cannot use a customer-managed key.** The ELB log delivery principal cannot write
   to a CMK-encrypted bucket, so that one bucket uses SSE-S3, against KSI-SVC-SIN build row 1.
4. **The root applies in two phases.** KSI-SVC-VRI requires digest-pinned images, and a digest cannot
   be looked up before the image exists — so services cannot be declared in the same apply that
   creates the registry. This is the indicator working correctly, not a defect.
5. **There is no container runtime on the workstation**, so images must be built in CI. This is also
   where signing, digest pinning and provenance need to happen, so it is the right place — but it
   means the CI/CD pipeline is now a hard prerequisite for the application environment ever running.

---

## 8. Build-order consequence

Whatever is decided, **the CI/CD pipeline is the next build step.** Phase 2 of the application
environment cannot happen without images, images cannot be built locally, and the pipeline is itself
required by the design (KSI-SVC-ACM's declared pipeline principal, the whole CMT cluster,
KSI-SCR-MON, and KSI-SVC-VRI's signing and digest pinning).

The free-tier decision does not block starting it.

---

## 9. Facts worth carrying back verbatim

- Region: `us-east-1`. Account created 2026-07-31.
- Apply result: 119 planned, 4 failed, remainder created successfully, then torn down.
- The teardown itself failed once: the load balancer writes an `ELBAccessLogTestFile` into its access
  log bucket at creation, and that single 90-byte object made `DeleteBucket` fail with
  `BucketNotEmpty`. Fixed with `force_destroy` on that bucket only — the Object Locked log store
  deliberately does not have it.
- Preserved across the teardown, as the cost posture requires: log store, CloudTrail, Config
  recorder, Athena workgroup and Glue catalog, normalization and detection Lambdas, SNS topic,
  budget guardrail. 39 resources.
- A code review of the build found two silent-failure bugs before the apply: an EventBridge→SNS
  target with no topic policy (GuardDuty findings would never have been delivered) and WAF logging
  with no CloudWatch Logs resource policy (blocked-request records would never have been written).
  Both fixed. Both are the failure mode this project cares most about — a control reporting healthy
  while producing no evidence.
