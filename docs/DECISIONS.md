# Decision Log

Dated record of design choices with more than one reasonable answer. Written as decisions are
made, not reconstructed afterward. Each entry carries the question, what was considered, what
was chosen, why, and what the choice gives up.

Companion to the design matrix. The matrix states what the system does. This states why, and
what else was on the table.

**Catalog in force:** FedRAMP Consolidated Rules for 2026, version 2026.09.13.02, last updated
2026-09-13, from `fedramp-consolidated-rules.json` in the FedRAMP/rules repository. Re-verified
2026-09-14 against the prior pin 2026.07.14.01; no indicator text or control mapping changed. Every
determination in this project is made against that version.

---

## 2026-09-05 — Non-machine-based information resources are out of scope project-wide

**Question.** Information Resource is defined from 44 USC 3502(6) and expressly includes
organizational policies, procedures and employees alongside technology, with a note making any
untyped reference inclusive of both. Several indicators reference information resources without
a type qualifier. Does this project attempt the non-machine half?

**Considered.** Maintain a register of the persona's policies, procedures and personnel so
coverage claims can be made in full. Or declare the non-machine half out of scope.

**Chosen.** Out of scope, project-wide.

**Why.** The environment is synthetic. A personnel and procedure register for a fictional
two-person team would be invented content demonstrating nothing, and generating it in order to
satisfy a coverage claim is the failure mode the framework's own assessor guidance warns about,
a green result standing on something that was never real. The project's purpose is technical
capability against the framework, and the non-machine half offers no technical surface: nothing
in it is provisioned in Terraform, queried from an API, or remediated by re-applying
configuration. Scoping it out costs indicator depth, not technical depth.

**How the gap is handled.** Declared, not redefined. Where an indicator's literal scope exceeds
the machine-based half, the determination is "in scope, partially satisfied" and the limitation
states the residual risk in the terms SDR-CSX-KSI asks for. The term is not reinterpreted to
make the gap disappear.

**Gives up.** Complete coverage claims on any indicator that reaches beyond machine-based
resources. Expect later indicators to be deferred entirely rather than narrowed, particularly
in PIY, CED, INR and RPL, which skew process-oriented. The in-scope set will concentrate in
CNA, SVC, IAM and MLA. Comprehensiveness is carried by the determination pass across all 46
indicators rather than by the build.

---

## 2026-09-05 — Authoritative means the provider's asset service, not Terraform state

**Question.** GIV requires inventories generated from authoritative sources. Terraform state
already describes every resource this project provisions. Does it qualify?

**Considered.** Terraform state as the source, since it is machine-readable, already exists and
covers everything the project builds. Or the cloud provider's own asset service.

**Chosen.** The provider's asset service. AWS Config and GCP Cloud Asset Inventory.

**Why.** State describes intent; the asset service describes reality. A resource created outside
Terraform, or modified in the console, or left behind by a failed apply, exists in the account
and not in state. An inventory built from state would report the environment as designed rather
than as running, and would be structurally blind to exactly the drift that makes inventory worth
having. Authoritative is undefined in the catalog, so this is an interpretation, and the reason
it holds is that the alternative cannot detect its own blind spot.

**Gives up.** A simpler implementation. State is a local file; the asset services require
provisioning, permissions and per-cloud API handling, and their supported-type coverage becomes
a ceiling the project has to declare.

---

## 2026-09-05 — Real-time means generated at query time, and is tested by observation

**Question.** Real-time is undefined in the catalog. What satisfies it, and how is it proven?

**Chosen.** Generated at query time from live sources, no cached intermediate. Proven by
creating a resource and confirming it appears in the next generation without a manual refresh.

**Why.** The statement pairs "real-time" with "when needed," which reads as a requirement that a
current inventory can be produced on demand rather than that one is continuously maintained and
displayed. A cached inventory can satisfy the letter of "generated automatically" while being
arbitrarily stale, and no configuration check would catch it, because the cache is working as
designed. The only evidence that separates demonstrated currency from asserted currency is
observing a resource that did not exist at the previous generation.

**Gives up.** Generation cost on every request, and a slower answer than serving a cache would
give. Accepted, because the cached version cannot be validated.

---

## 2026-09-05 — Feasibility is stated as a position, not assumed (IAM-APM)

**Question.** APM requires passwordless "when feasible." Feasible is undefined, and the provider
decides. What satisfies the indicator?

**Considered.** Read it as a passwordless mandate and treat any password as a failure. Or treat
"when feasible" as broad discretion and justify whatever is convenient. Or state a specific
feasibility position and let it be tested.

**Chosen.** A stated position: passwordless is feasible for every human identity in this
environment, because both clouds support WebAuthn and passkeys natively and there are no legacy
clients, shared workstations, or unmanaged devices. AWS root is the sole genuine infeasibility,
since root sign-in is a username and password flow by platform design.

**Why.** The indicator cannot be satisfied by asserting passwordless, because it does not
require passwordless unconditionally. It also cannot be satisfied by invoking the escape hatch
without argument, because then nothing is being claimed. What makes it testable is naming the
identities in each lane and why, which is what an assessor can then disagree with.

**Gives up.** This is the part of the determination most open to challenge. An assessor could
argue passwordless was feasible for an identity placed in the fallback lane, and the position
would have to be defended rather than cited.

---

## 2026-09-05 — "Strong" is bound to cited guidance, not an invented threshold (IAM-APM)

**Question.** The fallback lane requires strong passwords. Strong is undefined in the catalog.

**Chosen.** Bind to the NIST SP 800-63B position the mapped IA-5 controls point at:
length-driven rather than composition-driven, screened against known-breached secrets, no forced
periodic rotation.

**Why.** Picking a character count and a complexity rule would be inventing a standard and
calling it compliance. Citing the guidance the control family already references makes the
choice traceable to something outside this project, which is what makes it defensible rather
than arbitrary.

**Gives up.** A simpler check. Breach screening is a real implementation requirement rather than
a policy flag, and it is more work than asserting a minimum length would have been.

---

## 2026-09-05 — Phishing-resistance is scoped to the fallback lane only (IAM-APM)

**Question.** What counts as phishing-resistant, and where in the statement does the requirement
bite?

**Chosen.** Origin-bound authenticators only, hardware or platform, not TOTP or SMS. The
requirement governs the fallback lane specifically.

**Why.** The clause is structurally attached to the "otherwise" branch. Where passwordless is in
force, origin binding is inherent to WebAuthn and passkeys, so there is no separate factor
question to answer. That confines the interpretation to what qualifies as a fallback factor,
where the security argument is straightforward: TOTP and SMS are defeatable by real-time relay
phishing, so accepting them would mean the fallback lane offers less protection than the primary
lane it substitutes for.

**Worth recording explicitly.** An earlier version of this project reached a strict conclusion
about MFA by parsing an unconditional indicator against a conditional neighbour. Neither
indicator exists in the current catalog. This is a narrower argument reached from the current
structure, not that verdict recovered. The distinction matters because carrying a conclusion
forward past the removal of its justification is exactly the failure this log exists to prevent.

---

## 2026-09-05 — Indeterminate is a reportable state (IAM-APM)

**Question.** Some provider APIs report that MFA is present without naming the method. How is
that reported?

**Chosen.** As indeterminate. Neither a pass nor a fail, surfaced by identity.

**Why.** Passing it would claim knowledge the evidence does not support, which is the failure the
assessor guidance describes, a green result concealing an unverified path. Failing it would
report a defect that may not exist and would train whoever reads the output to discount the
result. Not knowing is reported as not knowing. This is the same principle as the declared gap
in GIV, applied to a different failure mode: there the limit was coverage, here it is resolution.

**Gives up.** A clean binary output, and it puts a burden on whatever consumes the results to
handle a third state.

---

## 2026-09-05 — "Appropriately secure" defined as a durability hierarchy (IAM-SNU)

**Question.** SNU requires appropriately secure authentication for non-user accounts. The term is
undefined and, unlike "strong" in APM, the mapped controls do not point anywhere specific enough
to borrow from.

**Considered.** Treat any credential in a managed secret store as acceptable. Or set the line at
rotation frequency. Or set it at credential durability.

**Chosen.** Durability. Best is no credential at all, an identity assumed by a workload from its
runtime. Acceptable is a short-lived credential obtained through a federated trust. Not
acceptable is a static long-lived credential regardless of storage.

**Why.** The property that determines blast radius is whether a leaked artifact grants access
without a live trust exchange. Encryption at rest and rotation schedules change how likely a leak
is and how long it lasts; they do not change what the artifact is worth once leaked. Setting the
line at storage quality would let a project store a permanent key well and call it secure, which
is the outcome the indicator is trying to prevent.

**The explicit position:** a service account key in a secrets manager is a mitigation, not a
satisfaction. That sentence is the whole determination.

**Gives up.** A defensible alternative reading. An assessor could hold that a short-rotation key
in a managed store is appropriately secure for a small provider, and the argument would have to
be had rather than cited.

---

## 2026-09-05 — Automated review satisfies "persistently reviewed," within a stated boundary (IAM-SNU)

**Question.** SNU requires methods be persistently reviewed. Does an automated conformance check
satisfy "reviewed," or does review imply human judgment?

**Chosen.** Automated conformance checking on the 3-day required cycle satisfies it. The standard
being checked is reviewed on change, stated rather than automated.

**Why.** Persistently is a defined term and is explicitly not continuously: activities may occur
irregularly with intentional, documented interruptions provided status is always known. Nothing
in it requires a human. And at Class C the framework requires machine-based resources be verified
and validated on the 3-day cycle, so a quarterly human review would be the weaker answer rather
than the more conservative one.

**The boundary that matters.** Automation can check conformance to a standard. It cannot check
whether the standard is still right. The collector re-applies our definition of appropriately
secure every cycle without ever asking whether that definition still holds. Naming that boundary
matters because "automated review" otherwise implies more than it delivers.

**Recurs.** This phrasing appears throughout the catalog, so this reading is being set once here
and referenced rather than re-argued each time.

---

## 2026-09-05 — Cross-cloud access is federated, not keyed (IAM-SNU)

**Question.** The GCP analytics pipeline needs to read from AWS. How does it authenticate?

**Considered.** An AWS access key stored in GCP Secret Manager. Or workload identity federation,
a GCP service account exchanging its own identity token for short-lived AWS credentials through
an OIDC trust.

**Chosen.** Federation, with no stored secret on either side.

**Why.** The stored key fails the standard set in this same indicator, so choosing it would mean
the project's most visible architectural decision contradicted its own definition of appropriately
secure. It is also the honest answer to the question the two-cloud persona raises: this is the
indicator where "how do these clouds talk to each other" actually gets decided, rather than being
deferred as an implementation detail.

**Gives up.** Significant implementation complexity. Federation requires a workload identity pool,
an OIDC provider, and a correctly constrained trust policy on the AWS side, against an alternative
that is a single stored string. If it proves unworkable, the fallback is a stored key with the
failure declared rather than the standard relaxed to accommodate it.

---

## 2026-09-05 — Prevention preferred over detection where a guardrail exists (IAM-SNU)

**Question.** Service account keys are the main failure mode for this indicator. Detect them, or
prevent them?

**Chosen.** Both, with an organization policy denying key creation as the primary measure and the
collector as the check that the policy holds.

**Why.** A detected violation means the violation happened and existed for up to a cycle. A denied
action means it never existed. Where the platform offers a guardrail at the organization level,
using it is strictly better evidence than catching what it would have stopped, and it changes the
expected steady state: once remediated, this class of finding cannot recur rather than recurring
until someone notices.

**Gives up.** Nothing directly, but it creates a dependency: the guardrail is only as strong as
the privilege required to change it, which pushes the real question into ELP rather than resolving
it here.

---

## 2026-09-05 — Persona expanded to five declared roles (IAM-ELP)

**Question.** ELP requires that each user can access only what they need. With two identities and
no stated job functions, there is no baseline to check against, and "need" is unprovable.

**Considered.** Leave the persona at two identities and accept that ELP cannot be meaningfully
determined. Or declare a set of roles with explicit entitlements as design input.

**Chosen.** Five roles: security engineer, software engineer, data analyst, platform engineer,
support. Roughly six to seven people, since the security team is two.

**Reconciliation with the earlier scoping decision, because they look contradictory.** We declined
to fabricate a personnel and procedure register for GIV. That was declining invented *evidence*
supporting a coverage claim. This is declaring *design input*: a role definition is an entitlement
specification, versioned in Terraform and checkable against actual grants. It is a technical
artifact that happens to carry a job title. One invents proof; the other declares intent so that
conformance becomes measurable.

**Also worth noting the persona never said two employees.** It said a two-person security team. A
SaaS company with a two-person security function plausibly has ten to fifteen people. Nothing was
changed, only made explicit.

**Gives up.** Some fiction enters the model. The role boundaries are chosen by us and a different
organization would draw them differently, which is a real limit on how much the conformance result
means.

**Pays off beyond this indicator.** AAM's lifecycle and JIT's elevation model both need multiple
distinct roles to be worth building. With two identities, all three would have been thin.

---

## 2026-09-05 — "Need" made checkable by declaring intent (IAM-ELP)

**Question.** Configuration cannot express whether a permission is necessary. How is the indicator
satisfied?

**Chosen.** Declare the intent baseline per role in code, then check conformance against it rather
than asserting need directly.

**Why.** This is the same move as SNU's constructed standard, applied to a different undefined
term. What cannot be proven in the abstract can be enforced against a stated position, and the
stated position is inspectable and arguable in a way an implicit one is not.

**The residual, named.** The gap narrows from "need is inexpressible" to "need is declared and
enforced, and the declaration is asserted." It does not close. No real provider closes it either,
which is worth saying plainly rather than presenting the role model as if it settled the question.

---

## 2026-09-05 — Prohibition checks preferred over allow-list checks (IAM-ELP)

**Question.** Should the collector verify that roles have the permissions they need, or that they
lack the permissions they should not have?

**Chosen.** Primarily the latter. Each role's prohibition list becomes a zero-results query.

**Why.** An allow-list check confirms a grant exists, which proves the role works, not that it is
least-privileged. A prohibition check is falsifiable: "the data analyst has zero AWS presence" is a
claim that fails loudly the moment it stops being true. Least privilege is a claim about absence,
so the evidence should be about absence too.

---

## 2026-09-05 — Zero-results queries must be self-testing (IAM-ELP)

**Question.** A prohibition check passes by returning nothing. How do we know it would return
something if a violation occurred?

**Chosen.** Each zero-results query is tested by generating a matching event and confirming the
query stops returning zero.

**Why.** A query watching the wrong log, filtering on a misspelled field, or scoped to the wrong
account returns zero forever, and its output is identical to a correct query on a clean
environment. Nothing distinguishes them from the result alone. This is the concrete form of the
requirement to verify that automation is accurate and sufficient, and it applies to every
zero-results check in this project rather than just this indicator.

---

## 2026-09-05 — Device-scoped least privilege declared undemonstrated (IAM-ELP)

**Question.** The statement says "each user or device." The persona has no managed device fleet.

**Chosen.** State the device half as unaddressed and mark the indicator partially satisfied.

**Why.** Folding devices into the user claim would be answering a question that was not asked and
implying coverage that does not exist. Declaring it undemonstrated is the same handling GIV's
non-machine gap received: the term is not reinterpreted to make the gap disappear.

**Gives up.** A clean full-satisfaction determination on an indicator where the user half is
genuinely well covered.

---

## 2026-09-05 — Mixed standing and elevated model, not universal JIT (IAM-JIT)

**Question.** JIT requires a just-in-time authorization model. Does every grant become an
elevation request?

**Considered.** Universal elevation for all privilege. Or a mixed model with standing access for
daily work and elevation reserved for high-blast-radius grants.

**Chosen.** Mixed. Standing: security engineer read, software engineer deploy, data analyst
BigQuery query, support log read. Elevated only: platform engineer's IAM, organization policy and
Terraform apply; security engineer's incident response write; data analyst's production dataset
access.

**Why.** Universal elevation is not more secure. If every action requires a request, people
elevate reflexively and the request stops carrying information, which is the outcome the control
exists to prevent. Google's own guidance says as much: not every role belongs behind JIT, and the
right starting point is the roles that could cause the most damage. The security value is
concentrated where the blast radius is.

**Gives up.** A simpler claim. "Everything is JIT" is easier to state than a lane model that has
to be defended role by role.

---

## 2026-09-05 — Platform engineer holds zero standing privilege (IAM-JIT)

**Question.** SNU depends on an organization policy denying service account key creation, which is
only as strong as the privilege to change it. ELP established platform engineer as the sole holder
of that privilege. Should it be standing?

**Chosen.** No standing privilege at all for platform engineer.

**Why.** This closes a loop that has been open across three indicators. SNU's guardrail is
protected by ELP's restriction, and ELP's restriction is protected by JIT's removal of it as a
standing grant. The result is that the guardrail can only be changed by someone who requested and
was approved for the ability to change it, with a justification recorded and an expiry attached.
Without this, the whole chain rests on one account nobody is watching.

**Gives up.** Operational friction on the role that does the most infrastructure work. Every
Terraform apply becomes an elevation, which is a real cost and the reason many organizations do
not do this.

---

## 2026-09-05 — Attribute-based constructed as time plus resource scope (IAM-JIT)

**Question.** The statement requires an attribute-based model. Attribute-based is undefined and
ranges from a single condition key to a full ABAC implementation.

**Chosen.** Every elevated grant must carry at least a time condition and a resource-scope
condition.

**Why.** A minimum that is checkable and meaningful. It makes an elevation "this role, against
this scope, until this moment" rather than "this role, now," which is the difference between an
attribute-conditioned grant and a role assignment with a timer. Setting the bar at any condition
key would be satisfiable trivially; setting it at full ABAC would be inventing a requirement the
statement does not make.

---

## 2026-09-05 — Cloud capability asymmetry stated, not smoothed (IAM-JIT)

**Question.** GCP has a native privileged access manager. AWS has no native equivalent. How is
this handled?

**Considered.** Configure GCP natively and declare AWS partially satisfied. Or build the AWS side
to match.

**Chosen.** Build it. A Step Functions state machine handling justification, assignment, TTL and
revocation, against Identity Center permission sets that are defined but unassigned by default.

**Why.** This is the first place in the project where the two clouds differ in capability rather
than in API shape. Solving one side and declaring the other would produce a weaker artifact than
solving both and showing the work was different. The cost was checked before committing: dollars
are effectively zero, and the effort is roughly a day against roughly an hour on GCP.

**Gives up.** Operational reliability. A managed service does not fail between assignment and
revocation; a self-built workflow can, and that risk is real rather than theoretical.

**Rejected alternative worth recording.** AWS's documented JIT path integrates an external
identity provider's PIM with Identity Center. That was closed by this project's earlier decision
to run without a central IdP, which is an example of an earlier choice constraining a later one
rather than the two being independent.

---

## 2026-09-05 — Revocation backstop must be independent of the workflow it backstops (IAM-JIT)

**Question.** The elevation workflow creates an assignment and deletes it after a TTL. What
happens if it fails in between?

**Chosen.** A separately scheduled reconciliation that deletes any elevated assignment older than
its TTL, running independently of the state machine.

**Why.** The workflow is the only thing standing between an elevation and permanent privilege. If
the check that catches its failure lives inside it, a failure takes both down together and the
result is standing privilege nobody knows about. The backstop narrows the exposure window rather
than closing it, and that limit is stated rather than implied.

---

## 2026-09-05 — Non-user just-in-time satisfied by federated assumption (IAM-JIT)

**Question.** The statement covers non-user accounts and services. Machine identities do not
request elevation. How is JIT satisfied for them?

**Chosen.** A workload assuming a role for the duration of a task is treated as just-in-time
authorization by construction, satisfying the requirement without a separate elevation gate.

**Why.** SNU already established that non-user identities hold no standing credential and obtain
short-lived tokens through a federated exchange. The privilege exists only for the task and
expires with it, which is what just-in-time describes.

**Flagged as an interpretation.** This is an argument rather than a mechanism, and an assessor
could reasonably hold that non-user accounts require their own request-and-approve gate. Recorded
here so the position is visible rather than assumed.

---

## 2026-09-05 — Amendment: Cloud Identity becomes the workforce identity provider

**Supersedes the earlier position that human identity is native to each cloud.**

**Question.** AAM requires that account lifecycle be managed using automation. With two
independent identity stores, offboarding is a change applied twice and nothing propagates from a
single authoritative event. Is that automated lifecycle management, or two manual processes with
Terraform in front of them?

**What changed the answer.** AWS IAM Identity Center supports Google Workspace and Cloud Identity
as an external SAML identity provider with automatic user provisioning over SCIM, added by AWS in
2023 and documented by both vendors. It replaced what used to require a custom sync function.
Cloud Identity Free covers 50 users indefinitely and includes SAML SSO and user and group
management, so the cost is zero.

**Chosen.** Cloud Identity is the workforce identity provider. AWS Identity Center trusts its
assertion. Users provision and deprovision over SCIM. Groups and permission set assignments are
managed in Terraform, because SCIM sync from Google covers users only and group provisioning is
not supported.

**Why this is not the decision we already rejected.** We declined a third-party identity provider
on two grounds: cost, and that Entra would duplicate skills already exercised at work. Neither
applies. Cloud Identity is already a component of this architecture rather than a fourth vendor,
it is free at this scale, and it is not the day-job stack. But it is a reversal of the stated
position, and recording it as an amendment rather than quietly rewriting the earlier entry is the
point of keeping this log.

**What it costs, stated plainly.** GCP becomes a dependency for AWS console access, which is why
root and break-glass remain native and why their continued existence is now a design decision
rather than a leftover. Federation also collapses most of the two-cloud normalization example for
workforce identity, since the factor is presented in one place; that example thins to root and
break-glass against Cloud Identity. Machine identity, inventory, network and encryption still span
both clouds, so the multi-cloud story survives elsewhere.

**Consequential amendments made at the same time.**
- KSI-IAM-APM: enforcement moves to Cloud Identity; AWS holds no enrollment record for federated
  users, so AWS-side credential evidence narrows to root and break-glass; the limitation about two
  independent identity stores and offboarding drift is resolved rather than carried.
- KSI-IAM-JIT: the conclusion stands but its stated reason was wrong. The AWS path via an external
  provider's PIM is unavailable not because this project has no identity provider, but because
  Cloud Identity has no privileged identity management equivalent, unlike Entra. Same outcome,
  correct reason.
- KSI-IAM-ELP: unchanged in substance; identities now source from Cloud Identity through SCIM
  rather than from two directories.
- KSI-IAM-SNU and KSI-PIY-GIV: unaffected. Workforce identity does not bear on machine credentials
  or resource inventory.

**Worth watching.** This is the second identity architecture reversal in this project. Two driven
by new evidence is defensible. A fourth would be thrashing rather than judgment.

---

## 2026-09-05 — Automation means propagation without further human action (IAM-AAM)

**Question.** AAM names its mechanism rather than stating an outcome: lifecycle must be managed
using automation. What separates that from a manual process with tooling in front of it?

**Considered.** Terraform-declared users applied to each cloud, with the pull request as the
lifecycle workflow. Or a single authoritative directory propagating changes automatically.

**Chosen.** The latter. Automation means one authoritative event propagates without further human
action.

**Why.** Declaring users in code is automated provisioning, not automated lifecycle. Nothing
happens unless a person remembers to open the change, and the failure mode the indicator exists to
prevent is precisely the leaver nobody remembers. A suspension in Cloud Identity reaching AWS over
SCIM is automation because propagation is the system's responsibility. That distinction is the
determination.

**Gives up.** A dependency on asynchronous propagation with no guaranteed bound, replacing a
process whose timing was at least predictable because a human controlled it.

---

## 2026-09-05 — The SCIM group gap is closed, not declared (IAM-AAM)

**Question.** SCIM sync from Google covers users only; group provisioning is unsupported and
groups must be created through the Identity Store API, the CLI, or a sync tool. Declare the gap or
close it?

**Chosen.** Close it. Groups and permission set assignments are declared in Terraform.

**Why.** The vendor documentation prescribes exactly this, so it is the supported path rather than
a workaround. It also aligns with what the cluster already does: ELP declares the role model in
code and JIT declares lane assignments in code, so managing groups the same way is consistent
rather than an exception. The honest framing is two mechanisms, users through SCIM and groups
through Terraform, stated as two rather than presented as one pipeline.

---

## 2026-09-05 — "Securely" is a property of the pipeline, not the outcome (IAM-AAM)

**Question.** The statement requires lifecycle be securely managed. Secure is undefined.

**Chosen.** Read it as a requirement on the mechanism. The pipeline that manages accounts is
itself an access path and is held to the standards this cluster already set.

**Why.** A pipeline that can create and delete identities is among the most privileged things in
the environment, and a determination that checked only its outputs would miss that entirely. So
the SCIM bearer token is a credential subject to SNU's durability standard, with scheduled rotation
and expiry monitoring, and the Terraform identity that mutates Identity Center is subject to ELP's
restriction and JIT's elevation requirement.

**The specific failure this catches.** An expired SCIM token silently stops deprovisioning, and
nothing about the steady state looks different when it happens. AWS's own documentation calls out
monitoring token expiry, and the expiry gap is treated as a finding in its own right rather than
resolved by rotating and moving on, because during that gap the control was not working regardless
of what the configuration said.

---

## 2026-09-05 — Drift is remediated by deletion, not adoption (IAM-AAM)

**Question.** A group or assignment exists in Identity Center that is not declared in code. Import
it into state, or delete it?

**Chosen.** Delete it by re-applying the declared state.

**Why.** Adopting a console change into code legitimises the bypass. If out-of-band changes get
absorbed into the declared state, the pipeline stops being authoritative and becomes one of several
ways to change things, which is the outcome this indicator is meant to prevent. Deleting keeps the
declared state as the only path and makes the bypass visible rather than normalised.

**Gives up.** This is destructive, and a legitimate emergency change made outside the pipeline
would be reverted. That is the intended behaviour, but it means break-glass has to be a designed
path rather than an improvised one.

---

## 2026-09-05 — Root and break-glass sit outside the lifecycle pipeline (IAM-AAM)

**Question.** Are root and break-glass identities managed by the same automation as everything
else?

**Chosen.** No. They are enumerated and monitored, not managed.

**Why.** They exist for the case where the pipeline or its identity provider is unavailable. An
identity managed by the system it is meant to survive is not a break-glass identity. This became a
design decision rather than an artifact once workforce identity federated to Cloud Identity, since
GCP is now a dependency for AWS console access and something has to remain outside that
dependency.

**Gives up.** A complete coverage claim. Two identities are permanently outside the automation, and
that is stated rather than folded into the pipeline's numbers.

---

## 2026-09-05 — Correction: the SUS statement was quoted from memory (IAM-SUS)

**What happened.** I introduced this indicator with a statement written from memory rather than
pulled from the pinned catalog: "Suspicious user and non-user account and service activity is
persistently detected and appropriately responded to, including automatically disabling or
otherwise limiting access as necessary."

**The actual text.** "Accounts with privileged access are disabled or otherwise secured in response
to suspicious activity."

**What the error changed.** Three things, all material. Scope is privileged accounts only, not all
accounts and services. There is no detection requirement in the statement. And automation is not
mandated by the text at all. The framing built on the invented version treated this as an
automation-required indicator covering the whole identity population, which is a substantially
larger and differently shaped determination than the one the catalog asks for.

**Why it is recorded rather than quietly fixed.** This is the second time in this project that
control text has been worked from memory instead of source, and the first time produced a whole
cluster of determinations against a superseded catalog. The rule already existed and was not
followed. Recording the repeat is the point.

---

## 2026-09-05 — Privileged account resolved from the definition, not intuition (IAM-SUS)

**Question.** Which accounts are "accounts with privileged access"?

**First answer, wrong.** Active JIT elevations plus root and break-glass, reasoned from the
architecture without checking whether the catalog defines the term.

**It does.** FRD-PAC defines a privileged account as one with elevated privileges enabling
administrative functions over some aspect of the offering that may affect confidentiality,
integrity or availability beyond those given to normal users, and its note presumes any reference
to privileged accounts applies equally to privileged roles and other capabilities used to assign
privilege.

**Chosen.** Five categories. Top-level administrative and break-glass, declared by name. Privileged
roles as constructs, declared in Terraform. Active JIT elevations, resolved at run time. Privileged
automation — the responder, the Terraform apply identity, the SCIM provisioning principal —
declared.

**What the definition caught that intuition missed.** The note pulls capabilities into scope, and
"administrative functions affecting availability" reaches the automation identities. The first
answer treated privileged accounts as a human population and excluded machine identities entirely.

**Consequence.** The enumeration is partly live state, so the collector resolves it at run time and
reconciles against effective-permission analysis rather than trusting a declared list.

---

## 2026-09-05 — Suspicious constructed from vendor detection plus local rules (IAM-SUS)

**Question.** Suspicious is undefined. What triggers a response?

**Considered.** Managed threat detection alone. Hand-written audit-log rules alone. Both.

**Chosen.** Both, weighted to managed detection.

**Why.** Relying only on our own rules means the definition of suspicious is entirely our guesswork,
and a thin rule set is easy to characterise as decorative. Relying only on the vendor means the
determination shows no thinking about this specific environment. The local rules cover what the
vendor will not flag but this environment cares about: root console login, IAM change outside the
Terraform pipeline, elevation on a long-unused role, repeated failed authentication against a
privileged identity.

**Cost checked before committing.** GuardDuty has a 30-day trial and no permanent free tier, but its
meters are volume-based — CloudTrail management events at $4 per million, flow logs tiered from
$1/GB — so an intermittent sandbox generates a trivial fraction of a million events. Optional
protection plans stay off; those are where the bill-shock reports come from.

---

## 2026-09-05 — Automatic response with fast undo, not approval-gated (IAM-SUS)

**Question.** Should containment fire automatically or wait for human approval?

**Chosen.** Automatic, with reversal as a single documented command.

**Why.** A two-person team has no credible overnight approval coverage, so an approval gate means
the control does not operate at night, which is when it matters most. What makes acting first
defensible is that containment is reversible by construction: attaching a deny and revoking
sessions stops access without destroying anything. The design depends on that reversibility, so the
undo path is tested rather than assumed, since a reversible design that has never been reversed is
an assumption.

**Gives up.** False positives will lock out working engineers, and for a team this size that is
operationally serious. Accepted because the alternative is a control that sleeps.

---

## 2026-09-05 — Responder privilege split to reversible containment only (IAM-SUS)

**Question.** ELP restricted IAM mutation and JIT removed it as a standing grant. An automated
responder needs privilege over identities. How is that reconciled?

**Considered.** A standing narrow exception. Responder elevates through JIT. No automated responder
at all. Split by reversibility.

**Chosen.** Split. Standing capability for reversible containment; anything destructive requires
human action through JIT.

**Why.** Elevating through JIT was rejected because the responder would depend on the elevation
system, and a compromise involving that system would leave the responder unable to act. A single
broad standing exception was rejected because it grants permanent destructive capability to an
unattended process. Splitting shrinks the standing hole to the smallest surface where a mistake is
undoable.

**Gives up.** Two code paths and a slower response to anything requiring destruction. Accepted.

---

## 2026-09-05 — The responder is itself a privileged account (IAM-SUS)

**Question.** Under FRD-PAC the responder holds administrative capability affecting availability, so
the mechanism implementing this indicator is in scope for it. It cannot secure itself.

**Chosen.** Two mitigations and a stated residual. Responder actions are written to storage the
responder identity cannot write to or modify, so tampering is visible. Changes to the responder
require JIT elevation, so modification leaves an elevation record. The residual is that a
compromised responder can still contain identities it should not.

**Why state it rather than solve it.** There is no configuration that lets a component secure
itself, and any design that appears to is hiding the dependency somewhere else. Making the failure
visible and the modification path evidenced is the achievable version. Claiming otherwise would be
the green-result-concealing-an-unverified-path failure this project keeps returning to.

---

## 2026-09-05 — Root and break-glass excluded from automated response (IAM-SUS)

**Question.** Should the responder be able to disable the top-level administrative and break-glass
accounts?

**Chosen.** No. Excluded by name, handled manually.

**Why.** An automated responder that can disable root is a self-inflicted denial of service waiting
for a false positive, and break-glass exists precisely for the case where automated paths have
failed. This is the same reasoning AAM used to place them outside the lifecycle pipeline, applied
more sharply because the action here is immediate rather than propagated.

**Gives up.** The two most privileged accounts in the environment carry human response times, which
for a two-person team means hours rather than seconds. Stated rather than folded into the
automation claim.

---

## 2026-09-05 — ACM is fully satisfiable where GIV was partial (SVC-ACM)

**Question.** GIV was marked partially satisfied because "all information resources" reaches
non-machine resources this project excludes. Does ACM inherit the same limitation?

**Chosen.** No. ACM is fully satisfiable.

**Why.** The catalog scopes this indicator itself: it says "machine-based information resources"
explicitly, where GIV said "all information resources" with no type qualifier. Under the note in
FRD-IRS, an untyped reference is inclusive of both types, and a typed one is not. So the project's
exclusion decision does not bite here.

**Worth recording because it is a general rule.** Where an indicator names machine-based, the
project's scope decision is invisible. Where it omits the qualifier, the determination is partial.
That distinction should be checked per indicator rather than assumed either way, and it means the
scoping decision costs less across the catalog than it first appeared to.

---

## 2026-09-05 — Drift read against its full definition (SVC-ACM)

**Question.** What does "reviewed for drift" require?

**Chosen.** Drift covers deviation from the intended and assessed state, and the definition names
five common forms: configurations, deployed software, privileges, running processes, availability.
Three are covered, two are declared out of reach.

**Why.** The obvious implementation diffs declared state against live configuration and calls it
drift detection. That covers one named form. Reading the definition rather than the phrase makes
the gap visible: privilege drift is already handled by ELP's conformance checks and deployed
software is caught at resource configuration, but running processes and availability are not
observable from configuration state at all. Declaring those two rather than omitting them silently
is the same handling used for the device half of ELP.

**A consequence in the definition worth naming.** Drift is deviation from the intended *and
assessed* state, so the baseline is not simply whatever was last applied. Drift detection and
evidence collection must read the same state, or the baseline itself drifts.

---

## 2026-09-05 — Terraform state is a security-relevant asset (SVC-ACM)

**Question.** The declared baseline lives in a state file. Does it need protection in its own
right?

**Chosen.** Yes. Versioned, encrypted, locked remote backend, and its configuration is verified as
part of this indicator rather than treated as build hygiene.

**Why.** Every drift claim in this project is relative to that baseline. A compromised or corrupted
state file makes drift detection report clean against the wrong reference, and nothing about the
output would look different. This is the same shape as the SUS responder logging to storage it
cannot modify: the evidence has to be trustworthy independently of the thing producing it.

---

## 2026-09-05 — Undeclared resources get a recorded choice, not an automatic rule (SVC-ACM)

**Question.** AAM established that drift is remediated by deletion rather than adoption, because
adopting an out-of-band change legitimises bypassing the pipeline. Does the same rule apply to
infrastructure?

**Chosen.** Partly. Configuration drift on a declared resource is reverted by re-applying, as in
AAM. But a resource that exists with no declaration is either imported deliberately or destroyed,
and the choice is recorded rather than defaulted.

**Why the departure.** AAM dealt with identity assignments, where deletion is recoverable in
seconds. Infrastructure destruction can be irreversible, and a blanket destroy rule would eventually
delete something real that someone created under pressure. Importing normalises undeclared creation,
which is the risk AAM was guarding against, so neither default is safe and the decision is made
explicitly each time.

**Gives up.** A clean automatic rule, replaced by a human judgment that has to be recorded. That is
the correct trade where the actions are asymmetric in consequence.

---

## 2026-09-05 — Infrastructure design settled as a design input

**Question.** Determinations from SIN onward turn on what the environment actually contains.
Encryption of what, communication between which resources, integrity of which artifacts. Continuing
without deciding would repeat the failure that parked the first attempt at a network indicator.

**Chosen.** AWS runs the SaaS product on ECS Fargate with an RDS PostgreSQL db.t4g.small behind an
Application Load Balancer, private subnets reaching AWS services through VPC interface endpoints
rather than a NAT gateway, secrets in Secrets Manager, customer-managed KMS keys, and CloudTrail,
Config and GuardDuty foundational for evidence. GCP runs the analytics side on BigQuery with a
scheduled Cloud Run job pulling from AWS through the federated path, a GCS landing bucket, and
Cloud Asset Inventory, Audit Logs and Security Command Center at the free tier. GitHub Actions is
the pipeline principal, authenticating to both clouds by OIDC with no stored credentials.

**Why these choices specifically.**

Fargate over EC2 or Lambda: containers scale to zero between sessions and carry image digests, which
gives VRI a genuine cryptographic check rather than an assertion. EC2 would add OS patching and a
continuous bill; Lambda would give integrity validation almost nothing to work with.

RDS db.t4g.small over Aurora Serverless v2: this reverses my own earlier proposal. Aurora Serverless
bills a continuous capacity floor for elasticity this environment would never exercise, and no
indicator gets better material from it. Within RDS, db.t4g.micro is cheaper at about 12 dollars but
has 1 GiB of RAM, which Postgres struggles with under any real load, so db.t4g.small at about 27.71
is the honest middle.

Interface endpoints over a NAT gateway: a single NAT gateway is about 32 dollars a month before
traffic, and four interface endpoints are about 29 combined, so the cost is comparable. The
deciding factor is posture rather than price: traffic to AWS services never traverses the internet
at all. Worth revisiting when CNA is determined, since the margin is thin enough that a fifth
endpoint would flip it.

Secrets Manager over Parameter Store: Parameter Store is free but has no native rotation, and ASM
requires regular rotation. Paying about two dollars a month for the mechanism is better than
building it.

**Cost posture.** Apply and destroy per session. Only the state backend, evidence storage, audit
logs and KMS keys persist. Standing continuously the stack is roughly 90 to 95 dollars a month;
torn down between sessions the residual is under 5. A billing alarm at 50 is the signal that
something was not destroyed, which is the failure mode that actually costs money rather than the
architecture itself.

**Gives up.** Realism at the edges. A real SaaS product would run multi-AZ, would likely have more
than two services, and would not be destroyed nightly. Those are stated as environmental
limitations in the determinations that touch them rather than papered over.

---

## 2026-09-05 — Architecture checked against all 46 indicators before continuing

**Question.** The environment was designed to serve the indicators immediately ahead. Does it
conflict with any of the 38 not yet determined?

**Method.** Every remaining indicator statement read against the proposed architecture, looking for
components that would force a partial or failed determination downstream.

**Four conflicts found, four changes made.**

**Single-AZ database against CNA-OFA and the RPL cluster.** High availability, backup alignment,
recovery objectives and tested recovery are five indicators undermined by one component. The fix is
not multi-AZ: it is automated backups with point-in-time recovery, honest recovery objectives
defined against what a restore actually delivers rather than what a failover would, and an actually
tested restore. RPL-TRC asks for tested recovery capability, and a tested restore with a measured
RTO is stronger evidence than an untested multi-AZ deployment. CNA-OFA remains partially satisfied,
which is the correct answer rather than a gap, since "appropriately optimized" is relative to the
provider's needs and a pre-certification two-person team running single-AZ with tested restores is a
defensible position.

**Teardown against recovery testing and log continuity.** Destroying the environment between
sessions destroys the thing being recovered and interrupts the log stream, which leaves MLA-OSM,
MLA-RVL and RPL-TRC with nothing durable. Database snapshots and the central log store are added to
the teardown exclusion list. Both are near-free: RDS backup storage is included up to the size of
the instance and log storage is pennies.

**No SIEM in the architecture.** MLA-OSM names a SIEM or similar system for centralized
tamper-resistant logging, and CloudTrail and Cloud Audit Logs are sources rather than a SIEM.
Security Lake or OpenSearch are the realistic answers and both cost real money. Chosen instead: a
single S3 bucket with object lock receiving both clouds' logs, which delivers centralized and
tamper-resistant without a query layer. That satisfies the substance and not the name, and the
absence of a query layer is declared rather than glossed.

**Supply chain with nothing to bite on.** SCR-MON requires third-party software be monitored for
upstream vulnerabilities. A placeholder container image has no dependencies worth scanning, so the
Fargate services are specified as real application code with a dependency manifest. No structural
change, but it constrains what gets built.

**Non-conflicts confirmed.** Fargate suits CMT-RMV, since containers are replaced rather than
modified. CNA-DFP and CNA-MAT work with task roles and private subnets. CNA-RVP is satisfiable via
Shield Standard on the load balancer. CNA-EIS aligns with the drift detection already built for ACM.

**Not fixable by architecture.** CED, INR, the four remaining PIY indicators and CMT-RVP are
process-oriented and will defer under the project scoping decision. No component choice changes
that, and pretending otherwise would mean fabricating the organizational material already excluded.

**Cost impact.** A few dollars a month. The changes are backup retention, snapshot persistence, a
log bucket with object lock, and real application dependencies.

---

## 2026-09-05 — "Information" read as unqualified (SVC-SIN)

**Question.** Does SIN cover federal customer data, or everything?

**Chosen.** Everything the offering holds: customer data, audit logs, evidence, secrets, backups,
container images and configuration state.

**Why.** FRD-FCD defines federal customer data narrowly and explicitly excludes provider-generated
metadata, telemetry and analytics. SIN does not use that term; it says "information." Reading it as
customer-data-only would leave the log store and the state backend outside a claim the statement
plainly covers, and those are the two stores whose compromise would most undermine every other
determination in this project.

---

## 2026-09-05 — DNS is in scope by mapping and declared as a gap (SVC-SIN)

**Question.** SC-20, SC-21 and SC-22 are the name-resolution controls and they are mapped to this
indicator, though nothing in the statement's wording suggests DNS. Implement DNSSEC or declare it?

**Chosen.** Declare it. The mapping is cited so the requirement is visibly found rather than missed.

**Why.** Signing a hosted zone requires the registrar to accept a DS record against a real personal
domain, with a genuine risk of breaking resolution, and the resulting check is a boolean. High
friction, low demonstrative value. Declaring it with the mapping cited shows the requirement was
found, which is the part worth demonstrating.

**Worth recording separately.** The mapping expanded scope in a direction the statement gave no hint
of, and the same is true of CP-9(8) for backups and AC-17(2) for remote access. Reading only the
statement would have missed three surfaces. That is a general lesson for the remaining indicators.

---

## 2026-09-05 — Access and modification separated (SVC-SIN)

**Question.** The statement covers both unwanted access and unwanted modification. Does encryption
answer both?

**Chosen.** No. They are carried by different mechanisms and determined separately.

**Why.** Encryption at rest does essentially nothing against an authorised principal modifying data.
A determination that answered both halves with encryption would be claiming protection it does not
have. Modification is carried by object lock, versioning, retention and CloudTrail log file
validation, and those are different properties: object lock prevents deletion, digest validation
detects alteration. Treating them as one control would leave alteration undetected.

---

## 2026-09-05 — Key policy resolution is part of the encryption claim (SVC-SIN)

**Question.** Is checking that encryption is enabled sufficient?

**Chosen.** No. Key policies are resolved and reconciled against the declared role model, and an
over-broad decrypt grant fails the indicator.

**Why.** Encryption is only as strong as who may decrypt. A key policy granting broad decrypt makes
every encryption flag in this determination decorative while every check still reports green. This
is the same failure the assessor guidance describes, a passing status concealing an unverified path,
and it is the one check in this indicator that requires resolving effective access rather than
reading a boolean.

**The strongest evidence in the determination follows from it:** zero decrypt calls by principals
outside the role model, as a standing query. That proves protection rather than configuration.

**Gives up.** Real implementation effort. Resolving effective decrypt access across key policies,
grants and IAM is meaningfully harder than reading an encryption flag, and it is where most of this
indicator's build time goes.

---

## 2026-09-05 — Encryption surfaces swept exhaustively after the first draft missed nine (SVC-SIN)

**What happened.** The first draft of this determination covered the obvious data stores and missed
nine surfaces: container registries, application log destinations, Fargate ephemeral storage, the
event and workflow services holding elevation justifications, the load-balancer-to-task leg, the
GCP-to-S3 log shipping path, CloudTrail log file validation, key policies, and GitHub.

**Why it matters beyond this indicator.** Container registries were not in the environment design at
all, so this was an architecture gap rather than only a determination gap, and VRI would have hit it
next. The sweep also produced the key policy insight above, which is the most substantive part of
the final determination.

**What was cut after the sweep, deliberately.** DNSSEC, for registrar friction. The Fargate
ephemeral storage key, because it is encrypted by default with a provider key and a customer-managed
key would change almost nothing about the posture while adding cost. Both stated rather than
silently omitted.

**Method worth repeating.** Enumerating every surface in the architecture and asking what protects
it, rather than working from the indicator's wording outward. The wording named encryption; the
architecture named nine things the wording did not.

---

## 2026-09-05 — Regularly and Persistently are deliberately different (SVC-ASM)

**Question.** The statement requires "regular rotation" and that the whole be "persistently
reviewed." Both are defined terms and both appear in one sentence. Do they mean the same thing?

**Chosen.** No. Rotation is on fixed intervals. Review is on the irregular machine cycle.

**Why.** Regularly is defined as performing the activity on a consistent, predictable and repeated
basis at set intervals, automatically if possible, following a documented plan. Persistently is
defined to permit irregular occurrence with interruptions and waiting periods, and its note states
outright that it indicates a process which may not occur on a consistent predictable basis. The
terms are opposites on the predictability axis and the drafting is intentional: a secret's age is
itself a security property, so rotation must be schedulable and auditable against a schedule,
whereas review only needs to keep status known.

**Consequence.** This is the first indicator in the project whose cadence is not simply the 3-day
machine cycle. Two cadences coexist, and the cycle column has to carry both.

---

## 2026-09-05 — The documented plan is a deliverable (SVC-ASM)

**Question.** "Following a documented plan" sits inside the definition of Regularly. Does that make
the plan an artifact rather than an implied practice?

**Chosen.** Yes. A versioned table of secret class to rotation interval, in the repository, checked
in CI.

**Why.** The definition names it. A rotation schedule that exists only as a Terraform argument
satisfies "at set intervals" but not "following a documented plan," and the difference is whether
someone can review the intervals as a set and argue with them. This is the first indicator where a
defined term forced a documentation artifact rather than a configuration.

---

## 2026-09-05 — The SCIM token debt is discharged here (SVC-ASM)

**Question.** AAM created a SCIM provisioning token and specified scheduled rotation with expiry
monitoring. SNU set the standard that a credential surviving without a live trust exchange fails.
Neither indicator built the rotation. Where does it happen?

**Chosen.** Here, with a built workflow: generate a new token, update the provisioning
configuration, verify provisioning still functions, then discard the old one.

**Why verification before discard is the whole point.** A rotation that completes but silently
breaks provisioning is worse than no rotation, because AAM's entire lifecycle claim depends on that
token working, and the failure would be invisible until someone was offboarded and stayed active.
So the workflow proves the thing the token exists for still works before removing the fallback.

**Worth recording as a pattern.** Two indicators created an obligation and a third discharged it.
That is a chain that could easily have been dropped, and it was only caught because ASM was worked
after both rather than before either. Dependency-ordered evaluation earned its keep here.

---

## 2026-09-05 — Secrets must be absent from state, not merely protected in it (SVC-ASM)

**Question.** SIN protects the Terraform state backend with encryption, versioning and locking. Is
that sufficient for secrets that state may capture?

**Chosen.** No. ASM requires that secrets are not in state at all.

**Why.** These are different claims and the second is stronger. Protecting the store where a secret
sits reduces who can reach it; keeping the secret out means a compromise of that store does not
expose it. State is also copied, backed up and read by tooling in ways a purpose-built secret store
is not, so the exposure surface is wider than its encryption suggests.

---

## 2026-09-05 — Key rotation does not limit exposure the way credential rotation does (SVC-ASM)

**Question.** Automatic key rotation is enabled on customer-managed keys. Does that carry the same
security property as rotating a credential?

**Chosen.** No, and the determination says so rather than letting the word "rotation" imply it.

**Why.** Provider key rotation rotates the underlying key material while the key identifier
persists, so data encrypted under prior material remains decryptable by design. That is how the
mechanism is built and it is not a gap, but it means an attacker holding decrypt access is not cut
off by rotation the way a leaked credential is. Claiming otherwise would overstate what the control
delivers, which is the failure this project keeps returning to.

---

## 2026-09-05 — The imperative form narrows the answer space (SVC-VRI)

**Question.** VRI says "use cryptographic methods to validate the integrity of machine-based
information resources." Every other indicator in the catalog describes a state that must hold. Does
the imperative phrasing change what satisfies it?

**Chosen.** Yes. Non-cryptographic controls do not substitute. A resource whose integrity claim
rests on access control, review discipline or process rigour does not satisfy this indicator, and
is declared as unaddressed rather than counted.

**Why.** The statement prescribes a method rather than an outcome, which is unique in the catalog
and hard to read as accidental. Stretching "cryptographic" to cover an access control would be the
kind of reframing that makes a green result mean less than it appears to.

**Consequence.** This is what forces the partial determination. A looser reading would have let
managed services and process state be covered by something, and would have produced a fully
satisfied indicator that was less true.

---

## 2026-09-05 — Per-class integrity positions, with a register that forbids silence (SVC-VRI)

**Question.** Machine-Based is defined expansively and the mappings reach unauthorised component
detection and supply chain inspection. Which resources can actually be validated cryptographically?

**Chosen.** Four classes covered — images, infrastructure definition, audit logs, dependencies — and
two declared: managed service internals as inherited, running process and memory state as
unaddressed. Every class must hold a recorded position in a register, and a resource with no
position fails the indicator.

**Why the register matters more than the classification.** Without it, a resource with no available
method simply does not appear, and absence looks identical to coverage. Requiring an explicit
"inherited" or "unaddressed" marking turns a silent gap into a stated one, which is the same
mechanism GIV used for its declared gap and ELP used for devices.

**Worth noting the overlap.** Running process and memory state is the same gap ACM declared for two
of the five named forms of drift. The same limitation surfacing in two indicators for the same
underlying reason is a sign the limitation is real rather than a scoping convenience.

---

## 2026-09-05 — Digest pinning over tag references (SVC-VRI)

**Question.** Images can be referenced by tag or by digest. Which does the determination require?

**Chosen.** Digest, with tag references rejected in CI.

**Why.** A tag is a mutable pointer. It provides no integrity property at all, and an image behind a
tag can be replaced without any declared configuration changing, which means ACM's drift detection
would report clean on a tampered artifact. Digest pinning is the only reference form that makes the
deployed artifact identical to the verified one.

**Gives up.** Real deployment friction. Every image update changes the reference, where a tag would
not. That friction is the property being bought.

---

## 2026-09-05 — Validation must block, not report (SVC-VRI)

**Question.** Does a signature check that logs a failure satisfy the indicator?

**Chosen.** No. Verification blocks deployment.

**Why.** Validation is a defined term meaning confirmation through objective evidence that
capabilities support expected outcomes. A check that reports a failure and lets the deployment
proceed has produced evidence that the outcome is not supported, and then permitted it anyway. That
is not confirmation of anything.

---

## 2026-09-05 — Failed log digest validation escalates rather than remediates (SVC-VRI)

**Question.** What happens when CloudTrail digest validation fails?

**Chosen.** It routes to the SUS incident response path rather than to a re-apply.

**Why.** Every other remediation in this project corrects a configuration that drifted. This one
means log content may have been altered, which is a potential integrity incident rather than a
defect, and re-applying configuration would neither restore the logs nor establish what happened.
Treating it as a config fix would destroy the signal.

**First of its kind in the project.** Worth recording because it establishes that remediation is not
always correction, and later indicators may have similar cases where the right response is
escalation.

---

## 2026-09-05 — Authenticity and integrity are separate claims (SVC-VCM)

**Question.** The statement requires both the authenticity and the integrity of inter-resource
communications. Does TLS answer both?

**Chosen.** No. TLS answers integrity and only server-side authenticity. Peer authenticity rests on
federated platform identity.

**Why.** In ordinary TLS the client verifies the server's certificate and the server verifies
nothing about the client. A determination pointing at TLS for both halves would be answering half
the statement twice while leaving the harder half unaddressed. Federated identity is also stronger
here than mutual TLS would be, because the identity is issued and validated by the platform rather
than by a certificate authority we operate and could misissue.

---

## 2026-09-05 — Public ingress is out of scope by the statement's wording (SVC-VCM)

**Question.** Does VCM cover the load balancer's public listener?

**Chosen.** No. The statement says "between machine-based information resources," and a user's
browser is not a machine-based information resource of this offering.

**Why record a scope reduction.** Because the consequence is uncomfortable and worth stating: the
most exposed communication path in the architecture is not covered by this indicator. It is covered
by SIN, so nothing falls through, but a reader tracing VCM alone would find the public path absent
and should find the reason rather than the silence.

---

## 2026-09-05 — IAM database authentication over a stored password (SVC-VCM)

**Question.** The application connects to the database. Password from the secret store, or platform
identity?

**Chosen.** IAM database authentication. Password authentication disabled for the application user.

**Why.** A password authenticates possession of a secret; IAM authentication authenticates the
workload's platform identity. Only the second makes the peer's authenticity provable rather than
inferred, which is what this indicator asks for. It also removes a rotating secret from ASM's scope,
so two indicators get simpler from one decision.

**Gives up.** A more conventional setup, and a dependency on the task role being correct rather than
on a secret being protected. That is the intended trade.

---

## 2026-09-05 — Authentication failures must reach the detection path (SVC-VCM)

**Question.** Is a path that authenticates peers correctly already validated?

**Chosen.** No. Failed authentications route to the detection path built for SUS rather than sitting
in logs.

**Why.** Validation is a defined term requiring confirmation through objective evidence. A peer
authentication that fails and is recorded but never consumed has produced evidence nobody looked at,
which is authentication rather than validation. The same reasoning that required VRI's verification
to block rather than report applies here in a different shape: the result has to go somewhere.

---

## 2026-09-05 — Unobservable peers are marked, not counted (SVC-VCM)

**Question.** Some providers do not log the authenticating principal for a connection. How are those
paths treated?

**Chosen.** Marked in the path register as configuration-attested rather than counted as validated.

**Why.** The same principle as the indeterminate state in APM and the integrity register in VRI: a
claim resting on configuration alone is weaker than one resting on observation, and collapsing the
two would overstate the evidence. Marking it keeps the register honest about which paths are proven
and which are asserted.

---

## 2026-09-05 — RUD deferred: the triggering condition does not exist (SVC-RUD)

**Question.** RUD requires unwanted federal customer data be removed promptly when an agency
requests it, in alignment with customer agreements, including from backups.

**Chosen.** Deferred.

**Why.** The trigger is an agency request under a customer agreement. The persona has no federal
agency customers, no agreements, and no federal customer data as FRD-FCD defines it, which is
information an agency uploads or supplies. Building a deletion capability with no request mechanism
would demonstrate the easy half and skip the half the statement is about, which is responding within
an agreed timeframe.

**A real technical problem worth naming rather than hiding.** Removing data from backups conflicts
directly with the point-in-time recovery window this project enabled for the recovery cluster: a
restorable window necessarily retains prior state, so honouring a deletion request means either
breaking recoverability or leaving the data recoverable. That is a genuine design problem a live
provider must solve, and it is not solved here.

**Resulting risk to customers.** A provider unable to remove spilled data on request leaves it
recoverable from backups for the length of the retention window.

---

## 2026-09-05 — Split by subject rather than deferring the indicator (SVC-PRR)

**Superseded an earlier decision to defer PRR in full, made the same day.**

**Question.** PRR names plans, procedures, and the state of information resources. Two are
non-machine and out of scope project-wide. Does the indicator defer entirely?

**Chosen.** No. Determine the machine-based subject and declare the rest. PRR is partially
satisfied.

**Why the reversal.** Deferring in full would have left something technically achievable unbuilt,
which is different from something being impossible or out of scope, and the earlier entry recorded
that discomfort rather than resolving it. The residue half reuses machinery that already exists:
inventory from GIV, change attribution from ACM, and a diff between them.

**The general rule this establishes.** Where a statement names several subjects and some are
machine-based and some are not, determine the machine-based ones and declare the rest. Defer
wholesale only when the triggering condition does not exist, or when every subject is non-machine.
This matters beyond PRR: the remaining clusters skew process-heavy, and a rule of "any process
language means defer" would strand real technical surface in monitoring and change management.

**Resulting risk from the declared half.** Procedural residue is not reviewed: a runbook referencing
a decommissioned system, or an access process for a role that no longer exists.

---

## 2026-09-05 — Residue defined against a change event, not a point in time (SVC-PRR)

**Question.** What is a residual element, and how does it differ from drift?

**Chosen.** Anything that outlives the change that created or superseded it. Detected by diffing
inventory across a change event rather than scanning at a point in time.

**Why the distinction matters.** ACM compares declared state against live state and would report
clean on residue that nobody ever declared and nobody deleted. An orphaned snapshot is not drift,
because nothing drifted; it is something left behind. The statement says "after making changes,"
which is a temporal relationship, so the mechanism has to be relative to a change rather than
absolute.

**Severity bounded by a defined term.** Likely means reasonable probability based on context, so
items rank by whether they could plausibly hold or grant access to customer data. An unreferenced
image is residue and is unlikely to matter; an orphaned snapshot of the application database is both
residue and a direct exposure. SC-4, the single mapped control, is specifically about information
remaining in shared resources after use, which confirms the reading.

---

## 2026-09-05 — Retention permitted, but only as a recorded decision (SVC-PRR)

**Question.** Some residue is legitimately kept. How is that handled without letting the collector
become noise?

**Chosen.** Deletion is the default. Retention requires a register entry with a reason and an
expiry.

**Why this inverts ACM deliberately.** ACM treats an undeclared resource as requiring a recorded
choice between import and destroy, because it might be something real created under pressure. Here
the item is by definition something that outlived its purpose, so the default flips. Stating the
inversion and its reason matters, because otherwise the two indicators appear to contradict each
other on the same class of finding.

**The exception path is tested, not just built.** A collector that cannot accept a legitimate
exception gets ignored, and an ignored collector is worse than none.

---

## 2026-09-05 — Deferral format established

**Question.** How does a deferred indicator appear, given the design matrix is meant to show what
the system does?

**Chosen.** A full block with a grey bar, the verbatim requirement, a rationale explaining the
reason and the resulting risk to customers, N/A rows in build and prove, and a limitations band.

**Why a full block rather than an omission.** SDR-CSX-KSI requires, where measures do not exist, an
explanation of the reason and the resulting risk to customers. An omitted indicator supplies
neither, and an absent row looks like an oversight where a grey bar with a stated reason looks like
a decision. This is the same principle applied earlier to declared gaps within satisfied indicators.

---

## 2026-09-05 — Correction: EIS is technical, not a program property (SVC-EIS)

**What I got wrong.** When surveying the SVC cluster I described EIS's improvement half as closer to
a program property than an infrastructure state, and suggested it might be thin.

**What the mappings say.** SI-2(2) is automated flaw remediation status, SI-4 is system monitoring,
CM-7(1) is periodic review of functions and ports, SC-39 is process isolation, MA-2 is controlled
maintenance, SR-10 is supply chain inspection. That is vulnerability management and attack-surface
reduction, which is squarely technical.

**Pattern worth noting.** This is the second time in this cluster that reading only the statement
produced a wrong scope, after SIN's mappings pulled in DNS, backups and remote access. The statement
says what the outcome is; the mappings say how wide it reaches. Both have to be read.

---

## 2026-09-05 — "Opportunities to improve security" bounded to three named sources (SVC-EIS)

**Question.** The phrase is the softest in the cluster. What counts as an opportunity?

**Chosen.** Three sources, named: vulnerability findings from image and dependency scanning,
provider posture findings, and attack-surface findings covering enabled functions, open ports and
unused permissions.

**Why bound it.** An unbounded reading makes the indicator unfalsifiable, since there is always
another opportunity nobody took. Naming three sources makes the claim testable and makes what is
excluded visible. Unused permissions come from the ELP collector rather than being re-derived, so
the boundary also avoids duplicating work already done.

---

## 2026-09-05 — Improvement measured as rebuild cadence, not patch cadence (SVC-EIS)

**Question.** How is "improvements are persistently made" measured?

**Chosen.** Base image currency and rebuild cadence against open findings.

**Why.** Fargate tasks are immutable; you do not patch a running container, you build a new image
and redeploy. Measuring a patch schedule would be measuring something the architecture does not do.
This is a case where an earlier architecture decision made a later determination cleaner rather than
harder, since rebuild timestamps are more observable than patch state inside an instance.

---

## 2026-09-05 — Finding-to-change linkage required (SVC-EIS)

**Question.** What separates this indicator from a scan-and-report setup?

**Chosen.** Every closed finding must reference the commit, image digest or apply that closed it. A
finding closed with no linked change is reopened.

**Why.** The statement has two halves and most implementations answer only the first. Scanning
proves evaluation; nothing about a closed finding proves improvement. Without the linkage, closure
and suppression are indistinguishable in the data, and the easiest way to hit a clean dashboard is
to close findings rather than fix them.

---

## 2026-09-05 — Cadence adopted from recommendations, labelled as such (SVC-EIS)

**Question.** The vulnerability response rules set Class C detection at 14 days for drift-prone
resources and 3 days for representative samples of similar machine-based resources. Are those
obligations?

**Chosen.** No. They are stated as SHOULD rather than MUST, so the plan adopts them as a declared
choice and says so.

**Why the distinction is worth the words.** Presenting a followed recommendation as a met obligation
overstates compliance, and an assessor who knows the rules would catch it. Saying "we chose to
follow the recommended interval" is both accurate and a stronger signal that the rules were read
closely.

---

## 2026-09-05 — Security Hub Essentials added to the architecture (SVC-EIS)

**What happened.** The EIS draft referenced Security Hub as a posture-findings source before it
existed in the environment design. Same class of error as container registries in SIN: a
determination reaching for a component the architecture did not contain.

**Options considered.** Basic registry scanning, which is free but covers operating-system packages
only. Inspector enhanced scanning alone, at roughly nine cents per image initial scan and a cent per
rescan. Security Hub Essentials, which bundles Inspector scanning, posture checks and CIS benchmark
assessments under resource-based pricing anchored on EC2 instances, with container images at one
eighteenth of a unit and IAM principals at one one-hundred-and-twenty-fifth.

**Chosen.** Security Hub Essentials.

**Why, and not on cost.** Basic scanning would leave application dependencies unscanned, which
undercuts both EIS and the supply chain indicator that the Fargate services were specified with a
real dependency manifest to serve. Inspector alone covers vulnerabilities but supplies none of the
posture findings EIS names as its second source. Essentials covers both, and its CIS benchmark
assessments become the comparison basis for CNA-IBP, which asks for configuration compared against
the provider's own best practices. For an environment with no EC2 instances and few images the
resource count is small, so cost is a few dollars rather than the deciding factor.

---

## 2026-09-05 — Correction: the endpoint count was wrong and the cost comparison flipped

**What I recorded earlier.** Four VPC interface endpoints at roughly 29 USD combined, cheaper than a
single NAT gateway at about 32, with the posture advantage as a bonus. I noted at the time that a
fifth endpoint would flip the comparison.

**What is actually required.** A private-subnet Fargate task pulling from ECR needs interface
endpoints for ecr.api and ecr.dkr, plus a gateway endpoint for S3, because ECR stores image layers
in S3 and the pull fails silently without it. Add CloudWatch Logs for container logging, Secrets
Manager, KMS and STS, and the count is six interface endpoints rather than four. The S3 gateway
endpoint is free; the rest are roughly 7 each, so 42 to 49 against a NAT gateway's 32.

**Chosen.** Keep the endpoints. Correct the reasoning.

**Why the conclusion survives the reversal of its premise.** The original entry gave two reasons,
cost and posture, and one of them is now wrong. The posture reason is stronger than the cost reason
ever was: with no NAT gateway there is no internet egress path at all, which is a materially
different claim for CNA-RNT and CNA-MAT than egress that happens to be filtered. Ten to fifteen
dollars a month is a fair price for it, and saying so is more honest than leaving an entry that
claims a cost advantage that does not exist.

---

## 2026-09-05 — AWS WAF added so CNA-RVP has something to review

**Question.** CNA-RVP requires the effectiveness of denial-of-service protection and other
unwanted-activity protection to be persistently reviewed. The architecture has Shield Standard.

**The problem.** Shield Standard is free and automatic and exposes almost nothing about its own
effectiveness. There is very little to review, so the indicator would be close to unsatisfiable as
designed. Shield Advanced provides the visibility and costs roughly 3,000 USD per month, which is
not a real option.

**Chosen.** Add AWS WAF on the load balancer with managed rule groups and rate limiting, at roughly
5 to 8 USD per month plus per-request charges.

**Why.** WAF supplies both halves the statement asks for: rate limiting is denial-of-service
protection with observable metrics, and managed rule groups are the other-unwanted-activity half.
More importantly it produces reviewable data, where Shield Standard produces almost none. An
indicator about reviewing effectiveness needs something whose effectiveness can be seen.

---

## 2026-09-05 — Per-service network segmentation specified

**Question.** CNA-MAT requires lateral movement be minimized if a resource is compromised. The
architecture had two Fargate services and said nothing about segmenting them from each other.

**Chosen.** One security group per service, with explicit service-to-service rules rather than a
shared group.

**Why.** With a shared security group, compromising either service yields the network position of
both, and the lateral-movement half of MAT would be an assertion rather than a claim. This costs
nothing and it is a design specification rather than a component change, which is why it was missed:
the architecture pass looked at what components exist rather than how they are bounded from each
other.

---

## 2026-09-05 — Automatic enforcement resolved narrowly, ahead of CNA-EIS

**Question.** ACM detects drift and remediates by re-applying declared state, but never specified
whether that re-apply is automatic. CNA-EIS requires automated services to automatically enforce the
intended operational state, which is a stronger claim than detection.

**Considered.** Automatic apply on any detected drift. Narrow automatic remediation for specific
safe drift types, with everything else corrected on approval. No automatic enforcement, declaring
the indicator partial.

**Chosen.** Narrow automatic remediation, with the remainder declared.

**Why.** Unattended apply of a full plan is genuinely dangerous: a plan that includes a destructive
change executes without anyone reading it, and this project has already established that
infrastructure destruction is irreversible in a way identity changes are not. Narrow remediation
covers the drift types where correction is safe and reversible, and everything else is detected
automatically and corrected deliberately.

**Gives up.** Full satisfaction of CNA-EIS. The indicator will be partial, and the partial is a
choice about blast radius rather than a capability gap, which is what the determination should say.

---

## 2026-09-05 — GCP posture coverage flagged for verification

**Open item, not a decision.** Security Hub's CIS benchmark assessments give the AWS side a concrete
comparison basis for CNA-IBP, which requires configuration compared against the original provider's
best practices. Security Command Center's free tier is narrower, so the GCP side of that indicator
may be asymmetric.

**To do.** Verify SCC free tier posture coverage when IBP is determined rather than assuming parity
now. If the gap is real, the options are to accept an asymmetric determination and state it, or to
find another comparison basis on the GCP side.

---

## 2026-09-05 — "Limit" read as explicit allow-lists in both directions (CNA-RNT)

**Question.** The statement requires resources be configured to limit inbound and outbound traffic.
What counts as limiting?

**Chosen.** Explicit allow-lists in both directions. Default-allow-all outbound fails.

**Why.** Security groups deny all inbound by default and allow all outbound by default. A resource
with a stock group therefore already has a restriction on one side and none on the other, so a check
accepting "some restriction exists" would pass nearly every resource in the account and prove
nothing. The permissive reading is not merely weak, it is degenerate.

---

## 2026-09-05 — "Appropriately" bounded by the mapped control, not by business judgment (CNA-RNT)

**Question.** Appropriately configured is undefined. Does it mean configured to suit the business?

**Chosen.** No. Bounded by SC-7(5), deny by default and allow by exception.

**Why.** Reading it as a business-need judgment makes the indicator unfalsifiable, since any
configuration can be described as appropriate to some need. The mapped control supplies a structural
property instead: every allowed flow is enumerated and anything unmatched is denied. That is
checkable, and it is what the control family actually says.

**Pattern.** This is the third time the mappings have resolved something the statement left open,
after SIN and EIS. Reading the statement alone would have left this to invention.

---

## 2026-09-05 — Absent egress claimed rather than filtered egress (CNA-RNT)

**Question.** How strong is the outbound claim, given the architecture has no NAT gateway?

**Chosen.** Claim that outbound to the internet is absent, not filtered, and make it falsifiable.

**Why.** These are materially different claims. Filtered egress means a rule stands between a
compromised task and the internet; absent egress means there is no route at all. The second is
stronger and it is what this architecture actually has, so understating it would be as inaccurate as
overstating it.

**What makes it testable rather than asserted.** A failure criterion on private subnet route tables
containing any internet or NAT route, and a validation step that attempts an outbound connection
from a running task and confirms it fails. A route table with no internet route is a configuration
claim until a connection actually fails.

**And it names the price.** The endpoint decision cost roughly ten to fifteen dollars a month more
than a NAT gateway. This claim is what that bought, which is why the corrected endpoint entry and
this one belong together.

**Remediation consequence.** An internet route appearing on a private subnet is a significant
finding rather than routine drift, because it silently converts the claim from absent to filtered
and everything downstream depending on it becomes false without anything else changing.

---

## 2026-09-05 — RNT kept distinct from ULN, MAT and RVP (CNA-RNT)

**Question.** Four CNA indicators touch networking. Where are the boundaries?

**Chosen.** RNT is per-resource traffic configuration. ULN is logical networking enforcing flow
controls at the architecture level. MAT is attack surface and lateral movement. RVP is protection
against attack traffic.

**Why it needs stating.** An earlier attempt at this project folded RNT and ULN together on the
grounds that they use the same evidence, and that was wrong: the same security group state answers
two different questions, one about whether a resource's own traffic is bounded and one about whether
the network topology enforces flow control. Collapsing them would have produced one determination
doing half of each job.

---

## 2026-09-05 — "Related capabilities" reaches session lifecycle, not only topology (CNA-ULN)

**Question.** The statement says logical networking "and related capabilities." Is that padding, or
does it extend scope?

**Chosen.** It extends scope, and the mappings decide it. AC-12 is session termination and SC-10 is
network disconnect. Neither is topological. Both are about connections ending.

**Why this matters more than a vocabulary point.** It resolves the asymmetry between the two clouds.
The analytics warehouse has no VPC and the pipeline service's ingress control is a service setting
rather than a network boundary, so a purely topological reading would leave half the architecture
outside the indicator. "Related capabilities" admits boundary and session controls as flow control
by other mechanisms, and the mappings support that reading rather than it being a stretch made for
convenience.

**What would otherwise have been missed.** The session layer entirely. A connection that never
terminates defeats flow control by outliving the conditions that authorised it, and no security
group notices. Idle timeouts, connection lifetimes and bounded token lifetimes are flow control in
the temporal dimension.

---

## 2026-09-05 — ULN separated from RNT by a test, not an argument (CNA-ULN)

**Question.** RNT and ULN read against the same security groups and route tables. What actually
distinguishes them?

**Chosen.** RNT asks whether each resource's own traffic is bounded. ULN asks whether the topology
constrains flows independently of any resource's configuration. The test: if every security group
were wiped, would flows still be constrained?

**Built as evidence rather than left as reasoning.** A validation step permits all traffic on a
disposable resource's security group and confirms internet egress still fails. That is the only
piece of evidence separating the two indicators, and without it ULN would be RNT described twice.

**Why it is likely to be skipped and should not be.** It requires deliberately weakening a control
to prove another one holds, which feels wrong and is exactly the point: defence in depth is a claim
about what survives a failure, and it cannot be demonstrated without simulating the failure.

---

## 2026-09-05 — Flow control recorded per layer so no path rests on one mechanism (CNA-ULN)

**Chosen.** A register mapping every flow path to the layer or layers enforcing it, across topology,
boundary, service boundary and session.

**Why.** Defence in depth is easy to assert and hard to check. A register makes it visible which
paths are covered by more than one layer and which rest on a single mechanism, and it is what keeps
the asymmetry between the two clouds honest: the GCP side has three layers rather than four, and the
register shows that per path rather than the determination implying parity.

---

## 2026-09-05 — VPC Service Controls not used, recorded as a design gap (CNA-ULN)

**Chosen.** The GCP side has no topological perimeter. VPC Service Controls would supply one and is
not used.

**Why record it as a gap rather than a limitation.** A limitation is something the platform cannot
do; this is something the platform offers and the project declined. The distinction matters because
an assessor could reasonably ask why, and "the platform does not support it" would be false.

---

## 2026-09-05 — Attack surface is three-dimensional, and the third is not infrastructure (CNA-MAT)

**Question.** What counts as attack surface for this indicator?

**Chosen.** Three dimensions: network, identity and application.

**Why the third.** The mappings include SI-10 input validation, SI-11 error handling and information
leakage, and SI-16 memory protection. Those are properties of the code running inside the container,
not of the infrastructure around it. Nothing in the statement hints at them.

**Why it is declared rather than narrowed away.** It would have been easy to read "machine-based
information resources" as infrastructure and produce a fully satisfied indicator. The mappings say
otherwise, so the determination is partial and the gap is structural: an infrastructure collector
cannot inspect application logic. Static analysis and dependency scanning in the pipeline partially
cover input handling and error paths; memory protection is a runtime property of the language and
platform and is inherited.

**Fourth time the mappings changed scope.** After SIN pulling in DNS, EIS being reclassified as
technical, and ULN reaching session lifecycle. The pattern is consistent enough to state as method:
the statement gives the outcome, the mappings give the reach, and reading only the first produces a
determination that is narrower than the framework asks for.

---

## 2026-09-05 — Lateral movement computed across network and identity together (CNA-MAT)

**Question.** How is lateral movement measured?

**Chosen.** A combined reachability graph over network paths and identity permissions, compared
against a declared blast radius per resource.

**Why neither alone works.** A compromised task with a narrow security group and a broad task role
has poor containment while looking correct on the network. The reverse is also true. These are
usually assessed by separate tools and separate teams, and the gap between them is exactly where
lateral movement lives.

**What made the network half non-trivial.** The per-service segmentation added during the
architecture review. Without it both services would share a group, and compromising either would
yield the network position of both, which would make the lateral movement claim an assertion rather
than a measurement.

---

## 2026-09-05 — "Minimal" bounded against existing baselines, not a new one (CNA-MAT)

**Chosen.** No port open that no declared flow uses, no permission granted that no declared
operation needs, no capability enabled that no declared function requires. Flows come from the ULN
register, permissions from the ELP role model.

**Why reuse rather than invent.** Minimal is comparative and unfalsifiable without a baseline. A
third baseline would have to be kept in sync with the other two, and the first time they diverged
the determination would be measuring against something nobody maintained.

---

## 2026-09-05 — Blast radius findings are remediated by narrowing the condition (CNA-MAT)

**Chosen.** A widened blast radius is fixed by correcting the role or the security group. Never by
adjusting the declared blast radius to match.

**Why it needs saying explicitly.** It is the tempting fix. Widening the declaration turns the
finding green immediately and changes nothing about the exposure, which is remediating the
measurement rather than the condition. The same failure shape appears wherever a control is measured
against a declared baseline, so this is worth carrying as a general rule rather than a note on one
indicator.

---

## 2026-09-05 — Container hardening included as cheap surface reduction (CNA-MAT)

**Chosen.** Read-only root filesystem, non-root user, dropped Linux capabilities, no privileged
mode.

**Why.** These cost nothing on Fargate, are set in the task definition, and are the container-level
analogue of the network segmentation. They also narrow what an attacker can do after compromise
without narrowing what the application can do, which is the cleanest kind of surface reduction
available.

---

## 2026-09-05 — "Strictly defined" means enumerated, not minimised (CNA-DFP)

**Question.** DFP requires functionality and privileges be strictly defined. MAT requires attack
surface be minimal. Where is the line?

**Chosen.** DFP is about enumeration, MAT is about size.

**Why.** A service with a large but fully enumerated permitted set satisfies DFP and fails MAT. A
service with a small but undeclared set does the reverse. Treating both as "keep it tight" would
collapse two indicators into one and leave the enumeration question unasked. CM-2, baseline
configuration, supports the reading: a baseline defines intended state rather than judging how tight
it is.

**What this catches that nothing else does.** Functionality or privilege arriving by default rather
than by declaration. A managed service with its default feature set, a role with a managed policy, a
container inheriting its image entrypoint. None is necessarily excessive, so MAT may pass them; none
is declared, so DFP does not.

---

## 2026-09-05 — SI-3 satisfied by strict definition, not by a scanner (CNA-DFP)

**Question.** Malicious code protection is mapped to an indicator about functionality and
privileges, and this architecture has no anti-malware capability.

**Chosen.** Strictly defined executable functionality is the malicious-code control here: immutable
digest-pinned images, read-only root filesystems, dropped capabilities. A workload that can execute
only the code it was defined to run has no path to execute injected code.

**Why declared rather than assumed.** This is a defensible reading and it is not the conventional
one. On Fargate with an immutable read-only filesystem there is nowhere for a scanner to run and
little for it to scan, so the alternative is not a better control, it is no control. But an assessor
expecting a scanner should find the reasoning rather than an omission.

---

## 2026-09-05 — Managed and predefined policies barred entirely (CNA-DFP)

**Chosen.** No AWS-managed or GCP predefined policy on any workload identity. Enumerated
customer-managed policies only.

**Why.** A managed policy's contents are controlled by the provider and change when the provider
changes them. Privilege then arrives undeclared and can widen without anything in the repository
changing, which is precisely the failure this indicator exists to catch. Convenience is the reason
managed policies are the most common source of undeclared privilege.

**Gives up.** Real ergonomics. Enumerating equivalents by hand is more work and will drift from the
managed policy as services add actions, which is a maintenance cost accepted deliberately.

---

## 2026-09-05 — Pipeline actions pinned to commit SHAs (CNA-DFP)

**Chosen.** Workflow steps reference commit SHAs rather than tags or branches.

**Why.** A pipeline action referenced by tag is functionality defined by whoever controls that tag.
This is the same reasoning VRI applied to image digests, arriving at the same conclusion from the
supply chain direction: a mutable pointer supplies no definition of what will actually run.

---

## 2026-09-05 — Runtime execution visibility declared as a platform limitation (CNA-DFP)

**Chosen.** The claim that a container executes only its declared functionality rests on image
immutability and the read-only filesystem rather than on runtime inspection.

**Why say so.** Fargate exposes limited runtime process visibility, so a check on executing
processes is partial by platform rather than by design. Presenting it as complete would overstate
the evidence, and the honest version is that the control is structural rather than observed.

---

## 2026-09-05 — Assessment split so the evidence does not rest on the collector (CNA-EIS)

**Question.** The statement requires automated services to assess security. Does this project's own
collector count?

**Considered.** Read "automated services" loosely so the collector satisfies it. Use managed
services only and sideline the collector. Split the roles.

**Chosen.** Split. Managed services assess and generate findings; the collector verifies those
services are enabled, correctly scoped and producing results.

**Why.** The loose reading makes the indicator self-referential: a tool asserting a tool exists.
The split removes that, because the findings come from services independent of anything this project
built and the collector's job becomes confirming the independent services work. Same concern as SUS
logging responder actions to storage the responder cannot modify, applied to assessment rather than
response.

**What the meta-assessment catches.** An assessment layer failing silently. A disabled rule produces
no findings, which is indistinguishable from a clean environment unless something checks the rule is
running.

---

## 2026-09-05 — "Intended operational state" read as three layers (CNA-EIS)

**Question.** Does operational state mean configuration?

**Chosen.** No. Declared configuration, running health, and security posture.

**Why.** If operational means configured, the word adds nothing to a statement that already has
"assess the security of." A service declared correctly and not running is in an unintended
operational state by any ordinary reading, and nothing in ACM's declared-versus-live comparison
notices.

**Where the best evidence turned out to be.** The container service maintaining desired count and
replacing failing tasks. That is automatic enforcement in the strictest sense, acting in seconds
without a human, and it is a platform guarantee rather than project code. Claiming it is more honest
than claiming our own remediation, and it is stronger. Worth noting that the strongest evidence for
this indicator is something the project inherited rather than built.

---

## 2026-09-05 — Automatic enforcement bounded to a declared safe list (CNA-EIS)

**Question.** The statement says automatically enforce. How much is automated?

**Chosen.** Native health enforcement, plus remediation actions for declared safe, reversible drift
types. Everything else detected automatically and corrected deliberately.

**Why.** Unattended apply of a full plan executes destructive changes unread, and this project has
already established that infrastructure destruction is irreversible in a way identity changes are
not. The safe list is where correction cannot make things worse.

**Tested in both directions, which is the part that matters.** One test confirms safe-list drift
corrects. A second confirms non-safe-list drift is detected and *not* corrected. Without the second,
"we only auto-remediate safe things" is an assertion about intent rather than a demonstrated
boundary. Auto-remediating something off the list is a failure even though it fixed the drift,
because the control that failed is the boundary.

**The partial is a choice, not a gap.** Stated that way in the determination, because a reader
should be able to tell the difference between cannot and chose not to.

---

## 2026-09-05 — Config recorder scoped for cost, with the coverage consequence stated (CNA-EIS)

**What the cost check found.** AWS Config bills per configuration item in continuous mode, and a new
item is generated on every create, delete and relationship change. Apply-and-destroy creates and
destroys every resource each session, so a few hundred items per cycle is realistic, around a dollar
per cycle and roughly ten dollars a month at ten sessions.

**Why it is worth recording.** This is the one meter in the architecture that gets worse with
teardown discipline rather than better. The earlier cost reasoning assumed teardown reduces
everything, and that was wrong for this service specifically.

**Chosen.** Scope the recorder to the resource types the determinations actually use rather than all
supported types.

**The consequence, stated rather than hidden.** Narrower recorder scope means narrower assessment
coverage. This is a cost decision with a coverage effect, and the determination says so rather than
presenting the scoping as a tidiness measure.

---

## 2026-09-05 — Third-party scope reaches the clouds themselves (CNA-IBP)

**Question.** What counts as a third-party machine-based information resource?

**Chosen.** Anything not entirely inside the Minimum Assessment Scope, per the definition. That
makes both clouds themselves third-party resources, along with the code hosting platform and the
container base images.

**Why it matters.** The intuitive reading is that third party means add-ons and vendors bolted onto
the architecture. The definition says otherwise, and under it essentially every managed service in
this project is a third-party resource whose configuration must be compared against its own vendor's
guidance. A narrower reading would have produced an indicator about two or three components rather
than about the whole environment.

**Also worth being precise about.** Provider is a defined term meaning the cloud service provider
seeking certification, which is us. "The original provider" is the qualifier pointing the other way,
at the vendor of the resource.

---

## 2026-09-05 — GCP benchmark mapping declared absent, as a licensing boundary (CNA-IBP)

**Question.** The AWS side compares configuration against a named benchmark through the posture
service already in the architecture. Does the GCP side have an equivalent?

**What the check found.** Security Health Analytics at the free tier produces real misconfiguration
findings, but mapping those findings to CIS controls requires the paid tier. Sources are consistent
that the free tier gives findings without compliance mapping.

**Chosen.** Accept the asymmetry. Compare against the vendor's detectors on that side and declare
the benchmark mapping absent.

**Why the distinction matters for this indicator specifically.** A benchmark is the structured form
of a vendor's guidance. Findings tell you what is wrong; a benchmark tells you what fraction of the
guidance you meet. The indicator asks for comparison against guidance, so losing the benchmark
mapping loses the ability to state coverage, not just tidiness.

**Recorded as a licensing boundary rather than a capability gap.** The detectors exist and run; the
mapping is behind a price. That is a cost decision and should read as one, not as something the
platform cannot do.

---

## 2026-09-05 — GitHub comparison declared not performed, rather than inferred (CNA-IBP)

**Question.** The code hosting platform publishes hardening guidance for its pipeline product. Is
that compared?

**Chosen.** No. Declared as not performed.

**The tempting alternative.** Several of its recommendations are already implemented: actions pinned
to commit SHAs from DFP, federated identity rather than stored credentials from SNU. It would be
easy to list those and call the indicator satisfied for this vendor.

**Why that would be wrong.** Those choices were made for other reasons and happen to align. Alignment
is not comparison, and an indicator that asks whether configuration is compared against guidance is
not satisfied by configuration that coincidentally matches some of it. The guidance is published
prose with no automated comparison service, so the honest answer is that the comparison is manual and
is not being done.

---

## 2026-09-05 — A failure criterion for claiming automation that does not exist (CNA-IBP)

**Chosen.** The indicator fails if any comparison basis is recorded as automated where no automated
mechanism exists.

**Why this indicator needs it and others did not.** The characteristic failure here is asserting a
comparison that is really an assumption. Every other indicator's failure modes are about the
environment being wrong; this one's is about the register being optimistic. The criterion puts the
register itself under test.

---

## 2026-09-05 — An exception record required for benchmark comparison (CNA-IBP)

**Chosen.** Benchmark controls deliberately not met are recorded with a reason and a review date.
Never suppressed.

**Why.** A benchmark applied to a small environment produces findings for controls that genuinely do
not apply, and the path of least resistance is to suppress them until the dashboard is green.
Suppression without a record is how benchmark comparison becomes theatre, and an unreviewed exception
is a suppression with extra steps, which is why the review date is part of the entry rather than
optional.

---

## 2026-09-05 — "Appropriately" read against the provider's circumstances, with no mapping to anchor it (CNA-OFA)

**Question.** OFA requires resources be appropriately optimized. On RNT, appropriately was bounded
by SC-7(5). What bounds it here?

**The complication.** This indicator has no control mappings at all, the first in the catalog so far.
The mappings have resolved open language on four previous determinations, and here there is nothing
to read.

**Chosen.** Appropriateness is relative to the provider's own circumstances, consistent with how
RPL-RRO defines recovery objectives against the provider's business needs and capabilities.

**Why that is not just convenient.** The adjacent cluster states the referent explicitly for the same
subject matter. Borrowing it is a defensible reading rather than an invented one, and the alternative
is either an absolute standard the statement does not supply or no standard at all.

---

## 2026-09-05 — Availability and recovery separated, with the asymmetry shown per resource (CNA-OFA)

**Chosen.** The compute tier is genuinely highly available; the data tier deliberately is not.
Recorded as a per-resource table rather than a summary claim.

**Why the table rather than a sentence.** A summary would have to choose between overstating the
compute posture or understating it. Services run multiple tasks across zones with automatic
replacement in seconds, which is real high availability. The database is single-AZ with restore
measured in tens of minutes. Both are true and they are true of different resources, so the honest
form is per resource.

**The cost behind it.** Multi-AZ roughly doubles the instance charge. That is the whole reason, and
it is stated rather than dressed as an architectural preference.

---

## 2026-09-05 — A tested restore argued as better evidence than an untested failover (CNA-OFA)

**The claim.** A restore that has been performed, timed and recorded is demonstrated capability.
Multi-AZ failover is a configuration property whose behaviour and duration are unknown until it
happens, and most providers never test it.

**What the claim is not.** It is not an argument that single-AZ is equivalent to multi-AZ. It is an
argument about evidence quality, and it holds only for the recovery half. The availability half is
genuinely weaker and the determination says so.

**Why it is worth making at all.** RPL-TRC asks for tested recovery capability specifically. This
project is stronger on the evidence half than on the configuration half, and that is an unusual shape
worth stating rather than hiding behind the partial.

**What makes it real.** A failure criterion requiring the declared recovery time to have been measured
against an actual restore. Without it, "rapid recovery" is an estimate.

---

## 2026-09-05 — Revising an objective to meet a measurement is recorded as a position change (CNA-OFA)

**Chosen.** A measured restore time exceeding the objective is remediated by improving the mechanism
or by revising the objective, and where the objective is revised that is recorded as a change to the
declared position rather than as the finding clearing.

**Why.** Moving the target to meet the measurement turns the finding green and changes nothing about
the capability. This is the same failure shape as widening a blast radius declaration in MAT, and it
appears wherever a control is measured against a declared baseline, which is most of this project.
Worth carrying as a general rule rather than a note on two indicators.

---

## 2026-09-05 — Effectiveness distinguished from presence by exercise testing (CNA-RVP)

**Question.** The statement asks for the effectiveness of protections to be reviewed. What
distinguishes that from checking the protections are enabled?

**The core problem.** A web application firewall with zero blocked requests could mean it is working
perfectly or that nothing ever tried. Those are indistinguishable from the data alone, and in a
synthetic environment the second is almost certainly true.

**Chosen.** Generate traffic that should be blocked and confirm it is. Same resolution as the
self-testing zero-results rule from ELP, applied to a protective control rather than a detective
query.

**Run in both directions.** A request that should be blocked is confirmed blocked, and a legitimate
request is confirmed allowed. A firewall blocking everything would pass a one-sided test while
breaking the service, so the second direction is not a formality.

---

## 2026-09-05 — Three evidence levels named, with the third declared unavailable (CNA-RVP)

**Chosen.** Configured, exercised, operationally effective. The first two are demonstrated here. The
third is not.

**Why name the level that cannot be reached.** A real provider's evidence for this indicator is
blocked attacks. This project's is exercised mechanisms. Presenting the second as the first would
overstate the claim, and simply omitting the distinction would let a reader assume the stronger one.
Naming all three makes the boundary legible rather than hidden in a limitations paragraph.

**The register enforces it.** Every protection mechanism records which level its evidence reaches, so
the distinction survives in the artifact rather than living only in this entry.

---

## 2026-09-05 — "Other unwanted activity" narrowed by the mappings (CNA-RVP)

**Question.** The phrase reads as generic malicious traffic. Is it?

**Chosen.** No. SI-8 is spam protection and SI-8(2) is automatic signature updates, neither of which
is a generic malicious-traffic control. Read against this architecture, the applicable meaning is
content-based protection that updates its own rules automatically, which managed rule groups satisfy
exactly: the vendor maintains and updates the rule content, which is the signature-update half
observable as rule group versions changing without our intervention.

**Spam protection declared inapplicable.** The offering neither sends nor accepts mail. Declared
rather than stretched into something adjacent, which would have been the easy move given the phrase
invites a broad reading.

**Sixth time the mappings changed a reading.** After SIN, EIS, ULN, MAT and RNT. Here they narrowed
rather than widened, which is the first time that has happened and is worth noting: the mappings are
not simply a source of extra scope, they are the referent.

---

## 2026-09-05 — Shield Standard named as weak rather than padded (CNA-RVP)

**Chosen.** The denial-of-service claim rests on WAF rate limiting and load balancer metrics, not on
the standard protection tier.

**Why say it.** The standard tier is automatic, free, always on and exposes almost nothing about its
own operation. It would be easy to list it as the denial-of-service protection and move on, since it
genuinely is one. But this indicator is about reviewing effectiveness, and a control that produces no
reviewable output contributes nothing to that. The tier that would supply the visibility costs
roughly 3,000 USD per month, which is the reason it is not used and is recorded as such.

---

## 2026-09-05 — A failed exercise test is a protection failure, not a test failure (CNA-RVP)

**Chosen.** It routes to the detection path rather than being treated as a broken test.

**Why.** If a request that should be blocked gets through, the mechanism did not do what it was
configured to do. Treating that as a test problem would be diagnosing the instrument rather than the
condition, which is the same error as remediating a measurement instead of a cause, seen in MAT with
blast radius and OFA with recovery objectives.

---

## 2026-09-05 — Registers consolidated into one artifact at implementation

**What the consistency pass found.** The CNA cluster alone declares seven registers: flow control,
surface, definition, third-party, availability position, protection position, and the safe
remediation list. Adding the integrity position register from VRI, the path register from VCM,
retention from PRR, rotation intervals from ASM and the evaluation plan from SVC-EIS, the project is
carrying roughly a dozen separate version-controlled registers.

**Why each exists.** Every one was justified individually. They are what turn an assertion into a
checkable claim: a resource with no recorded position fails, where a resource simply absent from
consideration would pass silently.

**The collective problem.** Adding a resource to the environment would require entries in five or six
registers independently, and nothing would catch a missed entry in one of them. A maintenance surface
that large drifts, and a drifted register produces a determination measuring against something nobody
maintained.

**Chosen.** One resource register at implementation, generated from the inventory, with a column per
indicator. A new resource appears automatically with empty cells that fail their respective checks.

**Why this changes nothing about the determinations.** Each indicator's claim is unchanged, and each
still fails on a missing position. What changes is that the positions live in one generated artifact
rather than a dozen hand-maintained ones, so the failure mode shifts from "somebody forgot a file" to
"a cell is empty," which is visible.

**Recorded as an implementation decision rather than a determination change**, and noted in the
design matrix conventions so the determinations' references to named registers are read as columns
rather than files.

---

## 2026-09-05 — The final clause is the indicator (MLA-LET)

**Question.** LET requires a list of resources and event types be maintained and persistently
reviewed to ensure these activities occur. Is this an indicator about maintaining a list?

**Chosen.** No. The operative clause is the last one. The review is of whether the logging described
is actually happening.

**Why it changes the evidence design.** A well-maintained list sitting over a silently failed
delivery pipeline satisfies the first half of the statement and fails it as a whole. So the evidence
needs a per-source check that events are arriving within an expected interval, not a check that the
list exists and is current. The strongest form is generating an event of each category and confirming
it lands, which proves the path end to end where a configuration check proves only the first link.

---

## 2026-09-05 — Event categories taken from the mappings, not chosen (MLA-LET)

**Question.** What has to be on the list?

**Chosen.** The categories the mappings name: automated account management actions, privileged
function execution, remote and external access, audit record generation, and inbound and outbound
traffic monitoring and alerting.

**Why.** The statement says "a list of information resources and event types" without saying which,
which reads as provider discretion. The control family removes most of that discretion. A list chosen
freely could omit privileged function execution and still look complete; the mapping to AC-6(9) says
otherwise.

**Seventh time the mappings determined a reading.** The pattern is now consistent enough that reading
the statement without them should be treated as an incomplete first pass rather than a shortcut.

---

## 2026-09-05 — Logged, monitored and audited recorded as three states (MLA-LET)

**Question.** The statement lists three activities. Are they synonyms?

**Chosen.** No, and each source records which of the three apply to it.

**Why.** Logged means the record is produced. Monitored means something watches it and can alert,
which is the detection path built for SUS. Audited means it is reviewed, which is RVL. Several
sources in this architecture are logged and audited but not monitored, and a determination implying
uniformity would claim monitoring coverage that does not exist.

**Where it pays off.** OSM, RVL and the detection work each inherit a precise picture of which sources
they actually cover, rather than each rediscovering the distinction.

---

## 2026-09-05 — Data access logging scoped for cost (MLA-LET)

**Chosen.** Data access events logged for the stores holding customer data, not all stores.

**Why.** Data events are billed per event and can dwarf management event costs, which is the same
economics that made the configuration recorder a per-cycle charge. Scoping is the mitigation and the
coverage consequence is that access to non-customer-data stores is not individually logged.

**Recorded as a cost decision with a coverage consequence**, following the precedent set for the
recorder, rather than presented as a scoping judgment about what matters.

---

## 2026-09-05 — Silent sources are investigated, not re-enabled (MLA-LET)

**Chosen.** A source that has delivered nothing within its expected interval is investigated rather
than assumed broken.

**Why.** Silence has two causes and they need different responses. The source may have failed, or the
declared expectation may be wrong. Re-enabling blindly treats the second case as the first and leaves
an expectation nobody corrected, which is the same failure shape as remediating a measurement instead
of a condition.

**Known weakness in this environment.** Event volume is low and irregular, so a source legitimately
producing nothing for days is hard to distinguish from a broken one. This check would be sharp in a
real environment and is weak here, which is stated rather than glossed.

---

## 2026-09-14 — Catalog re-verified after an upstream version bump

**What happened.** The catalog moved from 2026.07.14.01 to 2026.09.13.02 between working sessions.
The project had twenty-four determinations pinned to the earlier version.

**What was checked.** Structure first: 46 indicators across 10 clusters, all marked stable, and every
indicator ID this project has determined still exists. Then change history: no indicator carries an
update entry later than the original 2026-06-24 launch, and no ruleset does either. Then spot checks
of four determination statements against their recorded text, all matching exactly, plus the
eighteen mappings for the indicator being worked.

**Result.** A version bump with no substantive change. All twenty-four determinations remain valid
and the pin moves forward.

**Why this is recorded rather than passed over.** This is the first exercise of the re-verification
discipline the project committed to when the source was pinned, and the outcome matters less than
the fact that it was checked. The failure this guards against is the one that already happened once
in this project: working from a superseded catalog without noticing, which cost a cluster of
determinations. A clean result is evidence the discipline works, and a record of it is what
distinguishes a checked pin from an assumed one.

**Method worth keeping.** Check structure, then change history, then spot-check known text. The
change history is the cheapest signal and would have caught a real revision immediately; the spot
checks guard against a revision that did not update its own history.

---

## 2026-09-14 — "Or similar system(s)" read as anticipating composition (MLA-OSM)

**Question.** The architecture has no SIEM. Does the indicator fail?

**Chosen.** No. The statement says "a SIEM or similar system(s)," plural, and the determination is a
composition: managed threat services for continuous detection and alerting, an object-locked store
for tamper-resistant retention, a serverless query engine for investigation, schema normalization
plus scheduled queries for correlation, and the existing responder for response.

**Why the plural matters.** Calling any single component a SIEM would be wrong and an assessor would
catch it. Calling the composition "similar systems" is accurate, and the statement's own wording
appears to anticipate that a capability may be assembled rather than bought.

---

## 2026-09-14 — OCSF adopted to close cross-cloud correlation (MLA-OSM)

**Question.** Nothing correlated across the two clouds. Managed detection sees each cloud
separately, and no rule ran across both looking for a pattern visible only in the combination. That
is a real SIEM's central value.

**Chosen.** Normalize both clouds' events to the Open Cybersecurity Schema Framework in the delivery
pipeline, before they land in the store.

**Why it works.** The problem OCSF exists to solve is stated almost exactly: a user in one system is
an account in another, and a block becomes a deny or a drop depending on which vendor wrote the log.
Once events share a schema, a single query correlates across clouds natively because an identity is
the same field regardless of origin.

**Why it is realistic rather than aspirational.** Vendor-neutral open standard backed by AWS,
Splunk, IBM and Palo Alto, adopted by the Linux Foundation, roughly 200 organizations reporting
production deployments. Security Lake uses it natively. Crucially, Security Lake is not required:
the transformation happens in the pipeline layer, and partial adoption mapping the most critical
event classes first is the documented norm rather than a compromise.

**Why it matters for this project specifically.** It is the multi-cloud normalization thesis this
project started with, resurfacing in a harder form with an industry standard behind it. Earlier the
normalization was of API shapes into control claims; here it is of event schemas into a queryable
corpus. Same skill, and now with a name a reviewer recognises.

**Cost: zero.** OCSF is a schema, not a service.

**Honest limit.** Field-level fidelity is the hard part, and doing two or three event classes well
beats mapping everything badly.

---

## 2026-09-14 — Correction: a query layer did not require Security Lake or OpenSearch (MLA-OSM)

**What I said during the architecture check.** That Security Lake and OpenSearch were the realistic
options for a query layer, both cost real money, and the cheap alternative was centralized storage
with the absence of a query layer declared.

**Why that was wrong.** Athena is serverless with no standing cost, billed per terabyte scanned with
a 10 MB minimum per query. At this log volume every query hits the minimum, which is a fraction of a
cent. There is no idle charge because nothing runs.

**What the false constraint cost.** OSM was heading for a partial on the grounds of having no query
layer at all, which would have been a materially weaker determination for no reason. The user
pushed back on the constraint rather than accepting it, which is what surfaced it.

**What the correct answer adds beyond cost.** Partitioned Parquet with partition projection is the
standard real-world pattern for log analytics on object storage, and it is where the technical
substance lives: compression and columnar format cut scanned bytes by an order of magnitude or more,
and projection avoids crawler charges entirely. Workgroup per-query scan limits are the safety net
against a single bad query, set before rather than after a billing surprise.

---

## 2026-09-14 — Four mapped controls imposed obligations the statement did not signal (MLA-OSM)

**AU-4, storage capacity.** Object storage has no capacity limit, so the real obligation is cost and
growth monitoring rather than disk space. An alarm on store growth rather than a fill percentage.

**AU-5, response to audit processing failure.** The significant one. Delivery failure previously had
no defined response anywhere in this project, and silently losing logs is worse than most findings
the tool detects. Now an alarm routed to the detection path.

**AU-8, time stamps.** Correlation across clouds is meaningless if time representations differ, so
this became a concrete field-mapping requirement on the normalization layer rather than a general
concern.

**AU-11, retention.** A declared retention period, separate from immutability. Object lock supplies
the second and says nothing about the first.

**Eighth time the mappings changed a determination.** With eighteen mappings this indicator had the
most to say, and the pattern holds: the statement gives the outcome, the mappings give the
obligations.

---

## 2026-09-14 — A six-word statement resolved by its mappings (MLA-RVL)

**The statement.** "Logs are persistently reviewed and audited." That is the entire text.

**What resolves it.** AU-6 is audit record review, analysis and reporting for indications of
inappropriate activity. AU-6(1) is automated process integration. SI-4 and SI-4(4) are system and
traffic monitoring. AC-2(4) and AC-6(9) name account management actions and privileged function
execution as the things to review specifically.

**Why it is worth recording as an instance rather than just a determination.** This is the clearest
case in the project of a statement that says almost nothing and mappings that say almost everything.
Nine previous determinations have been changed by their mappings; here there is no determination at
all without them. Any method statement for this work has to put the mappings on equal footing with
the statement rather than treating them as supporting material.

---

## 2026-09-14 — Reviewed is not monitored, and RVL takes the slower half (MLA-RVL)

**Question.** The detection services already watch logs continuously. Does RVL duplicate them?

**Chosen.** No. LET established three states per source — logged, monitored, audited — and RVL covers
the third. Monitored means something watches continuously and can alert. Audited means examined for
indications of inappropriate activity, which is slower, retrospective, and looks for patterns rather
than triggers.

**Why the distinction earns its keep.** Without it, RVL either duplicates the detection work or has
nothing to do. With it, RVL covers what continuous detection cannot: patterns visible only across
the normalized corpus, over a window, after the fact.

---

## 2026-09-14 — Review runs must record nil results (MLA-RVL)

**Question.** A detection query fires on a match and is silent otherwise. Is that sufficient for
review?

**Chosen.** No. Every review run writes a record of what it examined, over what window, and what it
found, including when it found nothing.

**Why.** "Persistently reviewed" is a claim about the activity occurring, not about what it
discovered. Without a nil-result record, a review that never ran and a review that found nothing are
indistinguishable in the data. That is the same failure shape as the zero-results problem in ELP and
the protection-with-no-blocked-requests problem in RVP, appearing a third time in a different guise.

---

## 2026-09-14 — Window continuity required (MLA-RVL)

**Chosen.** Each query's examined window overlaps its run interval, and consecutive windows are
checked for gaps.

**Why.** A query running every 24 hours but examining 12 hours reviews half the logs and reports
success. Nothing about its output would reveal the gap. This is the most easily missed failure in
the determination and it is the kind that produces a confident and false claim.

**A property worth noting.** A missed window is recoverable here, by re-running the query over the
gap, precisely because logs are retained and queryable. A streaming-only review would have lost that
window permanently. Retention plus a query layer turns a missed review from a permanent hole into a
backlog item.

---

## 2026-09-14 — The human half declared out, as an assertion rather than a caveat (MLA-RVL)

**Question raised.** Whether this indicator is out of scope entirely, since log review sounds like a
person reading logs.

**Chosen.** In scope and partial. Logs are machine-based information resources, so the subject is in
scope; the split-by-subject rule from PRR applies to the activity. Automated examination is
determined, and the human element of AU-6 — reading output and judging activity inappropriate rather
than merely unusual — is declared out.

**What the mappings settle.** AU-6(1) is automated process integration, which would not be mapped if
the framework meant only human review. At Class C, machine-based resources are verified and validated
every three days, which is not a human-review cadence.

**Structural change made in response.** The human half appears as a named assertion with a stated
determination rather than as a line in the limitations, so the partial is legible in the structure
the way ELP made devices visible rather than footnoted.

---

## 2026-09-14 — A sensitivity classification is built, not declared absent (MLA-ALA)

**Question.** The statement requires access based on "organizationally defined data sensitivity."
This project declined to fabricate personnel registers and risk ratings on the grounds that inventing
facts about a fictional organization demonstrates nothing. Does a data classification fall the same
way?

**Chosen.** No. Build it.

**The distinction that decides it.** A personnel register invents facts about people who do not
exist. A sensitivity classification classifies artifacts that genuinely exist and whose contents this
project designed. We built every source in the event type list and we know what each carries. That
places it on the same side of the line as the declared role model, which was design input, rather
than with the registers, which would have been invented evidence.

**Worth recording because the line has now been drawn three times** and the reasoning has been
consistent each time: does this invent facts about things that do not exist, or record judgments
about things that do.

---

## 2026-09-14 — SI-11 tells you what the classification is for (MLA-ALA)

**The single mapping.** SI-11 is error handling — reveal error information only to authorized
personnel.

**What it settles.** Without it, a sensitivity classification is an abstract taxonomy and the tiers
are arbitrary. With it, the question becomes concrete: what can each log source disclose? Error
detail lands in logs and reveals internals, so application and database logs are sensitive because of
what they can leak, not because logs are generally sensitive.

**Result.** Three tiers with a stated basis: sensitive for content and error detail, operational for
structure and activity, public-safe for derived records.

---

## 2026-09-14 — Write-time redaction rejected in favour of access control (MLA-ALA)

**Considered.** Strip identifiers and error detail in the normalization pipeline, so no tier is
sensitive. That is arguably the stronger security posture and some organizations do exactly it.

**Chosen.** Keep the content, control the access.

**Why.** Redaction destroys evidence the review queries under RVL depend on. A denied access attempt
with the principal stripped is much less useful, and the review queries are the mechanism by which
another indicator is satisfied. Choosing the apparently stronger control here would have weakened a
neighbouring determination.

**Worth noting as a class of decision.** This is a cross-indicator trade-off, and it is the kind that
working control-by-control in isolation would miss entirely. The cost is real and stated: sensitive
content exists in the store rather than being absent, so a store compromise exposes more than a
redacted store would.

---

## 2026-09-14 — Cross-tier joins are the characteristic bypass of a query-layer access model (MLA-ALA)

**Question.** Where is tier separation actually enforced?

**Chosen.** Catalog-level permissions per tier, with a dedicated test that a join across tiers fails
without elevation, run separately from single-table tests.

**Why it needs its own test.** A permission model can be correct on every individual table and still
permit a join that returns sensitive data to a principal authorized only for operational. Nothing in
a per-table permission review reveals that. It is the same shape as the zero-results problem: the
control looks correct and the bypass is invisible from the artifact being reviewed.

**Why this is where the engineering value sits.** Of the four decisions in this determination, three
are judgment and cost hours. This one is a genuine data access control problem with a failure mode
worth understanding, and it is the reason the full composite was chosen over a workgroup-separation
shortcut.

---

## 2026-09-14 — Direct object access closed, so the catalog is the only path (MLA-ALA)

**Chosen.** Bucket policy denying object reads to any principal other than the query engine role.

**Why it was added rather than declared as a limitation.** Catalog permissions control the query path.
They say nothing about a principal reading objects directly from the store, and that path would make
the entire tier model decorative. Closing it turns "we control query access" into "query access is
the only access," which is a materially different claim for a couple of hours of work.

**Second enforcement point, stated as such.** The determination now depends on two mechanisms holding
rather than one, and both are tested.

---

## 2026-09-14 — Expectation corrected: EVC is not purely a pipeline indicator (MLA-EVC)

**What I expected.** That "especially infrastructure as code" plus "tested" made this a pipeline
indicator, distinct from ACM and CNA-EIS, which assess live state.

**What the mappings say.** CA-7 continuous monitoring, CM-2 baseline configuration, CM-6
configuration settings with deviation identification, SI-7(7) integration of change detection into
incident response. Those describe live monitoring, not pre-application testing. Only the statement's
own words point at the pipeline.

**Chosen.** Take both halves. Reference the evaluation half to ACM and CNA-EIS, since SI-7(7) is
already satisfied by ACM's mutation query routing to the detection path, and name the testing half as
the new contribution.

**Worth recording as a reversal of the usual pattern.** Nine times the mappings have widened or
sharpened a reading the statement left open. Here they pulled against the statement, and the
resolution was to hold both rather than let either win.

---

## 2026-09-14 — What EVC catches that drift detection cannot (MLA-EVC)

**The distinction.** ACM tells you the environment drifted from what you declared. EVC tells you what
you declared is wrong before it is applied.

**Why it justifies a separate build.** A misconfiguration that is correctly declared and correctly
applied is invisible to drift detection, because live state matches the declaration perfectly. Drift
detection compares two things that agree. Only evaluating the declaration itself catches a wrong
declaration.

**This is the strongest argument in the determination** and it is what stopped EVC collapsing into a
cross-reference to ACM, which would have been a weak outcome for the last indicator in the cluster.

---

## 2026-09-14 — Plan output rather than source as the evaluation target (MLA-EVC)

**Chosen.** Render the plan to JSON and evaluate that, not the source files.

**Why it is a technical point rather than a preference.** Source scanning misses anything resolved at
plan time: variables, data sources, module outputs, computed values. The tooling documentation is
explicit that plan evaluation supplies additional dependencies and context producing a more complete
result. Most implementations scan source because it is easier, and they miss exactly the
misconfigurations that come from a wrong variable rather than a wrong resource block.

**Made testable.** A validation step introduces a misconfiguration through a variable rather than a
resource block. A source scanner passes that test; a plan evaluator fails it. That single test case
is the proof the right target was chosen.

---

## 2026-09-14 — Two tools doing different jobs, with only one mapped (MLA-EVC)

**Chosen.** A rules-shipping scanner for breadth, and a policy engine evaluated against the plan for
rules that encode this project's determinations.

**Why both.** The scanner ships thousands of maintained checks at near-zero setup cost. The policy
engine ships with none, which is precisely why it is where project-specific governance goes. The
mature stack runs two, and they answer different questions.

**Coverage mapping scoped deliberately.** Only the authored rules are mapped to determinations.
Mapping thousands of scanner rules to a project they were not written for would be busywork producing
a false impression of traceability. The scanner baseline is unmapped breadth and the determination
says so.

**Tooling correction.** An earlier draft named tfsec as an option. It is deprecated, its checks folded
into Trivy, and new projects should not adopt it.

---

## 2026-09-14 — A supply chain principle arrives as a concrete instance (MLA-EVC)

**What surfaced.** A scanning action in this category was compromised in a March 2026 supply chain
incident, with the guidance being to pin to a known-good commit SHA rather than a mutable tag.

**Why it matters here.** CNA-DFP already required pipeline actions be pinned to commit SHAs, reasoning
that an action referenced by tag is functionality defined by whoever controls that tag. That was an
argument from first principles. This is the same principle arriving as a documented incident in
exactly the tool category this indicator introduces.

**Recorded because the sequence is the useful part.** The principle was adopted before the instance
was known, which is the better order and worth being able to show.

---

## 2026-09-14 — "Wherever reasonable" bounded to two declared categories (CMT-RMV)

**Question.** The statement permits direct modification "wherever reasonable." Who decides what is
reasonable?

**Chosen.** Two categories, declared, with per-instance entries carrying a reason. Resources that
cannot be redeployed without data loss, and emergency response actions. Anything else is a finding
rather than an exception.

**Why it needs bounding at all.** Unbounded, the phrase swallows the indicator. Anything can be
called unreasonable to redeploy when someone is under pressure, and an exception with no boundary is
indistinguishable from no requirement. Adding a third category is possible and is itself the decision
point, which is the property worth having.

**The database exception stated honestly.** It rests on disproportionality, not impossibility. The
instance can be replaced through snapshot and restore, and SIN already requires exactly that for
encryption remediation. Saying "cannot be redeployed" would have been false; saying "would be
disproportionate for routine changes" is true and weaker, which is the correct trade.

---

## 2026-09-14 — Version control read as a provenance requirement (CMT-RMV)

**Question.** Is redeployment sufficient, or does the redeployed thing have to come from somewhere
specific?

**Chosen.** Provenance is part of the claim. Every running artifact traces to a commit.

**Why.** A container rebuilt from an untracked file and pushed by hand satisfies "redeployment" and
fails the statement, which says version controlled resources. Without provenance the indicator
reduces to "we replace things," which is a deployment style rather than a control.

**Where it connects.** VRI established that the deployed artifact is cryptographically what it claims
to be. DFP established that pipeline actions are pinned so their behaviour is defined. RMV adds that
the artifact came from the declared source. Three indicators covering three different properties of
the same artifact, and none of them substitutes for the others.

---

## 2026-09-14 — Post-incident reconciliation required (CMT-RMV)

**Chosen.** Emergency direct modifications are reconciled back into declared state, and the
reconciliation is recorded.

**Why.** Without it the emergency exception is a permanent hole. A deny policy attached during an
incident and never reconciled becomes undeclared state that drift detection will keep reporting and
somebody will eventually suppress. The exception is for the duration of the incident, not for the
lifetime of the environment.

---

## 2026-09-14 — Drift detection reused, with a deliberate divergence (CMT-RMV)

**Chosen.** RMV uses the mutation query built for ACM rather than building a second one, cross
referenced against the exception register.

**The divergence, which is correct and is tested.** A permitted direct change still registers as
drift. ACM reports it because the environment no longer matches declared state, which is true. RMV
clears it because the change was permitted, which is also true. Each determination says what it means
and neither silences the other.

**Why test that explicitly.** The tempting simplification is to have the register suppress the drift
finding, which would make one determination quietly weaken another. The test confirms both behave
independently.

---

## 2026-09-14 — The controls that govern the offering are part of the offering (CMT-LMC)

**How it surfaced.** The defined term for cloud service offering points at the Minimum Assessment
Scope, which is everything likely to handle federal customer data or affect its confidentiality,
integrity or availability. Reading modifications against that scope rather than against
infrastructure brought three surfaces into view that nothing built so far covered: repository
content, pipeline definition, and policy and detection content.

**Why they count.** A change to the policy set alters what the merge gate enforces. A change to a
detection query alters what log review examines. A change to the role model alters what the
least-privilege checks compare against. Each modifies the offering's security posture and leaves no
trace in a cloud audit log.

**The generalisation.** This project reached the same position three times in narrower forms: the log
access model had to protect the logs the review depends on, the integrity indicator had to account
for the responder, and the suspicious-activity responder turned out to be a privileged account under
the definition. LMC is where it generalises. The controls are configuration, and changes to them are
modifications.

**Worth carrying into the write-up.** It is the kind of conclusion that only appears after enough
indicators to see the pattern, and it would be invisible working a single control in isolation.

---

## 2026-09-14 — Monitoring applied selectively, not uniformly (CMT-LMC)

**Question.** The statement says logged and monitored. Does everything get alerted?

**Chosen.** No. Changes to policy rules, the role model and detection content alert. Routine
infrastructure changes are logged and reviewed.

**Why.** A silent weakening of a control is exactly what an actor with repository access would do, so
control content earns real-time attention. Infrastructure changes arrive through the pipeline, which
is the expected source, and alerting on expected events trains people to ignore alerts. That is the
same reasoning JIT used to reject universal elevation: a signal that fires constantly stops being a
signal.

**Tested in both directions**, because alerting on everything is the same failure as alerting on
nothing.

---

## 2026-09-14 — MA-2 read as maintenance actions on the offering (CMT-LMC)

**The odd mapping.** Controlled maintenance, in a cloud-hosted offering with no hardware.

**Chosen.** Maintenance means actions performed on the offering itself: the scheduled restore tests
from OFA, the rotation workflows from ASM, the rebuild executions from SVC-EIS. Those modify the
offering and are logged as modifications rather than treated as background activity.

**Why it is not a stretch.** These are scheduled operational actions that change system state, which
is what the control family is about. Treating them as invisible because they are routine is how
routine maintenance becomes an unlogged change surface.

---

## 2026-09-14 — The EVC boundary revised: VTD is the sequence, EVC is its first stage (CMT-VTD)

**Earlier reading.** When EVC was determined, the overlap with VTD was named and split as: EVC tests
the configuration artifact against policy, VTD tests the change through the deployment lifecycle. That
was recorded as a reading rather than something the catalog stated.

**Why it was wrong.** "Throughout deployment" plainly includes the pre-apply gate as one stage among
several. The earlier split put EVC outside VTD, when it sits inside it.

**Revised.** VTD is the whole sequence and EVC is its first stage. VTD's own contribution is the
post-apply half — apply validation, health, outcome verification, rollback — plus the chaining that
makes the stages a sequence rather than a set.

**Why this is better than the original split.** Two adjacent indicators dividing a pipeline between
them produces an arbitrary line that has to be defended. One indicator covering the sequence, with
another covering a stage of it in depth, is a relationship the catalog's own wording supports.

---

## 2026-09-14 — A deployment completing is not a deployment validated (CMT-VTD)

**Chosen.** Post-apply health and outcome verification are required. A successful apply is not
evidence.

**Why.** Validation is a defined term meaning confirmation through objective evidence that
capabilities support expected outcomes. An apply that returns success has demonstrated that the API
accepted the change, which is not the same as the change achieving anything. This is the third time
that definition has forced a stronger requirement, after VRI's blocking checks and VCM's failure
routing.

---

## 2026-09-14 — Generate-apply-reverify becomes structural (CMT-VTD)

**What changed.** The remediation loop was committed to early: generate, apply, re-verify, rather
than read-only reporting. Every determination since has restated it in its remediation band.

**Chosen here.** After any change, the determinations covering affected resources re-run and their
records supersede. It becomes a property of deployment rather than something each indicator repeats.

**Why that matters beyond tidiness.** Stated per indicator, it is a promise each collector makes.
Stated as a deployment stage, it happens whether or not a given collector remembered to say so, which
is the difference between a convention and a mechanism.

**Honest limit.** Determinations resting on behavioural evidence may need an observation window longer
than a deployment, so their re-verification is delayed rather than immediate.

---

## 2026-09-14 — Native rollback claimed rather than built, and tested (CMT-VTD)

**Chosen.** The deployment circuit breaker performs rollback. Nothing is built for it.

**Why claim rather than build.** Same reasoning as CNA-EIS claiming native health enforcement: it is a
platform guarantee, it acts faster than our code would, and inherited evidence that works is stronger
than built evidence that might.

**Why it still needs a test.** A circuit breaker configured and a circuit breaker firing are different
claims. Deploying a deliberately unhealthy task and watching it revert is cheap, and it is the only
evidence the configuration is correct. Run separately from the stage tests, because a deployment can
fail at apply and never reach the stage rollback protects.

**Asymmetry stated.** Rollback exists for service deployments and not for infrastructure applies,
where a failure leaves partial state and recovery is re-apply rather than revert. The two halves of
the pipeline genuinely differ and the determination says so rather than implying uniform coverage.

---

## 2026-09-14 — "Documented procedure" read as the encoded pipeline (CMT-RVP)

**The question.** Does a documented change management procedure mean prose a human follows, or does
an enforced pipeline count? This decided whether the indicator deferred or landed partial.

**The case for prose.** CM-9 is a configuration management plan and CM-3(4) is security
representative involvement in a change control board. Both describe organizational process, which is
non-machine and out of scope project-wide.

**The case that wins.** In this architecture the procedure is the pipeline. There is no separate
prose describing what people should do, because RMV restricted apply and registry push to the
pipeline principal, so the procedure is not a description of intent — it is the only available path.
A pipeline definition in version control is also documented in a more literal sense than a document:
written down, versioned, and executed exactly as written rather than as remembered.

**Split by subject.** The encoded procedure is machine-based and measurable. The organizational
wrapper is not, and is declared out, which is why this is partial rather than satisfied.

---

## 2026-09-14 — Effectiveness distinguished from conformance (CMT-RVP)

**The distinction.** Every other indicator in this cluster asks whether the procedure was followed.
RVP asks whether following it works. A procedure can score perfectly on the first and fail the
second.

**Six signals, all derived from records the pipeline already produces.** Changes that passed all
gates and still required rollback. Findings arising from changes that passed review. Manual overrides
and their reasons. Emergency direct modifications under RMV's exception. Time from finding to
remediated change. Distribution of stage failures.

**The last one is the most useful and the most easily skipped.** A gate that has never failed
anything is either protecting against something that never happens or is misconfigured to pass
everything. Both are effectiveness findings and neither appears in any conformance check. Tracking
what each gate actually catches turns the pipeline from a set of checks into something with
measurable value per check.

---

## 2026-09-14 — Remediation here may correctly mean deleting a control (CMT-RVP)

**Chosen.** A gate that has never failed anything is either given a recorded justification or
removed. An ineffective gate is changed, removed, or its position recorded, and is never left running
as ceremony.

**Why it is worth stating plainly.** Every other remediation in this project adds or corrects a
control. This is the only one where the right answer is sometimes to take one away. That follows
directly from measuring effectiveness rather than conformance: a control that catches nothing is cost
without benefit, and keeping it because removing controls feels wrong is how pipelines accumulate
ceremony.

---

## 2026-09-14 — First non-machine cadence in the project (CMT-RVP)

**Chosen.** The effectiveness review runs every 3 months, not every 3 days.

**Why.** Thirty determinations have run at the 3-day machine cadence because their subjects are
machine-based resources. Here the subject is a process's effectiveness, which does not meaningfully
change every three days, and a review that frequent would produce noise rather than signal. The
non-machine cadence exists in the rules for exactly this case.

**Worth noting as the exception rather than a slip.** Signal collection remains continuous and
automated; only the judgment about what the signals mean runs quarterly.

---

## 2026-09-14 — The determination most degraded by low volume (CMT-RVP)

**Stated rather than glossed.** Gate efficacy over a handful of deployments tells you nothing. Most
signals in this determination will be statistically meaningless in a synthetic environment that
changes deliberately and rarely.

**Why it still earns its place.** The mechanism is correct and the reasoning is transferable; what is
missing is volume, which is an environmental limitation rather than a design one. But this is the
clearest case in the project where the determination would be genuinely informative in production and
is close to decorative here, and saying so is better than presenting thin signals as evidence.

**Also worth recording.** The procedure being reviewed is the one this project built, so the review is
self-assessment of self-authored machinery with no independent party judging whether the procedure is
appropriate in the first place.

---

## 2026-09-14 — "Vulnerability" read against its statutory definition (SCR-MON)

**What the definition says.** It takes its meaning from statute and covers any attribute of hardware,
software, process or procedure that could facilitate defeating a control, explicitly including
misconfigurations, exposures, weak credentials, insecure services, and gaps in the indicators
themselves.

**What that changes.** Monitoring for upstream vulnerabilities is not only watching for published
advisories in dependencies. A provider changing a service default, deprecating a capability, or
altering behaviour in a way that weakens a control we rely on is an upstream vulnerability under this
definition.

**Why it matters more than it sounds.** A changed provider default produces no advisory, appears in
no scanner, and can silently invalidate a determination that was correct when it was written. Nothing
in this project would have caught it before this indicator.

---

## 2026-09-14 — Provider change monitoring built as a distinct mechanism (SCR-MON)

**Chosen.** Service change and deprecation notifications ingested separately from advisory feeds.

**Why separate.** The remediation differs. A dependency advisory is fixed by rebuilding and
redeploying. A provider changing a default is fixed by reviewing the determination that relied on the
old default, which is a design change rather than a version bump. Folding the two together would
route a design problem into a patch pipeline.

---

## 2026-09-14 — Correlation required, since subscription is not monitoring (SCR-MON)

**Chosen.** Ingested advisories are matched against the dependency inventory, and matches route to the
detection path.

**Why.** A feed that arrives and is filed proves an integration works, not that anything is monitored.
The requirement is that upstream vulnerabilities in resources this offering actually uses are
surfaced, which means correlation rather than ingestion. The test reflects it: feed a historical
advisory for a package genuinely in the manifest and confirm it surfaces.

---

## 2026-09-14 — Contractual notification declared unavailable, not skipped (SCR-MON)

**The statement names its own mechanisms:** contractual notification requirements, or active
monitoring services. The persona has no vendor agreements, so the first is unavailable rather than
unchosen.

**What substitutes and why it is weaker.** Public security bulletins and advisory feeds. Pull rather
than push, no completeness guarantee, no timeliness obligation. A vulnerability a provider chooses not
to publish is invisible, where a contract would have obliged disclosure.

**Why the distinction is worth the words.** Unavailable and skipped read very differently to an
assessor. A real provider at this class would have vendor agreements, and stating that the substitute
is structurally weaker is more useful than implying the two mechanisms are interchangeable. The same
reasoning makes IR-6(3) supply chain incident coordination unavailable.

---

## 2026-09-14 — Boundary with SVC-EIS drawn by direction (SCR-MON)

**Chosen.** SVC-EIS looks inward at our posture and finds vulnerabilities in what we run. SCR-MON
looks outward at our suppliers and watches for vulnerabilities in what we depend on.

**Why direction rather than mechanism.** The scanner is the same for dependencies and images, and
duplicating it would be waste. What differs is the question being asked, which is why the same tool
serves two determinations without either becoming a cross-reference to the other.

---

## 2026-09-14 — End-of-support checking is the substantive new work (SCR-MIT)

**What SA-22 adds that nothing else covered.** A component can be fully patched and still unsupported.
A base image past its support window, a runtime no longer receiving security fixes, an abandoned
provider. That is a supply chain risk with no advisory attached, invisible to every scanner in the
project, and checkable by comparing component versions against published support windows.

**Why the finding is kept distinct from a vulnerability finding.** The remediation differs. A
vulnerable component is updated; an unsupported component is replaced, because there is no version to
update to. Combining them would route a replacement decision into a patch pipeline.

**Honest bound.** Support windows are declared by maintainers and are inconsistent across ecosystems,
so a component whose maintainer publishes no support policy is unassessable and is recorded as such
rather than assumed supported.

---

## 2026-09-14 — Criticality built, supplier assessment declared (SCR-MIT)

**The mapping that sits in the middle.** SA-15(3) criticality analysis is supplier-facing in the
control's sense, but the underlying question — which dependencies would hurt most if compromised or
abandoned — is answerable from our own architecture.

**Chosen.** Build the criticality rating, declare the supplier-facing half.

**Why it falls on the buildable side.** Rating a dependency by what it would affect is a judgment
about our system, not an invented fact about a supplier. That is the same line drawn for the declared
role model, the log sensitivity classification, and residue classification: judgments about things
that exist are design input, inventions about things that do not are fabrication.

---

## 2026-09-14 — Mitigation options bounded honestly (SCR-MIT)

**What a real provider can do.** Change supplier, negotiate terms, require remediation contractually,
impose development requirements.

**What is available here.** Pin, vendor, replace, remove, or accept with a recorded reason and review
date.

**Why state the difference rather than list only what we have.** The narrower set is a consequence of
having no vendor relationships, and an assessor comparing this determination against a real
provider's would notice the absence. Naming it is more useful than presenting a short list as
complete.

**One rule that matters.** A risk with no available mitigation is accepted explicitly rather than left
open, because an unresolved entry in a register is indistinguishable from an ignored one.

---

## 2026-09-14 — First determination carrying two cadences (SCR-MIT)

**Chosen.** Component state — end of support, staleness, criticality coverage — runs at the 3-day
machine cadence. The risk review runs quarterly at the non-machine cadence.

**Why within one indicator.** The statement's three verbs have different subjects. Identifying an
unsupported component is reading component state, which is machine-based and cheap to check often.
Reviewing whether a supplier risk is acceptable is a judgment, which does not change every three days
and would produce noise at that frequency.

**Precedent.** CMT-RVP established the non-machine cadence for a process subject. This is the first
determination where both apply to different halves of the same indicator, and recording it as a split
rather than picking one is more accurate than either alone.

---

## 2026-09-14 — One determination making another trivially satisfiable (SCR-MIT)

**Observed.** The no-runtime-fetch check is nearly free, because RNT established that private subnets
carry no internet route at all. An attempted runtime fetch fails at the network layer before it
becomes a supply chain question.

**Worth recording as a pattern rather than a convenience.** Earlier architecture decisions have been
paying off in later determinations repeatedly: immutable compute made RMV strong, the query layer
made RVL feasible, absent egress makes this check nearly automatic. The decisions were made for their
own reasons, and the compounding is a property of a coherent architecture rather than luck.

---

## 2026-09-14 — Objectives declared per resource class, not as a single pair (RPL-RRO)

**Question.** RTO and RPO are usually stated as two numbers for a system. Does that work here?

**Chosen.** No. Per resource class, with a stated basis for each.

**Why.** A single pair would be wrong for most of the architecture. Stateless compute recovers in
minutes by automatic replacement and has no recovery point at all, because there is no state to lose.
The database recovers in tens of minutes by restore. Object storage is multi-zone by construction.
Taking the worst case across all of them and calling it the system objective would produce a number
that describes nothing.

**The analytics warehouse is different in kind and is worth noting separately.** It holds derived
data, so recovery means re-running the pipeline rather than restoring a backup. Treating it as a
store to be backed up would be building recovery machinery for something reconstructible, which is
cost with no benefit.

---

## 2026-09-14 — Objectives bounded by capabilities fixed elsewhere (RPL-RRO)

**Chosen.** Declared objectives must be within what the mechanism can deliver, and an objective
exceeding capability is a failure criterion.

**Why it needs to be a check rather than an intention.** The most common failure in recovery planning
is numbers chosen because they sound acceptable. An RPO shorter than the backup interval is a promise
nobody can keep, and it is trivially checkable by comparing the two.

**What fixes the capabilities.** CNA-OFA's single-AZ decision, made for cost, means the database
objective is a restore time rather than a failover time. SIN's encryption remediation already
requires snapshot-restore, which establishes the mechanism. Declaring tighter numbers would be the
same failure as declaring a blast radius wider than reality, and this project has now refused that
move three times.

---

## 2026-09-14 — Review triggered by architecture change, not only scheduled (RPL-RRO)

**Chosen.** Quarterly review, plus a trigger on changes to backup configuration, availability posture
or recovery mechanism.

**Why.** A capability change invalidates an objective silently. Reducing backup retention makes a
declared RPO false the moment it applies, and a quarterly cycle would leave it false for up to three
months with nothing indicating a problem. The change surfaces established under CMT-LMC already
produce the events needed to trigger it.

---

## 2026-09-14 — The business-needs half is asserted, and that is the limit (RPL-RRO)

**Stated plainly.** The referent is the provider's business needs and capabilities. The capability
half is real, measurable and checked. The needs half is invented: there is no customer, no
contractual availability commitment, and no revenue impact to weigh.

**Why this determination is partial for a different reason than most.** Elsewhere partials come from
scope exclusions or platform limits. Here the mechanism is fully built and the gap is that half the
standard it measures against cannot be derived from anything real.

**Worth carrying to the write-up.** It is the clearest case in the project where a synthetic
environment limits not what can be built but what the built thing can be measured against.

---

## 2026-09-14 — Alignment is a comparison, not a presence check (RPL-ABO)

**Chosen.** Every backup interval and retention is compared against the objective register declared
under RRO. A resource backed up daily fails if its declared recovery point objective is one hour.

**Why it is worth stating.** The obvious implementation checks that backups exist, which is what most
backup monitoring does. The statement says alignment, and alignment is meaningless without something
to align to. This is the payoff for working RRO first: with the objectives declared, the check is
mechanical, and without them it would have been a presence check wearing the word alignment.

---

## 2026-09-14 — CM-2(3) brings configuration baselines into scope (RPL-ABO)

**What the mapping adds.** Retention of previous baseline configurations, which is not a data backup.
It is the ability to recover a prior configuration: state version history, prior task definitions,
prior image revisions.

**Why it would otherwise have been missed.** The word "backups" reads as data, and the determination
would have covered the database and object storage and stopped. ACM already established state as a
security-relevant asset with versioning; ABO adds that the versioning must be deep enough to recover
a prior baseline, which is a retention question ACM never asked.

**Made testable.** Restoring a prior state version and a prior task definition, because retaining
versions and being able to recover from one are different claims.

---

## 2026-09-14 — CP-6 read as a failure-domain property, with the region gap declared (RPL-ABO)

**The reading, set here because ARP is full of these controls.** In a cloud context, an alternate
storage site means backups do not share a failure domain with what they back up. Snapshots and
versioned objects satisfy that at zone granularity, since the provider stores them separately from
the instance.

**The gap, stated rather than argued around.** There is no cross-region backup. A region-level failure
takes the backups with it. That follows the same cost reasoning as the single-AZ decision under
CNA-OFA, and a provider serious about this would replicate cross-region.

**Why declare rather than reframe.** The tempting move is to argue that provider-managed snapshot
storage satisfies CP-6 fully and leave it there. It satisfies the property at one granularity and
fails at another, and an assessor would ask about the region. Saying it first is stronger than being
asked.

---

## 2026-09-14 — Deliberately unbacked resources recorded as decided (RPL-ABO)

**Chosen.** The analytics warehouse and the landing bucket have no backups, and the coverage check
recognises that as a recorded decision rather than a gap.

**Why the recognition matters mechanically.** Without it, two resources generate a finding every
cycle forever, and a check that always reports the same two known items is one people stop reading.
This is the same reasoning that made PRR's retention register include an exception path: a collector
that cannot accept a legitimate exception gets ignored.

---

## 2026-09-14 — Retention mechanisms differ across the project, and the determinations say so (RPL-ABO)

**Observed.** Log retention is enforced by object lock, which cannot be shortened. Backup retention is
enforced by lifecycle policy, which can. Both are retention, and they have materially different
properties.

**Chosen.** State which mechanism applies where rather than implying uniform retention handling.

**Why.** A reader comparing OSM's retention claim with ABO's would otherwise assume they carry the
same guarantee. One is immutable and the other is a policy anyone with sufficient privilege can
change, and that difference is exactly the kind of thing a determination should surface rather than
smooth.

---

## 2026-09-14 — "Incidents and contingencies" read as two categories (RPL-TRC)

**Chosen.** Recovery from compromise is tested separately from recovery from failure.

**Why.** Incident is a defined term taken from statute and covers occurrences jeopardising integrity
and confidentiality, not only availability. A determination testing only restore-after-crash would
answer half the statement while appearing complete.

**Why the operations genuinely differ.** Restoring after an instance failure returns to the last good
state, which is what a snapshot gives you. Recovering after a compromise means restoring to a moment
before a known event, which a snapshot cannot express and point-in-time recovery can. The mechanism
that makes the second possible was already provisioned for other reasons, so the test costs little
and the claim is materially stronger.

---

## 2026-09-14 — The incident response boundary drawn by tense (RPL-TRC)

**Chosen.** TRC tests the capability. The incident response cluster reviews what happened.

**Why it resolves cleanly.** All three indicators in that cluster are retrospective: after-action
reports, review of past incidents for patterns, review of procedure effectiveness. None of them
exercises anything. That is why IR-3, incident response testing, maps here rather than there: testing
is TRC's verb.

**Worth noting as a pattern.** Two cluster boundaries in this project have been settled by grammar
rather than subject — this one by tense, and MLA-EVC against CMT-VTD by the word "throughout." The
catalog's wording carries more structure than it first appears to.

---

## 2026-09-14 — Backup integrity verification is distinct from restore success (RPL-TRC)

**Chosen.** A separate consistency check on restored data, tested by deliberately corrupting a
restored dataset and confirming it fails.

**Why.** A backup can restore cleanly and contain corrupt data. The restore test proves the
mechanism; only the consistency check proves the backup. Most restore testing stops at the first.

**Why the remediation escalates rather than corrects.** A restore that succeeds with corrupt data is
worse than one that fails, because the failure is visible and the corruption is not. So a failed
integrity verification is a backup failure rather than a test defect and routes accordingly.

---

## 2026-09-14 — The reconstruction test validates a claim, not a mechanism (RPL-TRC)

**What it tests.** RRO declared the analytics warehouse reconstructible rather than backed up, on the
grounds that it holds derived data. That is a claim, and until the pipeline has actually rebuilt it
from source it is an assumption.

**Why it matters more than an ordinary test.** It converts a scoping decision into a demonstrated
capability. Without it, "we do not back this up because it is reconstructible" is an argument for
doing less work, and with it, it is a recovery strategy.

---

## 2026-09-14 — Successful test runs must produce records (RPL-TRC)

**Chosen.** Every test run writes a record, including successful ones.

**Why.** A framework that records only failures cannot demonstrate that testing occurred. A clean
period and a period where nothing ran look identical. This is the third appearance of the same
principle, after review runs recording nil results under MLA-RVL and zero-results queries requiring
self-tests under IAM-ELP, and it is worth stating as a general rule: absence of a finding is only
evidence if the looking was recorded.

---

## 2026-09-14 — "Recovery plan" read as the encoded recovery path (RPL-ARP)

**Chosen.** The automation is the plan. No separate document.

**Why it follows precedent.** CMT-RVP established that an encoded pipeline is a documented procedure,
because it is written down, versioned, and executed exactly as written rather than as remembered. The
same applies here, and with an additional advantage: this plan is executed monthly under TRC, where a
document would be a description of intent that may never have been tried.

---

## 2026-09-14 — Sixteen mappings taken in groups, with a position each (RPL-ARP)

**The problem.** Second-largest mapping set in the catalog, dominated by alternate storage site,
alternate processing site and telecommunications controls, which are data-centre-era in shape.

**Chosen.** A position per mapping — satisfied, inherited, unavailable or inapplicable — with a
reason, rather than constructing coverage collectively.

**The positions.** Contingency planning controls are satisfied by the encoded path. Alternate storage
follows the failure-domain reading from ABO, satisfied at zone and failing at region. Alternate
processing is satisfied continuously rather than as a failover site, since multi-zone compute with
automatic replacement is alternate processing that is always running. Priority of service provisions
are contractual and unavailable. Telecommunications controls are inapplicable in form, since the
offering procures no telecommunications service.

**Why a register rather than prose.** With this many mappings, prose lets an unaddressed control hide
in a paragraph. A register with a completeness check makes a missing position a finding.

---

## 2026-09-14 — Stated as the thinnest determination in the project (RPL-ARP)

**The honest arithmetic.** Of sixteen mappings, roughly four are directly satisfied, six inherited,
four unavailable, two inapplicable. The provider-controlled substance is the encoded recovery path
and its alignment with objectives.

**Why say it.** A determination citing sixteen mappings looks substantial, and this one is not. An
assessor working through the mappings would reach the same arithmetic, and reaching it first is
stronger than being led to it. The alternative — writing a paragraph per mapping to make the
determination look proportionate to its citation count — would be padding dressed as rigour.

**What keeps it from being empty.** The plan-to-objective mapping is real and checkable in both
directions. An objective with no path is a gap; a path with no objective is unexplained work. That
bidirectional check is small but it is genuine.

---

## 2026-09-14 — The disclosure program is required, not optional (PIY-RVD)

**What the rules say.** The vulnerability detection rule requires providers to discover
vulnerabilities using appropriate techniques "such as assessment, scanning, threat intelligence,
vulnerability disclosure mechanisms, bug bounties, penetration testing." Disclosure mechanisms are
named inside a MUST, and the reporting rules expect high-level overviews of disclosure and bug bounty
activity.

**Why it matters for the determination.** The statement only asks that effectiveness be reviewed,
which presupposes a program exists. Without checking the rulesets, it would have been reasonable to
read this as reviewing something the provider may or may not have. The rules make the program part of
how detection is satisfied.

---

## 2026-09-14 — The program must terminate in the response pipeline, not an inbox (PIY-RVD)

**Chosen.** A received report enters the same vulnerability response pipeline as a scanner finding,
with the same severity model and remediation timeframes.

**Why.** A disclosure program whose reports are handled separately is a facade with a published
address. The value of an external report is that it reaches the same machinery, gets the same
treatment, and is subject to the same clocks as anything the tooling found itself. Anything less
means the program exists for appearances.

**Made a failure criterion**, so a report received and then lost is a triage defect that escalates
rather than a gap someone notices later.

---

## 2026-09-14 — Contact liveness and expiry tested automatically (PIY-RVD)

**Chosen.** An automated test that a submission to the published contact arrives, and a check that the
published file's expiry is in the future.

**Why these two specifically.** They are the failures that silently kill these programs. A bouncing
contact or an expired file means the program does not exist regardless of how good the policy text
is, and neither is visible from reading the policy. Both are trivially checkable and almost nobody
checks them.

**Expiry treated as a failure condition** because the format carries an expiry field deliberately: an
expired file signals a stale program, and leaving it expired is worse than not publishing one.

---

## 2026-09-14 — Effectiveness undemonstrable at zero report volume (PIY-RVD)

**Stated.** Existence and function are demonstrated. Effectiveness is not, because the signals that
would show whether the program adds coverage — duplicate rate against known findings, unique findings
no other mechanism caught — are computed over an empty set.

**Same shape as CNA-RVP.** There, protection could be exercised but not proven operationally
effective. Here the program can be exercised end to end with a test report and cannot be shown to
surface anything real. Both are cases where the mechanism is complete and the environment cannot
supply the input that would prove it works.

**No bug bounty**, which the rules name alongside disclosure programs. A paid programme is out of
scope for a persona with no budget, and that connects directly to the reasoning that will defer the
investment indicator in this same cluster.

---

## 2026-09-14 — Principles, not the pledge (PIY-RSD)

**Verified against the publishing agency's own page.** Secure By Design is three principles: take
ownership of customer security outcomes, embrace radical transparency and accountability, and lead
from the top. The Pledge is a separate voluntary commitment of seven goals, and the agency neither
enforces nor verifies it.

**Why the distinction matters.** The catalog says principles. Aligning with principles is a posture
claim that can be evidenced. Signing the pledge is an announcement, and a determination resting on a
signature would be claiming credit for a statement rather than a practice.

---

## 2026-09-14 — The subject shift makes unreachable mappings partly tractable (PIY-RSD)

**What changed.** Input validation, error handling and memory protection were declared under CNA-MAT
as the application layer an infrastructure collector cannot inspect. The same controls map here.

**Why the answer differs.** MAT asked whether the running system has those properties. RSD asks
whether the development process builds them in, and a process leaves artifacts where a running system
does not expose its internals. The pipeline is the evidence: policy evaluation, signature
verification, scanning, stage chaining, signed commits.

**What still does not reach.** Static analysis proves checking happens. It does not prove input
validation is correct. The code-level mappings remain out of reach and the determination says so
rather than treating the presence of a scanner as satisfaction.

---

## 2026-09-14 — Design reasoning made a required artifact (PIY-RSD)

**Chosen.** Posture-changing changes are blocked at merge without recorded reasoning.

**Why it is the interesting build here.** The design-time mappings — security engineering principles,
security architecture — leave artifacts only if someone produces them. Making the rationale a merge
requirement converts the decision log from a habit into a checked artifact, which is what allows it to
be claimed as design-time evidence.

**And why reconstruction is refused.** Reasoning written after the fact is not design-time reasoning.
Blocking is the only version of this check that means anything.

---

## 2026-09-14 — Claiming our own decision log as evidence is self-serving, and is flagged (PIY-RSD)

**The claim.** The decision log is the closest thing this project has to contemporaneous design-time
security reasoning, and it is offered as evidence for the security architecture mappings.

**Why flag it rather than assert it.** It is genuinely contemporaneous and genuinely records security
reasoning, which is more than most projects have. It is also an artifact this project happens to
produce, and a determination that cites its own byproduct as evidence of rigour should say so.

**What a reviewer should weigh.** No threat model exists as a distinct structured artifact. Reasoning
is recorded per decision rather than as an analysis, which is a different and weaker thing than what
the mapped controls contemplate.

---

## 2026-09-14 — Two of three principles evidenced (PIY-RSD)

**Stated.** Lead from the top is not evidenced. Executive accountability is organizational and belongs
to the executive support indicator in this cluster, which is expected to defer.

**Why the register matters.** Each principle carries a position with evidence or a recorded reason.
Without that, "aligns with Secure By Design" would be a claim covering three things while
demonstrating two, and the gap would be invisible.

---

## 2026-09-14 — RIS deferred against a live counter-argument (PIY-RIS)

**Expected.** A clean deferral on budget grounds, since PM-3 information security resources and SA-2
allocation of resources are funding activities and this persona has no budget.

**What complicated it.** Four of the nine mappings describe activities this project actually performs:
control assessments, contingency plan and testing coordination, coordinated incident response
testing, and supply chain plan updates. It assesses controls continuously, tests recovery monthly and
updates supply chain positions quarterly. That supports a reading where investment means effort and
attention rather than money, with effectiveness measurable from automation coverage, gate efficacy
and remediation time.

**Why that reading was rejected.** The statement says the provider's investments, and the two mappings
that define investment in this control family are both explicitly about resources and funding.
Reading it as effort would substitute a meaning the mappings do not support in order to have
something to build — the same move this project has refused elsewhere when a determination could have
been made to look fuller by widening a term.

**And a second reason.** The measurable signals under the effort reading are already measured under
CMT-RVP and SVC-EIS. A third view of them under a different name would manufacture coverage rather
than add it.

**Recorded because the argument was close.** A different reader could reasonably reach the opposite
conclusion, so the counter-argument is preserved in the determination rather than only the outcome.

---

## 2026-09-14 — RES deferred, the cleanest deferral in the project (PIY-RES)

**No mappings at all, and no machine-based subject.** Executive sponsorship is a relationship between
people who do not exist, and it leaves no artifact this project could check.

**Why the absence of mappings is not decisive on its own.** GIV also had none and was buildable,
because its subject was inventories. What decides it here is the subject, not the citation count.

**And why there is no sliver.** PRR was split by subject and kept its machine-based half, because
resource state is machine-based even when plans and procedures are not. Nothing about executive
support has an equivalent half.

**The consequence that reaches beyond this indicator.** RSD claimed alignment with two of the three
Secure By Design principles and recorded lead from the top as belonging here. This deferral means
that principle is unevidenced across the project rather than merely unaddressed in one determination,
and both determinations carry the statement.

---

## 2026-09-14 — The assumption every technical control rests on

**Stated once, across both deferrals.** A provider without reviewed security investment and without
demonstrated executive support has no mechanism ensuring security work is funded, prioritised or
sustained when it competes with delivery.

**Why it is worth writing down rather than leaving as boilerplate.** Every technical control in this
project assumes someone keeps paying for it and keeps caring about it. Forty indicators of automation
rest on that assumption, and it is entirely invisible in a synthetic environment because there is no
budget cycle, no competing roadmap and no quarter where security loses. In a real organization it is
the first thing to fail, and these two indicators are the ones that would have caught it.

**That makes these deferrals different in kind from the others.** RUD deferred because a trigger did
not exist. These defer because the organization does not exist, and what they would have measured is
the thing most likely to undo everything that was built.

---

## 2026-09-14 — The encoded responder is the incident response procedure (INR-RIR)

**Chosen.** The responder built under IAM-SUS is the documented procedure for the cases it covers,
following the reasoning established in CMT-RVP: it is versioned, executes exactly as written, and is
the only path those responses take.

**Scope narrowed honestly.** What is encoded is detection-to-containment for one incident class, plus
escalation. A complete incident response procedure covers declaration, roles, communication,
containment, eradication, recovery and closure across all incident types. That gap is the largest in
the determination and it is stated in the rationale rather than left to the limitations.

**Why not claim more.** The temptation is to describe the responder as the incident response
procedure without qualification, since it genuinely is one for its class. Naming the class is what
keeps the claim true.

---

## 2026-09-14 — Incident reporting is unavailable, not unbuilt (INR-RIR)

**The mappings that require a recipient.** Incident reporting and automated reporting need someone to
report to. A real Class C provider reports to FedRAMP and to affected agencies within defined
timeframes.

**This persona has neither**, so the reporting half of incident response is unavailable in exactly the
sense SCR-MON used for contractual notification: the mechanism exists in the framework and the
counterparty does not exist here.

**Same for incident response assistance**, which has no subject because there are no users to assist.

---

## 2026-09-14 — Escalation disposition made a failure criterion (INR-RIR)

**Chosen.** Every escalation to the human path carries a recorded outcome, and an escalation without
one fails the indicator.

**Why this specific criterion.** The human path is where this procedure ends and where it is weakest.
Escalations are recorded and then nothing happens, because there is nobody to act. Making the
disposition a requirement means the gap is visible in the data rather than described only in a
limitations paragraph: an undispositioned escalation is an incident response that stopped, and the
check says so every cycle.

**And it is honest about the environment.** In a real organization this criterion would catch a
backlog. Here it will catch that the backlog is everything, which is the accurate picture.

---

## 2026-09-14 — AAR deferred: after-action reports about incidents that never happened (INR-AAR)

**Chosen.** Deferred by absent subject.

**The sliver considered and rejected.** The responder built under IAM-SUS produces structured records
for every exercised response, and those records are real. But they record sample findings this project
generated to test its own machinery. An after-action report about a test you ran yourself is a test
record, and naming it an after-action report would manufacture coverage in exactly the way this
project has refused elsewhere.

**The lessons-learned half is also organizational.** Incorporating a lesson means changing how people
work. Where it means changing how the machinery works, the mechanism already exists as effectiveness
review under CMT-RVP and INR-RIR.

---

## 2026-09-14 — RPI deferred: no corpus for patterns to appear in (INR-RPI)

**Chosen.** Deferred. The indicator needs past incidents and enough of them for patterns to exist.

**Why one incident would not have been enough either.** Pattern analysis over a single record is
arithmetic rather than review. The indicator's value is specifically what becomes apparent across a
corpus that no individual incident would show, so the threshold is not "an incident occurred" but "a
history accumulated."

**What does exist.** The retention and structure that would make this analysis possible: response
records are normalized and queryable alongside everything else. What is missing is history, which no
amount of building supplies.

---

## 2026-09-14 — CED-RAT deferred: the most complete deferral in the project (CED-RAT)

**Chosen.** Deferred. Nothing about the indicator is addressed.

**Why the split-by-subject rule rescues nothing.** PRR kept its machine-based half because resource
state is machine-based even when plans and procedures are not. CMT-RVP and INR-RIR treated encoded
pipelines as documented procedures because those pipelines execute. Training executes in people, and
there is nothing encoded to point at.

**Why the five declared roles do not help.** They exist as an entitlement baseline so access can be
bounded, not so people can be counted. Treating them as a workforce to train would convert design
input into invented headcount, which is the line this project drew when it excluded personnel
registers.

**The honest weight of this one.** It is the indicator whose absence a real assessor would weigh most
heavily against a small provider, because a two-person team's security posture depends more on what
those two people know than on any control they configure. Fabricating completion records would have
produced the weakest possible coverage — a spreadsheet asserting that people who do not exist attended
training that did not happen — and it is worth stating that the easy version of this determination was
available and declined.

---

## 2026-09-14 — Periodic human review cycles cut; signal generation kept

**The inconsistency that prompted this.** At KSI-PIY-GIV the project decided that non-machine
information resources are out of scope, because fabricating organizational material for a fictional
team demonstrates nothing. That decision excluded personnel registers and later excluded training
entirely. But eight indicators went on to declare a quarterly human review cycle, which is
organizational activity wearing a different name. Both positions cannot be right.

**Two forms of human oversight, and only one is affected.**

A human decision taken at a decision point and recorded as structured data stays in scope. The
import-or-destroy choice under SVC-ACM, retention entries under SVC-PRR, benchmark exceptions under
CNA-IBP, accepted risks under SCR-MIT, not-applicable reasons under MLA-LET, dispositions under
MLA-RVL and INR-RIR. Thirteen indicators rely on these, and they are machine-verifiable: the check is
that a record exists carrying the required fields, not that the judgment was sound. This is also
where a great deal of the project's honesty lives, since a recorded reason is what stops silent
suppression.

A periodic human review cycle does not. Someone sitting down quarterly to read signals and form a
judgment is organizational, it is not machine-verifiable in any meaningful way, and in an environment
with one contributor and statistically meaningless signal volume the record can be satisfied by
generating an empty file.

**Chosen.** Keep the signal generation, which is machine-based and is some of the more interesting
work in those indicators — gate efficacy, reversal rates, escalation backlog, support-window
findings, capability-bound checks. Declare the human judgment step out of scope, on the same basis as
plans and procedures under SVC-PRR, the human half of AU-6 under MLA-RVL, and lead-from-the-top under
PIY-RSD.

**What changed mechanically.** Eight per-indicator scheduled review jobs became one shared signal
report generator emitting a section per indicator. Eight evidence rows checking that a review "has
run" became rows checking that a signal section was generated with signals computed, which is
verifiable rather than ceremonial.

**What did not change.** All eight indicators were already partially satisfied for other reasons, so
no determination status moved and no catalog coverage was lost.

**Why this is a simplification and not a reduction.** The project builds less and claims the same,
and it stops contradicting a decision it made forty indicators earlier. The largest single piece of
fluff in the build surface was eight jobs producing records that a person was notionally going to
read.

---

## 2026-09-14 — Shared components made explicit rather than restated per indicator

**What the count showed.** 376 evidence rows and 224 build items across 40 indicators. But 65
standing zero-results queries sit across 34 indicators, the scanner is cited by 9, the detection path
by 9, and the evidence rows resolve to nine mechanism classes rather than 376 distinct mechanisms.

**The problem with the artifact as written.** Every indicator names what it relies on, which is
correct for a determination — an indicator that did not name its evidence source would be
incomplete. But read as a build plan it counts the same component once per consumer, and the
resulting surface looks three or four times larger than the work actually is.

**Chosen.** A shared components section in the index naming what is built once and how many
indicators consume it, with a stated convention that a build row naming a shared component is a
consumer rather than an additional build.

**Why this rather than rewriting 34 indicators.** The determinations are correct as they stand.
Stripping the references would make each indicator less self-contained and harder to defend on its
own, which is the property the whole artifact is built around. The duplication is a reading problem,
not a content problem, and it is fixed by saying so once.

**The honest effect on effort.** The build surface is mechanism-first: twelve shared components, then
376 check definitions as configuration on top. Roughly 400 hours rather than the 500 to 750 that a
naive per-indicator reading implies. No determinations cut, no coverage lost.

**The one component that resists consolidation.** The deliberate test harness covers 23 scenarios
that each require breaking something real, waiting a cycle, confirming a collector notices, and
reverting. They cannot be shared and they are slow. They are also the only evidence in the project
that the collectors detect anything rather than merely read configuration correctly, so they stay at
full cost.

---

## 2026-09-14 — Full structural verification, and damage found and repaired

**Why this pass happened.** A targeted edit to the object lock retention exposed that the Index
environment table had lost columns. That prompted a full sweep rather than a spot fix.

**What was damaged and why.** Adding each determination to the Index inserted a row at the top, 46
times. Each insertion made openpyxl migrate merged cell ranges downward, and a merged full-width
range keeps only the leftmost value. Twenty Environment table rows lost their cloud, choice,
provisioning and purpose columns. Eight evidence rows across the change management and policy
clusters lost theirs. All rebuilt from the determinations that produced them and verified.

**Method note worth keeping.** Appending to a live workbook is more fragile than regenerating it from
a script, and this is the second time it has caused damage. Verification after every write is load
bearing, not ceremony. The first time, a failed insert was caught immediately; this time the loss was
silent and only surfaced because an unrelated edit hit a cell that should have held content.

**What the full sweep then checked.** Merged ranges are all full-width single-row bands, with no
anomalies. No data row is missing later columns anywhere. Every block carries its required bands,
with deferrals held to the shorter set. All 46 catalog indicators appear in the index and have a
block; nothing appears that is not in the catalog. All 40 in-scope indicators have an assertion
coverage entry and no deferred indicator has one. All 46 statements match the pinned catalog
verbatim. Styling is consistent at three font sizes and seven fills.

**One real content gap found.** Five indicators carried "NIST SP 800-53: see catalog mapping" rather
than the actual list: CNA-EIS, IAM-AAM, IAM-ELP, IAM-JIT and IAM-SNU, together covering 90 mappings
including two indicators with 34 and 38 each. Given that the mappings changed a determination on nine
separate occasions in this project, a placeholder where the citations should be is a real omission
rather than a formatting one. All five now carry their full mapping lists, and no indicator cites a
mapping it does not list.

**Artifact state at close of verification.** 46 determinations — 18 in scope, 22 partial, 6 deferred.
12 tabs, 380 evidence rows, 225 build items, pinned to catalog version 2026.09.13.02.

---

## 2026-09-14 — The SDR schema is published by FedRAMP; ours is not written

**What was nearly done wrong.** The plan was to derive an SDR JSON schema from the field lists in
SDR-CSO-FRR and SDR-CSX-KSI. Reading SDR-CSX-KMT in full surfaced a `schema` block naming an official
file, and FedRAMP publishes machine-readable schemas for every submission artifact.

**Chosen.** Use the official schema. `fedramp-security-decision-record-schema-2026-06-24.json`,
retrieved from the FedRAMP/schemas repository, vendored into the project, and pinned.

**Why deriving would have been the wrong move even if it produced the same fields.** A derived schema
is this project's reading of a rule. The official one is the thing a submission is actually validated
against, and validating against your own interpretation proves nothing about whether a real
submission would pass.

---

## 2026-09-14 — Pin the schema version and hash, not the filename

**What the filename hides.** The file is dated 2026-06-24 and that date has not changed. Its internal
`$schemaVersion` has moved from 1.0.3 to 1.1.1, and a field-name typo fix changed `frrAssesment` to
`frrAssessment` and `ksiAssesment` to `ksiAssessment` after initial publication.

**So a filename pin would have caught neither change.** An emitter written against the typo'd field
names would produce JSON that silently fails validation later, and nothing about the filename would
indicate why.

**Chosen.** Pin the filename, the `$schemaVersion`, and a sha256 of the file. Re-verify on schedule
and fail on drift, the same discipline the catalog pin uses — which has already been exercised once,
when the catalog moved from 2026.07.14.01 to 2026.09.13.02 with no substantive change.

---

## 2026-09-14 — The schema requires a section this project does not produce

**The gap.** Top-level required fields are `certificationPackageOverviewUri` and
`fedRampRequirements`. The second covers how the provider meets the rulesets themselves, not the
indicators. This project determined all 46 KSIs and did not determine the FRR rules.

**Chosen.** Make it a switch in the emitter rather than a silent omission: either emit
`fedRampRequirements` as an empty array with the README stating that the project covers the indicator
half, or populate it for the rulesets the determinations already lean on — MAS, VDR, IVV and SDR
itself.

**Why not quietly omit.** A schema-valid artifact that validates because a required array is empty,
with no explanation, reads as complete when it is half. The switch forces the choice to be made and
recorded.

---

## 2026-09-14 — Assessment fields carry provider reasoning, labelled as such

**What the schema says.** `ksiAssessment` is described as the description of how the indicator is
assessed by an independent validator. SDR-CSO-FRR separately requires independent verification,
independent validation, and responses to assessor comments.

**The position.** No FedRAMP Recognized assessor is engaged. Those fields are emitted empty with a
stated reason rather than filled with self-assessment wearing an assessor's label.

**What `ksiAssessment` carries instead.** The automation assurance and limitations bands, explicitly
labelled as the provider's own assurance reasoning. That is honest and it is also the field's nearest
legitimate use, since the alternative is leaving the project's most substantive self-critique out of
the artifact entirely.

---

## 2026-09-14 — SDR-CSX-KMT is the hardest requirement for this persona

**What Class C requires.** Historical metrics per indicator: a 30-day summary, a summary up to the
past year where available, and all daily metric data up to the past year where available.

**Why it bites.** An environment applied and destroyed per session cannot produce a year of daily
metrics. This was flagged when the ephemeral-environment decision was first made and it is the point
where that decision meets a hard requirement rather than a soft one.

**What survives it.** The "where available" qualifier. The honest emission is the metrics that exist
with the collection window stated, and the README naming the limit rather than letting a reader
assume a year of data sits behind the artifact.

---

## 2026-09-18 — Cloud Asset Inventory scoped to the project, not the organization (PIY-GIV)

**What the build check found.** GIV's build table names an org-scope asset feed. During GCP
onboarding, `gcloud organizations list` returned a real organization tied to the account's domain,
auto-provisioned by Google — but `gcloud projects describe` showed the project this build created has
no parent: it sits outside that org, standalone.

**Why it is worth recording.** Moving the project into the org to get org-scope requires org-admin
permissions that were never set up as part of this persona, and stands up more identity surface
(org-level IAM bindings, folder structure) than a real two-person team without a Workspace deployment
would plausibly have. The org existing at all is an artifact of how Google provisions accounts now,
not something this persona asked for or is using for anything else.

**Chosen.** Build the asset feed at project scope. GIV's own design rationale already supports this
reading independent of the org question: "all" is inherited from MAS-CSO-IIR as resources within the
identified cloud service offering, not everything in the account — and with one project, project
scope *is* that offering's full scope here.

**The consequence, stated rather than hidden.** If this persona's GCP footprint ever grows past one
project, org-scope would need revisiting to keep "all" true. At one project, the two are equivalent in
practice; the gap is dormant, not resolved.

---

## 2026-09-19 — OSM's normalization and detection build split, four ways (MLA-OSM)

**What the build check found.** OSM's own build table names seven items. Two were already built
(central store, query layer scaffolding). The remaining five are not equally ready: schema
normalization and Parquet conversion have no cross-cloud blocker, but detection queries and delivery
alarms both say "results routed into the detection path" — and the detection path is a separate shared
component, built for KSI-IAM-SUS, which does not exist yet.

**Chosen, four scope cuts stated together rather than discovered one at a time:**

1. **AWS side only for normalization.** GCP audit log delivery into this AWS-hosted corpus needs its
   own cross-cloud pipeline (a Cloud Logging sink, Pub/Sub, and a puller or push target on the AWS
   side) that is separable work, not a detail of the normalization Lambda itself.
2. **NDJSON, not compiled Parquet.** The design's build item names Parquet explicitly. A CTAS-based
   compaction step would satisfy it, but adds a second scheduled job and real complexity for a
   dataset at this project's volume, where JSON with partition projection is fully queryable at
   identical functional correctness. Compaction is future work, not a functional gap today.
3. **Two OCSF classes.** Authentication and API Activity, chosen as the critical classes per the
   documented adoption norm. Every other CloudTrail event still lands, still queryable, just under
   the generic API Activity class rather than something more specific — the same "stored raw and
   queryable but not finely correlatable" shape OSM's own limitations section already describes for
   unmapped classes.
4. **Detection and alarms route to a standalone SNS topic, not the detection path.** The detection
   path doesn't exist. Routing there now would mean referencing a resource that isn't real. An interim
   topic keeps the alerting mechanism itself real and testable; rewiring the `alarm_actions` and the
   Lambda's `ALERT_TOPIC_ARN` to the real detection path once IAM-SUS is built is a small, contained
   change, not a redesign.

**Why record this now instead of after IAM-SUS exists.** Four separate readers finding four separate
"why isn't this the real thing" moments is worse than one entry saying so up front. None of these are
walked back; they're facts about build order, stated at the point they were made.

---

## 2026-09-19 — The application environment build, and four platform constraints it hit

The environment is the last shared component and the substrate every other one runs against.
Building it turned up four places where the design's build rows cannot be satisfied exactly as
written. None is a scope reduction chosen for convenience; each is a platform constraint met head-on,
and all four are recorded here together rather than discovered one at a time by a later reader.

**1. The task certificate is self-signed, not ACM-issued.**

KSI-SVC-SIN's build row 2 requires TLS continue to the task rather than terminate at the load
balancer, which needs a certificate the container can serve. KSI-SVC-ASM's build row 4 separately
wants ACM-issued certificates with automatic renewal.

Both cannot hold. ACM issues public certificates only after validating control of a domain name and
this persona owns no domain. AWS Private CA would issue a genuine internal certificate and costs
roughly 400 USD per month — more than three times the entire environment's standing cost, to satisfy
one build row.

Chosen: a self-signed certificate, generated in Terraform, stored in Secrets Manager for the task and
imported into ACM for the load balancer's public listener. What is lost is stated rather than
glossed: there is no chain of trust and no managed renewal, so KSI-SVC-ASM's certificate row is
partially satisfied and KSI-SVC-SIN's transit row holds for confidentiality on the internal hop but
not authenticity. The load balancer cannot be configured to verify a backend certificate in any case,
so the authenticity half of that hop was never available regardless of who issued it.

**2. VPC flow logs land in CloudWatch Logs, not the object-locked corpus.**

Flow logs are the evidence source for most of KSI-CNA-RNT's and KSI-CNA-ULN's validation rows. The
natural destination is the central log store, which is where everything else that produces an audit
trail writes.

It does not work. VPC flow log delivery to S3 fails when the destination bucket carries a default
Object Lock retention period, which the log store does and which is the whole point of it.

Chosen: CloudWatch Logs, encrypted with the logs-class customer-managed key, 30-day retention. The
consequence is that flow logs sit outside the tamper-resistant store, so the immutability claim
KSI-MLA-OSM makes for the corpus does not extend to them. Pulling them into the corpus through the
normalization path is future work; recording the gap now is not.

**3. Load balancer access logs use SSE-S3, not a customer-managed key.**

KSI-SVC-SIN's build row 1 asks for customer-managed keys across all stores. The ELB log delivery
principal cannot write to a bucket encrypted with one.

Chosen: a separate access-log bucket with SSE-S3, rather than weakening the log store's encryption to
accommodate one writer. This is the narrower concession — one bucket holding request metadata, rather
than the store holding every audit record in both clouds.

**4. The root applies in two phases, because digest pinning means images must exist first.**

KSI-SVC-VRI's build row 2 requires task definitions reference images by digest and that tag
references be rejected. A digest cannot be looked up for an image that has not been built, so the ECS
services cannot be declared in the same apply that creates the registry they pull from.

Chosen: a `deploy_services` variable, default false. The first apply builds network, database,
registry and identities; images are built and pushed; the second apply with the flag set creates the
services. The alternative — a tag reference resolving to whatever happens to be there at apply time —
is the mutable pointer VRI exists to reject, so the ordering constraint is the indicator working
rather than an inconvenience.

**Also recorded: the images cannot be built on the workstation.** There is no container runtime
installed locally, so image builds belong to the pipeline, which is where KSI-CMT-RMV and
KSI-SVC-VRI need them to happen anyway — signing, digest pinning and provenance are pipeline
properties, and a locally built image would satisfy none of them.

---

## 2026-09-19 — The AWS account's free-tier plan blocks three named services (open question)

**What the first apply found.** The environment was applied to prove the Terraform survives contact
with the real API. Most of it did: the VPC with no internet route, all seven endpoints with their
restrictive policies, the load balancer, the web firewall and its managed rule groups, the ECS
cluster, four customer-managed keys, the registries, the imported certificate and Secrets Manager all
created without complaint. Every IAM policy document, endpoint policy and WAF rule set — none of
which `terraform plan` validates — was accepted.

Four resources failed, all for the same reason. The account is on the **new AWS free-tier plan**:

- `aws_guardduty_detector` — `SubscriptionRequiredException` (403)
- `aws_securityhub_account` — `SubscriptionRequiredException` (403)
- `aws_inspector2_enabler` — `SubscriptionRequiredException` (403)
- `aws_db_instance` — `FreeTierRestrictionError`, backup retention of 7 days exceeds the free-tier
  maximum

RDS failing cascaded: the `api_task` and `migrate_task` inline policies reference the instance's
resource id and its managed master secret, so neither was created.

**Why this is not a configuration detail.** All three blocked services are named in the design
matrix's environment table and are load-bearing:

- **Inspector** is the vulnerability scanner shared component, consumed by nine indicators. The
  2026-09 entry rejecting basic ECR scanning did so precisely because it covers OS packages only and
  would leave the application dependencies unscanned — which is what KSI-SCR-MON exists to monitor.
- **Security Hub** is the whole benchmark basis for KSI-CNA-IBP and supplies two of the three finding
  sources KSI-SVC-EIS names.
- **GuardDuty** is the detection source KSI-IAM-SUS is determined against.

The RDS cap bites differently but is not cosmetic either: KSI-RPL-ABO compares the backup retention
against the recovery point objective declared in the objective register, and a one-day maximum
changes what that register can honestly claim.

**Not decided yet, and deliberately not decided quietly.** The options are to move the account off
the free-tier plan, or to re-determine the affected indicators against what a free-tier account can
actually evidence. The second is a real answer rather than a defeat — a provider whose platform
cannot supply a finding source has a genuine limitation to declare, which is the same shape as the
GCP benchmark gap already recorded under KSI-CNA-IBP. What is not acceptable is leaving the design
naming three services the environment cannot stand up.

**Also found and fixed.** The load balancer writes an `ELBAccessLogTestFile` into its access log
bucket at creation, and that single 90-byte object made `DeleteBucket` fail with `BucketNotEmpty`,
breaking the first teardown. The access log bucket now carries `force_destroy`. The central log store
deliberately does not, and is Object Locked, because destroying that one should be hard.

**Residual after teardown.** Four customer-managed keys in `PendingDeletion` for seven days, at
roughly one dollar per key per month prorated. No load balancer, no endpoints, no database, no
non-default VPC.

---

## 2026-09-19 — Resolved: the account moves to the Paid plan, no determinations change

**Supersedes the open question recorded earlier today.**

**What was verified.** AWS replaced its new-account model on 15 July 2025. Accounts created after
that date choose a Free plan or a Paid plan at signup, and the Free plan restricts a subset of
services. GuardDuty, Inspector and Security Hub short-term trials are among them, available only on
the Paid plan. The `SubscriptionRequiredException` responses were the restriction working as
designed, not a capability the architecture lacks.

**What upgrading actually costs: nothing.** AWS's own Free Tier FAQ states it will not charge the
payment method until the account upgrades, that the payment method does not need re-entering, and
that remaining Free Tier credits automatically apply to future bills until they expire twelve months
after account creation. This account was created 2026-07-31, so credits run to roughly 2027-07-31
and will absorb most of the early build months.

**Chosen: Option A.** Move to the Paid plan. All three services then work as designed and no
determination changes. KSI-SVC-EIS keeps both of its finding sources, KSI-CNA-IBP keeps its AWS
benchmark basis, KSI-SCR-MON keeps dependency scanning, KSI-IAM-SUS keeps its detection source, and
the objective register keeps its 7-day retention declaration.

**Why this is the faithful answer and not the expensive one.** A two-person team running a production
SaaS and pursuing FedRAMP certification is not on a free-tier account. Being on one was the
unrealistic detail, not paying to leave it. Since upgrading is free and credits carry forward, the
usual tension between faithful and cheap does not arise here.

**Why Option C was rejected despite being reasonable.** Substituting CI dependency scanning plus
basic ECR scan-on-push for Inspector would have covered much of the ground. But it leaves no
substitute for Security Hub's CIS benchmark — an open-source scanner asserting a benchmark is this
project grading itself, materially weaker than a managed service doing it — and no substitute for
provider-native threat detection, which is exactly what KSI-CNA-EIS's reading of "assessment by
managed services with the collector meta-assessing them" depends on. Taking a large, avoidable scope
cut to avoid a cost that turns out to be zero would have been the wrong trade.

**Cost effect.** Security Hub Essentials is priced per resource unit, Inspector per image scan at
roughly nine cents initial and a cent per rescan, GuardDuty per event volume. With no EC2 instances,
two repositories and low traffic, that is roughly 3 to 8 USD per month on top of the existing
estimate. The apply-and-destroy model and the 115 to 125 USD standing figure are unchanged.

---

## 2026-09-19 — A deadline the error message did not reveal

**Found while verifying the plan question.** The Free plan lasts at most six months, or until the
credits are exhausted, whichever comes first. If the account has not upgraded by the end of that
period, AWS closes it after a grace period and the resources are deleted.

**This account was created 2026-07-31**, so the six-month clock runs out around 2027-01-31.

**Why it matters more than the blocked services did.** Everything the cost posture deliberately
preserves across teardowns lives in this account: the Terraform state backend, the evidence storage,
the Object Locked log store, the database snapshots and the KMS keys. Account closure takes all of
it, including the log store that compliance-mode Object Lock was specifically chosen to make
undeletable.

**So the upgrade is not optional and is not only about the three services.** It is the condition for
the account continuing to exist. The service restrictions surfaced the deadline early, which is the
only fortunate part.

**Recorded because the build session could not have found this.** The API returned a service-level
rejection; the account lifecycle behind it is not visible in that error. Verifying what "upgrade your
account plan" actually meant is what surfaced it, and that verification happened only because the
question was carried back to the design conversation rather than settled at the keyboard.

---

## 2026-09-19 — Upgrade before creating the Organization, not by creating it

**The trap.** AWS's Free Tier FAQ states that if the account upgrades to the Paid plan *by joining an
AWS Organization or setting up a Control Tower landing zone*, the Free Tier credits expire
immediately and the account becomes ineligible to earn more.

**Why this project is exposed to it specifically.** IAM Identity Center requires AWS Organizations,
and Identity Center is load-bearing for the identity architecture — KSI-IAM-SNU, APM, AAM, ELP and
JIT all rest on it. Creating the Organization is therefore a certainty, not an option.

**Chosen order.** Upgrade to the Paid plan through the Billing console first, as a deliberate
standalone action. Create the Organization afterwards.

**What the wrong order costs.** Up to 200 USD in credits, immediately, for no benefit. Nothing about
the error would explain it, and the credits would simply be gone.

**Note for the build.** This is an ordering constraint on a manual console action, not something
Terraform can enforce. It belongs in the runbook rather than in code.

---

## 2026-09-19 — The certificate problem resolves through a domain the project already has

**The constraint as recorded.** The task-side TLS certificate is self-signed, because ACM issues
public certificates only after validating domain control and the persona owns no domain, while AWS
Private CA is roughly 400 USD per month. The internal hop therefore had confidentiality but no chain
of trust and no managed renewal, against KSI-SVC-ASM build row 4.

**What changes it.** A personal domain is already owned and managed at Cloudflare. Pointing a
subdomain at this project allows ACM to issue a real certificate through DNS validation, at no cost.

**Chosen.** Use a subdomain of the existing domain. ASM build row 4 is then satisfied properly —
managed issuance, automatic renewal, a real chain of trust — rather than carrying a self-signed
workaround as a declared limitation.

**A second indicator benefits.** KSI-PIY-RVD requires a `security.txt` served at the well-known path
on the offering's domain, along with a monitored contact. Without a domain that determination had
nowhere real to publish. With one, the disclosure program becomes genuinely discoverable in the way
the format expects, and the expiry and contact-liveness checks have a real target.

**The 400 USD Private CA figure never applies.** It was the cost of solving this the hard way, and
the hard way is not needed.

---

## 2026-09-19 — What the first apply actually validated

**Worth recording separately from the failures, because it is the more significant result.**

`terraform plan` validates almost nothing about whether AWS accepts a configuration. Policy documents
in particular — IAM policies, VPC endpoint policies, KMS key policies, WAF rule sets — are only
evaluated at apply time. All of them were accepted on first contact.

Specifically validated: the VPC with no internet route on the private tiers across three tiers with
distinct route tables; all seven endpoints, six interface and one S3 gateway, each with a restrictive
principal-and-action policy; the load balancer with a TLS 1.3/1.2 listener and HTTP redirect; WAF
with three managed rule groups, a rate-based rule and logging; the ECS cluster, four customer-managed
keys with rotation, two registries with immutable tags, Secrets Manager, and flow logs.

**So the network design, the segmentation model, the key model and the edge design are validated
against the real platform**, not merely against a plan. The four failures were account-plan
restrictions, not architectural faults, and the distinction matters: one is a setting, the other
would have been a redesign.

**The two bugs caught in review before the apply are the more instructive part.** An EventBridge rule
targeting SNS with no topic policy, meaning findings would never have been delivered, and WAF logging
with no CloudWatch Logs resource policy, meaning blocked-request records would never have been
written. Both were configurations that apply cleanly, report healthy, and produce no evidence. That
is the exact failure mode this project has been built to catch, and it appeared twice in the first
substantial apply.

---

## 2026-09-19 — Task-side TLS stays self-signed, because nothing would validate a real certificate

**The question.** KSI-SVC-ASM build row 4 wants managed certificates with automatic renewal. The
load balancer listener is solved by a DNS-validated public certificate at no cost. The task-side
certificate is not: a standard public certificate cannot be exported, and the container serves TLS
itself on the internal hop because KSI-SVC-SIN requires TLS continued to the task rather than
terminated at the load balancer. Exportable public certificates exist and cost per FQDN at issuance
and again at renewal.

**What settles it.** AWS documents that the load balancer establishes TLS to its targets using
whatever certificate is installed there and **does not validate it** — self-signed or expired
certificates work. It goes further: because the load balancer and its targets are both inside a VPC,
that traffic is authenticated at the packet level and is not at risk of man-in-the-middle or
spoofing even when the target certificate is not valid.

**Chosen.** Self-signed on the task side.

**Why buying the certificate would have been worse than not buying it.** An exportable certificate
would cost money at issuance and at every renewal, and would require a rotation workflow, because
the platform renews the certificate but the exported copy on the task does not update itself — a
task would serve an expired certificate after 395 days. All of that to obtain authenticity that the
only client on the hop does not check. Paying for a property nothing verifies is worse than
declaring its absence.

**How the limitation is stated.** Not as "a managed certificate was unaffordable." The hop carries
confidentiality; authenticity on it rests on VPC packet-level authentication and network isolation,
which is the platform's own documented behaviour, and a trusted chain would not be verified by
anything in the path. Peer authenticity for this architecture is established by platform identity
under KSI-SVC-VCM, not by certificates on this hop.

---

## 2026-09-19 — The domain is DNS-only, not proxied

**The question.** Whether the application subdomain sits behind the DNS provider's proxy.

**Chosen.** DNS-only.

**Why.** Proxied mode places the DNS provider inside the offering boundary and terminates TLS there,
which disturbs three determinations at once: KSI-CNA-RNT's versioned list of resources permitted
inbound from the internet stops reading "the load balancer only," the provider becomes a third party
under KSI-CNA-IBP's register, and KSI-SVC-VCM's path register gains a hop. What it buys is web
application firewalling and denial-of-service protection that this architecture already has from WAF
and Shield Standard, both already determined.

Three determinations disturbed for capability already present is a poor trade. Recorded as a
decision rather than left as the provider's default, because the default is proxied and silently
accepting it would have changed the boundary without anyone deciding to.

---

## 2026-09-19 — The disclosure file's expiry is generated at apply time

**The problem.** KSI-PIY-RVD treats an expired `security.txt` as a failure, on the grounds that the
format carries an expiry deliberately and a stale file signals a stale program. Nothing in the
design reissued it, so the check would eventually fail against a file nobody was maintaining.

**Chosen.** Compute the expiry from the apply timestamp in declared state. Every apply refreshes it.

**Why this rather than a scheduled job.** Under apply-and-destroy the environment is reapplied
whenever it is used, so the file self-maintains while the project is active, with no new scheduled
component and no new failure mode. A scheduled reissue job would be machinery that exists only to
maintain a single text file.

**The seam, declared.** Apply frequency is not a reliable expiry driver. A continuously running
deployment would need a scheduled reissue, because an environment that stays up for a year without
reapplying would let the file lapse. Same shape as the 3-day cadence limitation: the mechanism is
correct and the environment's uptime pattern is what bounds it.

---

## 2026-09-19 — Image signing is keyless, and enforcement is sequence-based with the bypass closed by IAM

**Mechanism chosen: keyless signing with the pipeline's federated identity**, rather than a managed
signing service with signing profiles. Keyless means no signing key exists to store, protect or
rotate, which matches the position established under KSI-IAM-SNU rather than reopening it. A managed
signing service would introduce key material and a rotation obligation for no gain here.

**The enforcement problem, stated plainly.** The container service has no admission control for
image signatures. A pipeline gate satisfies KSI-SVC-VRI build row 3 in sequence — verification
happens before deployment — but it does not enforce at the platform, and a direct service update
bypasses it.

**How the gap is narrowed rather than merely declared.** KSI-CMT-RMV already requires that only the
pipeline principal may push images or apply declared state. Extending that to service updates by IAM
policy means the bypass requires holding the pipeline principal, which is itself the thing being
protected. The remaining exposure is a compromised pipeline principal, which is the same exposure
every other pipeline-enforced control in this project carries.

**Declared as:** verification is sequence-enforced rather than admission-enforced, because the
platform provides no admission control, and the bypass path is closed by identity policy instead.
That is honest and it is materially different from leaving the bypass open.

---

## 2026-09-19 — Pipeline-only apply waits, as a dated exception rather than a blocked build

**The conflict.** KSI-CMT-RMV requires apply to be permitted only to the pipeline principal,
enforced by role rather than convention. Today a human identity applies. Moving the human path to
KSI-IAM-JIT's elevation workflow is the design's answer, and that workflow is not built.

**Why not simply build JIT first.** The dependency is circular. The pipeline is needed to build
images, images are needed for the application environment, and JIT's own state machine would be
deployed through the pipeline. Blocking the pipeline on JIT blocks JIT.

**Chosen.** The human identity retains apply as a recorded entry in the exception register, carrying
a reason and an explicit end condition: the exception closes when KSI-IAM-JIT build step 5 lands.

**Why this is not a quiet compromise.** The exception register already exists as a mechanism, used
the same way for benchmark exceptions under KSI-CNA-IBP and accepted risks under KSI-SCR-MIT, and
every entry in it carries a reason and a review date. This project has consistently refused undated
exceptions and consistently accepted dated ones with a named closing condition. This is the latter.

---

## 2026-09-19 — Cloud Identity gets its own subdomain, and deliberately not the apex

**Why this needed care.** The identity architecture places Google Cloud Identity as the workforce
identity provider, which requires a verified domain. Verifying a domain for Cloud Identity puts
Google in control of identity for addresses on it.

**The conflict that makes the apex wrong.** The apex of the available domain is in use for a
personal email migration away from Google. Verifying it for Cloud Identity would work directly
against that, and would entangle a portfolio project's identity boundary with personal
correspondence.

**Chosen.** A dedicated subdomain for Cloud Identity, distinct from both the apex and the
application subdomain.

**Sequencing consequence.** Five indicators rest on this identity architecture — KSI-IAM-SNU, APM,
AAM, ELP and JIT — and none can be built against a personal account rather than a Cloud Identity
tenant. This therefore belongs before or alongside the pipeline work, not after it.

---

## 2026-09-19 — Repository events reach the corpus through the pipeline's existing identity

**The question.** KSI-CMT-LMC requires commit and pull request events delivered to the central store
and normalized. The mechanism was unspecified.

**Rejected: a webhook into an API endpoint.** It creates a new public ingress path into the account
and requires a shared webhook secret, which is a new credential in KSI-SVC-ASM's scope and a new
rotation obligation — both for a delivery mechanism.

**Chosen.** The pipeline emits events to the event bus using the federated identity it already
holds. No new ingress, no new secret, and it reuses federation already determined under KSI-IAM-SNU
and KSI-SVC-VCM rather than introducing a parallel path.

**The seam, declared.** This captures events that trigger a workflow run, not every repository
event. Branch protection already routes changes through pull requests, so coverage is good rather
than total, and the difference is stated rather than assumed away.

---

## 2026-09-19 — External feed sources named

**Why naming them matters.** KSI-SCR-MON's determination turns on advisories being correlated
against the dependency inventory automatically rather than merely subscribed to. A determination
that cites unnamed feeds cannot be built or checked.

**Named.** OSV for ecosystem advisories, with the GitHub Advisory Database as a second source, since
the language ecosystems in the pinned manifests are covered by both. Vendor security bulletins for
provider-side advisories. `endoflife.date` for the published support windows that KSI-SCR-MIT's
end-of-support checking compares against.

**One left open deliberately.** KSI-SCR-MON build row 4 covers service change and deprecation
notifications, on the reading that a changed provider default is a vulnerability under the statutory
definition and produces no advisory. The obvious source is the provider's health API, and full
programmatic access to it has historically required a paid support plan rather than the basic tier.
**Verify against current documentation before designing around it.** If it does require a paid plan,
that is a cost decision of the same kind as the account plan question resolved today, and it should
be decided rather than assumed in either direction.

---

## 2026-09-19 — Certificate validation records are created by hand, not by a provider plugin

**The question.** Whether DNS validation records for certificate issuance are created manually or
through the DNS provider's Terraform integration.

**Chosen.** Manually, for now.

**Why.** The integration requires an API token for the DNS provider. That is a new credential inside
KSI-SVC-ASM's scope with its own rotation obligation, and it places a third party inside the
Terraform execution path, which reaches KSI-CNA-IBP's third-party register and KSI-SCR-MON's
monitoring scope. Real scope expansion across three determinations, for an action performed once per
certificate.

**Revisit condition.** If certificate churn makes manual validation genuinely painful, the trade
changes and this should be reconsidered as a decision rather than drifting into it.

---

## 2026-09-20 — The application certificate is issued in bootstrap, not in the application root

**A build decision following from a design one.** The 2026-09-19 entry chose manual DNS validation
over the provider's Terraform integration, to avoid a third-party API token inside the Terraform
execution path. It did not say which root issues the certificate, and the answer is not the obvious
one.

**Why not the aws root.** That root is destroyed between sessions. A certificate declared there dies
with it, and every rebuild would need a human to create validation records and wait for issuance
before the environment could come up at all. Manual validation and apply-and-destroy are individually
fine and together turn a five-minute apply into a manual gate, every session.

**Chosen.** Issue it in `infra/bootstrap`, which is applied once and rarely touched, and have the aws
root find it with a data source. The certificate then outlives the environment that consumes it, and
the consuming root cannot destroy it. ACM charges nothing to hold a certificate, so persisting it
carries no standing cost.

**Deliberately no validation resource.** `aws_acm_certificate_validation` blocks the apply until
issuance completes, which with hand-created records means the apply hangs while someone opens a
browser. The records are emitted as an output instead and issuance proceeds asynchronously.

**The renewal trap, recorded because it is silent.** ACM re-validates through the same DNS records
when it auto-renews. Deleting them after issuance — the natural instinct, since they look like
one-time setup — breaks renewal at the next renewal with no warning. The output says so
and so does `infra/README.md`.

**A fallback is kept, and is not an end state.** With no domain set the load balancer still imports
the self-signed certificate and the disclosure file is not published, so the environment remains
applyable while the domain work is outstanding. That is scaffolding for an unfinished migration, not
a supported configuration, and it is stated as such in the README.

---

## 2026-09-20 — The disclosure file's expiry rotates, rather than tracking every apply

**Refines the 2026-09-19 decision** to compute `security.txt`'s expiry from the apply timestamp.

**The trap in the obvious implementation.** `timestamp()` in Terraform re-evaluates on every plan, so
any resource carrying it shows a permanent diff. KSI-SVC-ACM's drift detection is a scheduled plan in
check mode whose exit status *is* the drift signal. A resource that always differs makes that signal
permanently positive, which does not merely add noise — it removes the project's ability to
distinguish drift from its own configuration. One indicator's implementation detail would have
quietly disabled another indicator's evidence.

**Chosen.** A rotating timestamp with a ninety-day period. The value changes only when the period has
actually elapsed, so plans are clean in between and the expiry still moves forward on its own.

**Same intent, kept.** The 2026-09-19 reasoning holds: no new scheduled component exists only to
maintain one text file, and the file self-maintains while the project is active. The declared seam is
unchanged and is now precise rather than approximate — a deployment left standing more than ninety
days without reapplying would let the file lapse.

**Served by the load balancer, not the application.** The build row is provisioned Terraform rather
than CI; the disclosure channel should survive an application outage, since a contact route that
disappears exactly when something is wrong inverts the intent; and it keeps an unauthenticated public
path out of the application's request handling. A policy link is omitted entirely when no URL is
supplied, because a dangling link implies a published policy that does not exist.

---

## 2026-09-20 — The cross-cloud path runs GCP-to-AWS, and carries no static credential

**The direction is a decision, not an accident.** The AWS worker lands extracts in S3 and the GCP
pipeline reads them, rather than the worker pushing into GCS. One federation exists instead of two,
and the AWS side holds no Google credential at all.

**How it authenticates.** The Cloud Run job holds a Google service account identity, asks Google for
an identity token, and exchanges it with AWS STS for a short-lived session. KSI-IAM-SNU's durability
hierarchy is satisfied on both ends: nothing static exists anywhere on this path. Unlike the GitHub
federation, no OIDC provider resource is declared on the AWS side, because AWS already trusts
`accounts.google.com` natively.

**The trust matches the numeric ID, not the email.** A service account email can be deleted and
recreated, and the recreated account would inherit trust granted to a different principal. The
numeric unique ID is never reused. The audience is pinned to the same value, so a token minted for
another purpose cannot be replayed here — KSI-SVC-VCM build row 1 is "no wildcards", and this is what
that means in practice on this hop.

**What the role can reach.** One prefix of one bucket, read-only, with listing scoped to the same
prefix so it cannot enumerate what else exists. KSI-CNA-MAT's identity surface question — what a
compromised resource reaches with the credentials it holds — has a one-line answer here.

---

## 2026-09-20 — The analytics load deduplicates, because the AWS side guarantees duplicates

**The constraint inherited from AWS.** The worker's extract window is deliberately wider than its
interval, so every row appears in at least two extract files. That trade was made on the grounds that
losing customer data is worse than duplicating it, and it makes deduplication the analytics side's
responsibility rather than an optional tidy-up.

**Chosen.** Load into a staging table, then `MERGE` on the source primary key into the target. A
plain append would duplicate every row in the overlap, and would do so silently.

**What this buys beyond correctness.** The pipeline becomes idempotent: running it twice over the
same data produces the same table. That is what lets the job read the whole extract prefix on every
run rather than maintaining a watermark — and it has no durable state to maintain one with, since it
starts cold on every scheduled execution.

---

## 2026-09-20 — Security Command Center is activated at project scope, and not in Terraform

**Two limitations, both following from the same root cause** already recorded on 2026-09-18: the GCP
project sits outside any organization.

**First, scope.** Standard-tier activation is supported at project level, so the service is
available. Google documents that certain detection modules and service integrations are unavailable
at project scope because of the reduced access. The findings that arrive are genuine; the set is
narrower than an organization-level activation would produce. This bounds KSI-SVC-EIS's GCP-side
finding source and KSI-IAM-SUS's GCP detection path, and it is the same shape as the gap
KSI-CNA-IBP already declares for the GCP benchmark mapping.

**Second, provisioning.** The google provider exposes no resource for Standard-tier project
activation — the paid tiers have one, the free tier does not. So this is an API enablement in
declared state plus a console action.

**That is an exception to KSI-SVC-ACM build row 1**, "no console-created resources", and it is
recorded as one rather than quietly tolerated. The reason is that the platform exposes no declarative
interface at this tier, which is a platform limit rather than a convenience. Wrapping a shell command
in a `null_resource` was rejected: it would put something in declared state that does not describe
the resource and cannot detect its drift, which is worse than an honest exception.

---

## 2026-09-20 — GCP audit logging is scoped to the stores that hold customer data

**What is off by default.** Admin Activity logs are always on and cannot be disabled. Data Access
logs are off for most services, which means reading every object in the landing bucket and querying
every row in the dataset would leave no trace. KSI-MLA-LET records logged, monitored and audited as
three distinct states per source; without Data Access logging the first state would be recorded
falsely.

**Chosen.** Data Access logging on Cloud Storage, BigQuery and Cloud KMS. Not `allServices`.

**Why not project-wide.** Data Access logging bills by volume, and a blanket configuration logs the
reads of the audit logs themselves. The three named services are the ones holding customer data or
controlling access to it. Key use is included deliberately: KSI-SVC-SIN's claim is not only that data
is encrypted but that decryption is controlled, and a decrypt nobody logged is a control nobody can
evidence.

---

## 2026-09-22 — What the interrupted session of 2026-09-21 actually did, and the teardown it never reached

**Written by the session that picked up afterwards.** The previous session ended mid-workflow with
the environment standing and nothing recorded, so the first task was reconstructing it from evidence
rather than from notes. Recorded here because a session that leaves no record leaves the repository
asserting the opposite of what is true in the account, and the next reader has no way to tell.

**How it was reconstructed.** S3 object-version history on `aws/terraform.tfstate` gives a timestamped
size curve, and CloudTrail gives the matching API calls. Together they date every phase to the minute
without any note having been written:

| Time (EDT) | What | State size |
|---|---|---|
| 19:05–19:31 | apply | 273KB → 433KB |
| 19:36–19:59 | destroy, down to the persistent set | 433KB → 137KB |
| 20:00–20:14 | apply again | 137KB → 452KB |

The final apply **completed**. A plan against the written configuration returns "No changes", there
are no orphaned network interfaces, no stale lock object and no duplicate target groups. The session
was cut short after the apply, not during it — which is why nothing was broken and nothing was
recorded.

**One false alarm worth recording so it is not re-investigated.** `aws acm list-certificates` returns
an empty list while the load balancer plainly has a working HTTPS listener. The CLI defaults to
filtering on RSA key types, and the imported certificate is EC-prime256v1, so it is hidden from the
list but returned by `describe-certificate`. Nothing is wrong.

---

## 2026-09-22 — Phase 1 verified against the project's own evidence machinery before teardown

**Why verify rather than simply destroy.** The environment was standing and about to be torn down.
Anything not checked while it was up could not be checked at all until the next apply, and the point
of the project is that claims are evidenced rather than asserted. The verification used the
project's own collectors, not ad-hoc commands, so it exercised the assessment machinery and the
infrastructure in the same pass.

**What passed.**

- **Inventory generator** — 75 resources across both clouds from the live cloud APIs.
- **Inventory self-test** — the one that matters, because it is the negative control. It seeds a
  watched resource type and an unwatched one in each cloud, polls AWS Config and Cloud Asset
  Inventory, and confirms the watched seed appears *and* the unwatched one does not. PASS on both
  clouds, both directions. KSI-PIY-GIV's liveness and accuracy claims hold.
- **Collector checks** — 5 of 5, including the Athena query over the normalized corpus returning
  rows. The normalization and detection path is live, not merely deployed.
- **Edge** — HTTPS listener serves over HTTP/2; HTTP returns a 301 to `https://...:443/`. The 503
  behind it is correct: phase 1 has no ECS services, so the target group is empty.
- **Routing** — the `app` and `data` route tables carry `10.20.0.0/16` and nothing else. Only
  `public` holds a `0.0.0.0/0`. KSI-CNA-RNT's "no internet route at all" is true of the tiers that
  claim it, confirmed against the live route tables rather than against the configuration that
  declared them.
- **Database** — not publicly accessible, encrypted, IAM authentication enabled, 7-day retention.
  The retention figure is the one the free plan previously capped, so this also confirms the Paid
  plan upgrade took effect.

**What this closes.** The 2026-09-19 brief listed the network, segmentation, key and edge design as
validated by the first apply. This adds the evidence layer: the collectors run against real
infrastructure and return real answers, and the inventory's negative control works. That was the
open question the brief could not answer.

---

## 2026-09-22 — Teardown is scoped by the file split, and is a script rather than a remembered command

**The problem this solves.** The cost posture says "destroy it between sessions" and no procedure was
ever written down. Three apply/destroy cycles have now happened, each reconstructed at the keyboard,
and the previous session's was recoverable only from S3 version history. A cost discipline that
depends on remembering an undocumented command is a cost discipline that will lapse.

**Why `terraform destroy` does not work.** It is refused outright. `aws_s3_bucket.log_store` carries
`prevent_destroy = true`, and Terraform aborts the entire plan rather than skipping the one resource:
`Error: Instance cannot be destroyed`. The guard is correct — the log store is the audit record,
carries Object Lock in compliance mode, and is meant to outlive every rebuild — so the teardown is
scoped with `-target` and the guard stays.

**Chosen: derive the target list from the file split, not from a hand-maintained list.** Five files
hold everything that survives — `log_corpus.tf`, `log_normalization.tf`, `detection.tf`,
`inventory.tf`, `billing.tf` — and everything else is the application environment. `infra/aws/teardown.sh`
maps each resource in state back to the file that declares it and targets the complement. 123 of 163
managed resources, with the other 40 preserved.

**Why a derived list rather than an enumerated one.** An enumerated list rots. A resource added to
`compute.tf` next month would silently survive every future teardown and bill indefinitely, and
nothing would report it. Deriving from the file split means a new resource is destroyed by default
and only a deliberate placement in one of the five named files exempts it. The script refuses to run
if any resource in state maps to no file at all, rather than guessing what a rename or an orphan
meant.

**The property that makes this possible, verified rather than assumed.** Nothing in the five
preserved files references a resource declared outside them. The evidence layer has no dependency on
the application environment. That is worth re-checking before moving a resource between files,
because it is the thing that makes a clean scoped teardown possible at all.

**A trap checked and found already avoided.** The teardown schedules four customer-managed KMS keys
for deletion. Had the log store been encrypted with the `logs` key, its contents would have become
permanently unreadable seven days later — an immutable audit record destroyed by the routine that was
supposed to be cheap. It is encrypted with SSE-S3 instead, so the risk does not exist. Recorded
because the next person to edit `kms.tf` or `log_corpus.tf` needs to know this is load-bearing and
not an oversight.

**Known residue, unchanged.** Each cycle leaves four KMS keys in `PendingDeletion` for seven days at
roughly 1 USD each. Twelve keys were live in the account at the time of writing: four in use and
eight already pending from earlier cycles. They clear on their own.

---

## 2026-09-22 — The GitHub trust policy pins the immutable subject, because that is what GitHub sends

**Both workflows had already run and both had failed**, which is not what the previous session's
absence of a record implied and not what this session first concluded. `build-and-push` ran on the
push of `2d6ecd0` at 00:20 UTC and failed after 5m19s; `drift` ran on schedule at 12:18 UTC and
failed after 40s. Both failed at the same step, `assume the build/drift role`, with
`Could not assume role with OIDC: Not authorized to perform sts:AssumeRoleWithWebIdentity`.

**Why this was nearly missed.** CloudTrail lookups keyed on the role name return only IAM management
events — the `CreateRole` and `PutRolePolicy` calls Terraform made — and show no sessions, which
reads as "nothing ever tried". The federation attempts are `sts.amazonaws.com` events under
`AssumeRoleWithWebIdentity`, a different lookup entirely. Absence of a finding was treated as
evidence before the looking had been recorded, which is the failure this project has a working rule
against. The rule applies to its own diagnosis too.

**The cause, from the event itself rather than inferred.** The recorded `userName` on the denied
calls is the subject GitHub actually presented:

```
repo:elvie-valmores@181586876/fedramp-20x-ksi-assessment@1375137942:ref:refs/heads/main
```

The trust policy pinned the documented form:

```
repo:elvie-valmores/fedramp-20x-ksi-assessment:ref:refs/heads/main
```

`gh api /repos/<owner>/<name>/actions/oidc/customization/sub` confirms why:
`use_immutable_subject` is `true`, and `sub_claim_prefix` is exactly the numbered prefix above. The
numbers are the owner ID and the repository ID, confirmed independently against the repository API.

**Chosen: pin the immutable subject.** `local.github_subject` now builds
`repo:<owner>@<owner_id>/<name>@<repo_id>:ref:refs/heads/main` from four hardcoded values, and both
roles use it. Still `StringEquals`, still a specific ref, still no wildcard — KSI-SVC-VCM build row 1
is unchanged in substance and stronger in fact.

**Why not the other fix.** GitHub allows `use_immutable_subject` to be turned off, which restores the
legacy form and would have made the existing policy match. That is remediating the measurement rather
than the condition, and this project has a working rule against it. The legacy subject is the one
that can be re-pointed by deleting an account or repository and recreating it with a familiar name;
the immutable one cannot. Turning the protection off to match a stale configuration would have
weakened the control to make a check go green.

**This is the same decision already made on the other federation, arrived at independently by the
platform.** `cross_cloud.tf` matches the GCP service account's *numeric unique ID* rather than its
email, and the 2026-09-20 entry records the reasoning: "A service account email can be deleted and
recreated, and the recreated account would inherit trust granted to a different principal. The
numeric ID is never reused." GitHub has since applied that reasoning to its own subject claim. The
project had the principle right on one hop and the stale form on the other.

**The failure mode worth naming.** This is a control that was configured, deployed, and completely
non-functional, reporting nothing until someone read the workflow history. Both roles existed, both
policies were valid, the OIDC provider was correct, and `terraform plan` was clean — the
configuration was internally consistent and externally wrong. Nothing in the infrastructure could
have detected it, because the mismatch only exists at the moment a token is presented.

**Not yet applied.** The fix plans to 2 in-place trust-policy updates. It has to be applied while the
environment is standing, and `pipeline.tf` is in the destroyable set, so it lands on the next apply
if not before.

---

## 2026-09-22 — The drift role reads one secret value, reversing an earlier deny

**Reverses the `NeverReadSecretValues` deny** in `infra/aws/pipeline.tf`, and records why rather than
deleting it quietly.

**What the original decision said.** "Refreshing a secret's state reads its metadata, never its
value. Stated as an explicit deny so that a later widening of the read grant above cannot quietly
pick it up." The reasoning was sound and the mechanism — an explicit `Deny` rather than merely
omitting the `Allow` — was the careful choice.

**Why it was wrong.** The premise holds for `aws_secretsmanager_secret` and fails for
`aws_secretsmanager_secret_version`. Refreshing a version calls `GetSecretValue`; there is no
metadata-only read of a version. The project holds a version of exactly one secret, `task_tls`, so
every drift plan hit the deny and exited 1.

**What that cost, which is the part worth noticing.** `terraform plan -detailed-exitcode` returns 0
for clean, 2 for drift and 1 for error, and the workflow treats anything but 0 as a failed run. So
the deny did not narrow drift detection — it eliminated it. KSI-SVC-ACM's signal never existed. A
guard protecting a claim the system could not keep blocked the control it was meant to protect, and
nothing reported that, because an erroring drift check and a drifting one look the same from
outside.

**Chosen: grant the read, scoped to the one secret, and keep the guard for every other.** The deny
becomes `NotResource`-scoped rather than deleted, so its original intent — that a later widening
cannot quietly pick up secret values — still holds for everything else in the account, including the
RDS-managed master password, which is the genuinely sensitive secret here and which nothing in the
pipeline has any reason to read. The decrypt grant is scoped to the secrets key and conditioned on
`kms:ViaService`, so the key cannot be used directly.

**What this costs, stated rather than buried.** The drift principal can read the task TLS private
key. That is accepted because the certificate is self-signed, Terraform generates it on every apply,
and the task-side TLS hop is already a declared stopgap under KSI-SVC-ASM. It would not be
acceptable for a secret the project did not generate itself, and the narrowed deny is what stops
this from becoming a general grant later.

**Why not the alternative.** Taking the secret version out of Terraform's management would have kept
least privilege and full drift coverage together, and is the better answer in a system where the
secret matters. It is a real change to `secrets.tf` and touches KSI-SVC-ASM's task-TLS story, so it
is recorded here as the option not taken rather than silently passed over.

---

## 2026-09-22 — Four read permissions the drift role never had

**Found the same way**, by reading a drift run's output rather than by review. With the trust policy
fixed, the plan got far enough to report four `AccessDenied` errors in one pass:

| Action | Why the policy missed it |
|---|---|
| `budgets:ListTagsForResource` | the grant had `budgets:Describe*` and `View*`, no `List*` |
| `athena:GetWorkGroup` | no `athena` entry existed at all |
| `inspector2:BatchGetAccountStatus` | the grant had `Get*` and `List*`; the action begins `BatchGet` |
| `secretsmanager:DescribeSecret` | no `secretsmanager` entry existed at all |

**The pattern worth naming.** Three of the four are verb-prefix wildcards that look complete and are
not. `Describe*`, `Get*`, `List*` reads as "every read action", and AWS action names do not
consistently begin with those verbs — `ListTagsForResource` is a read that `Describe*` misses, and
`BatchGetAccountStatus` is a read that `Get*` misses. A policy written by enumerating verbs will keep
developing holes of this shape as resource types are added.

**Only discoverable by running it.** `terraform validate` passes, `terraform plan` from a privileged
identity passes, and the policy is syntactically fine. The gap exists only for the drift principal,
only at refresh time. This is the second control in two days found non-functional while appearing
correctly configured — the first being the OIDC subject mismatch earlier today. Both were invisible
to every check short of executing the thing.

---

## 2026-09-22 — Open question: the daily drift check and apply-and-destroy are in direct conflict

**Not resolved. Recorded for the design conversation**, in the same way the free-tier plan question
was on 2026-09-19, because the answer changes what KSI-SVC-ACM can claim rather than how something is
built.

**The conflict.** `drift.yml` runs at 07:00 UTC daily and fails the run on anything but a clean plan.
The cost posture tears the application environment down between sessions. With it down, the plan
proposes to add the 123 resources that are declared but not standing.

**Measured, not predicted.** Run locally against the torn-down environment immediately after the
teardown on 2026-09-22:

```
terraform plan -detailed-exitcode  ->  2
```

Exit 2 is drift, and the workflow fails on it. So every scheduled run between sessions fails.

**The workflow's own summary text asserts the opposite** — it tells the reader that under
apply-and-destroy a clean result "confirms declared state matches an empty environment". That is
wrong, and wrong in the direction that matters: it describes an outcome the mechanism cannot produce
and would reassure a reader who never ran it. The comment was written from reasoning rather than from
a run.

**Why this is not merely noise.** This project's own rule, recorded on 2026-09-20 against the
`security.txt` timestamp: a signal that is always positive "does not merely add noise — it removes
the project's ability to distinguish drift from its own configuration". A daily failure that is
expected is a daily failure nobody reads, and the one run that means something arrives looking
identical to the three hundred that did not.

**The options, none yet chosen.**

1. **Scope the drift plan to the persistent set.** The same five-file boundary `teardown.sh` already
   derives. The claim becomes "the resources that persist are checked daily for drift", which is true,
   verifiable and narrower than the current claim. One boundary would then serve both teardown and
   drift, which is an argument for it beyond convenience.
2. **Run drift only while the environment stands.** Dispatch-only, no schedule, invoked as part of a
   session. Honest, but it stops being a standing control and becomes a manual check, which is a
   material weakening of KSI-SVC-ACM.
3. **Declare the limitation and accept the failures.** Cheapest, and the worst of the three: it
   knowingly leaves a control emitting a signal that cannot be read.

**Recommendation on the record: option 1.** It keeps a genuine daily signal, it is the only option
that does not weaken the determination, and it reuses a boundary that already exists and is already
tested. What it costs is that drift over the application environment is only checked while that
environment is up — which should be stated plainly under KSI-SVC-ACM rather than left implicit.

**Whatever is chosen, the workflow's summary text must be corrected.** It currently tells the reader
something the mechanism cannot do.

---

## 2026-09-22 — Resolved: drift is scoped to the persistence boundary

**Resolves the open question recorded earlier today.** Option 1 chosen: the daily plan is scoped to
the resources that persist between sessions.

**What KSI-SVC-ACM now claims.** That the persistent resources — the Object Locked log store, Athena,
Glue, CloudTrail, the Config recorder, both Lambdas and the budget guardrail — are checked daily
against declared state, and that the application environment is checked only while it stands. That is
narrower than the previous claim and, unlike it, true. It should be stated in the determination
rather than left to be inferred from the workflow.

**One boundary, two consumers, one implementation.** `infra/aws/boundary.py` derives both halves from
the five-file split and is consumed by `teardown.sh --ephemeral` and by `drift.yml --persistent`. A
boundary implemented twice is a boundary that diverges, and the two failure modes are silent in
opposite directions: a resource the teardown forgets bills forever, and a resource the drift check
forgets stops being watched. Neither would report itself.

**Verified against the condition it exists for**, rather than reasoned about — which is the mistake
the original summary text made. Run locally against the torn-down environment:

```
unscoped:  terraform plan -detailed-exitcode  ->  2   (would fail the run)
scoped:    terraform plan -detailed-exitcode  ->  0   ("No changes")
```

**Two implementation notes worth keeping**, both of which would have produced a control that looked
right and did not work:

- **Not `xargs`.** It collapses the command's exit status into 123 for anything between 1 and 125,
  and the exit status is the entire signal this job reads. Drift would have been reported as error,
  permanently.
- **Not `mapfile`.** It needs bash 4, and while the runners have bash 5, the workstation has 3.2. A
  step that cannot be rehearsed locally is a step that gets debugged in CI, which is how both of
  today's other faults survived as long as they did. A portable read loop runs in both places and was
  tested in both.

**The summary text is corrected.** It now states the scope and says plainly that the application
environment is not covered, instead of describing an outcome the mechanism cannot produce.

---

## 2026-09-22 — The drift identity moves to the persistent side, and the secret grant reverts

**Found by running the scoped check rather than by reviewing it.** The first CI run after scoping
failed with `The web identity token provided could not be validated` — which is what AWS returns when
no OIDC provider is registered in the account at all, not a trust mismatch. The teardown had
destroyed `aws_iam_openid_connect_provider.github` and both roles, because they were written in
`pipeline.tf`, which is on the ephemeral side.

**The error in the reasoning.** That `pipeline.tf` is destroyable was noted earlier the same day and
not connected when the drift scope was chosen. Scoping the plan was necessary and not sufficient: a
correct plan executed by a principal that does not exist is still no signal. The control was fixed in
the half that was examined and broken in the half that was not.

**Chosen.** `pipeline_identity.tf` holds the OIDC provider, the drift role and its policy, and
`boundary.py` lists it on the persistent side. Nothing about this is a cost decision — an OIDC
provider and IAM roles are free, and the only reason they were being destroyed nightly is the file
they happened to be written in.

**The build role deliberately stays ephemeral.** It grants push to repositories and use of a key that
are themselves torn down, so it has nothing to do while they are gone, and keeping it on the
persistent side would mean holding references to resources that do not exist. That asymmetry is the
point: the half of the pipeline that must work while the environment is down is exactly the half that
does not depend on the environment.

**A grant reverted, which is the welcome half.** Earlier today the `NeverReadSecretValues` deny was
removed so an unscoped plan could refresh `aws_secretsmanager_secret_version.task_tls`, at the cost of
letting the drift principal read a private key. Scoping removed the reason: `secrets.tf` is
ephemeral, so a scoped plan never refreshes a secret version and never needs to read one. The deny is
whole again and the metadata grants are gone with it.

**Worth noting as a pattern.** The secret grant was a real cost accepted for a real reason, and the
reason turned out to be an artifact of a scope that was itself wrong. Fixing the scope dissolved the
trade-off rather than resolving it. It is worth asking, when a decision requires accepting a cost,
whether the constraint forcing it is itself correct — here it was not, and two decisions collapsed
into one.

**If drift is ever widened** to cover the application environment, the deny is what will stop it.
That is the moment to re-take the decision, not to delete the line.

---

## 2026-09-22 — The Organization and Identity Center exist, in the right order and the right region

**Completes the ordering constraint recorded on 2026-09-19**, which held that the account must move
to the Paid plan as a standalone action *before* creating the Organization, because upgrading by
joining one expires the Free Tier credits immediately and permanently. The upgrade happened on
2026-09-19 and the Organization on 2026-09-22, so the constraint held and the credits survive.

**What exists.**

| | |
|---|---|
| Organization | `o-yyhciflg3u`, feature set `ALL` |
| Management account | `437672023758`, the only account |
| Identity Center instance | `ssoins-7223046591f7f9f9`, `ACTIVE` |
| Identity store | `d-90667e73f9` |
| Home region | `us-east-1` |

**Feature set `ALL` rather than consolidated billing**, because Identity Center requires it. Switching
afterwards requires every member account to approve, which is cheap with one account and expensive
later.

**The home region was verified rather than assumed.** `sso-admin list-instances` is regional and
returns one instance in `us-east-1` and none in `us-west-2` or `eu-west-1`. An Identity Center
instance has one home region per organization and moving it means deleting the instance and
rebuilding every assignment, so a mismatch would have been discovered late and been costly. Every
other resource in this project is in `us-east-1`.

**Deliberately not done by hand.** No users, groups or permission sets were created in the console.
The design declares groups and permission set assignments in Terraform, because SCIM group sync is
not supported and the assignments are what several determinations rest on. The console action was
enablement only.

**Still blocked, and on what.** Wiring Google Cloud Identity as the SAML IdP with SCIM provisioning
needs a verified domain in Cloud Identity, which needs the domain decision that is still outstanding.
Until then Identity Center exists with no external identity source, and KSI-IAM-SNU, APM, AAM, ELP
and JIT remain unbuildable — but the prerequisite they were all waiting on is now in place.

**AWS root and break-glass stay native**, per the identity design, and are not routed through
Identity Center.

---

## 2026-09-22 — GCP phase 1 applied, and the two faults it took to get there

**Applied.** 30 resources. Landing bucket, BigQuery dataset and table, Artifact Registry repository,
two KMS keys and their key ring, two service accounts, Data Access audit configuration on the three
named services, and six APIs enabled. `terraform plan` returns "No changes", which refreshes every
resource against the live API and is therefore the verification, not a substitute for it.

Audit configuration confirmed live and matching the 2026-09-20 decision: `storage` DATA_READ and
DATA_WRITE, `bigquery` DATA_READ and DATA_WRITE, `cloudkms` DATA_READ. Not `allServices`.

**Fault one: `roles/editor` cannot set IAM policy.** The apply created keys and service accounts and
then failed on every IAM binding — `cloudkms.cryptoKeys.setIamPolicy` denied, and project policy
updates forbidden. This is deliberate in GCP: editor can create and delete almost anything but cannot
grant, precisely so that an automation identity cannot escalate itself.

**Resolved by granting `roles/cloudkms.admin` and `roles/resourcemanager.projectIamAdmin`**, and the
second deserves naming rather than burying. Combined with the `roles/editor` it already held,
`projectIamAdmin` makes `terraform-admin` effectively owner-equivalent, because the ability to set
project IAM is the ability to grant itself anything. There is no way around it: declaring project IAM
in Terraform requires the Terraform identity to be able to set project IAM. The alternative was
dropping the audit configs from declared state, and those are KSI-MLA-LET's Data Access logging,
chosen deliberately two days ago. The working rule applies — state the limitation rather than narrow
the scope to avoid it. **The provisioning identity's blast radius is now the whole project**, and
KSI-CNA-MAT and KSI-IAM-ELP should say so rather than let a reader assume otherwise.

**Fault two: service agents do not exist until they are induced.** With IAM fixed, the same three
grants failed differently: `Service account service-<n>@gs-project-accounts... does not exist`, and
the same for BigQuery's encryption agent and Artifact Registry's. The file constructed all three
addresses from the project number. The strings were correct. The accounts were not there, because GCP
creates a service agent on first use of its service, and a CMEK grant is not a use.

**Chosen: read the identities rather than construct them.**
`data.google_storage_project_service_account` and `data.google_bigquery_default_service_account`
return the agent and create it as a side effect, which both induces the account and ties the grant to
the identity instead of to a guess about its name.

**Artifact Registry needed the beta provider.** It has no inducing data source and the GA provider
has no `google_project_service_identity`. So `google-beta` is declared, impersonating the same
service account, used for exactly one resource. That is preferable to running
`gcloud beta services identity create` by hand: a declarative interface exists here, and the
Security Command Center exception was recorded precisely because for that one it does not. An
exception is for a platform limit, not for a provider being inconvenient.

**Both faults share a shape with the two found in AWS earlier today.** The configuration was
internally consistent, `terraform validate` passed, and a plan looked clean — the fault existed only
at the moment of execution, against the real API. Four for four today.

**What this unblocks.** `pipeline_service_account_unique_id` is `104894493962317106056`.
`infra/aws/cross_cloud.tf` is gated on exactly that value and has been `count = 0` since it was
written; it can now be applied. The Artifact Registry repository at
`us-central1-docker.pkg.dev/fedramp-20x-ksi-assessment/fedramp-20x-ksi` also now exists to receive
the analytics image, once there is a way to build one.

**Still outstanding on GCP:** Security Command Center Standard remains a console activation, as
recorded on 2026-09-20. The API is now enabled, which is the declarable half.

---

## 2026-09-22 — The offering is named, and the two subdomains follow from it

**Extends the 2026-09-19 decisions** on using a subdomain of an existing domain and on giving Cloud
Identity its own subdomain, by settling what those subdomains are actually called.

**The offering is "Caliper".** Until now the product had no name anywhere in the design — it was "the
application", and the SDR's offering had no identity. The name is grounded in what the code already
does rather than invented around it: the API accepts `{customer, metric, value, recorded_at}` and
reads it back, the worker extracts it, the GCP pipeline loads it into BigQuery. It is a metrics
ingestion and analytics platform, and a caliper is a precision measuring instrument.

| | |
|---|---|
| Offering | `caliper.elvievalmores.com` |
| Workforce identity | `corp.elvievalmores.com` |
| Apex | untouched — GitHub Pages, ProtonMail MX |

**Why a product name at all, having gone this far without one.** The first proposal was
`ksi.elvievalmores.com`, which labels the assessment rather than the product. Paired with `corp.` for
workforce identity it would have been half-realistic: a company with a corporate identity domain
whose product is named after the compliance framework it is being assessed against. Realism applied
to one half and not the other is worse than either extreme, because an inconsistency invites a reader
to ask which parts of the persona are load-bearing.

**Why `corp.` rather than `id.`, `sso.` or `accounts.`** This subdomain becomes the identifier for
every workforce principal, and those strings appear in SAML assertions, Identity Center, CloudTrail
and throughout the SDR's evidence. `corp.` reads as an organisation people belong to;
`id.`/`sso.`/`accounts.` describe infrastructure. It is also the long-standing convention for a
workforce tenant carved off an apex in use for something else, which is exactly the situation the
2026-09-19 entry described.

**The asymmetry that drove the care.** The application subdomain is trivially reversible — a new
certificate and a new record. The Cloud Identity subdomain becomes a tenant's primary domain, and
changing it later means migrating every principal and redoing SAML and SCIM. The two were treated as
one choice and they are not.

**Deliberately not renamed: the Terraform resources.** Everything stays `fedramp-20x-ksi-*`. The repo
is the assessment; Caliper is the thing assessed. Renaming live resources to match a documentation
name would be destructive churn for no benefit, and the two names having different scopes is correct
rather than untidy.

**Certificate requested**, not yet issued. `aws_acm_certificate.app` exists in `infra/bootstrap` for
`caliper.elvievalmores.com`, pending the hand-created DNS validation record — per the 2026-09-19
decision that validation is manual rather than through a DNS provider plugin.

**A limitation to record once the record exists.** The load balancer's hostname carries a generated
ID and changes every time the environment is rebuilt, so the record pointing `caliper` at it must be
updated each session. The certificate validation record is one-time; the application record is not.
KSI-PIY-RVD's `security.txt` is therefore reachable only while the environment stands, which is the
same shape as the collector cadence limitation and should be declared the same way.

---

## 2026-09-22 — The pipeline mechanism is built, and two "not yet" notes had gone stale

**Built: `pipeline_config_read`,** the fourth of nine evidence mechanisms, with ten check definitions
against the two real workflows. All fifteen checks in `collector/checks/` now pass.

**Its recorded dependency was out of date.** `not_yet_built.py` said it waited on "a CI/CD pipeline,
which this repo does not have yet". The pipeline was built on 2026-09-20 and the note was never
revisited, so a mechanism that had been unblocked for two days still reported itself as waiting.
Re-reading the blocked list found a second one in the same state:
`declared_versus_live_comparison` waits on "a reader for Terraform state", and the state has been in
S3 and readable throughout. Both are stale notes rather than real blocks. The remaining four —
register read, deliberate test, record store, effective access analysis — are genuinely blocked on
components that do not exist or decisions not taken.

**It reads the committed files, not the GitHub API.** GitHub runs what is on the default branch, so
the file under assessment and the file on disk are the same artifact. That means these checks need no
network, no credentials, and no standing environment — they keep working with everything torn down,
which is most of the time.

**What the ten checks cover.** Actions pinned to commit SHAs in both workflows (KSI-CNA-DFP), no
static cloud credential referenced in either (KSI-IAM-SNU), token permissions declared rather than
inherited, dependency auditing present (KSI-SCR-MON), manifest integrity checked before anything is
installed (KSI-SCR-MIT), images signed and **the signature verified before the digest is recorded**
(KSI-SVC-VRI), and publishing confined to the default branch (KSI-CMT-RMV).

**Order is asserted, not just presence.** `step_precedes` exists because in a build pipeline the
ordering is the control. Scanning after publishing still scans, but it reports on an artifact already
pushed; verifying a signature after recording the digest verifies something already deployable. Both
would satisfy a presence check and neither is the thing the determination claims.

**Every assertion has a negative control.** `collector/self_test.py` runs each of the six assertions
against a good workflow and a deliberately broken one, and reports an assertion that passes both as
broken rather than as passing. Ten green checks are otherwise indistinguishable from ten checks that
cannot fail — and four controls this month were found configured, deployed and inert while reporting
nothing. All six discriminate.

**One dependency trap closed on the way.** The mechanism parses YAML, and PyYAML was present only as
a transitive dependency of a Google library. It is now pinned in `requirements.txt` directly: a
version bump elsewhere could have removed it, and the failure would have surfaced as a collector that
could not read the pipeline.

**A YAML trap worth knowing.** In YAML 1.1, which PyYAML implements, the bare word `on` is a boolean.
A workflow's `on:` key therefore parses as `True`, not as the string `"on"`, and every naive lookup of
`workflow["on"]` misses it silently. The parser normalises this once so no handler has to know.

---

## 2026-09-22 — The certificate issued, and two things the certificate itself corrected

**Issued.** `caliper.elvievalmores.com`, Amazon-issued, DNS validation `SUCCESS`, after the
validation CNAME was created by hand at Cloudflare per the 2026-09-19 decision. KSI-SVC-ASM build row
4 now has a real chain of trust on the public listener rather than the self-signed fallback, and
KSI-PIY-RVD has a real domain to publish `security.txt` on.

**Correction: the certificate is valid 197 days, not thirteen months.** `NotBefore 2026-09-21`,
`NotAfter 2027-04-07`. Three places in this repository warned that deleting the validation record
"breaks renewal roughly thirteen months later" — a figure carried from how long ACM public
certificates used to last. Public certificate lifetimes have been shortening across the industry, and
the measured value is a little over six months. All three are corrected to read the dates off the
certificate rather than assume a duration.

**Why the error mattered more than the number.** The warning's purpose is to stop someone deleting
the validation record after issuance, on the reasoning that it looks like one-time setup. A warning
that says "this breaks in about a year" invites deferral in a way that "this breaks in four months"
does not. Renewal begins around **2027-02-06**.

**Open question: managed renewal under apply-and-destroy.** The issued certificate reports
`InUseBy: []` and `RenewalEligibility: INELIGIBLE`. The second may mean nothing here — that field
governs the `RenewCertificate` API, which applies to private certificates — so this is recorded as a
question rather than a finding.

The concern behind it is real regardless. ACM's managed renewal is documented as applying to
certificates associated with an integrated AWS service, and under this project's cost posture the
load balancer exists only during working sessions. For most of any given month the certificate is
associated with nothing. If association is genuinely required at renewal time, then the automatic
renewal that KSI-SVC-ASM build row 4 claims would not happen, and the failure would be silent and
roughly four months out.

**What to do about it, cheaply.** Verify the behaviour before 2027-02-06 — the mitigation, if needed,
is only to have the environment standing during the renewal window, which is a note in the runbook
rather than a design change. Recorded now because the deadline is real, the check is five minutes,
and the alternative is discovering it from an expired certificate.

**The shape is familiar.** This is the fifth thing this month that was configured correctly, reported
healthy, and might not do what its determination claims — and like the others, it is only visible by
reading what the system actually produced rather than what the configuration says it should.

---

## 2026-09-22 — The workforce directory exists, on Cloud Identity Free for now

**Built.** A Cloud Identity tenant on `corp.elvievalmores.com`, domain-verified by TXT record at
Cloudflare, with three accounts.

| Account | Role |
|---|---|
| `admin@corp.elvievalmores.com` | Tenant administrator. Break-glass, not a working identity |
| `alex@corp.elvievalmores.com` | Platform Engineer |
| `sam@corp.elvievalmores.com` | Security Engineer |

**The two personas hold deliberately different roles.** KSI-IAM-ELP requires that each user reach only
what they need, and KSI-IAM-JIT requires a role and attribute-based model. Two equivalent
administrators would leave both determinations with nothing to demonstrate — one permission set
applied twice is not a least-privilege model. Alex deploys and operates and elevates for data and IAM;
Sam reads broadly and manages security services and elevates for infrastructure. The elevation paths
cross, which is what makes JIT's lanes meaningful rather than decorative.

**The admin account is treated as AWS root is treated** — high value, strongly protected, rarely used,
and outside the team. It is not one of the two personas and will hold no standing AWS access.

**Free tier now, Premium at AAM.** SAML SSO is included in Cloud Identity Free; automated (SCIM)
provisioning is not. Rather than pay from today for a capability that will sit idle for several build
steps, the tenant starts on Free and upgrades when KSI-IAM-AAM's evidence is actually built. The
upgrade is a license change in the admin console, not a migration, so nothing is foreclosed. Roughly
6 USD per user per month, so about 12 USD monthly against a project running 15 to 25 — a real
increase, and accepted because the alternative reverses a determination.

**Why paying is the right answer rather than declaring a limitation.** The 2026-09-05 AAM decision
already considered and rejected the manual path: "Declaring users in code is automated provisioning,
not automated lifecycle. Nothing happens unless a person remembers to open the change." AAM's
statement is *"the lifecycle and privileges of all accounts, roles, and groups are securely managed
using automation"*, and its mappings are AC-2(1), AC-2(3), AC-2(13) and IA-4(4) — automated account
management, automated disabling, user status. Automation is not incidental to that indicator; it is
the whole statement. Manual user creation in Identity Center is the thing the determination rejected.

**Why the users are created by hand and this is not a contradiction.** A Terraform provider for
Workspace users exists, and using it would require either a service account key — which KSI-IAM-SNU's
durability hierarchy rates as failing, and which this project has none of — or domain-wide delegation,
a standing grant to impersonate any user in the directory. Either is a permanent expansion of the
credential surface to create two users once. It also inverts AAM's model, which makes Google the
authoritative directory and everything downstream a replica. Users originating in the directory is
that model working, not a gap in it.

**Deliberately not done in the console:** groups, permission sets and assignments. Those are declared
in Terraform per the 2026-09-05 decision, because SCIM does not sync groups.

**The apex was never touched.** `elvievalmores.com` keeps its ProtonMail MX and its GitHub Pages
records throughout; the tenant is scoped to the subdomain, and no mail routing exists or is wanted on
`corp`. The persona addresses are identifiers that appear in SAML assertions and evidence, not
mailboxes.

**Open item, unrelated to identity but surfaced here.** `security.txt` will advertise
`security@caliper.elvievalmores.com`, and KSI-PIY-RVD requires that contact be monitored. That
subdomain has no MX and Cloud Identity Free has no mailbox, so the address would currently bounce. It
needs a forwarding rule to somewhere actually read before that determination can be evidenced.

---

## 2026-09-22 — The federation works, proven by using it

**Google Cloud Identity is now the workforce identity provider for AWS**, with IAM Identity Center
trusting its SAML assertions. Verified by authenticating through it, not by reading the configuration.

| | |
|---|---|
| Google tenant | `corp.elvievalmores.com`, customer ID `C01rucqxe` |
| IdP sign-in URL | `https://accounts.google.com/o/saml2/idp?idpid=C01rucqxe` |
| IdP issuer URL | `https://accounts.google.com/o/saml2?idpid=C01rucqxe` |
| Identity Center instance | `ssoins-7223046591f7f9f9`, identity store `d-90667e73f9` |
| ACS URL | `.../platform/saml/acs/4941442d9bf9ddcf-a64b-4b2e-b754-e15ff995f103` |
| Google signing certificate | expires **2031-09-21** |

**The catalog app is the wrong one, and it fails in a way that looks like success.** Google's
directory offers "Amazon Web Services", which is the classic IAM federation connector: it requires
`https://aws.amazon.com/SAML/Attributes/Role` and `RoleSessionName`, asserting an IAM role ARN
directly into an account. Identity Center works the other way round — it identifies the user by
NameID and decides access itself through permission sets. It has no use for a Role attribute.

Configuring the catalog app would have completed cleanly on both sides and failed only at sign-in,
with an assertion naming a role unrelated to any permission set. No Identity Center entry exists in
this edition's catalog, so the app is a **custom SAML app**, which is also what AWS documents for
Google Workspace. Its attributes screen is deliberately empty; that emptiness is the difference
between the two apps.

**A first-sign-in prompt is indistinguishable from a broken trust.** The first attempt failed with
"Looks like this code isn't right", and CloudTrail recorded no authentication at all — the flow never
reached AWS. The cause was Google's own new-user first-login sequence, forcing a password change
before it would authenticate anyone. Signing in to the account directly once, clearing the prompts,
and retrying the portal worked immediately.

Recorded because the symptom pointed at the wrong layer. The error surfaced on an AWS page with an
AWS request ID, while the fault was entirely in Google, one step before AWS was involved. CloudTrail
showing *nothing* is what located it: a SAML trust that is misconfigured produces a failed
authentication event, and an absence of events means the assertion never arrived.

**Users are still not provisioned, by design.** Identity Center does not create users from a SAML
assertion — the record must exist before an assertion for it is accepted. SCIM is what creates them
and SCIM is Premium, so a single user was created by hand purely to prove the trust, then deleted.
That user was a test fixture and is not the provisioning path.

**What this leaves buildable, and where the seam falls.** Permission sets and groups can be declared
in Terraform now: groups are declared there anyway, because SCIM does not sync them. Account
assignments binding a group to a permission set can also be declared. What cannot be declared is
*membership* — putting Alex and Sam into those groups needs the users to exist, which needs SCIM.

So the seam is exactly where the 2026-09-05 decision said it would be: users through SCIM, groups
through Terraform. The build can proceed to the edge of that seam without Premium, and stops there.

**Open item.** No Identity Center sign-in events have appeared in CloudTrail. This may be delivery
lag, which runs to roughly fifteen minutes. If federated authentications genuinely do not reach the
corpus, KSI-MLA-LET's claim that authentication is logged would not hold for the workforce path,
which is the path that matters most. To be checked rather than assumed.

---

## 2026-09-22 — The registry persists, and the artifacts key changes shape to allow it

**Moved to the persistent side:** the two ECR repositories with their lifecycle policies, the extract
bucket with its encryption, versioning and lifecycle configuration, and the artifacts key both
encrypt with. 54 resources now persist between sessions, up from 40.

**Why, in order of weight.** The vulnerability scanner is a shared component nine indicators consume,
and it scans images in ECR. With the registry destroyed between sessions there were no images to scan
for most of any month, so the component was idle exactly when the environment was not standing —
which is most of the time. Second, `cross_cloud.tf` depends on the extract bucket and the artifacts
key and nothing else ephemeral, so it was blocked behind a full environment apply. Third, images
surviving means AWS phase 2 is reachable on any apply rather than only after a CI run. Cost is about
one dollar a month, almost all of it the KMS key.

**The store persists, the grants to transient principals do not.** Both stores' policies name roles
from `compute.tf`, so `registry_grants.tf` holds the ECR repository policy and the extract bucket
policy and stays ephemeral. A repository outlives the roles permitted to pull from it and the
permission reappears with them. This is the third instance of the same shape today, after
`pipeline_identity.tf` and the artifacts key itself, and it is now the rule rather than a workaround:
a persistent resource may not reference an ephemeral one, and the seam falls between the thing and
the permission to use it.

**The artifacts key policy no longer names roles, and that is a real trade.** A KMS key policy
validates that the principals it names exist — `PutKeyPolicy` rejects an ARN that does not resolve —
so a persistent key could not carry a policy naming `worker_task` and `task_execution`. The key
policy now grants the account, and those roles are authorised by their own IAM policies.

**What that costs, precisely.** Nothing in capability: `compute.tf` already grants `worker_task`
`kms:GenerateDataKey` and `kms:DescribeKey` on this key with the same `kms:ViaService` condition, and
`task_execution` `kms:Decrypt` and `kms:DescribeKey`. The statements removed were duplicating grants
that already existed. What is lost is the key policy acting as a second, independent backstop behind
IAM — so an over-broad IAM policy on those roles is no longer caught twice. Separate keys per data
class are unchanged, so per-class blast radius is unchanged. The ECR service principal grant stays,
because a service principal has no existence to validate and ECR needs key access to encrypt layers.

**Rejected: an ephemeral `aws_kms_key_policy` overlay.** It would have preserved the per-principal
policy exactly, but the provider documents that combining it with `aws_kms_key.policy` produces a
perpetual diff — and a perpetual diff would make the drift signal permanently positive, which is the
failure this project spent today eliminating. Trading a redundant backstop for a working drift check
is the better side of that.

**A cross-boundary reference the check caught.** `output "github_build_role_arn"` had been carried
into `pipeline_identity.tf` when that file was split out this afternoon, and it names a role declared
in `pipeline.tf`. An output is a reference like any other, and it would have failed to evaluate
whenever the environment was down. Moved back. Worth noting that the boundary check found it and
review did not — the same file was read twice today without it being seen.

**The cross-cloud role now exists.** Applied with the GCP pipeline service account's numeric unique
ID `104894493962317106056`, and AWS accepted a trust policy pinning both `accounts.google.com:sub`
and `accounts.google.com:aud` to that value. This is the first time the cross-cloud path has been
anything but declared, and it validates the 2026-09-20 decision to match the numeric ID rather than
the service account email, along with the 2026-09-21 audience fix.

**Drift re-verified after the boundary moved**, because the boundary is what drift is scoped to: 54
persistent targets, exit 0, "No changes."

**One limitation of `boundary.py` noted rather than fixed.** It derives both halves from Terraform
state, so it lists what exists and cannot propose creating what does not. Moving resources onto the
persistent side therefore needed a one-time apply targeted by declaration rather than by boundary.
That is the right trade — deriving from state is what stops the list rotting — but it means the
script is for teardown and drift, not for provisioning.

---

## 2026-09-23 — The pipeline identity persists in full, so CI no longer needs the environment

**Moved to the persistent side:** `pipeline.tf` (the build role) and `cross_cloud.tf` (the role the
GCP analytics pipeline assumes). 58 resources now persist and nothing is ephemeral in state.

**This became possible rather than being decided.** Both files depended on the container registry and
the artifacts key, and once those moved on 2026-09-22 neither had an ephemeral dependency left. The
dependency check reported it; the change follows from it.

**Why it matters more than "two IAM roles".** The build role used to die with the application
environment, so `build-and-push` could only run after a full apply. That is circular: the workflow's
entire job is producing the images the environment is waiting for, and it could not run until the
environment it was blocking existed. CI can now run against a torn-down environment, which is the
state it will normally find.

**A gate that would have reported itself as drift.** `cross_cloud.tf` gates its role on
`var.gcp_pipeline_sa_unique_id`, and the drift workflow did not set it. While the file was ephemeral
the scoped plan never targeted it and the omission was invisible. On the persistent side the plan
targets it, the variable evaluates empty, `count` resolves to zero, and the plan proposes destroying
a role that should exist — reported as drift on every run.

The variable is now a repository variable, `GCP_PIPELINE_SA_UNIQUE_ID`, and `drift.yml` passes it.
Worth recording as a pattern: **moving a file across the boundary changes which variables the drift
plan must have**, because targeting determines what gets evaluated. A gated resource crossing to the
persistent side brings its gate with it.

**Verified after the move**, not before: 58 targets, exit 0, "No changes."

**Context from the same morning.** The first unattended scheduled drift run since the scoping fix
completed successfully — 2026-09-23T12:30:57Z, 37 seconds, against a torn-down environment. That is
the condition the check was failing on every day before yesterday, and it now passes without
anyone watching.

---

## 2026-09-23 — The pipeline produced signed images, for the first time

**`build-and-push` completed.** Five jobs green: dependency scanning for both services, both builds
published, and the change event emitted. It had never run to completion before — its first attempt on
2026-09-22 failed on the OIDC subject mismatch, and it could not run at all after that until the
build role stopped being destroyed with the environment.

| | api | worker |
|---|---|---|
| tag | `v1` | `v1` |
| digest | `sha256:b515cd4083afb1a4f…` | `sha256:2edeeb77b3d4469d7…` |
| signature | `sha256-b515cd40….sig` | `sha256-2edeeb77….sig` |

**Verified against the registry, not against the run's exit status.** The `.sig` artifacts exist in
ECR and their tags match their images' digests exactly, and the digests the workflow recorded match
what ECR reports. A green workflow that published nothing would look identical from the run page.

**What now has evidence that did not.** KSI-SVC-VRI has real signed images referenced by digest,
KSI-SCR-MON has a dependency audit that ran against real manifests, KSI-SCR-MIT has manifest
integrity checked before install, KSI-CMT-RMV has a registry push traceable to a commit, and
KSI-CNA-DFP has every action pinned to a commit SHA in a workflow that has actually executed.

**AWS phase 2 is now reachable** — the digests above are what `deploy_services = true` pins to.

---

## 2026-09-23 — Open question: the posture services are ephemeral, so nothing scans the images

**Found immediately after the images landed**, by checking whether Inspector had picked them up. It
had not: `list-coverage` returns empty, Inspector reports `DISABLED`, GuardDuty has no detector, and
the account is not subscribed to Security Hub. All three are declared in `posture.tf`, on the
ephemeral side, and the environment is down.

**This corrects a claim made yesterday.** Persisting the registry was argued for partly on the
grounds that it would give the vulnerability scanner something to scan continuously. That was wrong,
and wrong in a way that was checkable at the time: the images persist and the scanner does not, so
the benefit is not realised. The other two reasons — unblocking `cross_cloud.tf`, and making phase 2
reachable without a rebuild — held and have now both been demonstrated.

**Why it matters beyond the one argument.** The vulnerability scanner is a shared component nine
indicators consume. GuardDuty is KSI-IAM-SUS's detection source. Security Hub is KSI-CNA-IBP's entire
benchmark basis, and supplies two of KSI-SVC-EIS's three finding sources. None of them exists between
sessions.

**The word the catalog keeps using is "persistently".** KSI-IAM-ELP and KSI-IAM-JIT both require
access models "persistently reviewed"; KSI-SCR-... requires effectiveness "persistently reviewed". A
posture service that exists for a few hours a week is difficult to describe that way honestly, and
the honest description is what the determination has to carry.

**The cost, from the 2026-09-19 estimate.** Roughly 3 to 8 USD per month for the three together —
Security Hub priced per resource unit, Inspector per image scan at about nine cents initial and a
cent per rescan, GuardDuty per event volume. Against a residual currently near zero, that is the
largest standing cost the project would have taken on.

**`posture.tf` is eligible.** Its only reference outside itself is `aws_sns_topic.detection_interim`
in `detection.tf`, which is already persistent. So this is a cost decision and nothing else.

**Not decided.** Recorded for the design conversation, as the free-tier question was, because it
changes what several determinations can claim rather than how something is built.

---

## 2026-09-23 — Phase 2 ran, and the application served a request

**The first time the offering has ever run.** Both services deployed from digest-pinned images built
by the pipeline, the migration created the schema and the IAM database roles, and a request went in
and came back out:

```
GET  /readyz              200  {"status":"ready"}
POST /measurements        201  {"id":1,"recorded_at":"2026-09-23T21:19:55Z"}
GET  /measurements/acme   200  {"metric":"latency_ms","value":42.5}
```

**No database password exists anywhere in the system.** That insert authenticated with IAM. The path
had never been executed before and is the kind that looks correct in configuration and fails on first
connection.

**What the two-phase gate proved.** Phase 1 cannot declare services because a digest cannot be looked
up for an image that does not exist; phase 2 pins to the digest the tag resolves to. Both halves have
now run. KSI-SVC-VRI's constraint is not a inconvenience the build works around — it is the reason
the deployed task definitions name `@sha256:…` rather than a tag.

**The edge, end to end.** The load balancer carries the ACM certificate issued for
`caliper.elvievalmores.com` on 2026-09-22 — verified by ARN, not by assumption — HTTPS answers over
HTTP/2, and `security.txt` is served at the well-known path with its rotating expiry. KSI-SVC-ASM
build row 4 and KSI-PIY-RVD both have a real target for the first time.

**Least privilege in the database, from the migration itself.** `api_service` holds SELECT and INSERT
on `measurements`; `worker_service` holds SELECT only; `CREATE ON SCHEMA public` is revoked from
PUBLIC. Both roles are granted `rds_iam` and nothing else. That is KSI-IAM-ELP demonstrable at the
data layer rather than only at the cloud control plane.

---

## 2026-09-23 — Two hardening controls collided, and the fix is better than the design

**Every api task crashed on first start:**

```
PermissionError: [Errno 13] Permission denied: '/tmp/tls'
```

**Two deliberate decisions produced it.** `readonlyRootFilesystem = true` makes mounted volumes the
only writable paths. The container runs as uid 10001, declared in both the Dockerfile and the task
definition so the two can be compared. Fargate mounts the task's ephemeral volume owned by root with
mode 0755. So the single writable path was not writable by the process that needed it, and neither
decision was wrong on its own.

**The worker was unaffected**, which is why this surfaced as one service failing rather than the
environment failing. The worker has no TLS listener and writes nothing.

**Measured from inside a task on the cluster**, rather than reasoned about:

```
proc uid/gid  10001 10001
/dev/shm      owner 0 0  mode 0o1777  writable True
/var/tmp      owner 0 0  mode 0o1777  writable False
/tmp          owner 0 0  mode 0o0755  writable False
```

`/var/tmp` is world-writable in the image and still refused, because it belongs to the read-only root
filesystem. `/dev/shm` is a separate tmpfs mount and is not covered by that flag. Two diagnostic
tasks were needed: the first passed `["python","-c",…]` as a command override against an image whose
entrypoint is already `python`, and failed with `can't open file '/srv/python'`.

**Chosen: materialise the certificate in `/dev/shm`.** This is an improvement, not a workaround. The
code's own comment had described the volume as "ephemeral storage rather than tmpfs — encrypted at
rest and destroyed with the task, but not memory". `/dev/shm` *is* memory, so the TLS private key now
never reaches a filesystem at all. The property the author wanted and settled for missing is now the
one in place.

**The volume is kept and annotated** rather than removed, so that nobody reads it as writable again,
and so the task definitions do not diverge from the hardening block every service shares.

**Why this could not have been caught earlier.** `terraform validate` passes, the plan is clean, the
image builds, the dependency scan passes, the task definition and the Dockerfile agree on the uid,
and the container starts. It fails on the third line of application startup, in an environment that
had never been stood up. This is the fifth control this week found non-functional while appearing
correctly configured — and the first found by running the application rather than the tooling.

---

## 2026-09-23 — Inspector produced real findings, and they are not the ones CI reports

**With the environment standing, Inspector scanned the images** and reported per image: 4 critical,
14 high, 12 medium. A sample: `CVE-2026-82560 — perl`, high, `fixedInVersion: NotAvailable`.

**None of these are findings the pipeline's dependency audit can produce.** `pip-audit` runs against
`requirements.txt` and passed; these are operating-system packages in the
`python:3.12-slim-bookworm` base image. The 2026-09-19 decision rejected basic ECR scanning on the
grounds that it covers OS packages only and would leave application dependencies unscanned. The
inverse holds too, and both halves are now evidenced rather than argued: CI covers the dependency
manifest, Inspector covers the image, and the seam between them is the base image's own packages.

**`fixedInVersion: NotAvailable` on a high-severity finding is the interesting case** for KSI-SCR-MIT
and KSI-SCR-MON — a vulnerability with no available remediation is exactly what the accepted-risk
register exists for, and the project now has a real instance rather than a hypothetical one.

**This is what persisting the registry was supposed to buy** and, as recorded yesterday, does not
buy on its own: the images persist and Inspector does not. These findings exist because the
environment was standing. The open question about `posture.tf` is unchanged.

---

## 2026-09-23 — Torn down after phase 2, and drift checked over the full persistent set for the first time

**Most of this entry comes from a handoff file.** The session that ran phase 2 lost read access to the
repository partway through its final verification: first `archive_file` could not read the Lambda
sources, then the whole directory returned `Operation not permitted`, including to `git`. Writing new
files still worked, and so did the AWS and GitHub credentials. So the teardown outcome went into
`docs/HANDOFF-2026-09-23.md` (commit `78dda77`) and not into this log. The next session folded that
file in here and deleted it. Everything below was checked again against the live accounts before it
was written down.

**The teardown completed.**

```
Apply complete! Resources: 0 added, 0 changed, 118 destroyed.
```

The background process reported exit -1. The harness caused that by losing the process handle at a
session boundary. It was not a Terraform failure: the completion line comes from the run's own
output, and the AWS API confirmed the result afterwards.

**Verified gone, twice.** The first check was at the end of the session. The second was at the start
of the next one, 2026-09-23 around 21:35 UTC. No load balancer, no database, no ECS cluster, no VPC
other than the default one, no endpoints, no NAT gateway, no Elastic IP, no instances. The posture
services are gone as well: Inspector reports `DISABLED`, GuardDuty has no detector, and the account is
not subscribed to Security Hub.

**Verified preserved.** 58 managed resources remain in state, and `boundary.py --ephemeral` returns
nothing. `terraform state list` shows 103 entries; the other 45 are data sources, which the boundary
leaves out. The log store has Object Lock `COMPLIANCE` / 7 days. CloudTrail is multi-region and the
Config recorder is recording. Both Lambdas are present, and one customer-managed key is enabled, the
artifacts key. Fifteen other customer-managed keys are in `PendingDeletion` and will clear on their
own.

**The images survived. This is the first time the 2026-09-22 persistence decision has been tested by
a teardown.** ECR holds 8 manifests each for `api` and `worker`. The tags are `v1`, from the first
build, and `git-f9f2c35f8fd1`, from `build-and-push` run 35920972765 on commit `f9f2c35`. Each tagged
index has a `.sig` whose tag matches its digest exactly. **`git-f9f2c35f8fd1` is the tag to deploy**
because it carries the `/dev/shm` certificate fix; `v1` still crashes the api. Phase 2 no longer
needs a rebuild first. The pipeline verifies each signature before it records the digest. This
session checked only that the digests match: there is no `cosign` on the workstation, so nothing was
verified cryptographically from outside CI.

**GCP was unchanged, as expected.** 30 managed resources and no Cloud Run jobs. A full plan returned
"No changes".

**The handoff's drift reasoning was wrong.** It rated the unverified drift check as low risk because
the scheduled run at 12:30 UTC passed and "the persistent set has not changed since". That run was on
`7f78937`, the commit *before* `7806abe` moved `pipeline.tf` and `cross_cloud.tf` across. The
`GCP_PIPELINE_SA_UNIQUE_ID` repository variable was created at 20:38 UTC, eight hours after it. So the
scheduled run checked a smaller set of resources with a different variable set, and CI had never run
drift against the 58. The "58 targets, exit 0" recorded in the entry above was a local plan made with
administrator credentials. It could not show whether the *drift role* can read the two roles that had
just moved.

**Now it has.** Dispatched run 35923874415 on `78dda77` printed "checking 58 persistent resources"
and exited 0 with "No changes". It refreshed 58 resources, among them `aws_iam_role.github_build`,
`aws_iam_role.gcp_pipeline[0]` and both of their inline policies. The `[0]` shows the gate evaluated
non-empty, so the new variable is actually reaching the plan.

The lesson repeats the one in the pipeline-identity entry above from another direction. A green run
only covers what that run targeted. **A passing drift run is evidence about the boundary as of its
commit, not the boundary as it stands today.**

**Two corrections the handoff surfaced.**

- **`APP_DOMAIN` is not a repository variable**, although the handoff listed it among the values
  "held in GitHub repository variables". `drift.yml` passes `vars.APP_DOMAIN`, which comes through as
  an empty string. That is harmless at present: `var.app_domain` is used only in `edge.tf` and
  `secrets.tf`, and both are ephemeral, so the scoped plan never evaluates it. But the line looks as
  though it does something and does not. It becomes a real fault if anything using the domain moves
  to the persistent side, which is the same pattern as `GCP_PIPELINE_SA_UNIQUE_ID`. Left open.
- **`boundary.py`'s docstring said "Five files"** while listing ten. Corrected in the same commit as
  this entry.

**Also not in any variable store:** the GCP root needs `billing_account_id` for a plan. The value is
read with `gcloud billing projects describe`.

---

## 2026-09-23 — Resolved: the posture services persist

**Chosen.** `posture.tf` moves to the persistent side: GuardDuty, Security Hub with the CIS and FSBP
standards, Inspector for ECR, and the GuardDuty findings rule. This resolves the open question
recorded earlier today. 65 resources now persist.

**Considered.**

- **A.** Persist all three.
- **B.** Persist GuardDuty and Inspector, and keep Security Hub ephemeral.
- **C.** Keep all three ephemeral, but export their findings to the log store.
- **D.** Keep all three ephemeral, and declare that as a limitation.

**Why A.**

- **Teardown deleted the evidence.** Removing a detector or switching off Inspector deletes their
  findings. Before this change, the phase 2 Inspector results existed only as prose in this log.
  That includes the high-severity finding with `fixedInVersion: NotAvailable`, the project's first
  real accepted-risk case.
- **What the services watch persists.** That is the images, the CloudTrail stream, the IAM roles and
  the log store.
- **GuardDuty cannot catch up.** It analyses events as they arrive and does not go back over earlier
  ones, so anything that happens while it is off is never examined. Security Hub and Inspector
  evaluate current state and could be caught up at the start of a session. GuardDuty could not.

**What it gives up.** Roughly 3 to 8 USD a month. That figure comes from the 2026-09-19 estimate and
has not been measured. It is the first persistent resource chosen for evidence value rather than
because it is free or because the architecture needs it.

**The broader principle was not decided.** The counter-argument was that the 3-day collector cadence
limitation is an accepted precedent of the same shape. Several collector checks also target
persistent resources, so "what it watches persists" would reach the collector schedule too. This
decision covers `posture.tf` only. The collector schedule stays ephemeral and its limitation stands
until someone decides otherwise.

**How it was moved.** `posture.tf` was added to `PERSISTENT_FILES`, followed by a one-time apply
targeted at its seven resources (7 added, 0 changed, 0 destroyed). The file's references were checked
first. Outside itself it references only `aws_sns_topic.detection_interim` (persistent) and the
`aws_region` and `aws_caller_identity` data sources, which `pipeline.tf` already uses. It sets no
variables, so no drift gate comes with it. The drift role already held read permissions for all three
services from the 2026-09-22 work.

**Verified by using it.**

- GuardDuty is `ENABLED` and publishes every 15 minutes.
- Inspector is `ENABLED` for ECR, and the registry scan type switched to `ENHANCED`.
- Both Security Hub standards report `READY`.
- The findings rule is `ENABLED` and targets the detection topic.
- Inspector rescanned the persisted images and reproduced the phase 2 result exactly: 4 critical,
  14 high and 12 medium per image.
- Local drift plan over the 65 persistent resources: exit 0, "No changes". Then CI drift run
  35925317909 on `8440e6a` did the same, refreshing all 65 including the seven posture resources.

**Inspector scans 4 of the 16 manifests in ECR.** The other 12 report `UNSUPPORTED_MEDIA_TYPE`:
they are image indexes, cosign signatures and build attestations. The 4 are the platform images, one
per repository per build. That matters for cost, because Inspector bills per image scanned.

**The trials are running, so the cost can be measured before it is paid.**

| Service | Trial | Ends |
|---|---|---|
| Inspector (ECR) | Started 2026-09-21 19:05 EDT, when phase 1 was first applied | **2026-10-06** |
| GuardDuty | 29 days remaining on 2026-09-23 | about 2026-10-22 |
| Security Hub | No API reports trial status | Check the console |

Read each service's projected post-trial cost before 2026-10-06 and compare it with the 3 to 8 USD
estimate. If Security Hub is where the cost concentrates, option B is the recorded fallback.

**Still unverified.** Security Hub runs its controls as AWS Config rules, and the recorder is
deliberately scoped to the types the inventory needs. Controls for types the recorder does not
record will produce no findings, not passing ones. First evaluations take up to a day, so check
which controls report data. Whether those Config rule evaluations bill separately is part of the
same cost check.

---

## 2026-09-23 — Declared versus live is built, on a full plan rather than refresh-only, and the drift it found was not drift

**Built: `declared_versus_live_comparison`**, the fifth of nine mechanisms. It has two assertions:

- `no_drift` serves KSI-SVC-ACM's "zero drift between declared and live configuration".
- `declared_exists_live` serves "every resource in declared state exists in the environment".

There are four check definitions, one per assertion per cloud. All 19 checks pass. The reverse
direction, `live_is_declared`, is deferred on purpose (below).

**It runs Terraform itself.** It does not read the drift workflow's result, because reading CI's
verdict would only check that a check passed. It also covers GCP, which `drift.yml` explicitly does
not. If a required `TF_VAR_` is missing, the check reports an error, never a pass: the plan would be
evaluating a different configuration. The check definitions list those variables, so each
definition records what its plan was evaluated with.

**The approved design was refresh-only, and it was reversed on evidence.** The reasoning had been
that a refresh-only plan's `resource_drift` isolates changes made outside Terraform, which is the
catalog's meaning of drift. Tried against both real roots, it reported ten changes, and none of them
was an out-of-band change:

- `null` against `{}`, on `labels`, `resource_tags` and an event rule's `tags`.
- `null` against `0` or `false`, on six storage lifecycle condition fields.
- Server-side `etag` and `updated` metadata. Every project IAM binding shares one `etag`.
- A BigQuery access list returned in a different order, with `roles/bigquery.dataOwner` and
  `dataEditor` reported under their legacy names `OWNER` and `WRITER`. Same grants, different
  spelling.

Refresh compares raw stored values. It does not apply the provider's own rules for when two values
mean the same thing, which is why a full plan on the same roots was clean. Filtering this noise by
hand means writing rules like "treat `null` and `0` as equal" and "ignore `etag`", and each rule is
a place real drift could hide.

**Chosen: the verdict comes from a full plan, and refresh is used only where it is reliable.**

- **Classifying each change.** "Changed outside Terraform" means refresh saw the object move.
  "Follows from another change" means every differing attribute is unknown until apply. Otherwise it
  is "declaration not applied".
- **Detecting deletion.** An object is either there or it is not, so refresh's delete entries can
  be trusted.

This also matches the design matrix's own wording for the row: "Terraform plan in check mode, exit
status and diff".

**What it gives up.** An attribute the configuration does not manage is invisible to a full plan.
If someone attached a bucket policy out of band to a bucket whose policy resource is not standing,
`no_drift` would stay green. That belongs to a config-read check on the attribute itself.

**Scope is every managed address in state, passed as `-target`.** An untargeted plan evaluates the
whole configuration, and with the environment down it fails on `edge.tf` indexing
`time_rotating.security_txt[0]` and `aws_acm_certificate.public[0]`, which are not standing.
Targeting what is in state checks everything standing: the persistent set between sessions, and the
whole environment while it is up. The variables must match the phase that was applied. Run against
a standing phase 2 without `deploy_services=true`, the plan proposes destroying the services, and
reports that, correctly, as declared and live disagreeing under the configuration it was given.

**Proven against a real change, as SVC-ACM's automation assurance requires.** "A drift detector that
has never detected drift is an assumption rather than a property."

1. Clean: 65 of 65 match.
2. Added the tag `OutOfBandTest` to the extract bucket through the S3 API, preserving the existing
   three tags.
3. `no_drift` failed with 2 of 65. It attributed `aws_s3_bucket.extracts` (`tags`, `tags_all`) to
   "changed outside Terraform". `declared_exists_live` still passed, correctly, because the bucket
   still existed and had only changed.
4. Restored the original tag set exactly, confirmed by comparing it with the saved copy.
5. Clean again: 65 of 65.

**The live test found a flaw in the attribution.** The second change in step 3 was
`aws_iam_role_policy.gcp_pipeline[0]`. Its policy document is a data source that names the extract
bucket. With the bucket carrying a pending change, Terraform postponed reading that data source until
apply, so the policy showed as unknown. It had been labelled "declaration not applied", which was
wrong, and the third cause, "follows from another change", was added for it. Using fixtures alone,
this would never have come up.

**The self-test covers the new mechanism.** `self_test.py` has seven plan fixtures, including the
null-against-`{}` case, which must *pass* `no_drift`, and the knock-on case. The self-test was then
checked against two deliberately broken versions of the mechanism. One was the rejected refresh-based
`no_drift`; the other was a `declared_exists_live` that ignored deletions. The self-test flagged both.

**Deferred: `live_is_declared`.** This is SVC-ACM row 17 and IAM-AAM row 106. It needs a list of live
resources that are legitimately outside Terraform: service-linked roles, the bootstrap state bucket
(which has its own state), AWS-managed keys, Identity Center's `AWSReservedSSO_*` roles, the default
VPC and its subnets and security group, and the `terraform-admin` user. Each entry is a decision with
a reason, not an implementation detail.

---

**Found on the way: the extract bucket has no bucket policy between sessions.** The first
refresh-only run reported `aws_s3_bucket.extracts`'s `policy` as changed from a three-statement
document to empty. It is not out-of-band drift. The teardown removed `aws_s3_bucket_policy.extracts`
through Terraform, and the bucket's mirrored copy of the policy was left stale in state. But what it
points at is real: `get-bucket-policy` returns `NoSuchBucketPolicy`.

`DenyInsecureTransport` and `DenyUnencryptedWrites` are declared in `registry_grants.tf` alongside
the grant to the worker role, and that file is ephemeral. The 2026-09-22 rule, "the store persists,
the grants do not", was applied at file level, and the protective denies went with the grants. The
cross-cloud role is persistent and holds `s3:GetObject` on this bucket. So between sessions a
standing principal can read customer-data extracts from a bucket that does not require TLS. Default
encryption is persistent (`aws_s3_bucket_server_side_encryption_configuration.extracts`), so objects
are still encrypted at rest.

**Neither drift check could see it.** The policy resource is not in the persistent set, and the
bucket's `policy` attribute is computed, so a full plan refreshes it silently. By the count this log
has kept, this is the sixth control this week found configured and inert.

**Not fixed; it needs a decision.** S3 allows one policy per bucket. The policy's third statement,
`DenyWritesOutsideVPC`, names the worker role and the VPC endpoint, both ephemeral, so the policy
cannot simply move to the persistent side as written. Recorded in the open items.

---

**Two corrections.**

- **No collector schedule exists, and none ever did.** `PROJECT-CONTEXT.md`'s known limitations said
  the framework "runs on a real 3-day schedule via EventBridge and Cloud Scheduler". Neither root
  contains such a resource. The only schedules are the detection-query Lambda's and the GCP
  analytics pipeline's. The collectors are run by hand. The posture entry above, written earlier
  today, said "the collector schedule stays ephemeral and its limitation stands". That was wrong in
  the same way: there is no schedule to be ephemeral. The real gap is that no collector runtime or
  schedule exists. Whether one should persist is a question for when it does.
- **The drift workflow's own record understated its scope.** Every run's job summary said it checked
  "the log store, Athena, Glue, CloudTrail, the Config recorder, both Lambdas and the budget
  guardrail". The plan was checking 65 resources, including the registry, the CI roles, the
  cross-cloud role and the posture services. The list is now generated from `boundary.py --files`,
  so it cannot go stale again.

---

## 2026-09-23 — The extract bucket's protections persist, and the VPC restriction moves to the worker

**Chosen.** The extract bucket's policy is split by what each statement is about:

- **`DenyInsecureTransport` and `DenyUnencryptedWrites` move to `registry.tf` and persist.** They are
  properties of the store, not grants.
- **`DenyWritesOutsideVPC` becomes `WritesOnlyThroughEndpoint` in the worker role's own policy in
  `compute.tf`.** It is ephemeral, next to the VPC endpoint it names.

`aws_s3_bucket_policy.extracts` keeps its address, so there was no state move, only a one-time
targeted apply: 1 added, 0 changed, 0 destroyed. 66 resources now persist.

**Considered.**

- Keep the policy ephemeral and declare the gap.
- Make the whole policy persistent and rewrite the VPC statement so it names no ephemeral resource:
  the role ARN as a constructed string, and `aws:SourceVpc` or `aws:SourceVpce`. Both of those
  change on every apply, so the statement would still depend on something ephemeral.
- Two policy resources on one bucket. S3 allows one policy per bucket, so two resources would
  overwrite each other on every apply, and the teardown would delete the policy either way.

**Why this one.** It is the 2026-09-22 rule applied correctly, not a new rule. "The store persists,
the grants to transient principals do not." That rule had been applied at file level, and the file
held protections as well as a grant. A statement that restricts one transient principal belongs with
that principal.

**What it gives up.** An explicit deny wins wherever it sits, so the effect is the same. What changes
is who can remove it: whoever can edit the worker role's policy can now drop the restriction without
touching the bucket. Any such edit is a non-pipeline IAM mutation, which is what KSI-SVC-ACM's
mutation query exists to watch.

**Verified by trying it, as `terraform-admin`.**

| Request | Result |
|---|---|
| List over HTTPS | allowed |
| List over plain HTTP | `AccessDenied`, explicit deny in a resource-based policy |
| `PutObject` without the KMS header | `AccessDenied`, explicit deny in a resource-based policy; no object created |

The worker-side statement can only be tested while the environment stands. **Verify it at the next
phase 2:** an extract written by the worker must still land.

**The boundary property is now checked by a tool.** It has been checked by hand three times: on
2026-09-22 for the registry, and today for the pipeline identity and for `posture.tf`. Now
`boundary.py --check` reads the persistent files and fails on any reference to a resource declared
outside them, naming the file, the line and the target.

It was proven able to fail. A probe reference from `registry.tf` to `aws_vpc_endpoint.s3` was
reported as `registry.tf:203 -> aws_vpc_endpoint.s3 (network.tf)` with exit 1, then the probe was
removed. `drift.yml` runs `--check` before its plan, so a crossing is reported as a crossing instead
of as drift.

---

## 2026-09-23 — Live-is-declared built, exclusions are verified rules, and what the inventory held

**Built: `live_is_declared`**, the reverse direction of declared versus live. It serves KSI-SVC-ACM
row 17, "every machine-based resource in the inventory appears in declared state". The live side is
the KSI-PIY-GIV inventory, because the row names it as the source. The declared side is the union of
the named roots' state: `aws` together with `bootstrap`, because the bootstrap root holds what the
other root stands on.

**Exclusions are rules verified against the provider, never name patterns.** Each exclusion is
written into the check definition with its reason, and has one of two shapes:

- **A predicate the mechanism asks the owning service about.** Is this role's IAM path
  `/aws-service-role/`? Is this VPC the default? Is this key AWS-managed, or a customer key in
  `PendingDeletion`? Is this service account in a domain Google owns?
- **An exact match on one named identity.**

A role named `AWSServiceRoleForAnything` at an ordinary path is not excused, and the self-test
asserts that. An exclusion anyone could satisfy by choosing a name would be a hole with a reason
attached.

**The report of unused exclusions paid for itself immediately.** The first GCP run matched named
exclusions against the inventory's `name` field, which on GCP is a display name ("Terraform Admin").
Both exclusions went unused, and the report said so. GCP exclusions now match the full resource ID,
which no one can rename.

**Result.** GCP: 12 live resources, 9 declared, 3 excused, passes. AWS: 54 live resources, 53
accounted for, **fails on one**, and it is right to.

| Excused (AWS) | Count | Rule |
|---|---|---|
| Service-linked roles | 11 | IAM path is `/aws-service-role/` |
| KMS keys | 18 | 3 AWS-managed, 15 `PendingDeletion` from teardowns |
| Default VPC, its subnets, its default security group | 8 | `IsDefault`; only the group named `default` |
| `terraform-admin` user | 1 | by name, and see the finding below |

**The project VPC's default security group is deliberately not excused.** Nothing declares it
(`aws_default_security_group` is absent), so while the environment stands its rules are whatever AWS
defaults to, not code. The check will fail on it at every phase 1, and that is correct. The remedy is
to declare it with no rules. Recorded in the open items.

---

**Finding: the inventory lists a resource that does not exist.** The one unaccounted resource is
`sg-0ac03881f5bd7c3b7`, the default security group of the project VPC destroyed at 17:28 EDT. Config
recorded the VPC's deletion. It had not yet recorded the deletion of the VPC's default group, which
went implicitly with the VPC. `SelectResourceConfig` still reported the group as present, and EC2
answered `InvalidGroup.NotFound`. The check reported it with that note rather than silently
excusing it.

> **Corrected later the same day.** This paragraph originally said Config "never recorded" the
> deletion and that the group was still listed "five hours later". Both were wrong. The teardown
> finished minutes before this session began, so the check ran about 50 minutes after it, not five
> hours. Config recorded `ResourceDeleted` for the group at 18:38:57 EDT, about 70 minutes after the
> VPC, and the check then passed. The finding is a lag, not a permanent defect. See the SDR emitter
> entry below.

This belongs to KSI-PIY-GIV, not here. The Config-backed inventory lists a resource that is gone for
as long as Config's lag lasts on implicit deletions.

**Finding: `terraform-admin` on AWS is an IAM user with `AdministratorAccess`, a static access key
active since 2026-09-17, and no MFA device.** It is the identity every local apply in this project
runs as, including today's. No AWS-side decision about it is recorded. The GCP `terraform-admin`,
by contrast, is recorded (2026-09-22) and has no user-managed keys. It is impersonated.

This is the kind of credential KSI-IAM-SNU's durability hierarchy rates lowest, held by the
highest-privilege identity in the account. Identity Center now exists, so short-lived credentials
through `aws sso login` and an administrative permission set are available. **Not acted on**, because
changing the operator's own access is the user's call. It is excused from `live_is_declared` only,
and the exclusion's reason says so.

**Finding: the default Compute Engine service account holds `roles/editor` on the project.** Google
created it when the Compute Engine API was enabled. Nothing in this project uses Compute Engine. So
it is a standing grant of edit on everything, with no declared operation behind it, which is the
pattern KSI-IAM-ELP and KSI-CNA-MAT's blast-radius computation exist to surface. Not acted on.
Removing the binding or disabling the account are both one command, and the choice is the user's.

---

**Four KSI-SVC-SIN checks, and a gap one of them found.**

| Check | Row | Result |
|---|---|---|
| Every bucket denies non-TLS requests to itself and its objects | Build row 2, "TLS-only bucket policies". **No verify row checks it** | Failed on the Athena results bucket, which had no policy. Fixed; now 5 of 5 |
| Every bucket blocks all four public access paths | 40 | 5 of 5 |
| Log store Object Lock, `COMPLIANCE`, at least 7 days | 43 | Passes |
| Trail logging with log file validation | 43 | Passes |

The Athena results bucket now carries the same `DenyInsecureTransport` as the other four. It is
persistent, in `log_corpus.tf`, and references nothing ephemeral (`boundary.py --check`). It was
applied once, targeted, and plain HTTP is refused with an explicit deny. 67 resources now persist.

**The bucket checks take their population from `s3:ListBuckets`**, not from a list in the check.
"Every bucket" is the claim, and a list in the check would make it every bucket someone remembered
to add.

**Negative controls for the older handlers are still missing.** The new handlers are written as a
fetch plus a pure judgement, and `self_test.py` gives each judgement configurations that are wrong in
exactly one way. For the TLS judgement those are: an Allow, one principal, objects only, one action,
and an inverted condition. A deliberately loose judgement was flagged on four of them. The
pre-existing `cloud_api_config_read` handlers (Config recorder, asset feed), `log_query` and
`inventory_reconciliation` have **no negative control** in the collector's self-test. An earlier
statement today that every assertion has one was wrong, and is corrected in `PROJECT-CONTEXT.md`.

**Found and left for a decision: four of five buckets are not encrypted with a customer-managed
key.** SVC-SIN build row 1 says "customer-managed keys across all stores". The log store, the Config
delivery bucket, the Athena results bucket and the state bucket all use SSE-S3. For the log store
this was recorded and load-bearing on 2026-09-22. Every KMS key was then ephemeral, and an Object
Locked store encrypted with a key the teardown deletes would become permanently unreadable.

That premise changed the same day: the artifacts key persists. A persistent customer key for the
evidence stores is now possible. It is not risk-free, because a key scheduled for deletion by anyone
takes locked logs with it. That makes it a design decision, not a fix, and row 39's encryption check
is not written until it is taken.

**Also noted: no account-level S3 public access block.** Every bucket blocks public access
individually, so nothing is exposed. But a bucket created tomorrow would not inherit the block.

---

## 2026-09-23 — The SDR emitter is built, and the record says what it cannot claim

**Built: `sdr/emit.py`**, the project's actual deliverable. It reads the 46 determinations from
`KSI-Design-Matrix.xlsx` and the collector's results, and writes one Security Decision Record to
`sdr/out/`:

- `sdr.json`, in FedRAMP's schema.
- `sdr.md`, generated from that JSON, never from the matrix, so the two formats cannot disagree.

**The first emission is valid.** It covers 46 indicators (18 `Implemented`, 22 `Partially
Implemented`, 6 `Not Implemented`) and 25 evidence objects across 10 indicators, from one collector
run in which all 25 checks passed.

**Validation is on emit, and a failure writes nothing.** The emitter validates against the pinned
SDR schema with the pinned common-definitions schema resolved locally. Six deliberately broken
records were each rejected: a status outside the enum, a missing required field, a missing
`fedRampRequirements`, an evidence type outside the enum, an empty evidence object, and an overview
URI that is not a URI.

Two of those six are the emitter's own rules, not the schema's. `jsonschema` checks the `uri` and
`date-time` formats only when optional packages are installed, so a pass would not have meant they
were checked. The schema also allows an empty evidence object, which the spec forbids. The emitter
checks both itself.

**The common-definitions schema is now pinned too.** The SDR schema's
`certificationPackageOverviewUri` is a `$ref` into it, so it was fetched from FedRAMP/schemas and
pinned by filename, `$schemaVersion` 0.4.0 and hash. **FedRAMP changed that file at 15:31 UTC
today**, which is exactly why the pin includes the hash. `sdr/verify_pins.py` compares both pins with
upstream. It reports both as matching, and it was shown to report a wrong pin.

**Choices where the spec left one open:**

- **`certificationPackageOverviewUri` points at the README at the emitting commit.** The field is
  required and must be a URI, and no Certification Package Overview exists. The README is the
  project's overview, and the rendering states that it is not a FedRAMP CPO.
- **`--frr` is a required switch with no default.** Only `empty` is implemented. `populated` raises
  an error naming the missing FRR determinations. The spec wanted the omission to be a stated choice,
  and a required flag makes the person running the emitter state it.
- **`ksiTests` lists only tests that exist.** A check's negative control is listed only if
  `collector/self_test.py` reports one for that mechanism and assertion. `negative_controls()` was
  added so the SDR reads that list and cannot claim a test the file does not run. The
  determination's deliberate-test rows are listed as "designed, not yet automated", because a test
  that has not run has validated nothing.
- **Evidence type:** CFG maps to `Configuration`, OPS from `log_query` to `Log`, and other OPS to
  `Report`. Nothing produces `Screenshot`.
- **Each evidence object** links to its check definition at the emitting commit and carries the
  check's full evidence inline. If the tree has uncommitted changes, the version is suffixed
  `-dirty`, because the links may not show what ran.
- **The cycle statement is honest.** Every indicator's validation opens with its required cycle and
  the fact that the collector is run by hand, with no schedule. A determination's cadence is not a
  property of the system until something runs it.
- **SDR-CSX-KMT's metrics are stated as absent.** There is no record store and no schedule, so the
  collection window is one run, and every indicator says so. No custom fields were added to carry
  metrics. The schema has none, and a non-standard field would validate while meaning nothing to a
  reader of the standard.

**The parser refuses content it does not recognise.** Any row inside a determination block that is
not a known label, table header or table row stops the emitter, naming the sheet and row. A parser
that skipped what it did not understand would drop text from the SDR silently. It also refuses
collector results naming an indicator the matrix does not contain, whose evidence would otherwise
vanish.

**What the record covers, stated plainly.** 10 of 46 indicators carry automated evidence. The other
36 carry their full determination (rationale, build, verify and validate rows, assurance and
limitations) and the statement that no collector check exists for them yet. That is the true state
of the build, and the record shows it rather than implying coverage.

**Not built:**

- **CI.** The spec asks for validation in CI, but the collector needs credentials for both clouds
  and CI holds only the drift role. Emitting from the environment would need a collector runtime,
  which does not exist.
- **A schedule for `verify_pins.py`.**
- **`portsAndProtocols`.** It is optional and derivable, but only from a standing environment.

`sdr/out/` and collector result files are gitignored. The record is reproducible from a commit and
a run, and generated output committed beside its source goes stale.

**The collector now passes 25 of 25.** The one failure earlier today, the phantom security group,
cleared when Config recorded the deletion. See the correction in the live-is-declared entry above:
it was a roughly 70-minute lag, not a permanent defect. The consequence still stands. A collector run
shortly after a teardown can report resources Config has not yet caught up with. The check's
does-not-exist note makes that visible instead of looking like undeclared infrastructure.

---

## 2026-09-23 — Four open items acted on, one blocked, one waiting on the user

Recommendations were given for the four open items and the user asked for them to be carried out.
The state of each follows.

**1. Passkey on `admin@corp.elvievalmores.com`: with the user.** It is also a prerequisite for
moving the AWS operator off its static key. Identity Center has **no users and no permission sets**
yet, and sign-in to it goes through Google, where `admin@` has no second factor. Replacing a static
key without MFA by a Google login without MFA would not be an improvement. The order is:

1. passkey and a second method on `admin@`
2. an administrative permission set declared in Terraform, persistent
3. a hand-created Identity Center user, recorded as an exception because SCIM needs Premium
4. `aws sso login` proven
5. the access key deactivated, then deleted a week later
6. the IAM user kept as break-glass, with no key

Google's directory cannot be read with this project's GCP credentials, so enrolment will be recorded
on the user's word.

**2. Default Compute Engine service account's `roles/editor`: check built, fix blocked.** The new
check `iam-elp-cfg-gcp-basic-roles-allowed-only` allows a basic role (owner, editor, viewer)
anywhere in the project only as a named allowance with a reason. There are two allowances: the
human project owner, and `terraform-admin`'s editor grant from 2026-09-22. It reads bindings on the
project and on every resource under it through Cloud Asset. It **fails, correctly, on the default
compute account.**

Removing the binding and disabling the account were **refused by the session's permission
controls** as a permission grant change. They were not retried by another route. The commands are
left for the user. The check will pass once they run.

**3. Customer-managed keys for the evidence stores: not started.** It is a medium-sized change of its
own. The recommended shape:

- a dedicated persistent evidence key
- `prevent_destroy` and a 30-day deletion window
- a key policy denying `ScheduleKeyDeletion` and `DisableKey` to all but break-glass
- an EventBridge alert on either call
- grants for CloudTrail and Config

The state bucket stays SSE-S3 as a recorded exception.

**4. The smaller items: done.**

- **Account-level S3 public access block: applied.** It is in a new persistent file, `account.tf`,
  for account-wide guardrails, added to `boundary.py`. It was applied once, targeted; 68 resources
  now persist. All five buckets still list without error.
  `svc-sin-cfg-aws-account-public-access-block` checks it, reusing the four-settings judgement that
  already has negative controls.
- **Project VPC default security group: declared, not yet applied.** `aws_default_security_group`
  with no rules is in `network.tf`, on the ephemeral side, so it applies at the next phase 1.
  Before emptying it, every network-attached resource was checked for a named group of its own: both
  ECS services, the database, the load balancer, and the interface endpoints (the gateway endpoint
  and both Lambdas take none). The documented migration `run-task` also names its own group.
  **Verify at the next phase 1** that `live_is_declared` passes while the environment stands.
- **Config's lag: split into its own indicator.** The inventory can list a resource its service
  says is gone. That is no longer a KSI-SVC-ACM failure, because it is not undeclared
  infrastructure. It is now a KSI-PIY-GIV failure, `inventory_current`, because the inventory is
  inaccurate.
  - Any resource that is neither declared nor excused is checked against its own service. Probes
    exist for 13 of the 17 inventoried types.
  - Four types cannot be asked by ID from what Config returns: IAM policies, ECS services, WAF ACLs,
    and secrets pending deletion. Those stay unaccounted, because an unknown is not a reason to
    excuse something. GCP has no probe yet, for the same reason.
  - The two checks share one exclusion list by reference (`exclusions_from`), so they cannot drift
    apart.

**The recommended two-hour grace period was dropped.** It would need the time the resource was
deleted, and for exactly the implicit deletions this is about, nothing records one. So a collector
run inside Config's lag window fails `inventory_current`, which is true at that moment. The message
says what to expect.

**Self-test:** 16 of 16 assertions discriminate. The split was confirmed by mutation: restoring the
old behaviour, where stale entries failed `live_is_declared`, was flagged on both phantom fixtures.

**Collector: 29 checks, 28 pass.** The one failure is the editor binding above. The SDR re-emits
valid with 29 evidence objects and KSI-IAM-ELP's first evidence.

---

## 2026-09-25 — Session closed out: state re-verified, teardown confirmed, resume block rewritten

**No build work. This entry records what was true when the session ended**, checked rather than
carried forward, so the next session can start from it.

**The application environment was already down.** `boundary.py --ephemeral` returned nothing and
`teardown.sh` reported "already torn down" with exit 0. The API agreed.

The sweep, rerunnable as it stands:

```sh
export AWS_REGION=us-east-1 AWS_PAGER=""
aws elbv2 describe-load-balancers --query 'length(LoadBalancers)'          # 0
aws rds describe-db-instances --query 'length(DBInstances)'                # 0
aws ecs list-clusters --query 'length(clusterArns)'                        # 0
aws ec2 describe-vpcs --filters Name=is-default,Values=false --query 'length(Vpcs)'   # 0
aws ec2 describe-vpc-endpoints --query 'length(VpcEndpoints)'              # 0
aws ec2 describe-nat-gateways --filter Name=state,Values=pending,available --query 'length(NatGateways)'  # 0
aws ec2 describe-addresses --query 'length(Addresses)'                     # 0
aws ec2 describe-instances --filters Name=instance-state-name,Values=pending,running --query 'length(Reservations)'  # 0
aws guardduty list-detectors --query 'length(DetectorIds)'                 # 1 (persistent)
aws inspector2 batch-get-account-status --query 'accounts[0].state.status' # ENABLED (persistent)
```

**Standing, as intended:**

- **AWS:** 68 persistent resources. Posture is enabled, and the extract bucket carries its two
  denies.
- **GCP:** 30 resources in state and no Cloud Run job.
- **Keys:** fifteen customer keys from the 2026-09-23 teardown are pending deletion, clearing
  2026-09-26 to 2026-09-30.

**Unattended drift held.** The scheduled runs on 2026-09-24 and 2026-09-25 passed over all 68
persistent resources, including the boundary check. They are the first scheduled runs against the
current persistent set.

**Collector: 28 of 29, unchanged.** The one failure is still the default Compute Engine account's
`roles/editor`. The self-test is 16 of 16.

**The user's three items are still open**, all confirmed by tool except the passkey, which cannot be:

- **Passkey on `admin@`:** unconfirmed.
- **The `gcloud` commands:** not run. The binding is still present.
- **The static key:** still active, and Identity Center has 0 permission sets.

**One more hand-written list found and replaced.** `teardown.sh`'s closing message named seven
preserved things after the persistent set had grown to 68: the same fault `drift.yml`'s summary had
on 2026-09-23. It now prints the boundary's own count and file list. The rule is worth stating once:
**no consumer of the boundary keeps a copy of it, including in a message.**

**`PROJECT-CONTEXT.md`'s "Resume here" block was rewritten for a cold start.** It now opens with the
first actions for the next session. It separates what waits on the user from build work, drops a
duplicated open item, and puts the variables and commands for running everything in one place.

---

## 2026-09-29 — Three of the user's items closed; the operator's permission set is declared

**Re-verified first.** 68 persistent and 0 ephemeral, the 2026-09-25 API sweep all zeros, and the
scheduled drift runs green on every day from 2026-09-25 to 2026-09-29. The state recorded on
2026-09-25 held.

**The default Compute Engine account's `roles/editor`: removed, by the user.** They ran the
`remove-iam-policy-binding` and `service-accounts disable` commands, after saving a policy backup to
`~/gcp-iam-backup-2026-09-29.json`. The binding is gone, the account reports `disabled: True`, and
`iam-elp-cfg-gcp-basic-roles-allowed-only` passes: "all 2 basic-role grant(s) are named allowances".

**Passkeys: `admin@` and `alex@`, recorded on the user's word.** 2-Step Verification is allowed in
the Admin console, and enforcement is deliberately left off until every account is enrolled. Each
account has a passkey, a second method and offline backup codes. `alex@` had never signed in, so its
password was reset by `admin@` first. As before, this project's credentials cannot read the
directory, so none of this can be checked by tool.

**Alex, not `admin@`, is the account that signs in to AWS.** `admin@` is break-glass, per
2026-09-22, and holds no standing AWS access. Using it daily would make it a working identity.

**The permission set: `InterimOperatorAdmin`, in `identity_center.tf`, persistent.** It has
AdministratorAccess and four-hour sessions, and is assigned to `alex@` in this account. That is a
standing grant to the platform engineer, and KSI-IAM-JIT says the platform engineer holds none. It
is **not a new exception**. The 2026-09-19 entry lets a human identity keep apply until KSI-IAM-JIT
build step 5 lands, and this moves that same exception from an IAM user with a key that never
expires and no MFA to a four-hour session behind a passkey. When the elevation workflow exists, the
assignment goes and the permission set becomes an elevated one.

- **Why AdministratorAccess.** KSI-IAM-ELP rules out managed policies. But the role model is five
  scoped roles and this is none of them. Applying this root creates and deletes IAM, KMS and network
  resources, so a narrower policy would just list everything. The exception is the honest name for
  that.
- **Why four hours.** A phase 1 and phase 2 apply followed by a teardown fits in one session. A
  credential that expires mid-apply leaves a held lock and a partial state.
- **When the JIT check is built,** "Platform engineer holds zero standing assignments" will fail on
  this assignment. That is correct, and it should be cleared by the exception register, not by
  loosening the check.

**The drift role gained read on `sso` and `identitystore` in the same apply.** Without it, the
first scheduled run after the new resources would have errored rather than reported. That is the
2026-09-22 failure again, so the grant went in with the resources, not after.

**Applied by the user, not by this session.** The apply was refused by the session's permission
controls as a permission grant, like the GCP change on 2026-09-23. It was a targeted apply of a
saved plan, by declaration, as the boundary requires: 3 added, 1 changed, 0 destroyed. Verified
afterwards: the permission set is provisioned to the account, `AWSReservedSSO_InterimOperatorAdmin_*`
exists, the drift policy carries the six actions, and `boundary.py --persistent` gives **71**. A plan
scoped exactly as `drift.yml` scopes it returns "No changes" over all 71.

**Two traps on the way, both recorded because they will recur:**

- **`! command` in a real terminal applies nothing.** The `!` prefix runs a command from Claude
  Code's prompt. In zsh, a leading `!` inverts the exit status instead, so `! cd dir && terraform
  apply` makes a successful `cd` look like a failure, and `&&` skips Terraform with no error. It
  looked like it worked, and CloudTrail showed nothing had happened.
- **A target list in an unquoted zsh variable arrives as one argument.** zsh does not split words
  the way bash does. `drift.yml` builds a bash array, and a local rerun has to do the same.

**Alex's Identity Center user was created by hand, signed in to the console as root.** Hand
creation is the recorded exception, because SCIM needs Cloud Identity Premium. Root was the only
console identity available, because `terraform-admin` has a key but no console password. It is
recorded here because a root console login is one of KSI-IAM-SUS's local rules. This one is
explained, and it should be the last: with SSO working, console work goes through Alex.

**Still open from this list:** proving `aws sso login`, then deactivating the `terraform-admin`
key, and deleting it about a week later.

**A new finding, probably a lag.** Four KMS keys from the 2026-09-23 teardown finished their
scheduled deletion at 21:47 UTC. `inventory_current` failed on them within minutes, which is
correct. Config still reported all four as `OK` half an hour later, with its last item dated
2026-09-21. Three more delete on 2026-09-30. If Config never records a scheduled key deletion
completing, it is not a lag but a class of implicit deletion Config does not see. Recheck before
calling it either.

**Collector: 28 of 29.** The remaining failure is that KMS item.

---

## 2026-09-30 — `aws sso login` proven as `alex@`; the AWS-started sign-in does not work yet

**Proven by use.** `aws sts get-caller-identity --profile caliper-admin` returns
`assumed-role/AWSReservedSSO_InterimOperatorAdmin_fb048b20f7be7777/alex@corp.elvievalmores.com`.
Under that profile: `boundary.py` gives 71 and 0, a plan scoped exactly as `drift.yml` scopes it
returns "No changes", and the collector runs.

**The start URL is `https://ssoins-7223046591f7f9f9.portal.us-east-1.app.aws`.** The
`d-90667e73f9.awsapps.com/start` URL given on 2026-09-29 was assumed, not read, and it was in the
resume block. It also serves a portal, but the working sign-in used the `ssoins-` one.

**Only the Google-started sign-in works.** Five sign-ins started from AWS, on 2026-09-29 and
2026-09-30, all failed with the same CloudTrail event: `ExternalIdPDirectoryLogin`, "Responses must
contain exactly one Assertion". So Google replied with no assertion. Clicking the app tile in
Google's app grid, which starts the sign-in from Google, reached the portal as `alex@` the first
time. The CLI was then set up by approving its request in the window that already held the portal
session.

What that rules out, each checked rather than assumed:

- **The app is on for Alex.** User access is ON for all organizational units, and Alex sees the tile.
- **The Name ID is set correctly:** format `EMAIL`, value `Basic Information > Primary email`.
- **The assertion, certificate and ACS URL are fine.** A Google-started assertion was accepted.

**The recorded SAML app settings**, which 2026-09-22 did not capture: ACS URL
`https://us-east-1.sso.signin.aws/platform/saml/acs/4941442d9bf9ddcf-a64b-4b2e-b754-e15ff995f103`,
Entity ID `https://us-east-1.signin.aws.amazon.com/platform/saml/d-90667e73f9`, start URL empty,
signed response off, and a certificate expiring 2031-09-21.

**The lead:** the Entity ID and the ACS URL are on different hosts. When AWS starts a sign-in, it
names itself in the request, and Google refuses the request if that name differs from the Entity
ID. When Google starts it, nothing is compared. **Unconfirmed.** The next step is to compare the
issuer URL in Identity Center's service provider metadata with the Entity ID. Until then, a sign-in
starts at the Google tile.

**Identity Center sign-ins reach CloudTrail.** This closes the 2026-09-22 open item for
KSI-MLA-LET. Failures log as `ExternalIdPDirectoryLogin` with identity type `Unknown`. Successes
log as `UserAuthentication`, `Authenticate`, `CreateToken` and `GetRoleCredentials`, attributed to
Identity Center user `14a83458-a031-70ba-43d2-5a551fd66c1e`. The API calls made with the role
attribute to an assumed role under the same user ID.

**The root console login on 2026-09-29 used MFA** (`Proton_Auth`), per its `ConsoleLogin` event.

**Provisioning the permission set created an undeclared role, and the collector caught it.**
`svc-acm-cfg-aws-inventory-is-declared` failed on
`AWSReservedSSO_InterimOperatorAdmin_fb048b20f7be7777`. That was correct: nothing declared or
excused it. It is now excused by a new predicate, `identity_center_role`, with two conditions:

- the path IAM reserves for these roles, `/aws-reserved/sso.amazonaws.com/`, not the name
- a permission set of the same name still provisioned to this account

A role left behind by a deleted permission set is not excused, since it is the orphan the check
exists to find.

**The first self-test of the real predicate code.** Until now the path predicates were exercised
only through a fake provider, which proves the bookkeeping but not the predicates.
`reserved_path_predicates` in `self_test.py` calls `service_linked_role` and `identity_center_role`
themselves, against a stubbed IAM, on seven roles. It was run against two deliberately broken
versions of the new predicate, one trusting the name and one skipping the permission-set check, and
flagged both. The self-test is now 18 of 18.

**The KMS item is not a lag.** Four keys finished their scheduled deletion at 21:47 UTC on
2026-09-29, and more on 2026-09-30. More than 24 hours later, Config still reports the first four as
`OK`, with its last item dated 2026-09-21. The 70-minute lag of 2026-09-23 was an implicit deletion
Config eventually recorded; this one it has not. **Finding (KSI-PIY-GIV):** the Config-backed
inventory does not see a scheduled KMS key deletion complete. `inventory_current` reports it, which
is its job. Remediation is the condition, not the check: Config's own record has to be corrected or
the inventory has to stop trusting Config for this type. Not decided.

**Collector: 28 of 29.** The failure is the KMS finding.

**Still open:** deactivate `terraform-admin`'s key, then delete it a week later.

**Addendum, same day: the static key is deactivated.** The user deactivated `AKIA…QVP3` with the
`caliper-admin` profile, which also proves the new identity can do IAM administration. The key had
been active since 2026-09-17. Its last use was 22:27 UTC, by this session's CloudTrail polling
before it switched profiles. An immediate `sts get-caller-identity` with it still succeeded, and
seconds later it returned `InvalidClientTokenId`. IAM deactivation is eventually consistent, so
check it twice before calling it done. **Delete it about 2026-10-07.**

**An open decision the deletion creates.** The 2026-09-23 plan keeps `terraform-admin` "as
break-glass, with no key". But it has no console password either, so after deletion it holds no
credential at all and cannot break any glass. AWS break-glass is already root, with MFA, per
2026-09-05. Either give the user a console password and its own MFA and declare it the second
break-glass identity, or delete it. Not decided. The collector's exclusion wording now says the
same.

**Addendum, same day: `terraform-admin` is deleted, and the account has no IAM users.** The user
deleted the access key early rather than waiting a week, then chose deletion over a second
break-glass identity: root with MFA already fills that role, and a second one would be one more
credential to guard. Deleting the user took detaching AdministratorAccess and `delete-user`; it held
no password, MFA, group or other credential. CloudTrail attributes `UpdateAccessKey`,
`DeleteAccessKey` and `DetachUserPolicy` to `alex@corp.elvievalmores.com`, so administrative
changes now name a person. `~/.aws/credentials` was removed and `AWS_PROFILE=caliper-admin` set in
`~/.zshrc`. With no profile set, the CLI finds no credentials, so no static AWS credential remains
on the workstation.

The collector's `terraform-admin` exclusion was removed along with the user, since an exclusion
that matches nothing hides nothing and only waits to excuse a new user of that name.

**Config recorded this deletion in seconds, and that sharpens the KMS finding.** The user's
deletion was recorded at 23:06:29 UTC, seconds after `delete-user`. One run even straddled it: the
first inventory check saw the user as stale, and the second, moments later, no longer saw it at
all. So Config records explicit deletions promptly, and a scheduled KMS deletion finishing is what
it misses. The 8 stale entries left are all KMS keys.

**The 2026-09-23 finding is closed.** It was "an IAM user with AdministratorAccess, a static key
active since 2026-09-17, and no MFA". Every local apply now runs as a four-hour session behind a
passkey, under the 2026-09-19 exception.

---

## 2026-09-30 — The posture cost, measured: about 15 USD a month, not 3 to 8

**Nothing has been billed yet, which is why the estimate survived.** From 2026-09-17 to 2026-09-30,
usage was 6.23 USD, all of it covered by credits. Security Hub, GuardDuty and Inspector billed 0,
because all three are in trial. An idle day (2026-09-24 to 2026-09-28) costs about 0.05 USD, all of
it outside the posture services. So the bill cannot answer the question yet. Each service's own
usage figure can.

| Service | Measured | Projected monthly after trial | Trial ends |
|---|---|---|---|
| Security Hub | 372 checks observed in the last 24 hours (466 findings updated) | **11 to 14 USD** at 0.001 per check | about 2026-10-23 |
| Inspector | its own estimate: 2.23 for 8 initial ECR scans, 0.25 for rescans | **about 2.50 USD**, more with each image pushed | 2026-10-06 |
| GuardDuty | 0.16 USD of trial usage in 7 days (CloudTrail 0.09, RDS 0.06, S3 0.01) | **about 0.70 USD** | about 2026-10-21 |

**Security Hub is most of it, and most of what it checks is nothing.** Of the 372 checks, 331 are
account-level and 223 end in `WARNING`. These are controls for resource types the scoped Config
recorder does not record, or that this architecture does not use, so they cannot evaluate. This
is the "Security Hub control coverage" open item, now with a price: those checks bill daily and
produce no signal. 362 FSBP controls and 37 CIS controls are enabled.

**Config does not bill for them.** Config charged nothing on idle days despite about 400
Security Hub evaluations a day, so the service-linked rules' evaluations are not billed by Config
separately, at least during the trial. Recheck after 2026-10-23.

**Two smaller findings in GuardDuty's configuration.**

- **RDS login monitoring is on, but not declared.** It was enabled by default when the detector was
  created. `posture.tf` declares only the older `datasources` block, so drift cannot see it. It is
  cheap and relevant: it bills only while the database exists. But it is undeclared state.
- **S3 data-event monitoring is on, and declared.** `posture.tf`'s comment calls it "included in the
  foundational tier". It is a separate protection plan with its own meter. The choice is sound,
  since it is how exfiltration from the extract bucket would be seen. The comment is wrong.

**Not decided.** The options are in the next entry once the user chooses. The recorded fallback from
2026-09-23 is to drop Security Hub from the persistent set.

---

## 2026-09-30 — Security Hub scoped to the architecture; SSM document sharing blocked

**Chosen: option C** of the three put to the user, over keeping everything (about 15 USD a month)
and dropping Security Hub from the persistent set (about 3, the 2026-09-23 fallback). Security Hub
stays, and the controls that cannot find anything are disabled, each with a reason. The user asked
for the recommendation, and for the sequencing too: this first, then the evidence-store key, which
needs a session of its own.

**The rule, in `securityhub_controls.tf`, persistent:**

- **Off by service, never by result.** A control is disabled only if its service appears nowhere in
  this project's Terraform. Controls for declared services stay on, even while they fail or warn
  because the application environment is down. Disabling those would remediate the measurement.
- **Account-wide guardrails stay on, even for unused services:** `EMR.2` (block public access,
  passing) and `SSM.7` (document public sharing, failing).
- **The list was generated from the live FSBP control list,** not typed. So a control AWS adds
  later arrives enabled and is caught by review.

**186 disabled: 185 in FSBP, and `EFS.1` in CIS**, which is CIS v3.0's only control for an
undeployed service. 177 FSBP and 36 CIS controls remain enabled. Each disabled control carries its
reason in Security Hub itself, so the reason reaches an assessor looking at the console, not only
at this repository.

**Macie is a decision, not an absence, and is recorded as one.** The design classifies data by
declaration, through KSI-MLA-ALA's three tiers, not by scanning for it, and Macie bills per bucket
and per GB inspected. `Macie.1` and `Macie.2` are off with that reason. If discovery scanning is ever
wanted, the reason is where to start.

**`SSM.7` fixed, not excused.** The account's SSM document public sharing permission was `Enable`,
the default. So anyone holding `ssm:ModifyDocumentPermission` could share a document publicly, and
a document can carry commands and account details. Nothing uses SSM documents, which makes the block
free. It is `aws_ssm_service_setting.document_public_sharing` in `account.tf`, now `Disable`.

**GuardDuty's two items from the measurement, closed.** RDS Protection is declared as
`aws_guardduty_detector_feature.rds_login_events` and adopted on purpose: KSI-IAM-SUS watches for
repeated failed authentication against a privileged identity, and the database's is one. The
datasources block predates the features API and cannot express it. `posture.tf`'s comment no
longer claims S3 Protection is foundational.

**The drift role gained `securityhub:List*`, `securityhub:BatchGet*` and
`ssm:GetServiceSetting` in the same apply.** Its action list was also put back in alphabetical
order, which my 2026-09-29 insertion had broken. The IAM policy compares as a set, so the plan
showed only the three additions.

**Applied by the user**, since the drift role change is a permission grant: 188 added, 1 changed,
0 destroyed. Verified afterwards in Security Hub (185 and 1 `DISABLED`, `EMR.2` and `SSM.7`
`ENABLED`), in SSM (`Disable`, `Customized`) and in GuardDuty. A plan scoped as `drift.yml` scopes it
returns "No changes" in 25 seconds.

**The persistent count is now 259**: 73 resources plus 186 control associations, each its own
instance in state. Counts in this repository from here on are instances, which is what
`boundary.py` has always printed.

**Not yet proven: the saving.** The projection is about 5.50 USD a month for Security Hub and about
8.70 for all three services. It assumes a disabled control stops producing billed checks. Recount the
daily checks on 2026-10-01 (the method is in the previous entry), and confirm `SSM.7` has turned
`PASSED`.

**Collector: 28 of 29**, unchanged. Declared-exists-live and no-drift both cover all 259.

---

## 2026-09-30 — The evidence key: three stores, the trail and Athena under one customer key

**Built: SVC-SIN build row 1, for the audit-log data class.** One customer-managed key,
`alias/fedramp-20x-ksi-evidence` (`402d209c-…`), in `evidence_key.tf`, persistent. It has
`prevent_destroy`, a 30-day deletion window and annual rotation. It encrypts:

- the log store: CloudTrail files and normalized events
- the Config delivery bucket
- the Athena results bucket
- CloudTrail's own encryption of each file (`kms_key_id` on the trail)
- the Athena workgroup's results (`SSE_KMS`, enforced)

All three buckets were SSE-S3 before. The state bucket stays SSE-S3, as recorded on 2026-09-23.

**Build row 6, decrypt only to declared roles, is in the key policy and not delegated to IAM.** The
account can administer the key, which Terraform and the drift role need, but no statement lets an
IAM policy alone decrypt. Use is granted by name:

- the normalization Lambda and the detection Lambda, only through S3
- CloudTrail and Config, the services, scoped to this trail and this account
- the operator's SSO role, by ARN pattern, only through S3, under the 2026-09-19 exception

`ScheduleKeyDeletion` and `DisableKey` are denied to every principal except root. An EventBridge
rule sends any attempt on either, successful or denied, to the interim detection topic.

**What is not built: key policy changes still do not need JIT.** The operator's standing admin can
rewrite this policy, including to grant itself more. That is the 2026-09-19 exception again.
Policy changes appear in CloudTrail but raise no alert.

**The first apply half-failed, in exactly the way this change was meant to catch.** The key, the
trail, the Athena workgroup and all three bucket defaults applied. The Config delivery channel was
refused: "Insufficient delivery policy … unable to write to bucket". The key policy named Config's
recorder role, but Config delivers as the service `config.amazonaws.com`, which is what the Config
bucket's policy grants. So `PutDeliveryChannel`'s writability check failed. Worse, the bucket default
had already moved to the key, so Config's next scheduled delivery would also have been refused, with
no error anyone reads. It was caught at apply, because the writability check makes this failure
loud, with about four hours before the next delivery. The fix grants `config.amazonaws.com` the key,
scoped by `aws:SourceAccount`, which is AWS's documented statement. It also removes the recorder
role, since Config never writes as it.

**Two failure orders closed before the first apply:**

- **The log store's default waits for the trail.** If the bucket switched first and the trail update
  failed, CloudTrail would write with no key of its own. S3 would then apply the evidence key under an
  S3 encryption context the policy does not grant CloudTrail, and delivery would stop.
- **CloudTrail may also use the key through the bucket default, for this trail only.** This is in
  case digest files, which carry log validation, are written without CloudTrail's own encryption.

**Verified by watching each writer write, after the fix:**

| Writer | Evidence |
|---|---|
| CloudTrail | File at 00:10:06 UTC: `aws:kms`, the evidence key, bucket key on. No delivery error |
| Normalization Lambda | Read that file and wrote `normalized-raw/…` at 00:10:07 UTC under the key |
| Config | Forced snapshot `15a41756-…` delivered at 00:11:20 UTC, `SUCCESS`, under the key |
| Operator, through Athena | A count over 2026-10-01 returned 512. The result object is under the key |
| Detection Lambda | Invoked: `{"matches": 0}`, no error. Its query `SUCCEEDED` and scanned 515,337 bytes, so zero is a result, not a failure. Results `SSE_KMS` |

**Not yet verified:**

- **The first digest after the change: now verified, by the user.** This session's read-only check
  was refused by its permission controls (classified as a secret-store write), so the user ran
  `get-trail-status`. `LatestDigestDeliveryTime` was 2026-10-01T00:14:31Z, after the change, and
  `LatestDigestDeliveryError` was null. The validation chain is unbroken. Which encryption path the
  digest took was not read, and `CloudTrailWritesThroughBucketDefault` stays either way.
- **The deny on `DisableKey` and `ScheduleKeyDeletion`, and the alert.** The test is an attempt by
  the operator that must be refused. It was refused by this session's permission controls as
  audit-log tampering, which is fair: if the deny were wrong, the test would disable the key. Left to
  the user, with the restore commands beside it.

**Afterwards:** a plan scoped as `drift.yml` scopes it returns "No changes" over **263** instances.
The collector is 28 of 29 (the KMS finding). Every SVC-SIN check passes.

**Cost:** 1 USD a month for the key, plus requests. Bucket keys keep S3's requests to one per bucket
key. CloudTrail's own encryption calls KMS per file, about 200 an hour across regions, about
150,000 a month. After the free 20,000, that is under 0.50 USD.

**Next in row 1:** keys for the other data classes, and the stores the row names that are still on
AWS keys: log groups, the detection topic, the registries (already on the artifacts key), state
machines. Then a collector check for row 1's verify line, "every store reports encryption with the
expected key", and row 6's, "key policies grant decrypt only to declared roles, resolved".

---

## 2026-10-01 — Three controls that did nothing, found by making them run

The evidence key's verification ran into three controls that were configured, applied and
internally consistent, and did nothing. Each was found by making it fire, and each is now proven by
firing it again.

**1. The key's deletion alert could only catch root.** The deny worked first time: as
`caliper-admin`, the user's `disable-key` was refused with "explicit deny in a resource-based
policy". But the alert rule never matched. For a denied call, CloudTrail records `resources: null`
and `requestParameters: null`, and names the key only in `errorMessage`. The rule matched on
`resources.ARN`, so it could fire only for a successful call, and only root can make one. The
attempts the deny exists to stop would have raised no alert.

The rule now matches either shape (`$or` on `resources.ARN` and a wildcard on `errorMessage`).
EventBridge's own `test-event-pattern`, run against the real denied event, gave: old pattern False,
new pattern True, new pattern aimed at another key False. Live, the user's second denied attempt
triggered the rule at 00:39, invoked its target with no failures, and SNS delivered it.

**2. Failed sign-ins were recorded as successes, and workforce sign-ins were not authentication.**
The detection Lambda returned `{"matches": 0}` over a window holding two failed Identity Center
sign-ins. The normalizer had two faults:

- It decided `status` from `errorCode` alone. Sign-in events carry no `errorCode`; they report
  `{"<eventName>": "Failure"}` in `responseElements`. So every failed sign-in was a `Success`,
  including root `ConsoleLogin` failures.
- Its authentication event list predated federation, so `ExternalIdPDirectoryLogin` and
  `UserAuthentication` were filed as `API Activity`, where the detection never looks.

Since 2026-09-22, KSI-IAM-SUS's "repeated failed authentication against a privileged identity" could
not see a single failure. The fix reads `responseElements` and adds the Identity Center events.
`lambda/normalize_events/test_handler.py` holds the first tests the normalizer has had. They are
built on real records from this account, with IPs and the console sign-in's OAuth state replaced.
They include negative controls that reintroduce each fault and confirm the tests fail. The old code
on the same records: failed IdP sign-in gives API Activity/Success; failed root console login gives
Authentication/Success.

**Corpus data from before the fix stays misclassified.** It sits under Object Lock and ages out by
2026-10-08. The raw CloudTrail is intact. A query for failed sign-ins before 2026-10-01 has to read
`responseElements` from the raw files, not the normalized corpus.

**3. The two Lambda log groups were outside Terraform.** Lambda created them on first run,
unencrypted and never expiring. The scoped Config recorder does not record log groups, so neither
drift nor the inventory checks could see them. Both were imported (not recreated, so their history
stays), put under the evidence key, and given 30-day retention.

**The detection topic is encrypted with the evidence key.** Each publisher was granted in the key
policy and then made to publish:

| Publisher | Grant | Proof |
|---|---|---|
| CloudWatch alarms | `cloudwatch.amazonaws.com` | `set-alarm-state` on the normalizer's error alarm: "Successfully executed action" |
| EventBridge rules | `events.amazonaws.com` | The key alert above, delivered |
| Detection Lambda | its role, only through SNS | See the end of this entry |

**Row 1's verify line is built:** `svc-sin-cfg-aws-stores-use-declared-keys`.

- It lists every bucket, log group, topic, ECR repository, trail, Athena workgroup, Config delivery
  channel, secret and database from the APIs.
- It fails any store whose key, resolved to an ARN, is not its declared data class's. It also fails
  any store no class names.
- Its negative controls cover six bad inputs (wrong key, an AWS key where a customer key is declared,
  an unclassified store, the SSE-S3 exception in another mode, an expected key that is gone, and no
  stores). It was run against two broken evaluators, one passing unclassified stores and one comparing
  raw names, and flagged both. The self-test is 19 of 19.

**Its first run found two real gaps, out of 15 stores:**

- **Athena's `primary` workgroup**, which AWS creates and will not delete, enforced nothing:
  unencrypted results and no scan limit. It is now imported and governed like the evidence
  workgroup (`log_corpus.tf`, persistent).
- **`/aws/rds/instance/fedramp-20x-ksi/postgresql`**, 544 KB of database logs that outlived the
  2026-09-23 teardown. It is unencrypted and never expires. RDS creates its export log groups itself
  unless they already exist. Both are now declared in `database.tf`, with the logs key, 30 days, and
  `depends_on` from the instance, so they go with the database. The orphan is adopted by an `import`
  block at the next full apply, not deleted now: whether to keep phase 2's database logs is the
  record's call, not a cleanup's. Until then the check fails on it, correctly.

The check is 14 of 15 now.

**The sign-in started from AWS worked once,** as `alex@` in a fresh private window at 00:40:56 UTC.
It logged `UserAuthentication` with `CredentialType: EXTERNAL_IDP` and no failure before it. But a
successful federation logs the same event whichever side started it, so CloudTrail cannot confirm the
path. The earlier failures' cause stays unconfirmed. Google's app-access propagation, which Google
says can take up to 24 hours, fits the timing. Record it as working once, not as fixed.

**Persistent count: 266.**

**Row 6's verify line is built too:** `svc-sin-cfg-aws-keys-decrypt-only-declared`. For every
enabled customer key, listed from the API, it resolves who can decrypt and by which route:

- **named in the key policy**
- **by grant**
- **through IAM.** A key policy statement granting the account hands the decision to IAM. The
  check then simulates `kms:Decrypt` for every IAM role and user, with and without each
  `kms:ViaService` path, narrowed by any `aws:PrincipalArn` condition on the statement.
- **public.** `*` with nothing confining it to the account.

It fails any principal outside the key's declared model, and any key with no model. Deny statements
are not subtracted, so the answer can only be wider than the truth.

Negative controls cover six ways to over-grant: an undeclared role named, a public principal, account
delegation without the operator-only condition, `kms:*`, `NotAction`, and a grant. It was run against
two broken resolvers, one matching `kms:Decrypt` literally and one ignoring `aws:PrincipalArn`, and
flagged both. The self-test is 20 of 20.

**Live: both persistent keys pass.**

- **The evidence key's** decrypt set is exactly its policy's: two Lambda roles, Config, Logs,
  CloudWatch and EventBridge, and the operator through IAM. CloudTrail is correctly absent, since it
  can only generate data keys.
- **The artifacts key** delegates `kms:*` to the account, so its set is resolved through IAM: the
  operator, the GCP pipeline role (decrypt only through S3), and the **build role**, plus ECR by
  policy and by four repository-scoped grants.

**Open: the build role's decrypt is unconditioned.** `pipeline.tf` grants it `kms:Decrypt` on the
artifacts key with no `kms:ViaService`, on the reasoning that publishing layers needs it. That lets
it decrypt any artifacts-key ciphertext, extracts included, given read access to them. It is declared
in the model because it is the stated design. Narrowing it to `ecr` needs a CI build to prove a push
still works.

**Two operational notes.**

- The first full run hit IAM's simulation rate limit, because the simulations ran alongside other
  checks. The IAM client now uses adaptive retries.
- Batching every key into one simulation per principal and path cut the run from 141 to 63 seconds.

The ephemeral keys (database, secrets, logs) have no declared model yet. At the next phase 1 they
will fail as undeclared keys, which is how their models get written.

**A failed sign-in that AWS never recorded.** To give the detection Lambda a real failure to find,
the user signed in to the portal as `admin@`, a directory account with no Identity Center user.
AWS showed "Something went wrong / Looks like this code isn't right" at 00:42:49 UTC (request
`413ffb22-…`). CloudTrail has no sign-in event from it in any region, and nothing reached the
normalized corpus in 25 minutes. That matches 2026-09-22's symptom, where the cause was on Google's
side; here it may instead be AWS refusing an unknown user before logging. **Either way, an
unprovisioned directory account trying AWS leaves no trace in CloudTrail.** That is a coverage gap
for KSI-IAM-SUS and KSI-MLA-LET. The trace, if any, is in Google's SAML audit log (Admin console →
Reporting → Audit and investigation → SAML log events), which nothing here collects.

**So the detection Lambda's publish to the encrypted topic is not yet proven.** The proposed test
is one failed root console login (a wrong password, once). CloudTrail always records it, and it is
the exact shape the old normalizer filed as a success.

---

## 2026-10-01 — Session closed out: re-verified, torn down, resume block rewritten

**Re-verified at about 01:07 UTC:**

- **AWS:** `boundary.py` gives 266 persistent and 0 ephemeral, and `--check` is clean. The API
  sweep found nothing expensive (no load balancer, database, ECS cluster, non-default VPC,
  endpoint, NAT gateway, Elastic IP or instance), and no IAM users.
- **Evidence:** the evidence key is `Enabled`. CloudTrail delivery and digest errors are both
  `None`, and Config's last delivery `SUCCESS`.
- **Teardown:** `teardown.sh` reports "already torn down".
- **Drift:** a plan scoped as `drift.yml` returns "No changes", and so does GCP.
- **CI drift, run on demand (run 36799600607):** green, "No changes". This was triggered to prove
  the drift role can read everything added since the last scheduled run (the key, the log groups,
  `primary`, the SSM setting, the Security Hub controls), rather than learn it at 07:00.
- **Collector:** 29 of 31. The two failures are the KMS inventory finding and the RDS orphan log
  group, which is adopted at the next full apply.
- **Tests:** the self-test is 20 of 20, and the normalizer's tests pass. `sdr/emit.py` writes a valid
  record with 46 indicators and 31 evidence objects.

---

## 2026-10-01 (evening) — The detection chain proven end to end; Security Hub recounted

**Re-verified at the start (20:11 UTC):** 266 persistent and 0 ephemeral, the API sweep all zeros,
no IAM users. The **scheduled drift run at 14:07 UTC was green**, the first unattended run over the
previous session's additions. The SSO session from the night before had expired, as four-hour
sessions should; the user signed in from the Google tile.

**The detection Lambda's alert path, the one link unproven at close-out, is proven.** The user made
one failed root console sign-in, a wrong password once, at 20:10:52 UTC. It went through every
stage:

| Stage | Evidence |
|---|---|
| CloudTrail | `ConsoleLogin`, `Root`, `{"ConsoleLogin": "Failure"}`, "Failed authentication"; visible to lookup at 20:13 |
| Normalizer | In `normalized_events` by 20:16 as `Authentication` / `Failure` / "Failed authentication" / `Root`. The pre-fix code filed this exact shape as a success |
| Detection Lambda | Invoked at 20:16:18: `{"matches": 1}` |
| Encrypted topic, as the Lambda's role | SNS `NumberOfNotificationsDelivered` 1 and `NumberOfNotificationsFailed` 0, at 20:16 |
| Inbox | The user received "fedramp-20x-ksi: failed authentication detected" |

All three publishers to the encrypted detection topic are now proven: CloudWatch alarms, EventBridge
rules, and the detection Lambda.

**Security Hub recount: the saving is real, and the method has a limit.**

- **Disabled controls produced no findings** after 00:00 UTC, against 187 a day before.
- **`SSM.7` is `PASSED`.** The document-sharing block works.
- **Findings refreshed a day are down from 372 to about 230**, against a projected 185. The
  difference is the controls that stay on, now evaluating about a dozen resources added the
  evening before: the key, the log groups, topic encryption, `primary`, the alert rule and the SSM
  setting.
- **The limit:** a finding records only its *last* observation. Observations cluster at 00, 10 and
  18 UTC, so a control checked twice a day counts once. Both counts are the same proxy, so they
  compare, but neither is the billed number. The billed number is on the console's Security Hub →
  Settings → Usage page, and on the first bill after the trial ends (about 2026-10-23).
- **Revised projection:** about 7 USD a month for Security Hub, and about 10 for all three services
  (from about 15).

**The build role's decrypt narrowed to ECR, and proven by a build.** `pipeline.tf`'s
`EncryptImageLayers` now carries `kms:ViaService = ecr.us-east-1.amazonaws.com`. The user applied
it, being an IAM change. Build run 36920315329 (tag `git-bd43e9e59bab-kmsvia`) then pushed, signed
and verified the **worker** image under it in two minutes.

CloudTrail shows **no KMS calls by the build role at all** during that push. ECR encrypts layers
through its own repository-scoped grants, not with the pusher's permissions. So the statement
appears to be unused, not merely narrowed, and could be removed outright. Proving that takes
another build without it. Narrowed is the proven state.

**The api image's build hung,** 21 minutes in `docker build` with no ECR call, and was cancelled.
GitHub kept no log for the cancelled step, so the cause is unknown. It is not the grant: nothing
reached ECR. Neither workflow had a `timeout-minutes`, so a hung job would have run for GitHub's
6-hour default. Every job now has one: build 30, scans and the change event 10, drift 15. The
change to `build-and-push.yml` triggers a fresh build, which retries the api image under the
narrowed grant.

**A GuardDuty decrypt in CloudTrail, explained.** `AWSServiceRoleForAmazonGuardDuty` decrypted with
`alias/aws/lambda`, the AWS-managed key, in an encryption context naming the detection Lambda.
That is Lambda Protection reading function configuration. It is outside row 6, which covers
customer keys. The Lambdas' environment variables (names and ARNs, nothing secret) sit under AWS's
key, a low-priority row 1 item.

**SVC-SIN row 1 on GCP.** The analytics bucket, dataset and table, and Artifact Registry were
already on customer keys. What remained was audit and inventory data:

- **The asset-feed topic now uses a new GCP `evidence` key** (`analytics.tf`), the audit-log class
  (option C, chosen by the user). It is permanent: Cloud KMS keys cannot be deleted. Pub/Sub's
  service agent is read through `google_project_service_identity` and granted on that key alone.
  The topic changed in place. Applied by the user: 3 added, 1 changed.
- **`_Default` and `_Required` cannot take a customer key.** Google's documentation: "After a log
  bucket is created, you can't reconfigure the log bucket to change or remove CMEK" and "You can't
  enable CMEK for log buckets created in the global region". Both are `global`, and `_Required` is
  also `locked`. They are recorded exceptions for that reason, as `GOOGLE-MANAGED` in the check. An
  option kept open: route `_Default`'s Data Access logs to a new regional bucket created with the
  key. `_Required` cannot be rerouted.

**The feed was proven through the encrypted topic, by a seed.** A temporary subscription and a
throwaway GCS bucket were used. The feed's creation message arrived 4 seconds after the bucket was
created, and its deletion message 13 seconds after the bucket was deleted. Pub/Sub decrypted both
for the subscriber. Both seeds were removed.

**That probe exposed a gap: nothing consumes the GCP change feed.** The topic had **no
subscriptions**, so every change notice it carried was discarded. Cloud Monitoring showed no
publish data for it in seven days, consistent with that, though messages are not retained, so it
cannot be shown what was lost. The inventory generator queries Cloud Asset directly and is
unaffected. But `piy-giv-cfg-gcp-asset-feed` passes on "feed exists with asset types configured",
which proves configuration, not delivery. The feed needs a consumer or a stated reason to exist,
and its check needs a delivery test.

**`svc-sin-cfg-gcp-stores-use-declared-keys`**, the GCP half of row 1. One Cloud Asset search gives
both the stores and the key each reports, so the population comes from the API, as on AWS. It
reuses the AWS judgement, with a resolver that drops a version suffix, since BigQuery tables
report the key version. `GOOGLE-MANAGED` is now a declarable exception mode beside `SSE-S3`. Three
new negative controls: Google's key where a customer key is declared, another key's version, and
an exception store given a customer key. **Live: 7 of 7 stores pass.**

**A regression, caught by the live run and now guarded.** Adding the GCP handler put a module-level
function in the middle of `CloudAPIConfigRead`. That ended the class early, and the next two
handlers became unreachable. The two AWS SIN checks errored with "has no attribute". The self-test
passed throughout, because it calls the pure judgements directly. A new `handler_wiring` test
checks that every handler `run()` dispatches exists on the class. It was shown to fail with a
handler removed.

**State:** collector 30 of 32 (the KMS finding and the RDS orphan log group), self-test 22 of 22,
drift clean on both clouds.

**The GCP change feed: a stated reason, and a reader that proves delivery.** The design settles
what the feed is for:

- KSI-PIY-GIV's build row 2 names it, and its verify line asks that it be enabled.
- The inventory's "real-time" claim is met by generating at query time from Cloud Asset, not from
  the feed.
- GCP's change record is the Admin Activity audit log, 400 days in `_Required`.

So the feed's notices are **not retained**, by decision. Keeping them would duplicate the audit log.
What it lacked was proof that it delivers. `inventory/self_test.py` already created a subscription
on the feed's topic as its "unwatched type" seed, but never read from it, and created it after the
seed bucket, so it could not have received the creation notice anyway. It now:

1. creates the subscription before the bucket
2. pulls until a feed message names the seed (up to 120 seconds)
3. fails the GCP self-test if none arrives

Live, it passed for feed delivery, liveness and accuracy, through the encrypted topic. Negative
control: the same check on a fresh subscription for a resource that never existed returned False
after its 30-second window.

**The retry build passed** (run 36924507289, triggered by the timeout change). Both images built,
pushed and signed under the narrowed build-role grant, the api image in under two minutes. The
earlier hang was transient. The build-role narrowing is fully proven.

**The build role's KMS statement removed outright.** CloudTrail showed it made no KMS calls during
a push, because ECR encrypts through its own grants. So the narrowed statement was removed rather
than kept. The user applied the change, being IAM. Build run 36933935004 (tag
`git-b876c2075ce8-nokms`) then built, pushed, signed and verified **both** images with the role
holding only `AuthenticateToRegistry`, `PublishImages` and `EmitRepositoryEvents`.

The build role is out of the artifacts key's declared decrypt model, and
`svc-sin-cfg-aws-keys-decrypt-only-declared` passes. Through IAM it now resolves the key's decrypt
set to the operator and the GCP pipeline role (decrypt through S3 only). In one day this went from
an unconditioned decrypt that row 6 surfaced, to a narrowed one, to none, each step proven by a
build.

**GCP Data Access logs moved under the evidence key** (`audit.tf`). They record who read the
landing bucket, who queried the dataset and who decrypted with a key, and they had been going to
`_Default`, which is global and under Google's key. They are now routed to
`fedramp-20x-ksi-data-access`:

- a regional bucket in us-central1, created with the GCP evidence key (the only time it can be
  set), keeping the same 30 days
- fed by a sink filtering `LOG_ID("cloudaudit.googleapis.com/data_access")`
- with an exclusion attached to `_Default`'s sink, created after the routing sink

`_Required`, holding Admin Activity, cannot be rerouted and stays the documented exception.

**Two things the apply needed:**

- **A role Terraform lacked.** `terraform-admin` could not create the bucket: `roles/editor` holds
  none of `logging.buckets.create`, `logging.sinks.create` or `logging.exclusions.create`.
  `roles/logging.configWriter` holds all three. The user granted it by hand, as `terraform-admin`'s
  roles were granted on 2026-09-22.
- **The user applied it,** including the exclusion. An exclusion of audit logs from a bucket is
  the kind of action this session's controls have treated as tampering. Here it is a reroute.

**Proven by event, not by configuration.** Routing took about six minutes to settle, and
unevenly. Three minutes after creation, KMS Data Access logs were already routed and excluded,
while Storage's still went only to `_Default`. A fresh `storage.objects.list` at 22:33:39 then
landed in the new bucket and not in `_Default`, which received nothing. **Check a routing change
with a fresh event after several minutes, never immediately.**

**A small loop, recorded:** reading the encrypted bucket makes Logging's agent decrypt, and those
decrypts are KMS Data Access logs that land in the same bucket (6 for one read). It is bounded,
triggered only by reads, and negligible at this volume. It would matter for a reader polling the
bucket constantly.

---

## 2026-10-01 (evening) — GitHub federated to GCP: step A of the collector schedule

**The plan, agreed with the user**, has four steps, in this order:

- **A.** GitHub-to-GCP workload identity federation
- **B.** an AWS collector role on the existing OIDC provider
- **C.** a scheduled `collect.yml`
- **D.** proof, including a missing-permission negative

A comes first: it has the most unknowns, it also unblocks the analytics image build, and a schedule
without it would emit an SDR with every GCP check erroring.

**Built (`infra/gcp/github_federation.tf`, applied by the user):**

- **A pool and provider pinned to GitHub's immutable IDs.** The pool is `github-actions` and the
  provider `github`. The condition is `repository_owner_id == '181586876' && repository_id ==
  '1375137942' && ref == 'refs/heads/main'`, the same immutable-ID reasoning as
  `infra/aws/pipeline.tf`.
- **A custom role, `fedrampKsiCollector`**, granted directly to
  `principalSet://…/attribute.repository/1375137942`. **No service account**: nothing to
  impersonate, no token-creator grant, and GCP's logs name the repository. It is enumerated, not
  predefined, per CNA-DFP (2026-09-05). It starts with four Cloud Asset permissions, and grows only
  by what a CI run fails on.
- **`inventory/gcp_auth.py`** uses the ambient credentials when `GCP_IMPERSONATE=none`. CI must
  never get a token-creator grant on `terraform-admin`, because that would make a read-only
  workflow a provisioning one. Locally nothing changes.
- **`run_checks.py --only <glob>`**, and a manual-only `.github/workflows/collect.yml` (actions
  pinned, `google-github-actions/auth` at v3.0.0, `7c6bc770…`).

**`terraform-admin` needed two more roles,** granted by the user like its others:
`roles/iam.workloadIdentityPoolAdmin` and `roles/iam.roleAdmin`. Its `roles/editor` covers
neither. The first apply after the grants created the role but was refused on the pool. A
`testIamPermissions` call minutes later showed both granted: **an IAM grant can take minutes to
apply, and unevenly across permissions.** Neither widens what `terraform-admin` could already do,
since it holds `projectIamAdmin`.

**Proven:**

- **The positive.** Run 36936657680, from `main`, passed all four direct GCP checks: asset feed,
  basic roles, store keys and project inventory. No key, no service account, four permissions.
- **The negative.** Run 36936757047, the same workflow from a throwaway branch, failed at
  "authenticate to GCP" with `unauthorized_client`. The ref pin is enforced at token exchange,
  before any grant is consulted. The branch was deleted.

**The scope that remains,** recorded before it is built:

- **The GCP drift and inventory checks run `terraform plan` and read Terraform state.** The GCP
  provider impersonates `terraform-admin`, so CI needs that impersonation made optional, a
  read-only role wide enough for the plan, and AWS read access to the S3 state, which is step B.
- **The GCP budget sits on the billing account,** which accepts only predefined roles without an
  organization, and those are barred. The CI plan would exclude it, as a recorded exception.
- **`requirements.txt` pins versions but not hashes.** The app manifests require hashes. CI
  installing the collector should too.

**Step B: the AWS collector role, `fedramp-20x-ksi-github-collector`** (`collector_identity.tf`,
persistent, applied by the user). It is assumed from `main` through the existing OIDC provider,
with the drift role's trust document.

- **Its reads are the drift role's read policy, attached again**, so one list serves both, since
  several collector checks run the same plan.
- **One more policy covers only what the collector does:** `iam:SimulatePrincipalPolicy` (row 6),
  `secretsmanager:ListSecrets` (row 1; the drift policy's deny on secret values still applies),
  `config:SelectResourceConfig` (the inventory's query API), query execution in the evidence
  workgroup only, and writes under `athena-results/results/`.
- **The evidence key's policy names it,** through S3 only, as it does the two Lambdas, and so does
  row 6's declared model.
- **`AWS_COLLECTOR_ROLE`** is a repository variable.

**Step C1: `collect.yml` runs both clouds from CI.** One job assumes the collector role and the GCP
federated principal, and runs every check that needs no Terraform state. **Run 36937116498: 23 of
24 passed, with no permission error on either cloud.** The one failure is the known RDS orphan log
group, a real finding. That meant the Athena check read the encrypted corpus and wrote encrypted
results as the new role, and row 6's simulations and key-policy reads ran in CI. The drift policy
plus those four statements was the whole AWS permission set.

**Step C2, the remaining eight checks, needs two decisions:**

1. **Bootstrap's state is local by design.** It creates the bucket every other root uses, so it
   cannot start in it. The AWS inventory checks read it to know the state bucket is declared.
   **The usual answer is to migrate bootstrap's state into that bucket once it exists**
   (`terraform init -migrate-state`).
2. **The GCP plan in CI** needs the provider's impersonation of `terraform-admin` made optional, a
   read role wide enough for the plan, and the budget left out as a recorded exception.

**Known limits, recorded now:**

- **The collector's AWS plan covers everything in state,** where `drift.yml` covers only the
  persistent targets. With phase 2 up, it would try to refresh secret versions, and the deny on
  secret values would stop it. CI collection therefore assumes the environment is down, its
  normal state.
- **Every action runs from a commit**, but `requirements.txt` still has versions without hashes.

---

## 2026-10-01 (night) — The collector runs daily from CI, and the SDR comes with it

**C2: the eight state-based checks.**

- **Bootstrap's state moved into the state bucket** (`bootstrap/terraform.tfstate`), by
  `terraform init -migrate-state`, run by the user. It was checked first for secrets: the ACM
  certificate is Amazon-issued, so its `private_key` is empty. After the migration bootstrap plans
  "No changes", provided `TF_VAR_app_domain` is set. **Without it, the plan destroys the
  certificate**, because its `count` is 0. The first plan after the migration showed exactly that,
  and was not applied. Bootstrap's state needed the bucket to exist before it could live in it; if
  the bucket is ever recreated, bootstrap goes back to local state first (recorded in its
  `versions.tf`).
- **The GCP providers impersonate only when asked.** `var.impersonate_service_account` defaults to
  `terraform-admin` locally, and CI sets it empty, so the plan runs as the read-only federated
  principal. The CI identity never holds a token-creator grant on `terraform-admin`.
- **The collector role gained the plan's reads, from the state's resource types plus what CI
  failed on.** Two corrections came from running:
  - `logging.settings.get`, not `logging.cmekSettings.get`, which is not a project permission
  - `serviceusage.services.list`, because the provider reads enabled services by listing
- **One read was removed instead of granted.** Reading BigQuery's service agent requires
  `bigquery.jobs.create`, the right to run jobs. The agent exists, and its address matched state
  exactly, so `analytics.tf` now builds it from the project number, and the plan showed no change
  to the grant. That reverses the 2026-09-22 "read, not constructed" rule for this one agent, with
  the reason in the file.
- **The GCP budget is excluded from CI's plan, and the evidence says so.** The new
  `ci_plan_exclusions` applies only when running as the read-only identity
  (`GCP_IMPERSONATE=none`), and lands in each check's evidence as `excluded_from_plan` with its
  reason. Local runs still cover the budget.
- **`APP_DOMAIN` is now a repository variable**, which closes the open item: `drift.yml` passed it
  empty since 2026-09-23.

**D: the negatives.**

- **The ref pin:** a run from another branch is refused at token exchange (run 36936757047).
- **A missing permission surfaces as an error on exactly the checks that need it.** Run
  36938488520 lacked `serviceusage.services.list`; the two GCP plan checks errored naming it, and
  the other 30 were unaffected. With it added, they passed. This was not staged: the role was
  incomplete, and the run showed precisely where.

**The schedule:**

- `collect.yml` runs at **05:30 UTC daily**, ahead of `drift.yml` at 07:00, so they never contend
  for a state lock.
- **Each run:** self-test (22 of 22), then all 32 checks, then the SDR (emitted whatever the checks
  found), then `results.json` and the record kept as a 90-day artifact. Then the job fails if any
  check failed. A red run means findings, not a broken job.
- **`sdr/emit.py` takes a required `--runtime ci|local`,** so its cycle statement says which. SDR-
  CSX-KMT's limit is restated, not dropped: runs are daily, but no record store aggregates them, so
  each record's window is still one run.

**Proven: run 36941269154.** Every step ran, 30 of 32 checks passed (the two failures are the known
real findings), and the SDR is schema-valid at a **clean** version, `61ea761d1e1a`. Getting it
clean took two fixes:

- **The lock files held macOS hashes only,** so `terraform init` in CI added the Linux ones and
  changed tracked files. They now carry both platforms.
- **The Google auth action writes `gha-creds-*.json`** into the workspace (a pointer to the OIDC
  token, not a key). It is ignored now.

The emitter names the files whenever it marks a version dirty, and that is how both causes were
found.

**What remains:**

- No record store, so no 30-day or yearly metrics.
- `requirements.txt` has versions without hashes.
- Local Terraform is 1.16.3 while CI pins 1.10.5. It works, but they should match.
- CI collection assumes the environment is down, its normal state.

**A blind spot found at the end: Cloud Asset does not report regional log buckets.**
`svc-sin-cfg-gcp-stores-use-declared-keys` kept counting 7 stores after
`fedramp-20x-ksi-data-access` was created. Hours later, `gcloud asset search-all-resources` for
`logging.googleapis.com/LogBucket` still returns only the two global buckets, while Logging's own
`buckets list` shows the regional one under the evidence key. So the check passed "7 of 7" while
not covering the bucket that holds the customer-data access logs. Its rule for that bucket simply
matched nothing, which the evidence reports only as an unmatched rule.

It also means the GCP inventory source misses regional log buckets. **Fix, next:** take log buckets
from Logging's API, which is authoritative and listed it, not from Cloud Asset, and add
`logging.buckets.list` to the collector role. More generally, **an unmatched rule for a store
known to exist should fail, not just be reported.**

**The blind spot, closed the same night.** `svc-sin-cfg-gcp-stores-use-declared-keys` now takes log
buckets from Logging's own API (`locations/-/buckets`), which lists the regional bucket, and no
longer from Cloud Asset. The collector role gained `logging.buckets.list`, applied by the user. In
CI (run 36941973250) it reports **8 stores, `fedramp-20x-ksi-data-access` under the evidence key**,
and the SDR is clean at `5579ee273c67`.

**The general fix is in the judgement.** A rule can be marked `required`, and a required rule that
matches no store now **fails** ("required store not found in the population") instead of being
listed as unmatched. Every GCP rule is required. AWS rules are not yet, because several name
application-environment stores that legitimately do not exist while it is down. A new negative
control, "required store missing", feeds the judgement a population without a required store; the
old evaluator passed it, and the new one fails it.

**Still open from this:** the GCP inventory generator (`inventory/gcp_source.py`) also reads Cloud
Asset, so the inventory misses regional log buckets too. The bucket is declared, so no check fails
on it, but "the inventory is complete" is not true for that type until the generator reads Logging
too.

---

## 2026-10-02 — A record store, and SDR-CSX-KMT's metrics start accumulating

**What Class C asks** (read from the pinned rules, not from memory), per applicable indicator:

- a summary of each metric over the past 30 days
- a summary up to the past year
- all daily metric data up to the past year

The last two are "where available". The rule's `schema` block names the SDR schema itself, and that
schema has no metrics fields. So the metrics go where it does allow: an **evidence object**. Its
`evidenceType` is an enumeration (`Log`, `Report`, `Screenshot`, `Configuration`, `Policy`,
`Procedure`, `Audit Record`). The first emission used a type of its own and validation refused it,
so metrics are a `Report`, and the description says which kind.

**The store is the log store, under `collector-runs/`.** Each CI run of `collect.yml` writes its
results there, adding the run id, commit, event and `runtime: ci`. That puts each record under:

- **the evidence key**
- **Object Lock, COMPLIANCE** (undeletable for 7 days)
- **versioning** (a key written twice keeps both)

It costs nothing new. The log store's notification fires only for `AWSLogs/…json.gz`, so records
never reach the normalizer, and it has no expiry, so a year accumulates. The collector role gained
`s3:PutObject` on `collector-runs/*` only, applied by the user. It already reads the bucket and uses
the key through S3.

**`emit.py --history <dir>`** builds, per indicator with checks, one metrics object:

- **the 30-day and up-to-a-year summaries:** days with data, days on which every check passed, the
  mean daily pass rate, and which checks did not pass on how many days
- **every day's data, inline**

Three rules hold it, each with a test in `sdr/test_metrics.py`:

- **only CI runs count, never a workstation run**
- **one data point per day:** that day's latest CI run, scheduled or started by hand
- **every window states how many days actually had data**

The first emission run against a synthetic history planted a failure on one day and a failure in a
workstation record. The first showed on its day and in both summaries; the second appeared nowhere.

**Proven: run 36952160383.**

- **The record:** `collector-runs/dt=2026-10-02/run=36952160383.json`, under the evidence key,
  COMPLIANCE until 2026-10-09.
- **The read-back:** the run read its own record back as history.
- **The SDR:** clean at `40a788635849`, with a metrics object on all 11 indicators that have checks
  ("data on 1 of 30 days").
- **The tests:** CI now also runs the normalizer's and the metrics' tests every day.

**What it does not claim:** a year. The store began 2026-10-02, and every window says how many days
it covers. **Wording fixed after that run:** it said "scheduled runs" while counting a run started
by hand in CI. It now says CI runs, and what that includes.

---

## 2026-10-02 — Correction: the KMS inventory "finding" was a 27- to 51-hour lag

**What was claimed** (2026-09-30): "the Config-backed inventory does not see a scheduled KMS key
deletion complete … not a lag." That was wrong. **Config recorded all eleven deletions, within one
second of each other, at 2026-10-02 00:48:44 UTC.**

- The keys deleted on 2026-09-29 at about 21:47 were recorded about **51 hours** late.
- The ones deleted on 2026-09-30 at about 21:25 were recorded about **27 hours** late.

The single batch points to a periodic reconciliation by Config, not to per-event recording. The
claim was made after about 25 hours of waiting, which was too early, and it was called a finding
rather than a lag on the strength of the 70-minute lag seen on 2026-09-23. Two delays from two
kinds of deletion are not a pattern.

**Found by the schedule, not by looking.** The first daily-run era made `piy-giv-ops-aws-inventory-current`
pass in run 36952591062 with nobody touching anything, and that change is what prompted the check.

**What stands:**

- **An inventory sourced from Config can be stale for up to about two days** after a deletion
  Config is not told about. KSI-PIY-GIV's "real-time" claim holds for what Config records promptly,
  not for this.
- `inventory_current` makes the staleness visible while it lasts, and recovers by itself when Config
  catches up. **It did exactly that, and needs no change.**

**Collector now: 31 of 32.** The one failure is the RDS orphan log group, which waits for the next
phase 1.

**Also on 2026-10-02 (night):**

- `requirements.txt` is compiled from the new `requirements.in` with uv, universal, **45 packages
  and 694 hashes**, with every direct pin unchanged. `collect.yml` installs with
  `--require-hashes`, proven in run 36952591062.
- Both workflows run **Terraform 1.16.3**, the version that writes the state they read. That was
  proven by run 36952592951 (drift, "No changes" over 269) and the same collect run.

---

## 2026-10-02 — The analytics image has a build path; workflow-pinned GCP grants

**Every GCP grant now names its workflow, not just the repository.** The provider maps
`attribute.workflow` from `job_workflow_ref`, extracting the workflow file name; the provider's
condition still pins owner, repository and `main`. So:

- **The collector role moved from any workflow on `main` to `collect.yml` only.** It was proven
  live before the code was committed, by a collect run in which every GCP API check passed under
  the new grant.
- **A new `fedrampKsiImagePublisher` role,** six enumerated Artifact Registry permissions, is
  granted **on the one repository**, to `build-and-push.yml`. `terraform-admin` needed
  `roles/artifactregistry.admin` to set repository IAM; `roles/editor` cannot. The user granted
  it, as its other roles were granted.

**The collector caught the gap between applying and committing.** The apply ran from the local
tree before the code was on `main`, and the next collect run failed `svc-acm-ops-gcp-no-drift`
on 3 of 42 resources. That was correct: the live project was ahead of the repository. It cleared
on commit. This is the drift check doing its job on a change of ours.

**`build-and-push.yml` gained `build-analytics`.** It mirrors the ECR build:

- scanned first (analytics joined the `scan-dependencies` matrix)
- authenticated by direct workload identity federation
- logged in to Artifact Registry with a short-lived token on stdin
- built `linux/amd64` for Cloud Run (its manifest was already compiled for x86_64)
- pushed with provenance and SBOM, signed keylessly, and verified before the digest is recorded

Two new checks cover its signing, as the existing two cover the ECR job's:
`svc-vri-cfg-image-signed-analytics` and
`svc-vri-cfg-signature-verified-before-digest-recorded-analytics`. **34 checks now.**

**Proven by run 36954218125, all seven jobs green on the first attempt.** Artifact Registry holds
`analytics@sha256:19f7fda8771949788a858b389ca0cc83e16536dfbfcd1b133ef9fcf1c4df5d9f` (tag
`git-193454c1a7b2`), with its cosign signature and attestations, and the log shows the claims
validated for that digest. **The blocker on GCP phase 2 since 2026-09-22 is gone.**

---

## 2026-10-02 — GCP phase 2 deployed; the cross-cloud path proven from both clouds

**The first unattended collector run, and what it found.**

- **It started at 11:15 UTC, not 05:30.** GitHub delays scheduled workflows under load, so the
  cycle is daily but the hour is not guaranteed.
- **It caught a gap of mine.** The two GCP drift checks errored: the collector role could not read
  the Artifact Registry repository's IAM (`artifactregistry.repositories.getIamPolicy`). The
  repository grant to `build-and-push.yml` was added on 2026-10-02 without its drift read, which is
  this project's own rule, followed for the Cloud Run job the same night and missed for this. The
  role has it now.
- **Everything else in it was right:** the self-test passed 22 of 22, both test suites passed, and
  the SDR was clean.

**Phase 2 is declared in code.** `deploy_pipeline` defaults to true, and `pipeline_image` defaults
to `analytics@sha256:19f7fda8…`, the digest build run 36954218125 signed and verified. Changing what
runs is a reviewed commit, and the collector's CI plan, which passes no variables, sees the job as
declared and not as something to destroy.

**The first phase 2 apply was partial, and silently broken.** The job and the schedule were
created, but the schedule's invoke grant was not: `terraform-admin` could not set IAM on a Cloud
Run job. **From 18:00 on 2026-10-01 the schedule fired every six hours, and every attempt was
`PERMISSION_DENIED` (status code 7). The job never ran once.** No check and no alarm noticed. Every
configuration check passed, because the job existed and the schedule existed. That is this
project's recurring failure: configured, applied, consistent, non-functional. It was found by
reading the plan, which still listed the grant as "to be created".

The fix:

- **`roles/run.admin` for `terraform-admin`,** granted by the user like its other roles, and
  confirmed live with `testIamPermissions` before planning.
- **The grant applied,** with the collector role fix in the same apply.

**Proven, from both clouds:**

- **By hand, execution `analytics-pipeline-zstgv`:** it logged "read 0 records from 0 objects" and
  "no extracts found, nothing loaded", then exit 0. The extract bucket is empty while AWS phase 2 is
  down, and the job says so in words.
- **By the schedule, triggered at once and not waited for:** HTTP 200, where every earlier attempt
  had been code 7, starting `analytics-pipeline-mwnlh`, which succeeded.
- **AWS CloudTrail:** two `AssumeRoleWithWebIdentity` calls into `fedramp-20x-ksi-gcp-pipeline`,
  one per run (14:19:01 and 14:20:45). The issuer is `accounts.google.com`, the subject and audience
  are the pipeline service account's numeric ID `104894493962317106056` (the immutable identity the
  trust is pinned to), and there was no error. The S3 list itself is a data event, which the trail
  does not record; the job's own log covers it.

**The check that would have caught it:** `svc-vcm-ops-gcp-pipeline-schedule-runs`. It passes only
if the schedule is enabled and its last attempt succeeded within 7 hours. Its negative controls are:

- **"last attempt refused"** (today's failure exactly: on time, code 7)
- paused
- never attempted
- stale
- missing

It passes in CI as the collector (run 37019681402). It is **KSI-SVC-VCM's first automated
evidence**, so 12 of 46 indicators now have some. There are 35 checks; the self-test is 23 of 23.

**State:** the collector is 34 of 35, the one failure being the RDS orphan log group, which waits for
AWS phase 1. GCP drift covers 46 resources, including the job.

---

## 2026-10-02 — Data crossed the clouds for the first time, after a ninth non-functional control

**AWS phases 1 and 2 were applied, the full chain run, and the environment torn down** (14:30 to
about 17:30 UTC).

**With the environment up, the checks found three gaps in their own rules, all real:**

- **RDS's master user secret** (`rds!db-…`) was undeclared, because RDS creates it. It is now excused
  by a predicate that asks Secrets Manager for the secret's `OwningService` rather than trusting
  the `rds!` name. A negative control catches a name-trusting version.
- **The ALB access-log bucket is SSE-S3,** and that is a platform limit. AWS's ELB documentation:
  "The only server-side encryption option that's supported is Amazon S3-managed keys (SSE-S3)." It
  is a declared exception with that quote.
- **The database, logs and secrets keys had no decrypt models.** Each key's resolved set matched the
  design: RDS, Logs, and the api and migrate roles with Secrets Manager, plus the operator. They
  are now declared.

Then, with phase 1 up, all of SVC-SIN, inventory-is-declared (68 of 68) and drift (372) passed. The
project VPC's default security group had no rules, and the RDS log group was adopted and encrypted.

**`git-f9f2c35f8fd1` had expired.** The ECR lifecycle policy keeps "the last 10 images" counting
every artifact, signatures and attestations included, so about three builds survive. Three builds
since 2026-10-01 had removed the tag the resume block said to deploy. Deployed instead:
`git-193454c1a7b2`, after confirming no change to `app/api`, `app/worker` or `app/common` since
`f9f2c35`.

**The extract path had never worked: the ninth configured, applied, non-functional control.** The
worker's first landing failed with `AccessDenied`. Each layer was ruled out by evidence:

- **KMS:** CloudTrail showed the worker's `GenerateDataKey` succeeding, and it was the only call on
  the key.
- **The role and the bucket policy:** the IAM simulator, run with the real context (the endpoint, the
  KMS header, TLS), said allowed.
- **Routing:** both worker subnets send S3 traffic to the endpoint, and there is no NAT route.

A one-off task with the worker's own task definition then printed S3's message: *"because no VPC
endpoint policy allows the s3:PutObject action."* The S3 gateway endpoint's `AllowProjectBuckets`
named the two task roles as principals, and AWS's PrivateLink documentation says: "With gateway
endpoints, the Principal element must be set to *. To specify a principal, use the aws:PrincipalArn
condition key." So the statement had **never allowed anything**. ECR pulls worked only because their
statement uses `*`. The record had deferred this test on 2026-09-23 ("verify at the next phase 2:
an extract written by the worker must still land"), and no extract ever had. **Fixed** with
`Principal "*"` and `aws:PrincipalArn` naming the same two roles: the probe then succeeded, and the
worker landed.

**Then the chain ran, end to end:**

| Step | Evidence |
|---|---|
| api → RDS, IAM auth | 4 measurements written at 16:00:18 |
| worker → S3, through the endpoint | 16:06:38: "landed 4 records", under the artifacts key. The worker role denies `PutObject` unless `aws:SourceVpce` is the endpoint, so it could only have come that way |
| GCP job → AWS → GCS | 16:12:20: "read 4 records from 1 objects", landed under the analytics key |
| BigQuery | "merged 4 new rows". Queried as `terraform-admin`: the four values exactly as written |

The migration task had run first (exit 0). Its 16-second lag behind the worker's first cycle meant
that cycle could not connect.

**Found along the way, recorded as open:**

- **A failed landing loses its batch.** The worker logs "will retry next cycle", but each cycle
  extracts a fixed window behind now, so the records from the failed cycle had left the window
  before the next one. The three measurements from 14:53 were never extracted. This is data loss on
  any transient failure.
- **`caliper.elvievalmores.com` has no DNS record.** The load balancer is new on every phase 1.
  Requests were made with `--connect-to` and the real hostname, so TLS validated against the real
  certificate.
- **The operator's own Google account is not on the BigQuery dataset's access list.** That is
  correct for least privilege, but means a reviewer queries as `terraform-admin`.

**Fixed in code:**

- **The task definitions' perpetual diff.** ECS stores defaults the code did not state, so every plan
  with the services up "replaced" all three task definitions. That would be false drift. Stating
  them (`systemControls`, `volumesFrom`, `capabilities.add`, `hostPort`) made the full plan "No
  changes".
- **The collector with phase 2 up needs `TF_VAR_deploy_services=true` and `TF_VAR_app_image_tag`.**
  Without them, its plan reads the services as things to delete. With them: no drift across 382, and
  all checks pass.

**After teardown:**

- 269 persistent and 0 ephemeral; the API sweep is all zeros.
- The collector is 34 of 35. The failure is `inventory_current` on the project VPC's default security
  group, deleted with the VPC, which Config has not recorded yet: the known implicit-deletion lag,
  which clears.
- **The RDS orphan finding is resolved:** its log groups were declared with the database and left
  with it.

## 2026-10-02 — A failed landing no longer loses its batch: the worker keeps a high-water mark

**The defect** (found at the end-to-end run, entry above). Each cycle extracted a fixed window behind
the worker's clock: 20 minutes, every 15. When a landing failed, the worker logged "will retry next
cycle", but that was true only for the last five minutes of the batch. The rest had left the window
before the next cycle, and the three measurements from 14:53 were never extracted.

**The worker had durable state all along: the extracts it landed.** The old docstring rejected a
high-water mark because the worker "restarts with no memory". That ruled out keeping the mark in
the worker, but it did not rule out keeping it on the output.

**What changed** (`app/worker/main.py`):

- **Each extract's key carries its mark**, as in
  `measurements-<landed>-through-<mark>.ndjson`. The mark is the database's `now()`, read before the
  rows.
- **Each cycle lists the prefix and takes the largest mark.** It takes the largest mark rather than
  the last key, because keys sort by the worker's clock and marks by the database's. It then
  extracts rows stamped after that mark, less a five-minute overlap.
- **The overlap covers rows stamped before a mark but committed after it.** `recorded_at` defaults to
  `now()`, which is transaction start, so commit order is not stamp order.
- **A failed landing writes no key**, so the mark does not move and the next cycle reads the same rows.
  A database failure behaves the same way.
- **If the listing fails, the cycle is skipped.** Without a mark, any start point is a guess, and a
  late guess loses rows.
- **If no extract carries a mark, every row is read.** That covers the first cycle and extracts
  landed before this change. The table is rebuilt each session, so this means the session's rows
  and no more.
- `EXTRACT_WINDOW_MINUTES` is gone from the code and the task definition.

**Choices, and what was rejected:**

- **A timestamp, not an `id`.** The database is rebuilt each session and its ids restart at 1, so an
  id mark from an earlier session would skip every row of a new one.
- **The mark is the time read through, not the newest row landed.** A newest-row mark sits inside
  its own overlap. The row at the mark is re-read by every later cycle, so a new duplicate object
  lands every 15 minutes, forever, with no new data. With a read-through mark, a quiet cycle lands
  nothing.
- **The database's clock, not the worker's.** A skewed task clock cannot open a gap between what one
  cycle read and where the next starts.
- **In the key, not in object metadata.** Metadata would need `HeadObject`, which needs
  `s3:GetObject`. The worker role deliberately has no read access to what it lands (KSI-CNA-MAT's
  blast radius). Listing needs only `s3:ListBucket`, which reveals key names, not content.

**Permission added** (`infra/aws/compute.tf`, `FindHighWaterMark`): `s3:ListBucket` on the extracts
bucket, only for `s3:prefix` values matching `measurements/*`. The S3 gateway endpoint's policy
already allowed `ListBucket` for this role, and the bucket policy denies nothing that applies.
Extracts expire after 30 days, which bounds the listing at a few pages per cycle.

**The delivery contract is unchanged.** Delivery is still at-least-once: rows in the overlap land
twice, and the analytics MERGE on `id` absorbs the duplicates. `app/README.md` states the contract
in its new form.

**Proof so far is unit tests, not a run.** `app/worker/test_main.py` has eight hermetic tests,
covering:

- the regression: a failed landing, with the rows landed 30 minutes later
- a quiet cycle landing nothing
- a late commit inside the overlap being caught
- the mark being the database clock
- no mark meaning every row is read
- an unmarked newer key not hiding an older mark
- an unreadable listing skipping the cycle
- a database outage keeping the mark

Two negative controls ran against the same tests:

- **The old window logic** fails the regression test and three others.
- **A newest-row mark** fails four, including the quiet-cycle test.

The quiet-cycle test first passed the newest-row control by accident. In the fake, two landings in
the same second with the same mark share a key, so the duplicate overwrote and looked like no
landing. The fake now counts writes.

The tests run in `build-and-push.yml`'s scan job, which the build needs, so a failing test stops the
image.

**Still to verify at the next phase 2,** with an image built from this commit:

- The first cycle lands with a `-through-` key.
- A cycle with no new rows lands nothing.
- `s3:ListBucket` works through the endpoint.

## 2026-10-02 — The ECR lifecycle counts builds, not artifacts

**The defect.** The repositories kept "the last 10 images, any tag". Each build pushes four
artifacts:

- the `git-*` image index
- its untagged platform manifest
- an untagged buildx attestation
- the cosign signature, tagged `sha256-<index digest>.sig`

ECR counted three of these, so about three builds survived. `git-f9f2c35f8fd1` had expired by the
time a session went to deploy it. A preview of that policy today showed it was about to expire
`git-0eb149352c41` too.

**What ECR counts was measured, not assumed.** `start-lifecycle-policy-preview` evaluates a
candidate policy against the real repository without deleting anything. The preview of the old
policy showed:

- **Counted:** the indexes, their platform manifests, and the signatures.
- **Neither counted nor expired:** the attestations, which carry a subject. Two from 09-23 have
  outlived their images by nine days.

**The rules, by priority** (`infra/aws/registry.tf`):

1. **Keep the newest 10 `git-*` images.**
2. **Keep the newest 10 `sha256-*.sig` signatures.** There is one signature per build, pushed seconds
   after its image, so these are the kept builds' signatures. If they ever fell out of step, a kept
   build would fail at signature verification before deploy, loudly, rather than deploy unverified.
3. **Expire untagged artifacts after a day.**

**Each rule was previewed before applying.** I first ran a preview with both counts at 2, so it
would select something:

- **Rules 1 and 2** chose the same three builds: each expired signature's tag named an expired
  index's digest.
- **Rule 3** left the platform manifests of the kept images alone, because ECR does not select a
  manifest a kept index references.

The preview of the policy as written, with counts of 10, expired nothing in either repository.

**Applied** as a targeted apply of `aws_ecr_lifecycle_policy.service`. The provider replaces the
policy rather than updating it, so there were seconds with no policy. The live policies have the
three rules.

**Left as it is:** buildx attestations whose image has expired. No lifecycle rule selects them,
they are a few kilobytes each, and removing them would need a scheduled deletion job, which is more
machinery than the cost justifies. GCP's Artifact Registry has no cleanup policy, so nothing there
expires and the pipeline's pinned digest is not at risk.

## 2026-10-02 — Checks link the matrix rows they prove; coverage is counted by row

**The problem.** A check named only its indicator, so "12 of 46 indicators have automated evidence"
was the finest statement the project could make. It also overstated. One check counted an indicator
as covered, whether it proved one of the indicator's rows or all of them, and whether it proved any
row at all.

**Row identity.** The matrix's 380 evidence rows are the VERIFY and VALIDATE tables under 40
determinations. The six deferred determinations have only N/A PROVE rows. None of the rows has an
identifier, so each is given a positional one: `KSI-SVC-SIN.verify.1` is the first VERIFY row under
KSI-SVC-SIN.

A positional id moves if a row is inserted above it, which would silently move every later link onto
the wrong row. The guard is `docs/matrix-rows.json`, a generated snapshot of every id with its
row's text. `sdr/matrix_rows.py --check` fails when the workbook no longer produces the same file,
so a shifted row shows up as a reviewable diff.

Rows are read through the emitter's own strict parser, not a second one.

**Links** (a `matrix_rows` list on each check):

- **full:** the check proves the row as written.
- **full, with named checks:** used where a row spans both clouds. Each named check must link the
  same row back, naming this one. The validator refuses a one-sided group, which would let one cloud
  claim a two-cloud row.
- **partial:** must state what is missing.
- **No row:** a check that proves no evidence row carries an `unlinked_reason` instead, so no check
  sits outside the matrix silently.

**The mapping, judged row by row** against what each handler actually asserts, not its name:

- **8 checks prove no evidence row.** Examples are the workflow-level credential checks under
  IAM-SNU, the TLS-only bucket policy, and image signing. The matrix's rows ask for something else.
  For example, SVC-SIN validate.3 asks for *observed* plain-HTTP requests, not the policy that denies
  them.
- **Partial, with stated gaps.** Examples:
  - Config recorder: it doesn't check that all types are recorded.
  - Asset feed: it's at project scope, and there is no organization.
  - Inventory: one direction only.
  - Decrypt principals: AWS only.
  - Public access: AWS only.
  - Signature verification: at build, not at deploy.
  - Basic roles: two named allowances, where the row allows none.
- **Full**, each confirmed against its handler:
  - **SVC-SIN verify.1:** both clouds' store-key checks.
  - **SVC-SIN verify.5 and MLA-OSM verify.1:** the object lock and trail validation checks. The
    lock's 7-day floor is the declared retention.
  - **SVC-ACM verify.3, verify.4 and validate.1:** each by its AWS and GCP pair.
  - **CNA-DFP verify.4:** every action pinned to a SHA. This needed a new check,
    `cna-dfp-cfg-actions-pinned-collect`, because `collect.yml` had been unchecked; its 6 actions are
    pinned. The handler exempts only local `./` actions.

**Result:**

- **Rows:** of 380, 7 are fully automated, 11 partly, and 362 not at all.
- **Determinations:** 9 of 40 have any row with automated evidence.
- **Indicators with checks but no row:** IAM-SNU and SVC-VCM have checks, but none proves a matrix
  row.

This is the honest baseline the "12 of 46" figure stood in for.

**Where it shows:**

- **`docs/MATRIX-COVERAGE.md`:** a generated per-row report, including the unlinked checks and their
  reasons.
- **The SDR:** each VERIFY and VALIDATE statement in `ksiValidation` names its row id and the checks
  behind it, states any gap, or says "no automated check yet". The rendering's summary gives the row
  counts.

The coverage comes from the checks in the run being emitted, so an older results file reports every
row as not automated. That understates rather than overstates.

**Tests:**

- `sdr/test_matrix_rows.py` has negative controls for the validator: a dangling row, a partial link
  with no gap, an unknown `covers` value, neither or both of links and reason, a one-sided group, and
  a missing group member.
- `collect.yml` runs those tests and `matrix_rows.py --check` daily.
- An SDR emitted locally from the existing results, with the current definitions, validated against
  the pinned schema.
