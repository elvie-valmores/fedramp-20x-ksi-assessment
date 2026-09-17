# SDR Emitter Specification

**Purpose.** Map the 46 worked KSI determinations onto FedRAMP's official Security Decision Record
schema so the project emits a schema-valid artifact rather than a bespoke one.

**Self-contained context.** This project is a FedRAMP 20x Class C Key Security Indicator
self-assessment against a real two-cloud environment. A persona of a two-person security team runs a
SaaS product on AWS with an analytics pipeline on GCP, commercial cloud, not FedRAMP-authorized
hosting. All 46 indicators in the catalog have been determined: 18 in scope, 22 in scope with stated
partials, 6 deferred with recorded reasons. The determinations live in KSI-Design-Matrix.xlsx and the
reasoning behind them in DECISIONS.md.

---

## Pinned inputs

**Catalog.** FedRAMP Consolidated Rules for 2026, version 2026.09.13.02, from
`fedramp-consolidated-rules.json` in the FedRAMP/rules repository.

**Schema.** `fedramp-security-decision-record-schema-2026-06-24.json` from the FedRAMP/schemas
repository.

| Property | Value |
|---|---|
| `$id` | `https://fedramp.gov/schemas/fedramp-security-decision-record-schema-2026-06-24.json` |
| `title` | FedRAMP Security Decision Record (SDR-CSO-FRR) |
| `$schemaVersion` | **1.1.1** |
| JSON Schema draft | 2020-12 |
| sha256 | `94580404e8d4276ee3ced2a3c39cce5cc6565df6ae38a91f60f26cb96d833188` |
| Size | 11593 bytes |
| Retrieved | 2026-09-14 |

**Pin both the filename and the internal version.** The filename is dated 2026-06-24 and has not
changed, but the schema's own `$schemaVersion` has moved — it was 1.0.3 and is now 1.1.1, and a
field-name typo fix changed `frrAssesment` to `frrAssessment` and `ksiAssesment` to `ksiAssessment`
after initial publication. A filename pin alone would not have caught either. Pin the filename, the
`$schemaVersion`, and the hash, and re-verify on the same discipline the catalog pin uses.

---

## Schema shape

Top-level required: `certificationPackageOverviewUri`, `fedRampRequirements`.

| Property | Type | Role in this project |
|---|---|---|
| `metadata` | object | Required by SDR-CSO-MTD: `version`, `lastUpdated`, `updateSource` |
| `keySecurityIndicators` | array | **What this project produces.** One entry per indicator |
| `fedRampRequirements` | array | Required by the schema; **out of this project's scope** — see below |
| `securityControls` | array | NIST 800-53 control entries; not produced, 20x is indicator-based |
| `portsAndProtocols` | array | Service, port, protocol; derivable from the environment |
| `certificationPackageOverviewUri` | ref | Points at a Certification Package Overview that does not exist here |

### A gap worth naming up front

The schema requires `fedRampRequirements` — the FRR half, covering how the provider meets the rule
sets themselves, not the indicators. This project determined the 46 KSIs and did not determine the
FRR rules. A schema-valid SDR therefore needs an array this project does not populate.

Two honest options: emit `fedRampRequirements` as an empty array and state in the README that the
project covers the indicator half of the SDR, or populate it for the handful of rulesets the
determinations already lean on, which are MAS, VDR, IVV and SDR itself. Neither is fabrication; the
first is narrower and the second is more work. The emitter should make this a switch rather than a
silent omission.

---

## Per-indicator mapping

Each determination becomes one `keySecurityIndicators[]` entry. Required per entry: `ksiId`,
`ksiImplementation`, `ksiValidation`, `ksiAssessment`, `ksiTests`, `ksiEvidence`.

| Schema field | Type | Source in the determination |
|---|---|---|
| `ksiId` | string | The indicator ID |
| `ksiImplementationStatus` | enum | In scope → `Implemented`; In scope, partial → `Partially Implemented`; Deferred → `Not Implemented` |
| `ksiImplementation` | array of strings | Design rationale, then each BUILD row as "what to build — configuration". Markdown permitted |
| `ksiValidation` | array of strings | Each VALIDATE row as "artifact — source", plus the cycle statement, which is what SDR-CSX-KSI item 2 asks for |
| `ksiAssessment` | array of strings | Automation assurance and limitations. The schema calls this the independent validator's description; with no assessor engaged, this carries the provider's own assurance reasoning and says so |
| `ksiTests` | array of strings | The deliberate test scenarios and the self-tests for standing zero-results queries |
| `ksiEvidence` | array of objects | One per evidence row; see below |

### Evidence objects

`evidenceType` is an enum: `Log`, `Report`, `Screenshot`, `Configuration`, `Policy`, `Procedure`,
`Audit Record`. The project's two evidence classes map cleanly — CFG rows are `Configuration`, OPS
rows are `Log` or `Audit Record` depending on source. Nothing produces `Screenshot`, which is worth
noting as a sign the evidence is machine-generated rather than captured by hand.

Fields: `evidenceType`, `evidenceDescription`, `evidenceLocation` (URI), `evidenceText` (inline
command or log output), `lastUpdated`. None is required by the schema, which means an entry could be
empty and still validate — so the emitter enforces its own rule that every evidence object carries a
type, a description, and either a location or text.

---

## Mapping SDR-CSX-KSI's five required summaries

The rule requires five things per indicator. All five have a home:

| SDR-CSX-KSI requires | Emitted into |
|---|---|
| 1. Explanation of measures and their objectives, or the reason and resulting risk for having none | `ksiImplementation` — rationale plus build items; for deferrals, the deferral rationale and its stated customer risk |
| 2. Explanation of the cycle for persistent measures | `ksiValidation` — the cycle statement |
| 3. Verification that the measures demonstrate the indicator | `ksiValidation` — the CFG rows |
| 4. Verification that the automation is accurate and sufficient | `ksiAssessment` — the automation assurance band |
| 5. Validation that measures are accurately produced and working | `ksiValidation` — the OPS rows |

The six deferrals satisfy item 1 through its second clause, which is why every deferral in this
project carries a stated resulting risk to customers rather than only a reason.

---

## SDR-CSX-KMT: the metrics requirement, and the hard wall

At Class C the provider MUST include historical metrics per indicator: a 30-day summary, a summary up
to the past year where available, and **all daily metric data up to the past year where available**.

An environment that is applied and destroyed per session cannot produce a year of daily metrics. The
"where available" qualifier makes this survivable — the honest emission is the metrics that exist,
with the collection window stated. But this is the single hardest requirement in the SDR for this
persona, and the README should name it rather than let a reader assume a year of data sits behind the
artifact.

Emitted as: per indicator, the 30-day summary computed from the review record store, the longer
summary where the window allows, and the daily series for the period actually collected.

---

## Emitter behaviour

**One emitter, reading determinations and evidence, not per-indicator code.** 40 indicators produce
entries from their evidence records; 6 produce entries with `Not Implemented` status and the deferral
rationale.

**Validate on emit.** The generated JSON is checked against the pinned schema in CI and the build
fails on a validation error, not a warning.

**Verify the pin on schedule.** Re-fetch the schema, compare `$schemaVersion` and hash against the
pinned values, and fail on drift. The catalog pin already works this way and the schema needs the same
treatment for the reason stated above: the filename lies about the version.

**Human-readable output alongside JSON.** SDR-CSO-FRR requires both formats. The readable form is
generated from the same source, never maintained separately.

---

## What this does not produce

Independent verification and independent validation are two of the seven items SDR-CSO-FRR requires,
and both require a FedRAMP Recognized assessor. No assessor is engaged, so those fields are emitted
empty with a stated reason rather than filled with self-assessment wearing an assessor's label. The
same applies to the seventh item, responses to assessor comments, since there are no comments.
