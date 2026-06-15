# ANCHOR Receipt Schema Gap Analysis v0.1

> **Internal strategy artefact. Documentation only.** This document compares the **AI Governance Receipt Schema v0.1** (`2026-06-11_anchor_ai_governance_receipt_schema_v0_1.md`) against the **live ANCHOR implementation** as of 2026-06-15. It is **not implementation**, **not a migration plan**, and **not a connector brief**. It changes no code, schema, migration, test, or frontend file.
>
> ANCHOR is **governance, trust, learning, intelligence, and readiness infrastructure for safe AI use in veterinary clinics** — **not** a clinical decision-making AI, diagnostic tool, ambient scribe, EHR/PMS, or replacement for veterinary judgement. ANCHOR is **aligned, not compliant**: **not RCVS-approved**, **not GDPR-certified**, **not EU AI Act-compliant**, **not regulator-endorsed**, with **no protection from enforcement**. Live Workspace generation **remains production-off**. Nothing here authorises a pilot, real clinic data, or any external connector.

---

## 1. Status and purpose

**Status.** Documentation-only strategy artefact, dated 2026-06-15. It is a companion to the Receipt Schema v0.1 artefact and sits alongside the operative canon in `../canonical/`. It introduces no behaviour and modifies no doctrine.

This document is explicitly:

- **Documentation-only** — a comparison and scoping artefact, not an implementation contract.
- **Not implementation** — it builds nothing and grades nothing.
- **Not a migration plan** — it proposes no schema change and no migration.
- **Not a connector brief** — it builds no ingestion path to any external system.

**Purpose.** Capture the comparison between the new schema and the live implementation so that any future implementation can be **scoped deliberately rather than guessed**. The schema's §14 ("Recommended next action") asked for exactly this review: compare the schema against existing ANCHOR receipt fields and the Trust Pack evidence model, then identify gaps for a future implementation brief. This document is that review, recorded.

**Method.** Direct read of the receipt-related migrations, the consolidated `app/schema.sql`, the Trust Pack builders, and the incident/near-miss schema, mapped field-by-field against the v0.1 canonical field set (§5 of the schema) and its evidence-class (§3) and evidence-strength (§4) models.

---

## 2. Implementation surfaces reviewed

| Surface | Source | Role in the evidence model |
| --- | --- | --- |
| `assistant_runs` | `migrations/20260515_01_assistant_runs.sql` | Metadata-only run record (hashes, key lists, flags, governance pointers). |
| `assistant_run_receipts` | `migrations/20260524_01_assistant_run_receipts.sql` + `migrations/20260524_04_assistant_run_receipt_policy_metadata.sql` | The sealed, human-reviewed evidence snapshot. This **is** ANCHOR's "receipt". |
| `clinic_governance_events` | `app/schema.sql` (≈ line 351) | Per-request governance decisions (`decision`, `pii_action`, `policy_version`, `mode`). |
| Trust Pack / trust snapshot builders | `app/trust_snapshot.py` | Aggregate posture: governance-policy, self-assessment, client-transparency, incident/near-miss blocks; metadata-only self-assertions. |
| Trust scoring | `app/trust_scoring.py` | Derived posture score, trust state, receipt-coverage rate, recommended topics/actions. |
| Incident / near-miss receipt linkage | `migrations/20260603_03_incident_near_miss_schema.sql` | Enum-only, ID-only `ai_incident_near_miss_records` with `linked_receipt_id` referencing a receipt. |

---

## 3. Executive finding

- **Class A native ANCHOR capture is already substantially implemented.** `assistant_run_receipts` is, in all but name, the v0.1 Class A native receipt: it captures hashes, mode/contract/workflow origin, policy snapshot, review state and decision, model labels, safety/refusal flags, and timestamps — frozen at receipt time.
- **Classes B–E are not implemented and remain future.** There is no verified external runtime/feed (B), imported artefact (C), declared-use/manual attestation (D), or unverified narrative (E) path. `workflow_origin` is the designed extension seam but only ever holds the native value `'anchor_assistant'`.
- **Evidence-strength grading is the biggest missing moat.** Nothing in the receipt, run, governance event, or Trust Pack carries a Strong / Moderate / Limited / Weak provenance grade. The nearest concept, Trust `signal_quality` (low/moderate/strong), measures *recent event volume*, not *how verifiable the evidence is*. This is the single highest-value gap.
- **Current code enforces metadata-only posture more strongly than the v0.1 schema text describes.** `raw_content_stored`, `prompt_stored`, and `draft_stored` are not merely asserted — they are `CHECK`-constrained to `false`, and every Trust block self-asserts `raw_content_included: False`. The code is stricter than the doc; the doc currently undersells the implementation.
- **Some schema fields exist at different altitudes.** Several v0.1 "receipt fields" are real in ANCHOR but live at the **clinic-configuration** altitude (`clinic_client_transparency_profiles` permitted/prohibited-use categories), the **Trust Pack narrative** altitude (`governance_note` / `limitations[]` strings), or the **operational-documentation** altitude (retention via the prune runbook) — not on the per-interaction receipt.

---

## 4. Field-by-field comparison table

Status legend: **exists** (present on the receipt today) · **partial** (present but narrower/different shape) · **missing** (absent everywhere) · **different altitude** (real in ANCHOR, but not on the receipt record).

| v0.1 canonical field | Current implementation | Status | Notes |
| --- | --- | --- | --- |
| `receipt_id` | `assistant_run_receipts.id` (uuid PK) | exists | One receipt per `(clinic_id, assistant_run_id)` via unique index. |
| `receipt_version` | `receipt_version` (`'assistant_receipt_v1'`) + `receipt_kind` | exists | Per-kind version literal; reconcile naming with the schema-version concept. |
| `evidence_source_class` | — none; `workflow_origin` always `'anchor_assistant'` | missing | Everything is implicitly Class A. Extension seam exists but unused. |
| `evidence_strength` | — none; Trust `signal_quality` is volume, not provenance | missing | **The moat.** No Strong/Moderate/Limited/Weak grade anywhere. |
| `clinic_id` / tenant | `clinic_id` (FK to `clinics`, RLS **+ FORCE**) | exists | Stronger than the doc states; tenant-isolation enforced at DB. |
| user / staff role | `created_by_user_id` (uuid) | partial | Stores user UUID, not a role label; schema prefers role-not-identity. |
| reviewer identity or reviewer label | `assistant_run_reviewed_by_user_id` (uuid) | partial | UUID only; no "reviewer label" alternative mode. |
| workflow mode | `mode` + `workflow_origin` | exists | Native only; `mode` e.g. `client_comm` / `clinical_note`. |
| AI/tool identity | `model_name` | exists | Conflates identity and version. |
| AI/tool version | — folded into `model_name` | partial | No discrete version field. |
| provider/vendor | `model_provider` (nullable) | exists | Vendor-neutral; nullable by design. |
| policy/governance profile | `assistant_policy_id`, `assistant_policy_version`, `assistant_validation_profile`, `contract_version` | exists | Strong policy snapshot on the receipt. |
| permitted-use category | `permitted_use_categories` on `clinic_client_transparency_profiles` | different altitude | Clinic-level config, surfaced via Trust Pack; not per-receipt. |
| prohibited-use boundary | `prohibited_use_categories` on transparency profile | different altitude | Same as above. |
| data boundary | `storage_policy = 'metadata_only_by_default'` | exists | CHECK-guarded literal. |
| `raw_content_stored` | `raw_content_stored` (+ `prompt_stored`, `draft_stored`) **CHECK-forced false** | exists | Stronger than doc: DB CHECK enforces all three false. |
| input/output hash | `input_sha256` (NOT NULL), `output_sha256` (nullable) | exists | Hashes only; never raw content. |
| timestamps | `assistant_run_created_at`, `assistant_run_reviewed_at`, `receipt_created_at`, `created_at`, `updated_at` | exists | Richer than the doc's single `timestamps` field. |
| human-review state | `review_status` (CHECK: `reviewed_approved` / `reviewed_rejected` / `reviewed_needs_edit`) | exists | Receipts only sealed for reviewed runs. |
| review decision | `review_decision` (nullable) | exists | Present alongside review status. |
| output-use decision | — none | missing | No "was the output operationally used after review" field. |
| client-transparency posture | Trust `client_transparency` block (clinic-level): `human_review_statement_enabled`, `privacy_statement_enabled`, `client_explanation_statement_enabled` | different altitude | Posture exists at clinic level, not snapshotted per receipt. |
| consent/disclosure posture | — none per interaction | missing | Absent everywhere at the interaction grain. |
| safety/refusal flags | `safety_flags`, `refusal_reason_codes` (+ `pii_detected`, `pii_types`) | exists | Stronger than the doc's single field. |
| incident/near-miss linkage | `ai_incident_near_miss_records.linked_receipt_id → receipt` (ID-only) | partial | Link exists in the **reverse** direction; receipt does not point to incident. |
| retention posture | Operational only (`intake_retention.md` / prune runbook); not a receipt field | different altitude | No structured per-receipt retention field. |
| deletion/offboarding posture | Operational only; FKs use `ON DELETE RESTRICT` | different altitude | No structured per-receipt deletion/offboarding field. |
| linked artefacts | `assistant_runs.receipt_id`, `assistant_runs.governance_event_id`, `receipts.assistant_run_id`, incident `linked_receipt_id` | partial | A partial link graph exists; not a general `linked_artefacts` set. |
| standards/professional mapping | Narrative `governance_note` strings in Trust blocks | different altitude | Not a structured, per-record mapping. |
| non-claims | Narrative `limitations[]` / `governance_note` in Trust Pack | partial | Present as prose, not a structured receipt field. |

---

## 5. Strong existing implementation

The implementation is mature where it counts for Class A. Specifically:

- **`assistant_run_receipts` already acts as ANCHOR's Class A native receipt.** It is a metadata-only snapshot of one human-reviewed run, sealed as evidence — exactly the v0.1 Class A intent.
- **`clinic_id` and RLS/FORCE posture are stronger than the strategy doc needs to state.** Every receipt is tenant-scoped via `clinic_id` with **RLS ENABLED + FORCED** and a `USING` + `WITH CHECK` tenant policy on `app_current_clinic_id()`.
- **`raw_content_stored`, `prompt_stored`, and `draft_stored` are CHECK-enforced `false`.** A single table CHECK (`assistant_run_receipts_metadata_only_check`) makes the metadata-only boundary a database invariant, not a convention.
- **Input/output hashes exist** — `input_sha256` (NOT NULL) and `output_sha256` (nullable) carry provenance without raw content.
- **Policy metadata exists** — `assistant_policy_id`, `assistant_policy_version`, `assistant_validation_profile`, and `contract_version` capture the governance profile in force at seal time. Legacy receipts pre-dating M6.7.1 carry NULLs and deserialize cleanly.
- **Review state and review decision exist** — `review_status` (CHECK-constrained) and `review_decision`, plus reviewer UUID and reviewed-at timestamp.
- **Safety/refusal flags exist** — `safety_flags`, `refusal_reason_codes`, `pii_detected`, and `pii_types` are first-class metadata.

**Implication for the schema doc:** v0.1 §12 should state plainly that Class A is *already shipped* as `assistant_run_receipts`, and §6 should note the metadata-only boundary is `CHECK`-enforced in code. The doc is currently weaker than the code.

---

## 6. Highest-value missing fields

In rough priority order:

1. **`evidence_source_class`** — the A–E discriminator. Without it, nothing can distinguish native capture from a future declared-use or imported record.
2. **`evidence_strength`** — the Strong / Moderate / Limited / Weak grade.
3. **`output_use_decision`** — whether/how the reviewed output was actually used operationally.
4. **`consent_disclosure_posture`** — consent/disclosure posture at the interaction grain.
5. **Structured retention/deletion posture** — `retention_posture` and `deletion_offboarding_posture` as fields rather than runbook prose (if we choose to make them receipt-level).
6. **Structured standards/professional mapping** — a per-record mapping rather than narrative notes.
7. **Structured non-claims** — a standard receipt disclaimer field rather than Trust Pack prose.
8. **Per-receipt client-transparency / use-boundary snapshot** — *only if* we choose to denormalise permitted/prohibited-use and transparency posture onto the receipt (see §7).

**`evidence_strength` is the most strategically important.** It is the mechanism by which ANCHOR distinguishes **strong native evidence** (Class A captured inside a governed workflow) from **weaker declared-use records** (Class D/E with no verifiable runtime evidence). Without honest strength grading, every record reads as equivalent, which both understates the strength of native capture and risks over-stating weak records — the exact failure the schema's §4 and §11 forbid. It is the moat; it should be designed first.

---

## 7. Altitude decisions needed

Several v0.1 fields are real in ANCHOR but currently sit at a different altitude. Whether to pull them onto the receipt is a **design decision, not a defect**. Each needs a deliberate call in a future brief:

- **Permitted / prohibited use boundaries** may remain **clinic-level policy/transparency configuration** (`clinic_client_transparency_profiles`), with the receipt referencing the active profile/version rather than copying the lists. Denormalising onto the receipt buys point-in-time immutability at the cost of duplication.
- **Client-transparency posture** may be **denormalised onto receipts only when relevant** (e.g. client-facing `client_comm` runs), rather than on every receipt. Internal-only runs may legitimately carry "not applicable".
- **Non-claims** may remain **Trust Pack narrative** or become a **standard receipt disclaimer** field. A fixed disclaimer field is cheap and improves portability of an individual receipt outside the Trust Pack.
- **Retention / deletion posture** may remain **operational documentation** (the prune runbook) or become a **receipt field**. If receipts are ever exported to insurers/procurement, a per-record retention statement becomes more valuable.
- **Standards / professional mapping** may be **derived at render time** (from policy profile + mode) rather than **stored** on each receipt, avoiding stale mappings when standards interpretation evolves.

Default lean (for the brief to confirm, not a decision here): keep clinic-level config clinic-level and **reference** it from the receipt; snapshot only what must be immutable at seal time; derive standards mapping; make non-claims a standard disclaimer.

---

## 8. Proposed future implementation order

Documentation-only recommendation. **No code change is recommended now.**

1. **Evidence class and strength model design brief** — define the A–E enum, the Strong/Moderate/Limited/Weak grade, derivation rules, and the §4 honesty/over-grading guard. Design only.
2. **Native receipt backfill strategy** — define how existing `assistant_run_receipts` map to **Class A / Strong** under explicit, written derivation rules (e.g. native capture + sealed review + hashes present ⇒ Strong), including how exceptions/uncertainty states are graded.
3. **UI / Trust Pack evidence-strength display design** — decide how strength is shown so weak records are never visually equivalent to strong ones, honouring §4/§11.
4. **Only later: Class B–E ingestion / declared-use support** — verified external feed, imported artefact, declared-use, and narrative paths, each evidence-graded before persistence.
5. **Only later: connector-specific implementation briefs** — per-system briefs, written only once a connector is actually in scope.

Steps 1–3 are pure design/strategy and touch native evidence only. Steps 4–5 are gated future and must not begin without an explicit founder decision recorded in an addendum (consistent with M6.12/M6.13 being gated future).

---

## 9. Risks and non-claims

- **Do not over-grade weak/manual evidence.** A Class D/E declarative record must never be graded or presented as Strong. Over-grading is a doctrine violation, not a presentation choice.
- **Do not claim external runtime ingestion exists.** No Class B connector exists today; `workflow_origin` is native-only. Class B remains a target, not a capability.
- **Do not claim receipts prove clinical correctness, patient safety, regulatory compliance, or external AI-tool safety.** A receipt evidences governance posture at a stated strength — nothing more.
- **Do not move clinic-level responsibilities onto ANCHOR.** Permitted/prohibited-use definition, human review, and professional judgement remain the clinic's; ANCHOR evidences, it does not decide.
- **Do not weaken metadata-only doctrine.** The `CHECK`-enforced `raw_content_stored = false` invariant and the Trust Pack self-assertions must be preserved; no field added in any future work may introduce raw prompts, outputs, transcripts, drafts, or clinical content.

ANCHOR remains **aligned, not compliant**. No RCVS approval, certification, regulator endorsement, or enforcement protection is claimed or implied by any receipt, by the Trust Pack, by this analysis, or by the schema it analyses.

---

## 10. Recommended next action

**Keep this as strategy documentation.** It records the gap between the v0.1 schema and the live implementation so the work can be scoped deliberately later.

A future **implementation brief** should be created **only when the founder explicitly chooses** to bring **evidence-strength grading** or **connector preparation** into scope. Until then: no migration, no schema change, no grading logic, no connector. The native Class A receipt model continues to operate exactly as built.
