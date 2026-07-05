# M6.13 Clinical-Content Boundary Specification — DRAFT

> **Status: DRAFT for founder review. Not operative canon.** Produced as part of the 2026-07-05 code-completion experiment (see `docs/operations/2026-07-05_founder_code_completion_experiment_decision.md`). Roadmap v2.6 §9 lists a "clinical-content boundary specification" as an M6.13 precondition; this draft exists so that precondition has a concrete starting point. It binds nothing until the founder adopts it.
>
> ANCHOR is **aligned, not compliant**. ANCHOR is **not an ambient scribe** and this specification exists to keep it that way.

## 1. Principle

ANCHOR governs *around* ambient AI workflows; it never becomes a participant in them. The boundary is enforced at three layers so that a policy failure at one layer cannot leak content:

| Layer | Enforcement |
|---|---|
| Schema | `ambient_governance_events` has **no column capable of holding content** — no transcript, note-body, audio, or free-text clinical field exists. The only external pointer is `workflow_reference_hash`. |
| API | `workflow_reference_hash` must be exactly a SHA-256 hex digest (validated); `source_label` must be a single short line (anti-paste guard); unknown payload fields (e.g. `transcript`, `note_text`) are dropped by the request model. |
| Product | The whole surface is behind `ANCHOR_AMBIENT_GOVERNANCE_ENABLED` (default off), and no vendor adapter exists. Adding one requires an explicit founder decision plus security/legal review (Roadmap v2.6 §9). |

## 2. What may cross the boundary (metadata-only vocabulary)

- Clinic-controlled **tool label** (`source_label`) — names the ambient tool as the clinic refers to it; never names patients, clients, or cases.
- **Event type** from a closed vocabulary: `consult_recorded`, `note_generated`, `note_reviewed_externally`, `other`.
- **Timestamps** and optional **duration in seconds**.
- Optional **SHA-256 reference hash** of an artefact held in the clinic's own systems — proves existence and identity of an external document without ANCHOR ever seeing it.
- **Review-gate metadata**: reviewer identity, review time, and a decision category (`approved_for_record`, `amended_before_use`, `rejected`).

## 3. What must never cross the boundary

Transcripts (full or partial); audio in any form; generated note text; clinical facts extracted from a consult; patient, client, or case identifiers; free-text summaries of clinical content; vendor payloads passed through unnormalised. If a future integration cannot express an event in the §2 vocabulary, the event does not enter ANCHOR.

## 4. Review gate semantics

The gate evidences that a human professional dispositioned each ambient artefact — it does not perform, replace, or quality-assure that review. `rejected` maps to `discarded`; the other decisions map to `reviewed`. Events are reviewable exactly once (amendments would be a new event, keeping the trail append-only).

## 5. Open questions for founder decision (not resolved by this draft)

1. Should ambient events link into governance receipts (receipt-per-review) or remain a parallel metadata trail surfaced in Trust only?
2. Is `duration_seconds` acceptable, or is even duration too behaviourally revealing for some clinics? (Nullable today.)
3. Retention class for ambient events relative to the R2 retention note.
4. Whether `note_reviewed_externally` is needed at all, or whether external review should always be recorded through the ANCHOR review gate.

## 6. Preconditions before any activation (unchanged from canon)

Security audit + legal pack complete; this specification adopted by founder decision; normalised event schema and review-gate model confirmed; no real transcript storage by default; no vendor integration until legal/security review. Demand is unvalidated (Addendum v1.3); building further requires a deliberate founder decision.
