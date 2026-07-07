# M6.13 Clinical-Content Boundary Specification — v1 (ADOPTED WITH AMENDMENTS)

> **Status: adopted internal boundary document, 6 July 2026**, per the founder decision recorded in `docs/operations/2026-07-06_m6_13_boundary_adoption_decision.md`. Supersedes the 5 July DRAFT. Adoption authorises nothing beyond the boundary itself and the rule-13 hardening: no merge, no deployment, no flag enablement, no vendor integration, no real clinic data, no Trust Pack exposure, no public claims. **M6.13 remains experiment-only until separate founder, security, legal, and solicitor review.**
>
> ANCHOR is **aligned, not compliant**. ANCHOR is **not an ambient scribe** and this specification exists to keep it that way.

## 1. Principle

ANCHOR may hold **metadata-only governance records about ambient AI workflow events**, but ANCHOR remains the **governance layer, not the scribe**. It governs *around* ambient AI workflows; it never becomes a participant in them. The boundary is enforced at three layers so a failure at one layer cannot leak content:

| Layer | Enforcement |
|---|---|
| Schema | `ambient_governance_events` has **no column capable of holding content** — no transcript, note-body, audio, or free-text clinical field exists. The only external pointer is `workflow_reference_hash`. **Rule-13 hardening** (`migrations/20260706_01_ambient_boundary_check_hardening.sql`) makes this literal for the two text columns: `source_label` is CHECK-constrained to a single line of at most 200 characters, and `workflow_reference_hash` is CHECK-constrained to exactly a SHA-256 hex digest. |
| API | `workflow_reference_hash` must be exactly a SHA-256 hex digest (validated); `source_label` must be a single short line (anti-paste guard); unknown payload fields (e.g. `transcript`, `note_text`, `audio`) are dropped by the request model. All behaviours test-enforced. |
| Product | The whole surface is behind `ANCHOR_AMBIENT_GOVERNANCE_ENABLED` (default off; every endpoint 503s without it) and, on the portal side, the build-time internal-preview flag (default off). No vendor adapter exists. The portal has **no event-creation UI**. |

Canonical phrasing rule (from the 6 July founder wording review): use present-tense factual restrictions — *"the schema cannot store a transcript"* — never eternal promises ("never/ever").

## 2. What may cross the boundary (metadata-only vocabulary)

- Clinic-controlled **tool label** (`source_label`) — names the ambient tool as the clinic refers to it; **clinic-controlled and non-identifying** (rule 12): never patients, clients, or cases; single line, ≤ 200 characters at schema level.
- **Event type** from a closed vocabulary: `consult_recorded`, `note_generated`, `note_reviewed_externally`, `other`.
- **Timestamps** and optional **`duration_seconds`** — retained as **optional operational metadata** (rule 11; nullable, API-capped at 24h).
- Optional **SHA-256 reference hash** of an artefact held in the clinic's own systems — proves existence and identity of an external document without ANCHOR ever seeing it; SHA-256 shape enforced at schema and API level.
- **Review-gate metadata**: reviewer identity, review time, and a decision category (`approved_for_record`, `amended_before_use`, `rejected`).
- **Audit trail**: every successful review decision writes an append-only, metadata-only `admin_audit_events` row (`ambient_event_reviewed`, target = event id, meta = decision category + resulting status) — part of the review-gate contract.

## 3. What must never cross the boundary

Transcripts (full or partial); audio in any form; generated note text; clinical facts extracted from a consult; patient, client, or case identifiers; free-text summaries of clinical content; vendor payloads passed through unnormalised. If a future integration cannot express an event in the §2 vocabulary, the event does not enter ANCHOR.

## 4. Review gate semantics

The gate evidences that a named professional dispositioned each ambient artefact into a bounded category — **it evidences process, not clinical correctness** (rule 6), and it does not perform, replace, or quality-assure the review. The clinical record remains in the clinic's own systems (rule 7). `rejected` maps to `discarded`; the other decisions map to `reviewed`. Events are reviewable exactly once; amendments would be new events, keeping the trail append-only.

## 5. Decisions resolved by adoption (previously open)

| Question | Resolution |
|---|---|
| Receipt linkage | **Deferred** (rule 8). The trail is the event row + the admin audit event; receipt-per-review is a future design decision. |
| `duration_seconds` | **Retained**, optional operational metadata (rule 11); staff-monitoring adjacency flagged to the solicitor. |
| Retention class | **Incident/near-miss class**, pending solicitor confirmation (rule 10); no deletion automation. |
| Trust visibility | **Deferred** (rule 9); none until a separate decision after any merge; then counts-only. |
| Vendor reference metadata | Not added; `source_label` stays a clinic-controlled label; any vendor registry is separately-authorised future work. |
| `note_reviewed_externally` event type | Retained in the vocabulary; revisit at the first real integration design. |

## 6. Standing rules (adopted, verbatim intent)

1. The schema must not store transcripts, audio, note bodies, or raw clinical content.
2. The API must refuse or drop content-shaped input.
3. The product must remain disabled by default.
4. No portal event-creation UI without a separate founder decision.
5. No vendor adapter without separate founder authorisation, security review, and legal review.
6. Review decisions evidence process, not clinical correctness.
7. Clinical records remain in the clinic's own systems.
8. Receipt linkage is deferred.
9. Trust visibility is deferred.
10. Retention follows the incident/near-miss class pending solicitor confirmation.
11. `duration_seconds` remains optional operational metadata.
12. `source_label` remains a clinic-controlled, non-identifying label.
13. Schema-level CHECK hardening for `source_label` and `workflow_reference_hash` is required before any merge consideration (implemented: `20260706_01`).

## 7. Preconditions before any activation (unchanged from canon)

Security audit and legal pack complete; solicitor questions answered (controller/processor mapping; staff-monitoring adjacency; retention; client-transparency interplay; review-record liability wording); no real transcript storage; no vendor integration until legal/security review; demand remains unvalidated (Addendum v1.3) — building further requires a deliberate founder decision. Merge of the M6.13 slice itself additionally requires the selective-harvest decision and travels last in the recommended order.
