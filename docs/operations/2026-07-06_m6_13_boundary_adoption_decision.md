# Founder Decision Record — M6.13 Clinical-Content Boundary Adoption

> **Status: dated founder decision record. 6 July 2026.**
>
> **Decision: the M6.13 clinical-content boundary specification is ADOPTED WITH AMENDMENTS as an internal boundary document.** The adopted text is `docs/product/2026-07-06_m6_13_clinical_content_boundary_spec_v1.md`, which supersedes the 5 July DRAFT.
>
> ANCHOR is **aligned, not compliant** — this record makes no compliance, certification, approval, or endorsement claim.

---

## 1. What this decision does NOT authorise

Merge to main/master; deployment; production flag enablement; vendor integration; transcript storage; audio upload; raw clinical content storage; clinical note generation; EHR/PMS integration; real clinic data; Trust Pack exposure; public claims. **M6.13 remains experiment-only until separate founder, security, legal, and solicitor review.**

## 2. Accepted boundary

ANCHOR may hold **metadata-only governance records about ambient AI workflow events**, but ANCHOR remains a **governance layer, not an ambient scribe**.

## 3. Required boundary rules (adopted)

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
13. **Schema-level CHECK hardening for `source_label` and `workflow_reference_hash` is required before any merge consideration.**

## 4. Implementation of rule 13

Implemented on the experiment branch as new migration `migrations/20260706_01_ambient_boundary_check_hardening.sql` (a NEW migration — `20260705_05` is not edited), adding:

- `ambient_source_label_single_line` — `CHECK (char_length(source_label) <= 200 AND source_label !~ '[\n\r]')`
- `ambient_reference_hash_sha256_shape` — `CHECK (workflow_reference_hash IS NULL OR workflow_reference_hash ~ '^[a-f0-9]{64}$')`

Validated against a throwaway local PostgreSQL 16 (fresh path; constraint-violation inserts refused; valid insert accepted) — results recorded below in §6.

## 5. Basis

- Founder decision pack of 6 July 2026 (M6.13 decision preparation, this repo session record).
- Full-stack readiness audit (5 July 2026) and pre-merge validation note (`2026-07-06_pre_merge_fix_validation_note.md`): RLS ENABLED + FORCED with USING/WITH CHECK verified on real Postgres, both apply paths.
- Founder wording review and wording-only patch (frontend `80e3fb7`): present-tense factual restriction wording ("the schema cannot store a transcript") adopted as the canonical phrasing.
- FIX 2 (`64ac727`): every review decision writes an append-only, metadata-only `admin_audit_events` row — recorded as part of the review-gate contract.

## 6. Rule-13 validation evidence

Recorded at implementation time (see the adoption commit and test suite):

- Static tests assert both constraints and their exact predicates exist in the new migration and that the original `20260705_05` migration is unmodified.
- Real-Postgres run: fresh path applied base schema + all migrations including `20260706_01`; a multi-line `source_label` insert and a non-SHA-256 `workflow_reference_hash` insert were **refused by the database** with CHECK violations; a well-formed metadata-only insert succeeded. Throwaway instance torn down afterwards; no production or existing local database touched; no real clinic data used.

## 7. Standing posture after this decision

Both gates remain default-off (`ANCHOR_AMBIENT_GOVERNANCE_ENABLED` backend; `NEXT_PUBLIC_ANCHOR_INTERNAL_PREVIEW` frontend). The ingestion interface remains validation-only with no vendor adapter. Solicitor questions (controller/processor mapping; staff-monitoring adjacency of timestamps/durations; retention class; client-transparency interplay; review-record liability wording) remain open and gate any real-clinic activation.

*Documentation of a founder decision. Not legal advice. Authorises exactly what §1 says it does not exclude: adoption of the boundary document and the rule-13 hardening on the experiment branch.*
