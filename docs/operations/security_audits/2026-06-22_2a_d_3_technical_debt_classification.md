# 2A-D.3 Technical-Debt Classification Note

> **Status:** Documentation-only closure note — no product behaviour changed; not a blocker to the already-closed RC coherence lane.
>
> ANCHOR is **aligned, not compliant**. Live Workspace generation **remains production-off**. Paid pilots and real clinic data **remain blocked**. This note classifies pre-existing technical debt for traceability; it authorises and changes nothing.

---

## 1. Purpose

The 2A-D.3 RC coherence lane is **substantively complete and closed** (see [`2026-06-16_rc_coherence_closure.md`](./2026-06-16_rc_coherence_closure.md)). The canonical planning docs (Roadmap v2.6 §237; Decision Memo Addendum v1.3 §90) list a tech-debt classification sub-task — **TD-BE-1, TD-BE-2, TD-FE-1, TD-FE-2 → blocker / must-fix / should-fix / defer** — that was never produced as a labelled artefact.

This note resolves that remaining labelled classification gap **using the founder-provided 2A-D.3 source of truth** (which supplies the per-label detail) plus existing repo evidence. It does **not** reopen the RC coherence lane, does **not** authorise any code change, and does **not** alter product behaviour. It is a traceability artefact.

## 2. Evidence basis

- **Founder-provided 2A-D.3 source of truth** — authoritative for the TD-BE / TD-FE label definitions, the already-handled items, and the future policy-history enhancements recorded below.
- Already-handled `ON CONFLICT` fixes confirmed (read-only) in code: `app/assistant_policy.py:~334` (Assistant policy audit insert — "do NOT use ON CONFLICT … append-only"); `app/portal_submit.py:~546–554` (`SQL_INSERT_OVERRIDE_AUDIT` — audit is append-only by doctrine, `ON CONFLICT` removed).
- [`2026-06-16_rc_coherence_closure.md`](./2026-06-16_rc_coherence_closure.md) — RC coherence lane closure (§8 non-blocking follow-ups).
- [`2026-06-16_2a_d_current_status_checkpoint.md`](./2026-06-16_2a_d_current_status_checkpoint.md) — §6 watch items (AppShell custom-font lint warning known/non-blocking; future frontend polish for demonstration quality).
- Backend [`CLAUDE.md`](../../../CLAUDE.md) — "FastAPI/OpenAPI deprecated-route warnings — deferred technical debt."
- Frontend evidence (cross-referenced, not changed): `anchor-portal/docs/operations/frontend_rc_polish/2026-06-20_frontend_rc_polish_checkpoint.md` §10 (AppShell custom-font warning deferred — "do not fix"; broad UI redesign deferred); frontend `CLAUDE.md` §125 ("tech-debt classification (AppShell font, portal visual consistency)").
- Canonical label source: Roadmap v2.6 §237; Decision Memo Addendum v1.3 §90.

## 3. Classification scale

- **HANDLED** — already fixed in code; recorded for traceability.
- **BLOCKER** — must be fixed before RC can be treated as internally coherent.
- **MUST-FIX** — should be fixed before external pilot / real clinic use.
- **SHOULD-FIX** — valuable polish or maintainability item; not a hard RC blocker.
- **DEFER** — explicitly deferred by decision; track but do not block RC.
- **FUTURE** — deliberately out of current scope; design-gated enhancement; tracked, not RC tech debt and not a blocker.

## 4. Already-handled items (closed)

| Item | Area | Description | Classification | Evidence | Notes |
|---|---|---|---|---|---|
| TD-BE (handled) | Backend | Assistant policy audit insert partial-index `ON CONFLICT` bug. | **HANDLED** | `app/assistant_policy.py:~334` (append-only insert; no `ON CONFLICT` against the partial index) | Append-only audit doctrine; regression resolved. No further action. |
| TD-BE (handled) | Backend | `portal_submit` `SQL_INSERT_OVERRIDE_AUDIT` partial-index `ON CONFLICT` bug. | **HANDLED** | `app/portal_submit.py:~546–554` (audit append-only; `ON CONFLICT` removed) | Append-only audit doctrine; regression resolved. No further action. |

## 5. Active TD classification table

| Label | Area | Description | Classification | Evidence | Rationale | Action |
|---|---|---|---|---|---|---|
| **TD-BE-1** | Backend | FastAPI/OpenAPI deprecated-route warning cleanup. | **DEFER** | backend `CLAUDE.md` ("FastAPI/OpenAPI deprecated-route warnings — deferred technical debt"); founder source of truth | Cosmetic framework warning; no behaviour, security, or coherence impact; already recorded as deferred. | Track; revisit on a framework upgrade. Not blocking RC. |
| **TD-BE-2** | Backend | pytest broad collection/import cleanup. | **SHOULD-FIX** | founder-provided 2A-D.3 source of truth (later technical debt) | Test-suite maintainability/hygiene (collection/import tidy-up); improves developer ergonomics but does not affect product behaviour, governance, or RC coherence. | Schedule as a separate authorised test-only patch; not blocking RC. |
| **TD-FE-1** | Frontend | AppShell custom-font warning / font-loading architecture. | **DEFER** | frontend RC polish checkpoint §10; frontend `CLAUDE.md` (AppShell font — "do not fix"); `2026-06-16_2a_d_current_status_checkpoint.md` §6 | A single known lint warning explicitly marked "do not fix"; baseline is 0 errors; no functional or coherence impact. | Track; deferred by decision. No action. |
| **TD-FE-2** | Frontend | Portal-wide visual polish / colour and card consistency. | **SHOULD-FIX** | frontend RC polish checkpoint §10; frontend `CLAUDE.md` §125 | Demonstration-quality polish that improves the founder demo but does not affect governance behaviour, coherence, or safety; broad redesign explicitly deferred. | Optional polish before external demonstration; not an RC blocker. Broad redesign stays out of scope. |

**No BLOCKER and no MUST-FIX identified** — no repo evidence of a debt that blocks internal RC coherence or that must be fixed purely as tech debt before pilot. Anything touching live generation, legal/solicitor approval, paid pilots, or real clinic data is intentionally **out of scope of this TD note** and remains governed by the hard-stop gates in §9.

## 6. Future policy-history enhancements

Design-gated enhancements (not current tech debt; not RC blockers). All **FUTURE**.

| Item | Area | Description | Classification | Notes |
|---|---|---|---|---|
| Future-1 | Backend | Expose backend `changed_fields` in policy history. | **FUTURE** | Surfacing what changed between policy versions; metadata-only; design + review required before build. |
| Future-2 | Backend/Frontend | Actor display name / email resolution, **only if safe**. | **FUTURE** | Personal-data surface; must respect metadata-only doctrine + privacy review before any exposure. |
| Future-3 | Backend/Frontend | Policy "notes changed" marker **without** note content. | **FUTURE** | Indicate a notes change occurred without storing/displaying the note body; doctrine-aligned (metadata-only). |
| Future-4 | Backend | Rollback / revert workflow — **only if deliberately designed**. | **FUTURE** | Reverting policy versions is a governance-sensitive action; requires deliberate design, audit, and founder decision before any implementation. |

## 7. Other deferred hygiene / future housekeeping (unlabelled)

These are genuine but are **not** part of the TD-BE / TD-FE label set and are **not** assigned to any TD label. Recorded only so they are not lost. All non-blocking; each would be a separate authorised patch.

- Dockerfile explicit `--require-hashes` flag (per-wheel hashes already verified via the hashed lockfile; this is belt-and-braces). Ref: `2026-06-08_operational_resilience_checkpoint.md`.
- Base-image digest refresh cadence (operational hygiene). Ref: same.
- Optional `httpx<2` deprecation hygiene. Ref: same.
- CORS methods/headers/max-age hardcoded in `app/main.py` (documented and safe — no wildcard+credentials). Ref: `env.md` §16.

## 8. RC coherence conclusion

**2A-D.3 remains substantively complete. The TD-BE / TD-FE labels are now classified for traceability and do not reopen the RC coherence code lane.**

## 9. Non-claims

This note:

- does not certify RC readiness;
- does not authorise paid pilots;
- does not authorise real clinic data;
- does not authorise live generation;
- does not replace solicitor review;
- does not change product behaviour.

## 10. Remaining gates outside this note

- Solicitor review not complete.
- Legal / commercial pack not final.
- Live Workspace generation production-off until the local/staging safety gate and the hard-refusal boundary (diagnosis/treatment/prescribing) are proven on the live path.
- Paid pilots / real clinic data remain blocked.

## 11. Cross-references

- [`2026-06-16_rc_coherence_closure.md`](./2026-06-16_rc_coherence_closure.md) — RC coherence lane closure.
- [`2026-06-16_2a_d_current_status_checkpoint.md`](./2026-06-16_2a_d_current_status_checkpoint.md) — 2A-D consolidated status.
- [`2026-06-22_2a_d_1_security_audit_result.md`](./2026-06-22_2a_d_1_security_audit_result.md) — 2A-D.1 security audit result.
- [`2026-06-21_control_to_evidence_matrix.md`](./2026-06-21_control_to_evidence_matrix.md) — control-to-evidence index.
- Canonical: Roadmap v2.6 §237; Decision Memo Addendum v1.3 §90 (label source).
