# ANCHOR

## Phase 2A Build-Order Decision Memo — Addendum v1.3

*Strategic decision artefact | Amends Memo v1.1; corrects Addendum v1.2 | Companion to Roadmap v2.5 → v2.6 and Readiness Map v1 → v1.1 | 6 June 2026*

| DECISION (founder-approved) **The live product has moved past the canonical document set. Before further engineering, selling, or external positioning, the canonical artefacts are promoted to as-built.** **Next step is documentation reconciliation (2A-D.0), not selling and not a new feature build.** Building proceeds on **regulatory and professional-governance conviction**: there is no buyer-conversation gate and no parallel buyer-discovery requirement. The accepted trade-off is that ANCHOR is completed before market validation, because the founder has assessed weak current clinic urgency and limited time to wait. Paid pilots and any handling of real clinic data require a completed security audit, operational resilience, and legal/commercial pack. M4.6 Learn Maturity is deferred by decision. Live Workspace generation remains production-off until the local/staging safety gate passes. **Authority: Founder / Product Owner. Date: 6 June 2026.** |
| --- |

| **Field** | **Value** |
| --- | --- |
| **Addendum version** | v1.3 (corrects the buyer-conversation framing in v1.2) |
| **Amends / corrects** | Memo v1.1 (25 May 2026); corrects Addendum v1.2 (6 June 2026) |
| **Date** | 6 June 2026 |
| **Author / Owner** | Founder / Product Owner |
| **Status** | Approved |
| **Linked roadmap** | ANCHOR Roadmap v2.5 (to be superseded by v2.6) |
| **Linked defensibility artefact** | RCVS + EU AI Act Readiness Map v1 (to be superseded by v1.1) |
| **Doctrine governance** | All wording controlled by 'Aligned, not compliant' (Roadmap §1) |

**Correction recorded in this version.** Addendum v1.2 described buyer conversations as a "parallel listening cadence" and "buyer discovery as research only". That wording did not match the founder decision of 25 May 2026 — "I won't have the buyer conversation; I will move forward as I don't have time to lose." It originated as a softening of the removed M5.6 gate and propagated through Memo v1.1 and subsequent drafts. v1.3 removes it. ANCHOR proceeds on regulatory and professional-governance conviction, with no buyer-discovery requirement. The parallel-cadence wording in Memo v1.1 and Addendum v1.2 is superseded. All other v1.2 decisions are carried forward unchanged.

---

## 1. Why this addendum exists

Memo v1.1 authorised Phase 2A-1 and treated 2A-2 through 2A-5 as the forward sequence. The build tracker now records Phase 2A-1 through 2A-5 as materially complete and presentation-hardened (2A-C), plus readiness discipline R1–R4 and the closure of both honest M6 gaps.

The canonical document set has not kept pace. Roadmap v2.5 still describes Phase 2A as the next regulatory conversion wedge and lists the formal evaluation set and why-flagged → Learn linkage as open gaps; Readiness Map v1 still describes CPD-recordable Learn, attestation, self-assessment, client transparency, and near-miss logging as "not started" or future. Both CLAUDE.md files still name "Phase 2A-1" as the current implementation target.

This drift is now the binding risk. Every Claude Code session inherits the wrong mission, and every external defensibility claim rests on artefacts that contradict the live product. Reconciliation precedes all other work.

## 2. As-built state recorded (per build tracker)

- **Phase 2A-1** CPD-Recordable AI Literacy — built / functionally complete.
- **Phase 2A-2** Governance Policy Library + Staff Attestation — built.
- **Phase 2A-3** RCVS AI Governance Self-Assessment, incl. 2A-3.9 Regulatory Readiness Evidence Closure — built.
- **Phase 2A-4** Client-Facing Transparency Layer — built.
- **Phase 2A-5** Basic Incident / Near-Miss Logging — built.
- **Phase 2A-C** Presentation Hardening / Demo Readiness — complete, except 2A-C.4 (Backend Trust Pack polish) and 2A-C.5E (Local/Staging live Workspace smoke), both deferred.
- **M6.10 / M6.11** — built (Roadmap v2.5 listed these as Open / Optional).
- **Honest M6 gaps closed:** R3 Assistant Evaluation / Golden-Test Registry v1, and Why-flagged → Learn linkage.
- **Readiness discipline:** R1 Public Copy Audit, R2 Retention and Memory-Consent Note, R3 Evaluation Registry, R4 Official EU AI Act Source Note — complete.

## 3. Authorised reconciliation (2A-D.0)

| Artefact | Action |
| --- | --- |
| Roadmap v2.6 | Promote to as-built. Move Phase 2A-1–2A-5, M6.10, M6.11 to Complete. Close both honest M6 gaps. Record R1–R4. Carry the standing conviction position (§4); do not reintroduce a buyer-discovery step. |
| Readiness Map v1.1 | Update every "not started"/future status for Phase 2A surfaces to built. Apply the EU AI Act date check in §6. Re-audit public copy against §2 wording table. State linked Roadmap version and change summary. |
| Memo (this addendum) | File v1.3 alongside Memo v1.1 and Addendum v1.2. v1.1 and v1.2 remain the historical record; v1.3 is the operative decision. |
| Backend CLAUDE.md | Replace "Current implementation target: Phase 2A-1" with current target (reconciliation / RC hardening). Update built-state summary. Reference Addendum v1.3. |
| Frontend CLAUDE.md | Same correction. Reference Addendum v1.3. |
| Phase 2A-1 Engineering Brief v1.1 | Mark as delivered/closed. Retire as the current Claude Code target; retain as historical implementation record. |

## 4. Gate distinctions (corrected)

**Standing position.** Commercial-validation conversations were deliberately not used as a gate. ANCHOR proceeds on founder regulatory and professional-governance conviction. Security, operational resilience, and legal readiness remain mandatory gates before paid pilots or real clinic data.

| Activity | Gate required |
| --- | --- |
| Building / engineering / canonical reconciliation | No buyer-conversation gate and no parallel buyer-discovery requirement. Proceeds on founder regulatory/professional-governance conviction. |
| Selling / paid pilots / handling real clinic data | Security audit + operational resilience (backups, tested restore, breach runbook) AND legal/commercial pack with solicitor review. Both mandatory. |
| External positioning that mentions live generation | Local/staging live Workspace safety gate passed first (see §5). |

The accepted trade-off: ANCHOR is being completed before market validation. The founder has assessed that current clinic urgency is weak and that there is limited time to wait; this is a recorded, accepted decision, not an oversight. If buyer conversations are revived later, that is at founder discretion and is not part of the current plan.

## 5. Live Workspace generation — safety gate

Live generation remains **production-off** until the local/staging smoke (2A-C.5E) passes and the hard-refusal boundary (diagnosis, treatment, prescribing) is demonstrated on the live path. The refusal harness must ship *with* the first live LLM call, not after — deferring it opens a window of ungoverned runs. Until then, ANCHOR is presented as deterministic governed generation only.

The existing live Workspace integration (2A-C.5B / 5C) is built directly on the Anthropic API; it is not yet vendor-neutral. Two consequences follow: (a) the safety gate above applies to this existing Anthropic path now, not only to a future M6.12 connector layer; and (b) Anthropic is a subprocessor the moment live generation is enabled, so the legal pack's DPA and subprocessor list must name Anthropic before any paid pilot or real clinic data. Public copy must not claim present-tense vendor-neutrality while only one provider is wired — use "architected for vendor-neutrality" / "vendor-neutral over time".

## 6. EU AI Act date, penalty, and Article 4 amendment watch (for Readiness Map v1.1)

- **Dates — use "from August 2026"; do not assert a single day.** The Commission's own AI Literacy Q&A is internally inconsistent: one answer states the supervision and enforcement rules apply "from 3 August 2026 onwards"; the adjacent answer states national market surveillance authorities begin "as of 2 August 2026". The main AI Act page and EUR-Lex Article 113 give 2 August 2026 for full applicability and 2 February 2025 for AI literacy entry into application. Because the official source carries both phrasings, Readiness Map v1.1 must not assert that either day is correct or incorrect. Use "from August 2026" or cite the primary source directly, and note the one-day discrepancy in the official Q&A.
- **Penalty wording — do not headline a figure.** Article 99 sets penalty bands for specified categories of infringement, but Article 4 should not be reduced to a single standalone fine figure without jurisdiction-specific legal analysis. State only that an Article 99 penalty regime may apply, pending legal review.
- **Digital Omnibus — describe as provisional and adoption-status-sensitive.** Track as a live-document item. Political agreement was reached (7 May 2026) but formal adoption/publication is pending; the proposed Annex III high-risk deferral (to 2 December 2027) is not adopted law and the binding date remains 2 August 2026 unless amended. Describe cautiously and cite the current Commission/Council source at each Readiness Map update.
- **Article 4 amendment watch (strategically material).** The Commission's Digital Omnibus (presented 19 November 2025) proposes amending Article 4 itself: shifting the obligation to *promote* AI literacy onto Member States and the Commission, rather than enforcing an unspecific obligation on organisations. The human-oversight training obligation for deployers of high-risk systems remains. If adopted, the hard organisational Article 4 obligation softens for non-high-risk deployers — which includes most vet clinics using general AI tools. This does not invalidate Phase 2A-1 (RCVS Theme 3, Article 26 high-risk human oversight, and good-governance value remain), but it weakens the "Article 4 forces you to keep training records" legal stick. This reinforces the §4 standing position: lean on RCVS professional expectations and good-governance conviction, not on a hard Article 4 obligation. Readiness Map v1.1 must flag this as an open regulatory-change risk.

## 7. M4.6 Learn Maturity — deferred by decision

M4.6 Learn Maturity remains deferred. Current Learn is CPD-recordable AI literacy activity and metadata-only completion evidence. It is not proof of competence, certified CPD, RCVS-approved training, or compliance proof. Knowledge checks, scenario questions, role-based paths, renewal cycles, leadership dashboards, and adaptive recommendations remain future maturity work. Building a thin M4.6 before release candidate is scope creep and would edge copy toward competence/certification claims the wording table forbids. This is a recorded decision, not an oversight.

## 8. Corrected order

1. **2A-D.0** — Canonical documentation reconciliation / as-built promotion (Roadmap v2.6, Readiness Map v1.1, this addendum, both CLAUDE.md, retire Engineering Brief as current target).
2. **2A-D.1** — Security audit + operational resilience — mandatory before real clinic data / paid pilots.
3. **2A-D.2** — Legal / commercial pack with solicitor review — mandatory before paid pilots.
4. **2A-D.3** — Release-candidate coherence fixes — Trust Pack backend source-of-truth polish (reclassify 2A-C.4 from optional to should-fix); Workspace ↔ Receipt review-state coherence; "Content hash: None"; incident demo-state cleanup; technical-debt classification (TD-BE-1/2, TD-FE-1/2 → blocker / must-fix / should-fix / defer).
5. **2A-D.4** — Final wording / copy scan against Readiness Map v1.1 §2 across website, deck, Trust Pack, Learn/CPD, client transparency, social bios, pilot copy, demo script, and legal surfaces.
6. **2A-D.5** — Release-candidate sign-off.
7. **Only then:** paid pilots / onboarding / sales motion.

**Not in the plan** (do not reintroduce unless deliberately revived by founder decision): buyer discovery; 5–10 practice-owner conversations; parallel listening cadence.

## 9. Sign-off

| **Sign-off field** | **Value** |
| --- | --- |
| **Approved by** | Founder / Product Owner |
| **Approval date** | 6 June 2026 |
| **Approval scope** | As-built recording; reconciliation authorisation; corrected buyer-conversation framing (no buyer discovery; conviction-based); gate distinctions; live-generation safety gate; EU AI Act date/penalty correction and Article 4 amendment watch; M4.6 deferral by decision; corrected order. |
| **Conditions** | Reconciliation (2A-D.0) precedes all other work. Building proceeds on regulatory/professional conviction with no buyer-conversation gate. Security audit, operational resilience, and legal pack remain mandatory before paid pilots or real clinic data. Public copy re-audited against Readiness Map v1.1 §2. |
| **Supersession** | This addendum (v1.3) is operative over Memo v1.1 and Addendum v1.2 where they differ; it supersedes the parallel buyer-conversation cadence wording in both. Roadmap v2.6 and Readiness Map v1.1 supersede v2.5 and v1 respectively once issued. |

---

*Addendum v1.3 — 6 June 2026 — corrects the buyer-conversation framing of v1.2: ANCHOR proceeds on regulatory and professional-governance conviction with no buyer-discovery requirement; security, operational resilience, and legal readiness remain mandatory before paid pilots or real clinic data; all other v1.2 decisions (as-built reconciliation, gates, live-generation safety, EU AI Act date softening and Article 4 watch, M4.6 deferral) carried forward unchanged.*
