---
name: anchor-legal-prep
description: UK-first, veterinary-first, solicitor-preparation-only skill for reviewing and drafting ANCHOR legal and trust-centre material — public legal/trust copy, AI governance boundary copy, AI data-use / no-training copy, data-role / data-classification / subprocessor notes, customer-responsibility and offboarding language, and prohibited-claim scans. Not legal advice. Conservative on all compliance/regulatory claims, metadata-only aware, public-copy safe. No external connectors, no MCP, no scripts, no agents, no autonomous action.
---

# anchor-legal-prep

A local, ANCHOR-specific skill for **preparing** legal and trust-centre material for a UK solicitor and for keeping ANCHOR's public legal/trust copy doctrine-safe. This skill **prepares**; it never **decides**. It does not provide legal advice, does not approve contracts, and does not authorise selling, pilots, onboarding, or live generation.

This skill is **aligned, not compliant**. Every output is conservative on regulatory and compliance claims and must survive solicitor review and a final public-copy scan before any external use.

---

## 1. When to use this skill

**Use for:**

- reviewing ANCHOR public legal/trust pages (Privacy, Policy, Trust, Support, any future Trust Centre)
- drafting solicitor-preparation outlines (issue lists, question lists, structure for a legal/commercial pack)
- reviewing legal/commercial pack wording (DPA, privacy notice, AUP, disclaimers, pilot agreement drafts)
- reviewing **AI Governance Boundary** copy (what ANCHOR is / is not; clinical non-position)
- reviewing **AI Data Use / No-Training** copy (how AI tools are used; that data is not used to train models, where true and stated carefully)
- reviewing **Data Roles / Data Classification / Subprocessor** copy (controller/processor framing, data categories, subprocessor lists/notes)
- reviewing **customer-responsibility and offboarding** copy (what the clinic remains responsible for; export/deletion on exit)
- scanning any text for **prohibited claims** (see §4)

**Do not use for:**

- final legal advice
- contract execution
- live legal conclusions ("this is legally safe")
- regulator submissions
- client-specific legal advice
- processing real clinic data
- reviewing real patient/client records
- enabling paid pilots
- enabling live Workspace generation

If asked to do any "Do not use for" item, **stop and report** (see §10).

---

## 2. Canonical source order

Treat these as **operative** (current canonical state — defer to these):

1. `docs/canonical/ANCHOR_Roadmap_v2_6_June_2026_CORRECTED.md` — operative roadmap; §1 doctrine; current phase 2A-D.0 release-candidate hardening.
2. `docs/canonical/ANCHOR_RCVS_EU_AI_Act_Readiness_Map_v1_1_COMPLETE.md` — operative readiness artefact; §2 wording controls (operative for all clinic-facing copy); §3 RCVS principles; §4 EU AI Act articles.
3. `docs/canonical/ANCHOR_Phase_2A_Build_Order_Decision_Memo_Addendum_v1_3.md` — OPERATIVE decision; supersedes Memo v1.1 and Addendum v1.2 where they differ.
4. Current `CLAUDE.md` (and `AGENTS.md`) at repo root.
5. `docs/canonical/Official_EU_AI_Act_Source_Note_v1_1.md` — EU AI Act source discipline; EUR-Lex is the only acceptable primary source; cite Article 113 for applicability dates.
6. `docs/commercial/` — legal/commercial pack material (if present).
7. `docs/legal/` — legal / trust-centre material (if present).

`docs/commercial/` and `docs/legal/` may not yet exist; if absent, note that and proceed from the canonical set above. Do not create them as part of a copy review — creating new directories or routes is out of scope for this skill.

**Historical only** (consult for provenance, do not treat as operative unless explicitly requested): Roadmap v2.5, Readiness Map v1, Decision Memo v1.1, Addendum v1.2, the Phase 2A-1 Engineering Brief, and Official EU AI Act Source Note v1. Where these differ from the operative set, the operative set wins.

---

## 3. ANCHOR is / is not

**ANCHOR is:**

- governance, trust, learning, intelligence, and readiness infrastructure for safe AI use in veterinary clinics
- metadata-only by default
- human-review based
- receipt-backed
- trust-surface oriented
- multi-tenant and privacy-aware
- standalone now, integrable later
- architected for vendor-neutrality / vendor-neutral over time (future-tense framing only)

**ANCHOR is not:**

- diagnostic AI
- prescribing AI
- treatment-planning AI
- autonomous triage
- ambient scribe
- EHR / PMS
- clinical decision-support product
- GPAI model provider
- compliance guarantee
- RCVS-approved product
- regulator-endorsed product
- certified compliance system
- replacement for veterinary judgement

---

## 4. Prohibited claims

Flag and rewrite every occurrence of the following (in any tense or paraphrase). A single occurrence in external-facing copy blocks publication until reworded.

- "RCVS approved" / "RCVS-approved"
- "RCVS compliant"
- "EU AI Act compliant"
- "GDPR compliant"
- "certified" / "certification" / "certified compliance system"
- "regulator endorsed" / "regulator-endorsed"
- "guarantees compliance"
- "guarantees safety"
- "clinical decision support"
- "clinical record"
- "patient record"
- "diagnostic evidence"
- "proves clinical correctness"
- "RCVS-accredited CPD" (unless a formal accreditation has actually been achieved and is documented)
- "Article 4 compliant"
- "fine-proof"
- "vendor-neutral" as a current-state capability
- "provider-agnostic" as a current-state capability
- "live AI generation is active"
- "Anthropic/OpenAI provider choice is available today"

When found, quote the phrase with `file:line`, explain why it is prohibited (which doctrine/wording control), and supply a safer replacement from §5.

---

## 5. Required safer wording

Prefer these formulations (drawn from Readiness Map v1.1 §2):

- "aligned with emerging professional expectations"
- "governance and readiness infrastructure"
- "helps clinics evidence responsible AI governance practices"
- "metadata-only governance evidence"
- "human review required"
- "governance receipt"
- "CPD-recordable AI literacy activity"
- "Article 4 readiness theme, subject to legal review and amendment watch"
- "Article 99 penalty regime may apply pending legal review"
- "architected for vendor-neutrality" / "vendor-neutral over time"
- "deterministic governed generation today"
- "live Workspace generation remains production-off pending local/staging safety gate"

---

## 6. Legal-gate rules

Always preserve and never erode these gates. They are non-negotiable in any draft this skill produces or reviews:

- Static legal/trust pages **may** be drafted.
- Drafting legal/trust pages **does not** authorise selling.
- Drafting legal/trust pages **does not** authorise paid pilots.
- Drafting legal/trust pages **does not** authorise onboarding real clinics.
- Drafting legal/trust pages **does not** authorise processing real clinic data.
- Paid pilots or real clinic data require **security audit, operational resilience, and a solicitor-reviewed legal/commercial pack** first.
- Live Workspace generation remains **production-off** until the local/staging safety gate passes.

If a draft or request implies any of these gates has been crossed, flag it as a missing-gate caveat and recommend the gate language be added.

---

## 7. Article 4 / EU AI Act rule

Do **not** use Article 4 (or the EU AI Act generally) as a hard legal sales stick. Frame Article 4 as:

- an **AI-literacy readiness theme**
- **subject to legal review**
- **subject to amendment watch** (Digital Omnibus and any later amendment)
- one whose **UK applicability depends on EU nexus / legal analysis** — UK clinics are not automatically in scope

Cite the EU AI Act only as Regulation (EU) 2024/1689 by Article number; cite **Article 113** for applicability dates; use "from August 2026" softening for supervision/enforcement timing; never headline a precise fine figure (use "Article 99 penalty regime may apply pending legal review"). EUR-Lex is the only acceptable primary source.

---

## 8. Anthropic / AI provider rule

State, wherever provider posture appears:

- the current **live Workspace generation path has been built against Anthropic** but **remains production-off**
- **Anthropic becomes a subprocessor** when live generation is enabled
- **legal/subprocessor documentation must be complete** before any paid pilot or real clinic data
- do **not** claim present-tense vendor-neutrality (use "architected for vendor-neutrality" / "vendor-neutral over time")

---

## 9. Output format

When reviewing a document, report in this order:

1. **High-risk legal/claim issues** — anything that reads as legal advice, a compliance/certification claim, or a guarantee.
2. **Wording-control violations** — quoted phrase, `file:line`, the rule it breaks (§4 / §5), and a safer replacement.
3. **Stale-canonical-source issues** — references to historical artefacts (Roadmap v2.5, Readiness Map v1, Memo v1.1, Addendum v1.2, Source Note v1) where the operative set should be cited.
4. **Missing solicitor-review caveats** — where "prepared for solicitor review; not legal advice" framing is absent.
5. **Missing gate caveats** — where §6 gates (no selling / no pilots / no real data / live generation production-off) should be stated but are not.
6. **Recommended safer replacement wording** — concrete rewrites.
7. **Publication readiness** — state explicitly whether the text is safe for: **internal draft**, **solicitor review**, or **external publication**. Default to the most conservative tier when in doubt.

---

## 10. Hard stop conditions

Stop and report (do not proceed) if asked to:

- provide final legal advice
- approve a contract as legally safe
- claim compliance / certification
- process real clinic data
- enable live generation
- add MCP / connectors / scripts / agents
- create backend legal-evidence tables without a separate authorised brief

This skill performs no autonomous action: no external connectors, no MCP, no scripts, no agents, no app/route/component/backend edits. It reviews and drafts text for human and solicitor review only.
