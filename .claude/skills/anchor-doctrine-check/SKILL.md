---
name: anchor-doctrine-check
description: Verify a proposed change, doc, or copy string against ANCHOR doctrine. Use before merging any change that touches storage, AI output, error messages, marketing copy, API responses, or clinic-facing surfaces. Use whenever wording mentions RCVS, EU AI Act, compliance, certification, vendor neutrality, clinical, diagnostic, or treatment.
---

# ANCHOR Doctrine Check

Canonical sources (operative):

- `docs/canonical/ANCHOR_Roadmap_v2_6_June_2026_CORRECTED.md` (Roadmap v2.6)
- `docs/canonical/ANCHOR_RCVS_EU_AI_Act_Readiness_Map_v1_1_COMPLETE.md` (Readiness Map v1.1)
- `ANCHOR_Phase_2A_Build_Order_Decision_Memo_Addendum_v1_3` (Addendum v1.3 — operative over Memo v1.1 and Addendum v1.2 where they differ)

Older v2.5 / v1 documents are stale where they conflict with v2.6 / v1.1 / Addendum v1.3.

## What this skill does

Given a diff, file, or candidate string, check it against ANCHOR doctrine and report PASS / FAIL with line-level findings. Read-only.

## Hard rejections (FAIL immediately)

1. **Compliance / certification claims.** Reject any wording that asserts or implies: "RCVS approved", "RCVS-compliant", "EU AI Act compliant", "certified", "regulator-approved", "regulator endorsement", "guaranteed protection", "guaranteed safe", "audit-proof", "compliant by design", "fully compliant".
2. **Clinical decision-making drift.** Reject any wording or behaviour that frames ANCHOR as: diagnostic, prescribing, treatment-planning, autonomous triage, ambient scribe, EHR, clinical decision support, clinical record, or "high-risk AI" claiming Article-level compliance.
3. **Present-tense vendor neutrality.** Reject phrasing that states ANCHOR *is* vendor-neutral today. The correct posture is "structurally compatible with future vendor neutrality" / "vendor-neutral over time". Live Workspace generation currently uses the Anthropic API directly.
4. **Raw content storage.** Reject any change introducing storage of raw prompts, outputs, drafts, transcripts, clinical content, or identifier-shaped data that is not hashed at write time.
5. **Buyer discovery drift.** Reject any plan, doc, or roadmap edit that re-introduces "5–10 practice-owner conversations", "parallel listening cadence", or any buyer-discovery gate. Addendum v1.3 records the conviction-based position: there is no buyer-discovery step.
6. **Gated future treated as current.** Reject any change that begins building M6.12 or M6.13 without an explicit founder decision recorded in an addendum. Treat M4.6 as deferred.
7. **Live generation enablement.** Reject any change that would activate live Workspace generation in production before the local/staging safety gate (2A-C.5E) passes and the hard-refusal boundary (diagnosis/treatment/prescribing) is proven on the live path. Flag any change that would make Anthropic a production subprocessor.
8. **GPAI provider framing.** Reject any wording that treats ANCHOR as a GPAI provider under Chapter V. ANCHOR is a downstream integrator only.
9. **"Aligned, not compliant" violations.** ANCHOR is aligned to RCVS principles and EU AI Act articles. It is not compliant with them, and does not claim regulator endorsement or protection from enforcement.

## Soft warnings (FAIL unless justified in same change)

- New `# type: ignore`, `Any`, or suppression comment without a documented reason.
- New migration without RLS + FORCE RLS + `USING` *and* `WITH CHECK` on tenant tables.
- Endpoint added without request-scoped tenant context.
- Wording that will appear in API responses or clinic-facing surfaces but has not been checked against Readiness Map v1.1 §2.

## Output format

```
DOCTRINE CHECK: PASS | FAIL
Hard rejections: [list with file:line]
Soft warnings: [list with file:line]
Suggested rewording: [if applicable, with Readiness Map §2 reference]
```

Never rewrite production code from this skill. Report only.
