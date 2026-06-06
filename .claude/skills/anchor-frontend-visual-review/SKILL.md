---
name: anchor-frontend-visual-review
description: Polish-level visual review for ANCHOR portal — hierarchy, spacing, readability, alignment, state coverage, and cross-page consistency across Workspace, Assistant, Receipts, Trust, Learn, Intelligence, Settings, Dashboard, Governance Events, Privacy/Policy, and Support. Strictly polish; does NOT authorise redesign, new colour systems, new typography, or new layout patterns.
---

# anchor-frontend-visual-review

## What this skill is

A polish lens. It looks for inconsistencies, low-hanging legibility issues, hierarchy drift, and state-coverage gaps **within the existing approved visual direction**. It does not propose new visual languages.

## What this skill is NOT

- Not a redesign tool. No new colour systems. No new typography systems. No new layout grids. No new component libraries.
- Not a doctrine check (use `anchor-doctrine-check` for wording and scope).
- Not a security audit (use `anchor-security-audit`).
- Not authority to refactor `components/shell/AppShell.tsx` or address the deferred custom-font warning.

If the only honest fix for a problem is redesign, **stop and report** — escalate to founder. Do not introduce a partial redesign.

## Canonical sources

- `docs/canonical/ANCHOR_Roadmap_v2_6_June_2026_CORRECTED.md` — surfaces shipped (2A-1 → 2A-5, 2A-C presentation hardening). Treat these as stable.
- `docs/canonical/ANCHOR_RCVS_EU_AI_Act_Readiness_Map_v1_1_COMPLETE.md` — wording controls for any copy seen in the screenshots being reviewed.
- `docs/canonical/ANCHOR_Phase_2A_Build_Order_Decision_Memo_Addendum_v1_3.md` — current target is RC hardening, not feature build.

## Stable surfaces (do not redesign)

- `/workspace` — Workspace (live generation production-off).
- `/assistant` — Governed Assistant evidence loop.
- `/receipts` — deep-link contract `?assistantRunId=…`, `?assistantReceiptId=…` is stable.
- `/trust` and `/trust/posture` — Assistant receipt evidence card and counts are stable.
- `/learn` — CPD catalogue / detail / completion / export.
- `/intelligence` — metadata-only Assistant evidence surfaces.
- `/settings`, `/dashboard`, `/governance-events`, `/privacy`, `/support`.

Polish changes here must be additive and visually quiet.

## Review checklist

### A. Hierarchy
- [ ] One clear H1 per page; no competing visual H1s.
- [ ] Section grouping reflects information importance, not implementation order.
- [ ] Primary action per view is visually dominant; secondary actions clearly subordinate.
- [ ] Status / state badges are consistently positioned across pages.

### B. Spacing and alignment
- [ ] Vertical rhythm consistent within a page (no orphan single-line gaps).
- [ ] Card padding consistent across Workspace, Receipts, Trust, Learn.
- [ ] List rows align to the same left edge as section headings.
- [ ] No off-by-one px alignment between sibling cards on the same page.
- [ ] Tap/click targets meet the existing portal's established minimum (do not introduce a new minimum — match what neighbouring components use).

### C. Readability
- [ ] Body copy stays within the existing portal's line-length range.
- [ ] No paragraph relies solely on bold or italic for hierarchy.
- [ ] Truncation rules are consistent (ellipsis policy, tooltip-on-hover behaviour).
- [ ] Numeric counts use the same grouping/locale convention across Trust, Receipts, Intelligence.

### D. State coverage
- [ ] Loading state present and visually quiet.
- [ ] Empty state present, with copy that conforms to Readiness Map v1.1 §2.
- [ ] Error state surfaces a recoverable next step; never echoes free-text.
- [ ] Permission-denied / cross-tenant state handled.
- [ ] "Live generation production-off" surfaces (Workspace) clearly explain the gate without sounding broken.

### E. Cross-page consistency
- [ ] Page-title pattern matches across all listed surfaces.
- [ ] Breadcrumb / back-link convention consistent.
- [ ] Badge / chip vocabulary consistent (e.g. review state words mean the same thing in Workspace and Receipts).
- [ ] Date and timestamp formatting consistent.
- [ ] Iconography drawn from the existing icon set — no new icon families.

### F. Copy
- [ ] Run `anchor-doctrine-check` mentally on every visible string.
- [ ] No "compliant", "certified", "RCVS-approved", "guarantees", "chat history", "clinical record".
- [ ] No present-tense "vendor-neutral" / "multi-provider" / "provider-agnostic".
- [ ] CPD framed as "CPD-recordable AI literacy activity" only.
- [ ] EU AI Act dates softened to "from August 2026" with Article 4 amendment watch.

### G. Doctrine surfaces
- [ ] Metadata-only preserved — no raw prompts/outputs/drafts/transcripts in any reviewed view.
- [ ] Human-review state legible.
- [ ] Trust posture remains the receipt-evidence surface.

### H. Tech discipline
- [ ] No new `any`, `@ts-nocheck`, `eslint-disable` introduced.
- [ ] Lint baseline preserved: 0 errors, only the known AppShell font warning.
- [ ] `components/shell/AppShell.tsx` untouched.

## Output format

1. **Verdict** — `POLISH-OK` / `POLISH-FINDINGS` / `STOP-AND-ASK` (the last applies if the only fix is redesign).
2. **Findings** — table: severity (`nit` / `minor` / `notable`), surface, file or screenshot reference, description, suggested polish-level fix (CSS spacing, copy tweak, badge alignment — never "redesign").
3. **Cross-page inconsistencies** — list each, name both surfaces.
4. **Items deferred** — anything that genuinely needs redesign and should be escalated to founder.
5. **Recommendation** — apply now / batch with next RC pass / escalate.

This skill is review-only. It does not modify files.
