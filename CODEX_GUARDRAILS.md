# Codex Guardrails

## Current Source-of-Truth UI

Primary stitched surfaces:
- `app/workspace-live/page.tsx`
- `app/dashboard/page.tsx`
- `app/receipts/page.tsx`

Primary React-shell surfaces:
- `app/trust/**`
- `app/learn/**`
- `app/intelligence/**`
- `app/governance-events/page.tsx`
- `app/privacy-policy/page.tsx`
- `app/exports/page.tsx`

## Preserve For Reference

Retain this file as reference / experimental material:
- `app/workspace-stitch/page.tsx`

Do not treat it as safe-to-delete legacy by default.

## Labeled Unused / Reference Files

These are currently labeled as unused/reference and should not be treated as current source-of-truth UI:
- `components/anchor/AnchorSurface.tsx`
- `components/trust/TrustPostureCards.tsx`
- `components/trust/TrustProfileCards.tsx`

## Safe Codex Edit Rules

- Prefer read-only audits first before implementation.
- Make a checkpoint commit before implementation work.
- Avoid changes to auth, governance logic, RLS, receipts logic, and trust calculations unless explicitly instructed.
- Do not treat `app/workspace-stitch/page.tsx` as legacy to delete.
- Do not perform broad UI refactors without approval.
- Keep changes small, targeted, and easy to review.
