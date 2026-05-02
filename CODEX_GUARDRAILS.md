# Codex Guardrails

## Core ANCHOR Doctrine

ANCHOR is governance, trust, learning, and intelligence infrastructure for safe AI use in veterinary clinics.

Non-negotiables:
- Governance-first.
- Metadata-only accountability by default.
- Not clinical decision-making AI.
- Human-review based.
- Receipt-backed.
- Multi-tenant and privacy-aware.
- Veterinary wedge first.
- Vendor-neutral over time.
- Standalone plus integrable over time.
- Do not create diagnosis, treatment, prescribing, or case-management AI.
- Do not weaken auth, RLS, tenant isolation, governance receipts, auditability, or metadata-only doctrine.
- Do not store raw prompt or output content in governance logs, receipts, or operational surfaces.

## Current Phase

Roadmap v2.1 priority remains Product Finish & Commercial Readiness.

The emergency surface migration is complete. The three core signed-in surfaces (Receipts, Dashboard, Workspace) and shared portal chrome (card system, button language, TopBar notifications) are now native AppShell/React. The public website foundation and public `/demo` and `/start` request flows are live.

Continuing work focuses on:
- Workspace v2 product polish and continued visual finish.
- Public site refinement and portal/public visual consistency.
- Onboarding hardening.
- Plans / billing-payment foundations.
- Later: regulatory conversion features (RCVS self-assessment, governance policy library, attestation, near-miss logging, transparency, CPD-recordable Learn work), then deeper Learn/Intelligence, then connectors/ambient/institutional expansion.

## Current Native Signed-In Product Surfaces

Canonical native routes:
- `app/workspace/page.tsx` is the canonical Workspace route (native AppShell/React).
- `app/dashboard/page.tsx` is the native Dashboard route.
- `app/receipts/page.tsx` is the native Receipts route.

Compatibility and reference:
- `app/workspace-live/page.tsx` is legacy redirect compatibility only. It points traffic to `/workspace`. It is not the canonical route.
- `app/workspace-stitch/page.tsx` is retained as a visual/reference artifact only. It is not a live product route. Do not point traffic at it.

Other native AppShell portal surfaces:
- `app/trust/**`
- `app/learn/**`
- `app/intelligence/**`
- `app/governance-events/page.tsx`
- `app/notifications/page.tsx`
- `app/settings/page.tsx`
- `app/support/page.tsx`
- `app/privacy-policy/page.tsx`
- `app/exports/page.tsx`

Card system, button language, TopBar notifications, and shell chrome are unified across these surfaces. Future UI changes here should be small, intentional, and visually checked. Do not undertake broad rewrites.

## Current Public / Commercial Surfaces

Public/commercial routes:
- `app/page.tsx` is the public website front door.
- `app/marketing/page.tsx` is the marketing route.
- `app/demo/**` is the public walkthrough request flow.
- `app/start/**` is the public onboarding request flow.

Supporting code:
- `components/marketing/**` (MarketingShell, BrowserFrame, PublicWebsite, DemoRequestForm, StartRequestForm, MarketingFormFields).
- `lib/marketingContent.ts`, `lib/publicIntakeClient.ts`, `lib/demoRequest.ts`, `lib/startRequest.ts`, `lib/intake.ts`.
- `public/anchor-public/**` for marketing screenshots.

Public intake forms must not collect raw clinical or client-identifiable content. Public intake submits to backend `/v1/public/demo-request` and `/v1/public/start-request` via `publicIntakeClient` only. No Next API routes for public intake.

## Working Style

- Keep PRs small, isolated, and focused on one surface or concern.
- Prefer read-only audits first. Confirm branch state, file list, and intent before editing.
- Cut new PRs as a clean worktree off `origin/anchor-portal-master`. Do not mix unrelated WIP.
- Never `git add .`. Stage explicit files only.
- Run typecheck, targeted ESLint, and `npm run build` before reporting done. For UI changes, also do a browser visual check.
- Visual changes are small, deliberate polish, not broad UI refactors.
- If a task touches auth, RLS, tenant isolation, governance receipts, metadata doctrine, or backend behaviour, stop and confirm scope before proceeding.

## Do Not Do

- Do not change backend APIs, auth, RLS, tenant isolation, governance logic, receipt semantics, or metadata-only doctrine during UI or product-finish tasks unless explicitly scoped.
- Do not add clinical decision-making, diagnosis, treatment, prescribing, or case-management features.
- Do not store raw prompt or output content in governance logs, receipts, or operational surfaces.
- Do not point live traffic at `app/workspace-stitch/**`.
- Do not delete `app/workspace-live/page.tsx` while it remains the compatibility redirect to `/workspace`.
- Do not perform broad UI rewrites or revisit the stitched-vs-native debate. That migration is complete.
- Do not bundle unrelated WIP into a focused PR.
