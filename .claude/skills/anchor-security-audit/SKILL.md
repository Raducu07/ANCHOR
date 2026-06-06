---
name: anchor-security-audit
description: Frontend-side security and privacy audit for ANCHOR portal — checks metadata-only enforcement, tenant scoping, deep-link safety, secret leakage, dependency posture, headers, auth-state assumptions, and Phase 2A-D pre-pilot readiness. Use before any release-candidate sign-off, before any change that touches receipts/trust/assistant surfaces, or whenever the diff handles tokens, ids, query params, or external fetches.
---

# anchor-security-audit

## Scope

Frontend-only audit. This skill does **not** audit backend code, infra, or Render configuration. If a finding requires a backend or infra change, escalate — do not attempt cross-repo edits.

This audit supports the Phase 2A-D.0 release-candidate hardening track (Roadmap v2.6 §current-phase; Addendum v1.3 §gates). Paid pilots and any handling of real clinic data require a completed security audit, operational resilience, and legal/commercial pack — this skill produces the frontend slice of that audit.

## Canonical sources

- `docs/canonical/ANCHOR_Roadmap_v2_6_June_2026_CORRECTED.md` — current phase, security-audit gate.
- `docs/canonical/ANCHOR_RCVS_EU_AI_Act_Readiness_Map_v1_1_COMPLETE.md` — metadata-only doctrine, retention/memory-consent posture, R2 retention note.
- `docs/canonical/ANCHOR_Phase_2A_Build_Order_Decision_Memo_Addendum_v1_3.md` — security as mandatory gate; live Workspace generation production-off until safety gate passes.

## Checks

### 1. Metadata-only enforcement
- [ ] No component renders raw prompt, output, draft, transcript, or free-text clinical content from any API field.
- [ ] No `dangerouslySetInnerHTML` over content sourced from the backend.
- [ ] Receipt views render id/timestamp/status/hash/count/reason-code fields only.
- [ ] Error and empty states never echo back submitted free-text.
- [ ] Logging (client-side `console.*`, telemetry) excludes raw content fields.

### 2. Tenant scoping
- [ ] All list/detail fetches send the clinic-scoped identifier; no client-side join across tenants.
- [ ] Deep-link params (`assistantRunId`, `assistantReceiptId`, etc.) are validated server-side; the UI does not assume access from the param alone.
- [ ] No URL contains another tenant's id by construction (no admin-style global search exposed to clinic role).

### 3. Auth-state assumptions
- [ ] No code path renders authenticated UI before auth state is resolved (no "flash of authed shell").
- [ ] Logout clears in-memory caches that hold clinic-scoped data.
- [ ] Session-expiry surfaces a re-auth prompt without exposing the previous tenant's data.

### 4. Secrets and config
- [ ] No API key, token, signing secret, or service-role credential in client bundle, `NEXT_PUBLIC_*` env, or repo.
- [ ] `NEXT_PUBLIC_*` variables contain only safe-to-publish values (public URL, build tag).
- [ ] No `.env*` files staged or committed; `.gitignore` covers them.

### 5. External fetches and CSP posture
- [ ] All `fetch`/SDK targets go to `https://anchor-api-prod.onrender.com` or other allow-listed origins; no ad-hoc third-party endpoints.
- [ ] No `<script src>` to unknown CDNs added in this diff.
- [ ] Images and iframes do not load arbitrary user-supplied URLs.
- [ ] Next.js `images.remotePatterns` not loosened without justification.

### 6. Dependency posture
- [ ] No new third-party plugin or runtime dependency added without explicit founder approval.
- [ ] `npm audit` advisories: report `critical`/`high` count; flag any new `critical`/`high` introduced by this diff.
- [ ] Lockfile changes match `package.json` changes (no drift).

### 7. Headers and Next.js config
- [ ] No relaxation of `next.config` `headers()` (CSP, Referrer-Policy, X-Frame-Options, X-Content-Type-Options) in this diff.
- [ ] No `Access-Control-Allow-Origin: *` added.
- [ ] `poweredByHeader: false` preserved if currently set.

### 8. Client-side storage
- [ ] No clinic-scoped or user-identifying data written to `localStorage`/`sessionStorage`/IndexedDB without justification in the diff.
- [ ] No long-lived token stored in `localStorage`.
- [ ] Cache keys are tenant-scoped or invalidated on tenant change.

### 9. Workspace / Assistant live-generation gate
- [ ] No UI path triggers a live model call in production.
- [ ] Workspace remains gated; any "generate" CTA points at the local/staging-only path.
- [ ] No copy implies live AI generation is available to clinics today.

### 10. Receipt and trust surface integrity
- [ ] Deep-link contract preserved: `/receipts?assistantRunId=…` and `/receipts?assistantReceiptId=…` continue to resolve.
- [ ] Trust posture counts source from the same evidence aggregator; no parallel calc introduced.
- [ ] No client-side mutation of receipts/trust evidence.

### 11. Logging and analytics
- [ ] No new analytics provider added.
- [ ] Existing telemetry (if any) excludes free-text and tenant-identifying fields beyond what is already approved.
- [ ] `console.error` paths do not dump full response bodies in production builds.

### 12. Build hygiene
- [ ] `npm run build` passes.
- [ ] `npm run lint` passes with 0 errors; only the known AppShell custom-font warning present.
- [ ] No new `any`, `@ts-nocheck`, `eslint-disable`, or `@ts-expect-error` without an in-diff justification comment.

## Output format

1. **Verdict** — `PASS` / `FAIL` / `BLOCKER` (BLOCKER = halts RC sign-off).
2. **Findings** — table: severity (`critical` / `high` / `medium` / `low` / `info`), area, file:line, description, recommended fix. Frontend-only fixes.
3. **Backend / infra escalations** — list of findings that cannot be fixed in this repo; route to backend owner.
4. **RC-gate impact** — does this diff move 2A-D security audit forward, backward, or sideways?
5. **Next action** — concrete step, named owner where possible.

This skill is review-only. It does not modify files.
