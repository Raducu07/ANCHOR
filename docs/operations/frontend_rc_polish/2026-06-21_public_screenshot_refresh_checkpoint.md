# Public Screenshot Refresh Checkpoint — 2026-06-21

## 1. Status

Documentation-only evidence checkpoint. Frontend/public-site visual evidence
refresh **completed**.

- Not a final RC sign-off.
- Not a commercial release.
- Does **not** authorise paid pilots, real clinic data, live generation,
  Stripe/billing, connectors, customer onboarding, compliance claims, RCVS
  approval, or regulator endorsement.

## 2. Reason for checkpoint

After the frontend RC polish slice (see
[2026-06-20_frontend_rc_polish_checkpoint.md](2026-06-20_frontend_rc_polish_checkpoint.md)),
the previous public-site screenshots were **stale** — they no longer reflected
current app reality. The read-only audit verified the old captures still showed
the pre-polish UI, specifically missing:

- Dashboard-first SideNav ordering.
- Assistant present in the SideNav.
- Dashboard top actions **Open Workspace + Open Assistant**.
- Dashboard **Governance & readiness** card.
- Refreshed Trust / Learn / Receipts / Governance visual surfaces.

This checkpoint records closing that staleness gap with current-UI captures.

## 3. Scope

Asset-only public-site screenshot refresh. **No** code, copy, route, legal,
backend, env, deploy-setting, live-generation, Stripe, connector, or production
configuration changes. Existing files were replaced in place under the same
filenames, so no reference paths in `lib/marketingContent.ts` or
`components/marketing/PublicWebsite.tsx` required editing.

## 4. Files refreshed

All eight under `public/anchor-public/` (same filenames; binary swap):

- `public/anchor-public/dashboard-overview.png`
- `public/anchor-public/dashboard-receipts-learning-actions.png`
- `public/anchor-public/governance-events-overview.png`
- `public/anchor-public/learn-overview.png`
- `public/anchor-public/receipts-loaded-receipt.png`
- `public/anchor-public/trust-center-overview.png`
- `public/anchor-public/workspace-receipt-preview.png`
- `public/anchor-public/workspace-review-settings.png`

## 5. Capture discipline

- Screenshots were captured **manually by the founder/operator** using their own
  authenticated browser session.
- **No Claude/automation production authentication** was used.
- **No credentials were shared.**
- **Demo/test-data-only** discipline.
- No real clinic / client / patient / staff / clinical data intentionally
  included.
- No live-generated AI output intentionally shown.
- Metadata-only / governance-oriented visual evidence.

## 6. Screenshot mapping (source route / meaning)

| File | Source route / meaning |
|------|------------------------|
| `dashboard-overview.png` | `/dashboard` top overview — Dashboard-first nav, Open Workspace, Open Assistant, Governance & readiness card |
| `dashboard-receipts-learning-actions.png` | `/dashboard` lower learning / intelligence / quick-actions band |
| `governance-events-overview.png` | `/governance-events` overview and metadata signal context |
| `learn-overview.png` | `/learn` "why Learn exists" / practical learning view — not CPD-certificate framing |
| `receipts-loaded-receipt.png` | `/receipts` loaded active receipt metadata view |
| `trust-center-overview.png` | `/trust/profile` in-app Trust front-door view |
| `workspace-receipt-preview.png` | `/workspace` review boundaries / handoff / traceability / receipt-preview state |
| `workspace-review-settings.png` | `/workspace` source-material / review-preparation / governance summary setup state |

## 7. Git evidence

- Development commit: `5cc03f1` Refresh public product screenshots (8 image
  assets changed in place; 0 insertions / 0 deletions — binary swap).
- Production merge commit (operator-reported, on `anchor-portal-master`):
  `1b33bfa` Merge remote-tracking branch 'origin/anchor-portal-main-clean'
  into anchor-portal-master.
- Branch `anchor-portal-main-clean` pushed (HEAD = `5cc03f1` = origin).
- Branch `anchor-portal-master` synced/pushed (operator-reported).
- Working trees reported clean at completion.

## 8. Validation

- `npm run build` passed.
- 77/77 static pages generated.
- `git diff --check` clean.
- Changed files were **image assets only** (no code/content diff).
- Live/public site visually checked by the founder and reported working.

## 9. Public-site visual evidence result

The public site now reflects current app reality. The **stale-screenshot
mismatch gate is closed** — public visuals match the post-RC-polish UI
(Dashboard-first nav, Assistant present, Dashboard actions and Governance &
readiness card, refreshed Trust/Learn/Receipts/Governance surfaces).

## 10. Remaining non-blocking follow-ups

- Optional future housekeeping: remove orphaned `public/marketing/*.png`
  (`dashboard.png`, `intelligence.png`, `receipt.png` — unreferenced).
- Optional future copy audit around "safer AI use" wording, if desired.
- Later demo / walkthrough material refresh.
- Later Final Internal RC Sign-Off Note — only after the evidence pack is
  accepted.

## 11. Hard stops preserved

This checkpoint does **not** unlock:

- paid pilots
- real clinic data
- live Workspace generation
- billing / Stripe
- connectors
- ambient integrations
- customer onboarding
- compliance / certification / regulator-approval claims
