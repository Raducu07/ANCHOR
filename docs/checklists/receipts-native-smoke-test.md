# Receipts Native Smoke Test Checklist

Manual browser smoke test for the migrated native `/receipts` route. Run this end-to-end the first time after deploying the migration to a staging environment, and re-run it any time `components/receipts/*`, `lib/receipts/*`, `app/receipts/page.tsx`, or `components/shell/AppShell.tsx` changes substantially.

The route is now AppShell + React. The stitched iframe was retired during the Receipts native migration. Dashboard and Workspace remain stitched (`/dashboard`, `/workspace-live`).

---

## 1. Setup

1. Install dependencies and start the dev server:

   ```bash
   npm install
   npm run dev
   ```

2. Configure the API base in `.env.local` (or environment) before starting the dev server:

   ```bash
   NEXT_PUBLIC_API_BASE=https://staging.api.example.invalid
   ```

   Use a staging API only. Do not point smoke tests at production.

3. Open `http://localhost:3000/login` and sign in with a real test-clinic user. The smoke test does not seed credentials — log in manually.

4. From an existing receipt in the test clinic, capture two values to use later:

   - **`<known_good>`** — a `request_id` that returns a 200 from `GET /v1/portal/receipt/:id`.
   - **`<unknown>`** — a syntactically plausible but non-existent `request_id` (e.g. `req_smoke_does_not_exist_0001`) that returns a 4xx.

5. Open browser devtools. Keep the **Console** and **Network** panels visible throughout the run.

---

## 2. Route checks

| # | URL | Expected |
|---|---|---|
| R1 | `/receipts` | Loads native AppShell page. Sidebar Receipts entry is active. **No `<iframe>` element anywhere on the page.** |
| R2 | `/receipts?request_id=<known_good>` | Loads native AppShell page. Receipt summary populates with the known receipt's metadata. URL stays as `/receipts?request_id=<known_good>` (no rewrite to `/receipts-native`). |
| R3 | `/receipts?request_id=<unknown>` | Loads native AppShell page. Summary fields render `—`. The Interpretation block shows the API error message in rose-red. Page does not crash; recent ledger still renders. |
| R4 | `/dashboard` → click Receipts in the stitched nav | Parent shell navigates to `/receipts`. The native AppShell page renders. The stitched dashboard's postMessage bridge to the parent router still works. |
| R5 | `/workspace-live` → click Receipts in the stitched nav | Same as R4 — postMessage bridge from workspace-live navigates parent to native `/receipts`. |
| R6 | `/receipts-native` (any query) | **Returns 404.** This route was deleted during the migration and must not exist. |

Tip for R6: open it in a new tab, do not just rely on dev-server hot reload.

---

## 3. Functional checks

Run these on the native `/receipts` route in order.

### 3.1 Ready state and recent ledger

| # | Action | Expected |
|---|---|---|
| F1 | Land on `/receipts` with no query string | Hero chips read `RECEIPT STATUS (READY)`, `NO CONTENT STORED (YES)`, `SELECTED MODE (—)`. Summary fields all show `—`. Decision badge shows "Awaiting selection". Interpretation shows the default selector copy. |
| F2 | Network tab while loading | **Exactly one `GET /v1/portal/dashboard` request.** **No `GET /v1/portal/receipt/...` request.** |
| F3 | Recent receipt ledger | Populates with up to 8 rows of recent submissions if the test clinic has activity. Each row shows Request ID (mono violet), Mode (humanized), Decision pill, PII column (`Detected` red / `Not detected` italic gray), Time (en-GB formatted), and an "Open receipt" button. |
| F4 | Empty clinic case | If the clinic has no recent submissions, the ledger shows "No recent receipts available." (singular, no filter qualifier). |

### 3.2 Single receipt loading

| # | Action | Expected |
|---|---|---|
| F5 | Paste `<known_good>` into the Request ID input, click "Load receipt" | Decision badge shows "Loading" briefly, then flips to the decision tone. Summary card populates 10 fields. Traceability card shows policy hash + governance/review subgrids. Interpretation shows the receipt-specific narrative. URL becomes `/receipts?request_id=<known_good>`. |
| F6 | Same as F5 but press Enter in the input instead of clicking | Same behavior. |
| F7 | Click any "Open receipt" button in the ledger | Same behavior, with the ledger's `request_id` now selected. URL updates accordingly. |
| F8 | Browser back/forward across loaded receipts | Selected receipt updates to match the URL each time. No duplicate fetches in Network panel — should see one `GET /v1/portal/receipt/:id` per unique URL. |

### 3.3 Mode filter

| # | Action | Expected |
|---|---|---|
| F9 | Change "Filter ledger by mode" select to `Internal summary` | Ledger rows narrow to those whose `mode === "internal_summary"` (lowercase strict equality). **No new network request fires.** |
| F10 | Change to `Client communication` | Ledger narrows to `client_comm` rows. (Note: rows whose backend mode is `client_communication` will not appear; that's intentional parity with the stitched filter.) |
| F11 | Change to a value with no matching rows | Ledger shows "No recent receipts available for the current filter." |
| F12 | Reset to `All modes` | Full row set (≤8) returns. |

### 3.4 Refresh

| # | Action | Expected |
|---|---|---|
| F13 | With a receipt selected, click "Refresh receipts" | Network tab: one `GET /v1/portal/dashboard` then one `GET /v1/portal/receipt/:id`. Button label flips to "Working..." and is disabled while in flight. |
| F14 | With no receipt selected, click "Refresh receipts" | Network tab: one `GET /v1/portal/dashboard` only. No receipt call. |

### 3.5 Export metadata

| # | Action | Expected |
|---|---|---|
| F15 | With no receipt selected | Both "Export metadata" (hero) and "Export metadata bundle" (right rail) buttons are disabled. |
| F16 | With a receipt selected, click "Export metadata" | Browser downloads `anchor-receipt-<request_id>.json`. Open the file: top-level shape is `{ "receipt": { … } }` (pretty-printed, 2-space indent). Confirm the `receipt` object contains the same fields rendered in the summary card. |
| F17 | Same with "Export metadata bundle" in the right rail | Same download, identical shape. |

### 3.6 Copy policy hash

| # | Action | Expected |
|---|---|---|
| F18 | With no receipt loaded | Copy button in the Traceability card is disabled. |
| F19 | With a receipt that has a policy hash | Click Copy. Button label flips to "Copied" for ~1.5s and then back to "Copy". Paste into an external editor to confirm the hash matches the value rendered on screen. |
| F20 | With a receipt that has no `policy_hash` and no `policy_sha256` | Copy button disabled. Hash field shows `—`. |

### 3.7 Auth

| # | Action | Expected |
|---|---|---|
| F21 | While signed in, manually clear `localStorage.anchor_access_token` then reload `/receipts` | Page redirects to `/login`. (AppShell auth gate.) |
| F22 | Sign in again, return to `/receipts`, click sign-out in the TopBar profile menu | Returns to `/login`. `localStorage.anchor_access_token` and `anchor_session_user` are cleared. |
| F23 | Visit `/receipts` while signed out | Redirects to `/login` before any API call fires. Confirm in Network panel that no `/v1/portal/*` request was issued. |

### 3.8 Console / Network hygiene

| # | Check | Expected |
|---|---|---|
| F24 | Console panel during the entire run | No red errors. No hydration mismatch warnings. No "Cannot update during render" warnings. |
| F25 | Network panel | No 5xx responses. No CORS errors. Auth-required calls carry an `Authorization: Bearer <token>` header. |
| F26 | DOM inspection on `/receipts` | **No `<iframe>` element anywhere in the page.** Search DOM for `iframe` to confirm. |

---

## 4. Visual checks

### 4.1 1440px desktop

- Hero, lookup bar, and the 2-column layout (main + 320px right rail) all fit comfortably.
- Summary card 2-column field grid, Traceability card 2-column governance/review grid, and recent ledger all render without horizontal scroll.
- Right rail dark posture card is readable; recommended action tiles, quick action grid, and pillar tiles align cleanly.

### 4.2 1024px tablet width

- Right rail wraps under the main column (the grid drops to single-column at the `xl` breakpoint).
- Hero chips wrap as needed without overflowing.
- Lookup bar's input + select + button stack vertically.
- Recent ledger horizontally scrolls if needed; column headers remain readable.

### 4.3 Narrow / mobile (optional, ~375px)

- AppShell sidebar may overflow — known limitation, not a blocker for this sprint (AppShell does not yet have a mobile drawer).
- Receipts content (hero, summary, traceability, interpretation, ledger, right rail tiles) stacks vertically and remains readable.

### 4.4 Visual integrity

| Check | Expected |
|---|---|
| AppShell nav active state | Receipts entry highlighted in the sidebar on every `/receipts*` URL. |
| Decision tones | Allowed → emerald, Modified → amber, Replaced/Blocked → rose. Same tone in summary badge and ledger pill for the same decision. |
| Right rail dark posture card | `bg-slate-900` with white heading; bullets readable. |
| No stale stitched assets | No CDN Tailwind link in DOM, no Material Design `surface-container-*` classes, no inline `<style>` blocks from the iframe era. |

---

## 5. Accessibility checks

| # | Check | Expected |
|---|---|---|
| A1 | Tab order from page top | TopBar (search, notifications, settings, profile) → Refresh receipts → Export metadata → Request ID input → Mode filter select → Load receipt button → in-card controls (Copy hash) → Recent ledger row buttons in DOM order. |
| A2 | Enter on Request ID input | Submits the lookup. |
| A3 | Tab into ledger row | Each "Open receipt" button is keyboard-focusable; Enter / Space activates it. |
| A4 | Table headers | Inspect: each `<th>` has `scope="col"`. Screen-reader announces column names when navigating cells. |
| A5 | Disabled states | Export and Copy hash buttons report `aria-disabled` / `disabled` when no receipt / no hash; visibly dimmer; not reachable via Enter activation. |
| A6 | Dark card contrast | `text-slate-300` on `bg-slate-900` body text passes WCAG AA. White headings pass AAA. (Reference: ~7.4:1 and ~17:1.) |
| A7 | Form labels | Request ID input and Mode filter select both have explicit `<label htmlFor="...">` associations. |
| A8 | Material symbol icons | All have `aria-hidden="true"` so they don't double-announce. |

---

## 6. Pass / fail table

Copy this section into the run log. One row per check; mark each `pass`, `fail`, or `n/a`.

| Check | Result | Notes |
|---|---|---|
| R1 — `/receipts` loads, no iframe |  |  |
| R2 — `/receipts?request_id=<known_good>` loads metadata |  |  |
| R3 — `/receipts?request_id=<unknown>` shows error state |  |  |
| R4 — `/dashboard` nav lands on `/receipts` |  |  |
| R5 — `/workspace-live` nav lands on `/receipts` |  |  |
| R6 — `/receipts-native` returns 404 |  |  |
| F1 — Ready state chips/summary |  |  |
| F2 — Initial network calls (dashboard only, no receipt) |  |  |
| F3 — Recent ledger populates |  |  |
| F4 — Empty-clinic ledger copy |  |  |
| F5 — Load receipt via button |  |  |
| F6 — Load receipt via Enter |  |  |
| F7 — Open receipt from ledger row |  |  |
| F8 — Back/forward navigation |  |  |
| F9–F12 — Mode filter |  |  |
| F13 — Refresh with selection |  |  |
| F14 — Refresh without selection |  |  |
| F15 — Export disabled with no receipt |  |  |
| F16 — Export hero downloads JSON |  |  |
| F17 — Export bundle downloads JSON |  |  |
| F18 — Copy hash disabled with no receipt |  |  |
| F19 — Copy hash works |  |  |
| F20 — Copy hash disabled with no hash |  |  |
| F21 — Auth gate redirects when token cleared |  |  |
| F22 — Sign-out clears session |  |  |
| F23 — `/receipts` while signed out redirects |  |  |
| F24 — No console errors / hydration warnings |  |  |
| F25 — No 5xx / CORS issues |  |  |
| F26 — No iframe in DOM |  |  |
| 4.1 — 1440px layout |  |  |
| 4.2 — 1024px layout |  |  |
| 4.3 — Narrow width (optional) |  |  |
| 4.4 — Visual integrity |  |  |
| A1–A8 — Accessibility checks |  |  |

---

## 7. Doctrine reminders during the run

While testing, watch for any UI element that drifts away from ANCHOR doctrine. None of these should appear:

- Raw prompt or output content displayed on the page.
- Clinical decision-making suggestions, diagnoses, or treatment recommendations.
- Cross-tenant data leakage (every value shown should be scoped to the signed-in clinic).
- Text framing AI as an autonomous decision-maker rather than a governed, human-reviewed assistant.

If any of the above appears, stop and file a blocker.

---

## 8. Sign-off

After the run:

- Attach the completed pass/fail table to the migration ticket.
- Note the API base used, the test clinic, and the `<known_good>` / `<unknown>` request IDs (no patient context — request IDs only).
- If everything passes: mark `/receipts` as approved native-migrated. Dashboard becomes the next migration target.
- If anything fails: file blockers before announcing the migration externally and before starting Dashboard work.
