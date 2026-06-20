# Frontend RC Polish Checkpoint — 2026-06-20

## 1. Status

Documentation-only evidence checkpoint. Frontend RC polish for this slice is
**complete**.

This is **not** a final product RC sign-off. It does **not** authorise paid
pilots, real clinic data, live generation, Stripe/billing, connectors,
solicitor-approved claims, or any compliance/certification claims.

## 2. Product boundary

ANCHOR is governance, trust, learning, intelligence, and readiness
infrastructure for responsible AI use in veterinary clinics.

ANCHOR is **not** diagnostic AI, prescribing AI, treatment-planning AI,
autonomous clinical decision-making AI, autonomous triage, an ambient scribe,
an EHR/PMS, clinical decision-support software, a GPAI model provider,
regulator-approved software, RCVS-approved software, compliance certification,
or a replacement for veterinary judgement.

## 3. Scope of this checkpoint

Frontend/public-site and app-shell/product-coherence polish only.

No backend / API / database / env / Vercel / Render / live-generation /
Stripe / connectors / legal-copy changes.

- Production frontend branch: `anchor-portal-master`
- Development frontend branch: `anchor-portal-main-clean`
- Domain: `anchorvet.co.uk`

## 4. Audits performed

- **Read-only public/app finish audit** — public site, legal/Trust Centre,
  privacy surfaces, and app surfaces reviewed; verdict green for controlled
  public click-through with conservative, doctrine-aligned wording.
- **SideNav design / navigation review** — recommended a governance-first
  ordering with Dashboard as the operational home / command centre.
- **Dashboard refresh / action placement audit** — assessed app-wide
  refresh/action placement; found two accepted families (command-row refresh
  vs top-right header refresh) and recommended keeping the existing pattern.
- **Read-only frontend RC coherence audit** — full route/source sweep across
  public, app, legal, Trust Centre, and settings surfaces.

The RC coherence audit found **no Critical or High issues** and concluded the
frontend is **good enough for current RC polish**.

## 5. Changes included (development branch `anchor-portal-main-clean`)

| Commit | Purpose |
|--------|---------|
| `de9408c` | Soften privacy policy assurance wording |
| `5b70cc5` | Soften homepage AI safety wording |
| `fd0ac36` | Improve trust and privacy discoverability |
| `212c1c9` | Improve dashboard governance discoverability |
| `145ef65` | Reorder app navigation around dashboard |
| `7aa96ee` | Add assistant dashboard action |
| `6e9448f` | Add marketing route canonical metadata |

## 6. Production deploy evidence (production branch `anchor-portal-master`)

| Merge commit | Description |
|--------------|-------------|
| `a36ae3b` | Merged trust/privacy discoverability into `anchor-portal-master` |
| `dc50bc4` | Merged dashboard governance discoverability into `anchor-portal-master` |
| `006eaf3` | Merged SideNav reorder into `anchor-portal-master` |
| `3c088b1` | Merged Assistant dashboard action into `anchor-portal-master` |
| `0945916` | Merged marketing canonical metadata into `anchor-portal-master` |

Vercel showed deployment **Ready** for `0945916`.

## 7. Final current UI state

- Dashboard is **first** in the SideNav.
- SideNav order: **Dashboard, Workspace, Assistant, Receipts, Trust, Learn,
  Intelligence, Governance Events, Exports, Settings, Privacy / Policy,
  Support.**
- Dashboard top actions: **Refresh dashboard, Open Workspace, Open Assistant.**
- Dashboard "Governance & readiness" card: **Open Trust posture, Open
  Self-Assessment, Open Incidents** (Self-Assessment is admin-role-gated,
  mirroring Settings; the frontend gate is discoverability hardening only —
  the backend remains the authority).
- `/marketing` remains available but carries canonical `"/"` and
  `robots` noindex/follow metadata so the duplicate route is not indexed
  separately.
- Public homepage uses **responsible AI-use** wording and includes the
  **non-clinical-AI boundary statement** ("ANCHOR is not diagnostic,
  prescribing, treatment-planning, or autonomous clinical decision-making
  AI.").

## 8. Validation

Relevant frontend validations passed after each production merge:

- `npm run lint` — passed with **0 errors** and only the known AppShell
  custom-font warning.
- `npm run build` — passed with **77/77 static pages**.
- `git diff --check` — clean.
- Working trees clean after pushes.
- No backend smoke required: patches were frontend-only and did not alter
  API / env / auth / database / RLS / backend behaviour.

## 9. Explicitly not changed

- backend / API / database / RLS / auth
- legal / Trust Centre / privacy wording
- live Workspace generation
- Anthropic production subprocessor activation
- Stripe / billing
- connectors
- env vars
- Vercel / Render settings
- AppShell font architecture
- broader redesign / colour system
- real clinic data / paid pilot status

## 10. Deferred / known non-blocking items

- AppShell custom-font warning remains known/deferred; **do not fix** in this
  slice.
- TopBar external avatar is cosmetic and deferred.
- Refresh placement has two accepted families: Dashboard/Receipts command-row
  refresh and Trust/Intelligence/Governance Events top-right refresh; **no
  change recommended.**
- Deeper admin surfaces such as Policies, Policy Attestations, and Client
  Transparency remain discoverable through Settings; acceptable for current
  RC polish.
- Further broad UI redesign is deferred.

## 11. Conclusion

The frontend RC polish slice is **complete for current purposes**. No
Critical/High frontend coherence issues remain from the read-only audit.

Next recommended lane is a **final RC sign-off checklist** or a
**backend/legal/operational readiness checkpoint**, not more frontend
cosmetic patching.
