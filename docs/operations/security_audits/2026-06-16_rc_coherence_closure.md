# ANCHOR 2A-D RC Coherence Closure Note

> **Internal release-candidate hardening closure note.** Documentation only. **Not legal advice**, **not final RC sign-off**, and **not authorisation** for paid pilots, real clinic data, billing, Stripe activation, live Workspace generation, Anthropic production subprocessor activation, external connectors / runtime ingestion, or solicitor-approved / final legal status.
>
> ANCHOR is **aligned, not compliant** — not RCVS-approved, not regulator-endorsed, not certified. Live Workspace generation **remains production-off**.

## 1. Status and purpose

This note records closure of the 2A-D **RC coherence** lane for current internal hardening purposes. It is:

- An internal release-candidate hardening closure note.
- Documentation only.
- Not legal advice.
- Not final RC sign-off.
- Not authorisation for paid pilots, real clinic data, billing, Stripe activation, live Workspace generation, Anthropic production subprocessor activation, external connectors / runtime ingestion, or solicitor-approved / final legal status.

## 2. Scope

RC coherence items covered by this closure:

- Trust Pack Assistant receipt source-of-truth aggregate (backend).
- `output_blocked` assistant run-status filtering (backend).
- Frontend output-hash null rendering.
- Frontend sealed receipt snapshot labelling.
- Incident demo-state cleanup review.

## 3. Backend coherence outcome

- Commit `6074f1f` / full SHA `6074f1f38447e0f447f89046b12cf4542c148868` ("Add assistant receipt Trust Pack aggregate").
- Assistant receipt Trust Pack evidence now uses real `assistant_run_receipts` aggregate counts (total, recent-window, by review state, most-recent timestamp) instead of governance-event counts.
- The aggregate is **metadata-only and counts-only**.
- **No** raw prompt, draft, output, hash values, clinical content, client data, or patient data is exposed.
- `output_blocked` is now accepted as an assistant run-status filter (`GET /v1/assistant/runs?run_status=output_blocked`), consistent with the other run statuses.
- **No** migration / schema change.
- **No** frontend change in that backend patch.

## 4. Backend deploy smoke outcome

Reference: [`2026-06-16_rc_coherence_deploy_smoke_6074f1f.md`](./2026-06-16_rc_coherence_deploy_smoke_6074f1f.md) (recorded by documentation commit `1b1e1c9`, "Record RC coherence deploy smoke").

- Render **production** deploy smoke **PASS**.
- Runtime revision verified by `/v1/version.git_sha` = `6074f1f38447e0f447f89046b12cf4542c148868`, with `env=prod`.
- `/health` → `200 {"status":"ok"}`.
- Protected dashboard route remained protected: unauthenticated `/v1/portal/dashboard` → expected `401`.
- No env changes, migrations, destructive actions, or live-generation activation were performed.

## 5. Frontend coherence outcome

- PR #46 / merge commit `cd43de8` on `anchor-portal-master`.
- Fixes:
  - null `output_sha256` now displays `No output generated`;
  - output-hash `"None"` fallbacks removed;
  - receipt timestamp relabelled as `Receipt sealed at`;
  - sealed-snapshot captions added.
- Production-preview verification:
  - no `Output hash.*None` matches;
  - no `output_sha256.*None` matches;
  - `Receipt sealed at` labels present;
  - `sealed at receipt creation time` caption present;
  - `No output generated` helper present.
- No backend / API / type / env / route changes in the frontend patch.
- No hash fabrication and no raw content exposure — the frontend renders the backend's honest `null` output hash as a safe placeholder; it does not invent or backfill a hash.

## 6. Incident demo-state outcome

- The RC coherence audit found **no** incident seed / demo state (no incident seed migration, no demo/sample/fixture data, no bootstrap seeding script).
- Incident / Near-Miss Trust Pack evidence remains sourced from real rows / honest zero state.
- **No cleanup patch required.**

## 7. Standing blocks preserved

- No paid pilot authorised.
- No real clinic data authorised.
- No customer access authorised.
- No billing or Stripe activation.
- No invoice / VAT / payment treatment authorised.
- No live Workspace generation activation.
- No Anthropic production subprocessor activation.
- No external connector / runtime ingestion.
- No solicitor-approved / final legal status.
- No compliance / certification / regulator-approval claim.

## 8. Remaining non-blocking follow-ups

- Operational cadence evidence (backup/restore drill, intake-retention dry-run, incident-response tabletop, deploy smoke) should be repeated after material backend/data changes or immediately before any pilot / real-data readiness decision.
- Solicitor / accountant / founder review remains required before pilots, billing, Stripe, or real clinic data.
- The known AppShell custom-font lint warning remains unrelated to RC coherence.
- Any future receipt evidence-strength grading / connector work remains future / gated (per the strategy artefacts; M6.12 / M6.13 require an explicit founder decision recorded in an addendum).

## 9. Conclusion

- The **RC coherence lane is closed** for current 2A-D internal hardening purposes.
- The backend Trust Pack receipt source-of-truth ambiguity is **resolved**.
- The frontend receipt hash / seal-time presentation issues are **resolved**.
- Incident demo-state cleanup is **confirmed not required**.
- This is **not** final RC sign-off and **not** authorisation for any gated commercial, legal, AI, billing, or real-data activity.
