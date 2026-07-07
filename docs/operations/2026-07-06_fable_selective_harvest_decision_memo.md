# Fable Selective Harvest — Founder Decision Memo

> **Status: documentation-only decision-preparation, 6 July 2026 (verified against the repository 7 July 2026).** This memo helps the founder decide which Fable experiment commits, if any, are later harvested into main/production branches, in what order, and under which gates. **It performs nothing:** no harvest, no cherry-pick, no PR, no merge, no deploy, no push. All standing hard boundaries remain closed — no public launch, no paid pilots, no real clinic data, no production live generation, no live billing, no live provider switching, no OpenAI production use, no ambient transcript/audio storage, no clinical note generation, no EHR/PMS integration, and no compliance/certification/regulator-approval claims. ANCHOR remains **aligned, not compliant**.

**Verified branch tips at time of writing:**

| Branch | Type | Tip (verified) |
|---|---|---|
| `fable/roadmap-completion-experiment` | backend | `34d8f00` |
| `fable/frontend-roadmap-completion-experiment` (in separate repo `anchor-portal`) | frontend | `80e3fb7` |
| `fable/rcvs-scenario-preparation` | docs | `fa15c13` |

---

## 0. Read this first — three facts that shape every decision below

**Fact 1 — merging backend `main` is a production change, not an archival act.** If `main` auto-deploys to Render (the operative assumption for `anchor-api-prod`), any harvested backend commit ships its routes to prod and runs its migrations against the prod database at next boot. No real clinics exist and every new capability is flag-gated off — but a migration, once applied on prod, becomes **sealed** under checksum discipline (roll-forward only). Treat every migration-bearing harvest as one-way and gate it accordingly.

**Fact 2 — the route-count guards pin an exact total.** Commit `27ffcfe` bumps the guard tests **126 → 156**, which assumes *all five* new routers land. That +30 is fully accounted for and verified per module:

| Module | Commit | New routes |
|---|---|---|
| M5.7 assisted onboarding | `ab16dd2` | +2 |
| M4.6 Learn maturity | `c460a73` | +6 |
| M5.8 billing foundations | `76ec881` | +3 |
| M6-S sustainability | `2093543` | +15 |
| M6.13 ambient shell | `68679d3` | +4 |
| **Total** | | **+30** → 126→156 |

Any **partial** harvest of router-adding slices therefore needs a small per-harvest guard-adjustment commit (e.g. +2 for M5.7 alone), and `27ffcfe` itself must land **only with the final router group**. The multi-module fix `64ac727` (admin audit events) spans four modules — `ambient_governance`, `billing_foundations`, `learn_maturity`, `sustainability` — and must be **split at harvest time** so each module's audit slice travels with its own group.

**Fact 3 — the frontend lives in a separate repository.** The internal-preview surfaces are in **`anchor-portal`** (branch `fable/frontend-roadmap-completion-experiment`, verified tip **`80e3fb7`**), not in this backend repo. "Harvesting the frontend" therefore means merging into `anchor-portal`'s main line — a distinct operation from any backend harvest, reviewed and gated independently. All preview surfaces are gated behind the build-time flag **`NEXT_PUBLIC_ANCHOR_INTERNAL_PREVIEW` (default off)**, so a deployed build renders and fetches **zero** preview surface until that flag is explicitly set. Frontend build/lint previously passed on this branch. (Note on provenance: the frontend tip and the two pre-merge fixes `cb4831b`/`80e3fb7` are verified against `origin` after `git fetch --prune`; a backend-repo mirror of this ref can lag the `anchor-portal` origin, so always confirm the frontend tip from `anchor-portal` before any frontend harvest.)

---

## 1. Candidate group assessments

Each group uses the same field template: commits · files/areas · stack scope · benefit · risk · dependencies · legal gates · security gates · wording gates · RCVS/VATA dependency · recommendation (A harvest soon / B harvest after review / C keep experiment-only / D defer until RCVS/VATA final output / E do not harvest).

### Group 1 — RCVS/VATA scenario preparation docs
- **Commits:** `fa15c13` (branch `fable/rcvs-scenario-preparation`).
- **Files/areas:** 8 files, 729 insertions, all under `docs/strategy/rcvs_scenario_preparation/` (scenario matrix, comparison protocol, positioning options, response decision tree, post-RCVS prompt pack, action-plan templates, buyer/solicitor/insurer explanation pack, index).
- **Stack scope:** docs-only.
- **Benefit:** the comparison protocol and post-RCVS prompt pack must be discoverable on `main` **before** the final RCVS/VATA output lands — readiness before the event is their entire purpose.
- **Risk:** none functional. The buyer/solicitor/insurer explanation pack is a draft not-for-external-use; keep that marker intact.
- **Dependencies:** none.
- **Legal gates:** none (internal). **Security gates:** none.
- **Wording gates:** passed — written to Readiness Map v1.1 §2 controls; consultation referenced only in the neutral internal form (aligns with solicitor **Q38**); explanation-pack drafts marked internal.
- **RCVS/VATA dependency:** none holds it back — it exists to be ready *ahead of* the output.
- **Recommendation: A — harvest soon.**

### Group 2 — Backend hardening (pytest hygiene + HTTPS-only intake webhooks)
- **Commits:** `543a137` (pytest.ini collection confinement, TD-BE-2); `e4ec093` (HTTPS-only intake webhook delivery).
- **Files/areas:** `pytest.ini`; `app/intake_notifications.py` (+21) and `tests/test_intake_webhook_scheme.py` (+147). No routes, no migrations, no `main.py` change.
- **Stack scope:** backend-only.
- **Benefit:** closes TD-BE-2 (test-collection hygiene) and hardens the marketing-intake perimeter — a misconfigured webhook can no longer transmit intake contact/free-text fields over plaintext HTTP.
- **Risk:** minimal. The webhook change alters failure behaviour on a misconfigured (http://) target; intake persistence is unaffected. Behaviour is covered by the new test.
- **Dependencies:** none.
- **Legal gates:** none to harvest (the change *supports* the answer to solicitor **Q7** on the intake perimeter). **Security gates:** none — this is itself a security improvement.
- **Wording gates:** none. **RCVS/VATA dependency:** none.
- **Recommendation: A — harvest soon.**

### Group 3 — Safety infrastructure (provider skeleton, safety-gate harness, safety-gate docs)
- **Commits:** `3d853ea` (provider-neutral interface skeleton + Anthropic adapter + fail-closed registry); `0d71a79` (2A-C.5E hard-refusal safety-gate harness + runner + tests); `50c7f5b` (docs: harness note + `env.md` rows). **Excludes `c4d03d3`** (OpenAI adapter — see Group 3b).
- **Files/areas:** `app/assistant_provider.py`, `app/workspace_generation.py` (small hook), `app/workspace_safety_gate.py`, `scripts/run_live_safety_gate.py`, tests; docs `docs/operations/2026-07-05_2a_c_5e_safety_gate_harness.md` + `env.md`. No routes, no migrations.
- **Stack scope:** backend-only. Default runtime behaviour is unchanged (harness is local/staging-only; provider selection defaults to the existing path).
- **Benefit:** puts the doctrine-mandated hard-refusal harness on `main` **before** any live-generation decision (canon: the harness ships *with* live calls, never after). Prod gains the anthropic-only allow-list as an extra fail-closed layer.
- **Risk:** low technically. **Governance risk:** the provider interface is M6.12-adjacent, and Roadmap v2.6 §9 requires an explicit founder decision **recorded as a canonical memo addendum** to bring M6.12 work forward. The 5 July decision record exists in `docs/operations/`; promoting it into the canonical addendum series is a founder-authored step still outstanding.
- **Dependencies:** `0d71a79` imports from `3d853ea` (travel together). `c4d03d3` later edits both `assistant_provider.py` and `workspace_generation.py` — cherry-picking Group 3 without it is clean at these commits but needs a conflict-check at harvest time.
- **Legal gates:** none for the skeleton/harness themselves. **Security gates:** none new (adds a fail-closed layer).
- **Wording gates:** passed (`env.md` rows use future-tense vendor-neutral framing per **Q40**). **RCVS/VATA dependency:** none.
- **Recommendation: B — harvest after review** (specifically: after the founder records the canonical M6.12-adjacency addendum).

### Group 3b — M6.12 completion: gated OpenAI adapter + latency metadata
- **Commits:** `c4d03d3`.
- **Files/areas:** `app/assistant_provider.py` (+OpenAI adapter, unconfigured, prod allow-list refusal), `app/workspace_generation.py` (latency metadata), `env.md`, tests.
- **Stack scope:** backend-only.
- **Benefit:** completes the connector layer code-wise; adds latency metadata to governance events.
- **Risk:** places a dormant second-provider client on prod infrastructure before the solicitor has answered whether mere code existence needs disclosure (**Q20–Q21**). Reading its key is non-production-only and selection is allow-list-refused in prod, but the metadata sub-object shape change flows into governance events.
- **Dependencies:** Group 3.
- **Legal gates:** **Q20–Q21** (does code existence warrant disclosure; provider-switch notice mechanism). **Security gates:** confirm the prod allow-list refusal path at harvest.
- **Wording gates:** passed (`env.md` rows avoid present-tense "provider choice available today"). **RCVS/VATA dependency:** none.
- **Recommendation: C — keep experiment-only** until Q20–Q21 are answered and the canonical addendum exists; then B.

### Group 4 — M5.7 assisted onboarding
- **Commits:** backend `ab16dd2` (+2 routes; `app/portal_onboarding.py`, `app/main.py`, tests; **no migration**). Frontend Slice F2 `f93d396` (see Group 9).
- **Files/areas:** `app/portal_onboarding.py` (+382), `app/main.py` (+2 router include), `tests/test_portal_onboarding.py` (+293).
- **Stack scope:** full-stack; the backend is independently useful (read-only readiness checklist + invite-lifecycle visibility).
- **Benefit:** the natural first-run spine and the lowest-risk feature slice — no schema change, admin-only, tenant-internal.
- **Risk:** low. Invitee-email visibility has an open Privacy Notice question (**Q35**); it is admin-only and tenant-internal, so acceptable pre-real-data, but tidier to answer first. Needs a **+2 guard-adjustment** commit if harvested alone (do not bring `27ffcfe`).
- **Dependencies:** none backend. Frontend F2 needs the shared preview gate/chrome (F1/F8) or ships backend-only first.
- **Legal gates:** **Q35** (soft — invitee email visibility/retention). **Security gates:** none new (audited; add its `64ac727` audit slice if that lands separately — note M5.7's audit lives with the four-module split, verify at harvest).
- **Wording gates:** passed. **RCVS/VATA dependency:** none.
- **Recommendation: B — harvest after review** (backend first; frontend with Group 9 after visual review).

### Group 5 — M4.6 Learn maturity
- **Commits:** `c460a73` (2 migrations + module + tests, +6 routes) **plus the seed-fix portion of `be98e49`** (must travel together — `be98e49` fixes seed statement-splitting in `migrations/20260705_02_learn_maturity_seed.sql`) **plus the learn slice of `64ac727`** (renewal/completion audit event). Frontend Slice F3 `759ecfe` (see Group 9).
- **Files/areas:** `app/learn_maturity.py` (+633), `app/main.py` (+2), `migrations/20260705_01_learn_maturity_schema.sql`, `migrations/20260705_02_learn_maturity_seed.sql`, tests.
- **Stack scope:** full-stack.
- **Benefit:** completes the AI-literacy story; strongest candidate **if** the RCVS/VATA final output is literacy-heavy.
- **Risk:** seeds educational content into the prod DB (sealed after first boot); the non-certifying framing is strong but solicitor confirmation (**Q32–Q34**) is pending; +6 routes require a guard adjustment.
- **Dependencies:** seed fix (`be98e49` slice); audit-event split (`64ac727` slice).
- **Legal gates:** **Q32–Q34** (self-check counts not a competence assessment; employment-law adjacency of completion visibility; "CPD-recordable" wording). **Security gates:** none new.
- **Wording gates:** passed, with the standing rule that self-check counts are never rendered comparatively and every response carries the "self-check reinforcement only…" disclaimer.
- **RCVS/VATA dependency:** **genuine** — the final output may reshape emphasis or vocabulary before content is sealed into prod.
- **Recommendation: D — defer until RCVS/VATA final output** (then B).

### Group 6 — M5.8 billing foundations
- **Commits:** `76ec881` (1 migration + module + tests, +3 routes) + billing slice of `64ac727`. Frontend Slice F4 `77a1e2f` (see Group 9).
- **Files/areas:** `app/billing_foundations.py` (+312), `app/main.py` (+6), `env.md`, `migrations/20260705_03_billing_foundations_schema.sql`, tests.
- **Stack scope:** full-stack.
- **Benefit:** none realisable on prod until billing decisions exist (no Stripe, no keys, no prices, no charge capability).
- **Risk:** adds billing vocabulary and an (unauthenticated-by-design, disabled, prod-refusing) webhook-shaped route plus a schema to prod for zero current value.
- **Dependencies:** none beyond its audit slice.
- **Legal gates:** **Q16–Q18** entirely unanswered (pre-Stripe drafting; activation states; VAT/invoicing). **Security gates:** webhook posture review required at any enablement.
- **Wording gates:** passed. **RCVS/VATA dependency:** none.
- **Recommendation: C — keep experiment-only.**

### Group 7 — M6-S sustainability governance
- **Commits:** `2093543` (1 migration, largest schema surface, +15 routes) + sustainability slice of `64ac727`. Frontend Slice F5 `8a50534` (see Group 9).
- **Files/areas:** `app/sustainability.py` (+836), `app/main.py` (+2), `migrations/20260705_04_sustainability_schema.sql` (+337), tests.
- **Stack scope:** full-stack; largest single schema and route surface (+15).
- **Benefit:** none until activation is even contemplated.
- **Risk:** Roadmap v2.6 §8 queues M6-S behind **RC sign-off and commercial validation** — the experiment authorised *building* it, not *shipping* it; merging to prod would outrun canon. Introduces a new operational-data category (energy/waste/CO2e) beyond governance metadata; a single-line label-parity guard remains a pre-activation TODO.
- **Dependencies:** its audit slice.
- **Legal gates:** **Q28–Q31** (operational-data classification/DPA row; clinic-written labels; retention class; non-claims disclaimer). **Security gates:** none new. **Wording gates:** passed (non-claims copy already present). **RCVS/VATA dependency:** none.
- **Recommendation: C — keep experiment-only** (revisit only via a founder canon decision).

### Group 8 — M6.13 ambient governance shell
- **Commits:** `68679d3` (1 migration + module + spec DRAFT, +4 routes) + ambient slice of `64ac727` + **`7487909`** (rule-13 CHECK-hardening migration + tests — required companion). Frontend Slice F6 `786e89c` (see Group 9).
- **Files/areas:** `app/ambient_governance.py` (+401 then +64 audit), `app/main.py` (+2), `env.md`, `migrations/20260705_05_ambient_governance_schema.sql`, `migrations/20260706_01_ambient_boundary_check_hardening.sql`, spec DRAFT, tests.
- **Stack scope:** full-stack; highest sensitivity of any group.
- **Benefit:** none until an ambient activation decision exists.
- **Risk:** the adopted boundary decision (see Group 10) itself conditions any merge on solicitor **Q22–Q27** and **Q12** (DPIA) plus a separate founder + security review; by prior recommendation it travels **last** in any future order. The schema physically cannot hold transcripts/audio/notes (Rule-13 CHECK constraints), which is the whole point — but staff-monitoring adjacency (duration/reviewer metadata) is legally open.
- **Dependencies:** `7487909` (rule-13 migration); the adoption docs (Group 10).
- **Legal gates:** **Q22–Q27** (staff-monitoring, controller/processor, retention, review-gate liability, reference hashes, client-transparency interplay) + **Q12** (DPIA). **Security gates:** none new (validated), but a dedicated pre-activation security review is a stated precondition.
- **Wording gates:** passed. **RCVS/VATA dependency:** indirect — an ambient-relevant final output could reshape vocabulary before it is sealed.
- **Recommendation: C — keep experiment-only** (explicitly conditioned; last in any future order).

### Group 9 — Frontend internal-preview surfaces
- **Commits (verified in `anchor-portal`, branch `fable/frontend-roadmap-completion-experiment`, tip `80e3fb7`):**
  - `b48b68c` — align frontend Claude guardrail-identity wording (pre-slice foundation)
  - `d452d97` — Slice F1: backend contract map (docs)
  - `f93d396` — Slice F2: assisted onboarding preview → M5.7
  - `759ecfe` — Slice F3: Learn maturity preview → M4.6
  - `77a1e2f` — Slice F4: sandbox-only billing preview → M5.8
  - `8a50534` — Slice F5: sustainability governance preview → M6-S
  - `786e89c` — Slice F6: ambient governance shell preview → M6.13
  - `ac3c6ea` — Slice F7: static provider posture preview → M6.12
  - `fe1da16` — Slice F8: internal-preview dashboard tiles + gated links
  - `cb4831b` — **pre-merge FIX 3: unify internal-preview soft-fail posture** (adds `components/experiment/InternalPreviewGate.tsx`; edits billing/learn/onboarding/sustainability surfaces — cross-cutting)
  - `80e3fb7` — **founder wording-review fixes** (tip; edits `InternalPreviewTiles.tsx`, `OnboardingReadinessSurface.tsx`)
- **Files/areas:** Next.js portal preview surfaces + the shared `InternalPreviewGate`, all gated behind the build-time flag `NEXT_PUBLIC_ANCHOR_INTERNAL_PREVIEW` (default off → zero rendered/fetched surface in deployed builds). No backend. Lives in the separate `anchor-portal` repo.
- **Stack scope:** frontend-only (separate repo).
- **Benefit:** the surfaces exist and the soft-fail posture is now unified (`cb4831b`), so each preview degrades honestly against a backend that lacks its endpoints. Merging costs almost nothing operationally while the build flag is off, and it stops the portal experiment branch from drifting.
- **Risk:** surfaces are inert/undemonstrable against a prod backend lacking their endpoints; the audit's **frontend visual review has not happened**; a CI/build-flag misconfiguration WATCH stands. **Split note:** `cb4831b` (soft-fail, 5 surfaces) and `80e3fb7` (wording, 2 surfaces) are cross-cutting, so a *partial* per-surface harvest must split these two — or bring the shared soft-fail gate (`cb4831b`) with the first surface harvested.
- **Dependencies:** each surface depends on its backend group being accepted first; F1 (`d452d97`), the guardrail wording (`b48b68c`), the F8 chrome (`fe1da16`), and the soft-fail gate (`cb4831b`) form the shared substrate any surface needs.
- **Legal gates:** none directly (each surface inherits its backend group's gates at activation). **Security gates:** none (nothing new server-side). **Wording gates:** `b48b68c` (guardrail identity) and `80e3fb7` (founder wording review) already applied; treat as passed pending visual review. **RCVS/VATA dependency:** none directly (F3/M4.6 emphasis follows Group 5).
- **Recommendation: C — keep experiment-only**, harvesting each surface **with** its backend group, **after** frontend visual review **and** backend contract acceptance, into `anchor-portal` (not this repo). `d452d97` (contract map, docs) may travel with a docs wave (A).

### Group 10 — M6.13 adoption decision, spec v1, rule-13 hardening
- **Commits:** `e59277d` (decision record + boundary spec v1 + DRAFT supersession — docs), `7487909` (rule-13 CHECK-hardening migration + tests — code).
- **Files/areas:** `docs/operations/2026-07-06_m6_13_boundary_adoption_decision.md`, `..._boundary_spec_v1.md`, DRAFT marked superseded; `migrations/20260706_01_ambient_boundary_check_hardening.sql`, `tests/test_ambient_governance.py`.
- **Stack scope:** split — docs + backend migration.
- **Benefit:** the decision record and adopted spec belong on `main` as governance history regardless of when the shell ships.
- **Risk:** none for the docs; the migration is meaningless (and would fail) without Group 8's ambient table.
- **Dependencies:** the migration half is inseparable from Group 8. **Legal/security/wording gates:** docs carry none; migration inherits Group 8's. **RCVS/VATA dependency:** none for the docs.
- **Recommendation: split — docs part A (with the docs wave); migration part C (inseparable from Group 8).**

### Group 11 — Solicitor question pack (+ decision/validation records)
- **Commits:** `34d8f00` (solicitor question pack, docs-only, `docs/commercial/`). Same character: `84cff15` (founder decision record + experiment slice log) and the validation-note portion of `be98e49` (`docs/operations/2026-07-06_pre_merge_fix_validation_note.md`).
- **Files/areas:** `docs/commercial/2026-07-06_fable_experiment_solicitor_question_pack.md` (41 numbered questions + blocking-decision matrix); founder decision record; pre-merge validation note.
- **Stack scope:** docs-only (note: `be98e49` **also** carries the M4.6 seed fix, which belongs with Group 5, not here — split at harvest).
- **Benefit:** the pack is the working input to the actual solicitor engagement; commercial/decision docs live on `main` by convention.
- **Risk:** none; internal, non-claiming, gates restated throughout.
- **Legal/security/wording gates:** none to harvest; the pack is *how* the legal gates get answered. **RCVS/VATA dependency:** none (Q38 references the consultation neutrally).
- **Recommendation: A — harvest soon** (docs wave; keep the `be98e49` seed-fix code with Group 5).

---

## 2. Recommended low-risk-first harvest path

1. **Wave 1 — docs (A):** RCVS scenario pack (`fa15c13`); solicitor pack (`34d8f00`); founder decision/log (`84cff15`); validation-note *docs* of `be98e49`; M6.13 adoption *docs* of `e59277d`; safety-gate *docs* of `50c7f5b`. Docs-only; no behavioural deploy effect.
2. **Wave 2 — hardening (A):** `543a137` + `e4ec093`. Backend-only, no routes, no migrations; each ships with its own tests.
3. **Wave 3 — safety infrastructure (B):** `3d853ea` + `0d71a79` + `env.md`/notes of `50c7f5b` — **after** the founder records the canonical M6.12-adjacency addendum. Conflict-check against the `c4d03d3` exclusion.
4. **Wave 4 — M5.7 backend (B):** `ab16dd2` + its `64ac727` audit slice + a **+2** guard-adjustment commit — ideally after **Q35**.
5. **Pause.** Everything else waits on the gates in §§3–8. Do not bring `27ffcfe` until the final router group lands.

## 3. What should definitely NOT be harvested yet

M5.8 billing (Group 6), M6-S sustainability (Group 7), the M6.13 ambient shell code (Group 8), the OpenAI adapter (`c4d03d3`, Group 3b), all frontend preview surfaces F2–F8 (Group 9), and the guard reconciliation `27ffcfe` (only ever with the final router group). None of these delivers prod value now, and each carries an open legal, canon, or review gate.

## 4. What waits for the solicitor

- **`c4d03d3` (OpenAI adapter):** Q20–Q21.
- **M5.7 comfort:** Q35 (soft).
- **M4.6:** Q32–Q34.
- **M5.8:** Q16–Q18.
- **M6-S:** Q28–Q31.
- **M6.13 shell:** Q22–Q27 and Q12 (DPIA).
- **Any external wording change:** Q38–Q41.

First tranche to unblock the most: Q1–Q2, Q9–Q11, Q19, and Q39.

## 5. What waits for the RCVS/VATA final output

Only **M4.6 content/emphasis** (Group 5, recommendation D) is genuinely gated by it — the seeded literacy content should not be sealed into prod before the final output can reshape emphasis/vocabulary. Any positioning-led reordering is governed by the scenario-pack comparison protocol (`fa15c13`). Nothing else in this memo is blocked by RCVS/VATA; the scenario pack itself is deliberately harvested *ahead* of the output.

## 6. What waits for the live-generation safety gate

Nothing in this memo requires the live gate to *pass* first — but the **harness (Group 3) should be on `main` before** any documented live-gate run feeds an enablement decision (canon: harness ships with live calls, never after). The live-generation decision itself additionally awaits subprocessor closure (**Q19**) and a documented 2A-C.5E pass, and would make Anthropic a subprocessor the moment it is enabled. No group here enables live generation.

## 7. What waits for M6.13 boundary / legal closure

The entire ambient stack is conditioned on M6.13 boundary/legal closure and travels **last**:
- **Group 8** (ambient shell code `68679d3` + audit slice + rule-13 migration `7487909`).
- **Group 10 migration half** (`7487909` — inseparable from Group 8's table).
- **Group 9 Slice F6** (`786e89c`, ambient preview surface).

Closure means: solicitor **Q22–Q27** + **Q12** answered; the adopted boundary spec's activation preconditions met; a separate founder decision and dedicated security review recorded. Until then these stay experiment-only. **Exception:** the Group 10 **docs** (`e59277d` decision record + spec v1) are governance history and may harvest in the docs wave now — only the migration and shell code wait.

## 8. What waits for frontend visual review

All of **Group 9** except the F1 docs (`d452d97`, contract map). The slice surfaces (`f93d396`, `759ecfe`, `77a1e2f`, `8a50534`, `786e89c`, `ac3c6ea`, `fe1da16`), the guardrail-wording commit (`b48b68c`), the soft-fail unification (`cb4831b`), and the founder wording-review fixes (`80e3fb7`) each wait for the visual review, and each surface additionally waits for its backend group's gates and backend contract acceptance. All of this harvests into `anchor-portal`, not this repo.

## 9. Suggested PR / cherry-pick grouping (when authorised — none opened now)

| PR | Contents | Notes |
|---|---|---|
| PR-1 (backend) | Wave-1 docs cherry-picks (`fa15c13`, `34d8f00`, `84cff15`; docs slices of `be98e49`, `e59277d`, `50c7f5b`) | May combine with PR-2; keep `be98e49` seed-fix *code* out of this PR |
| PR-2 (backend) | `543a137`, `e4ec093` | Standalone tests included |
| PR-3 (backend) | `3d853ea`, `0d71a79`, `50c7f5b` (code/env) | After canon addendum; conflict-check vs the `c4d03d3` exclusion |
| PR-4 (backend) | `ab16dd2` + M5.7 slice of `64ac727` + guard **+2** | After Q35 |
| Held | Groups 5, 6, 7, 8, 3b; frontend F1-wording + F2–F8 | Per §§3–8; split `64ac727` per module; `27ffcfe` lands only with the final router group |
| PR-F1 (`anchor-portal`) | `d452d97` (contract map, docs) | Separate-repo PR; docs anytime. Slice surfaces + `b48b68c`, `cb4831b` (soft-fail gate), `80e3fb7` (wording) wait for visual review + backend contract acceptance |

## 10. Rollback considerations

- **Docs waves:** trivially revertible.
- **Code waves:** each PR reverts cleanly **until its migrations run on prod**. After first prod boot, applied migrations are sealed (checksum discipline); rollback becomes roll-forward (a new migration), so treat every migration-bearing harvest (Groups 5, 6, 7, 8 only) as one-way. Groups 2, 3, 3b, and 4-backend carry **no migrations** and revert cleanly.
- **Feature behaviour** has a second, faster layer: every dangerous capability is env/build-flag off by default, so "rolling back" an experience is unsetting nothing — it was never on. Frontend previews are build-flag-gated identically.
- **Route additions** are revertible pre-migration; the guard tests force honesty about route deltas in **both** directions, so a partial revert must adjust the guard back down.

## 11. Final founder decision checklist

1. **Approve/adjust the A-list (Waves 1–2)** — the only near-term action: RCVS pack, solicitor pack, decision/validation/spec/safety-gate docs, then pytest + HTTPS-webhook hardening.
2. **Decide** whether to author the canonical **M6.12-adjacency addendum** now (unlocks Wave 3) or hold.
3. **Confirm C-status** for M5.8, M6-S, the M6.13 shell code, the OpenAI adapter, and frontend F2–F8.
4. **Confirm D-status** for M4.6 pending the RCVS/VATA final output.
5. **Treat the frontend as a separate-repo track** (`anchor-portal`, verified tip `80e3fb7`, `NEXT_PUBLIC_ANCHOR_INTERNAL_PREVIEW` off): schedule its visual review and require backend contract acceptance before any frontend harvest; nothing frontend touches this repo.
6. **Send the solicitor pack** (first tranche: Q1–Q2, Q9–Q11, Q19, Q39) — it gates most of the held list.
7. **Schedule the frontend visual review** (gates Group 9).
8. **Confirm** no push/PR/merge/cherry-pick occurs until each wave is individually instructed.

---

*Memo only. Nothing was harvested, cherry-picked, merged, pushed, or deployed in its preparation. All hashes verified against `origin` after `git fetch --prune` on 7 July 2026 — backend `fable/roadmap-completion-experiment` @ `34d8f00`, frontend `anchor-portal` `fable/frontend-roadmap-completion-experiment` @ `80e3fb7`, RCVS docs `fa15c13`.*
