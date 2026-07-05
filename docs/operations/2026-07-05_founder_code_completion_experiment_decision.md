# Founder Decision Record — Code-Completion Experiment Authorisation

> **Status: dated internal decision record. Recorded 5 July 2026.**
>
> This note records a founder decision given directly in-session on 5 July 2026. It is filed under `docs/operations/` because the canonical strategy set under `docs/canonical/` is deliberately untracked in git; promoting this decision into the canonical Decision Memo addendum series (as a successor to Addendum v1.3) remains a founder-authored step and is **not** performed by this note.
>
> ANCHOR is **aligned, not compliant** — not RCVS-approved, not regulator-endorsed, not certified. Live Workspace generation **remains production-off**. Paid pilots and real clinic data **remain blocked**. Live billing **remains off**.

---

## 1. Decision

The founder authorises a **controlled code-completion experiment**: build the remaining ANCHOR roadmap items **code-wise**, as far as safely possible, on the isolated experiment branch `fable/roadmap-completion-experiment` (or clearly named child branches), keeping everything dangerous gated/off by default and preserving ANCHOR doctrine.

**Founder-authorised code-wise scope:**

1. M5.7 Assisted Onboarding
2. M5.8 Billing and Activation Foundations
3. M4.6 Learn Maturity and Enablement
4. M6-S Sustainability Governance Module
5. M6.12 Vendor-Neutral Connector Layer
6. M6.13 Ambient Governance Integration
7. Related frontend roadmap work

## 2. Supersession — narrow and explicit

For **code-completion experimentation on the experiment branch only**, this decision supersedes the prior deferred/gated posture recorded in Roadmap v2.6 (§2, §9), Addendum v1.3 (§7 M4.6 deferral), and backend `CLAUDE.md` for the six milestones listed above.

It does **not** supersede anything else. In particular the following remain **fully gated and unchanged**:

- Public readiness / public launch — **not approved**.
- Paid pilots — **not approved**.
- Real clinic data — **not approved**.
- Production live generation — **not approved**; `ANCHOR_WORKSPACE_LIVE_GENERATION_ENABLED` stays unset/falsy in production; the 2A-C.5E gate remains open until a documented live local/staging run passes.
- Live Stripe / billing / charge capability — **not approved**.
- Compliance claims — **no** RCVS compliance, EU AI Act compliance, GDPR compliance, certification, endorsement, or regulator-approval claims anywhere.
- Merge to `main`, deploy, or push — **not authorised** by this decision; push only on explicit founder instruction.
- Production environment settings — untouched.
- Ambient transcripts / raw clinical content storage — prohibited.

## 3. Branch discipline

- Work continues on `fable/roadmap-completion-experiment` or clearly named child branches.
- Local commits on the experiment branch are used to preserve reviewed slices (Slice 0 of this experiment was reviewed on 5 July 2026: full suite 1,567 passed; app import check OK; safety-gate runner smoke OK including prod-refusal path).
- No merge to `main`/`master`, no deploy, no push without explicit founder instruction.

## 4. Standing doctrine (unchanged)

Metadata-only by default; RLS/FORCE RLS and tenant isolation preserved; auth/admin controls preserved; human review preserved; receipts/traceability preserved; safety/refusal boundaries preserved; aligned-not-compliant wording preserved. New clinic-scoped tables must enable and force RLS with `USING` and `WITH CHECK` policies. Existing migrations are never retroactively edited.

## 5. Cross-references

- `docs/canonical/ANCHOR_Phase_2A_Build_Order_Decision_Memo_Addendum_v1_3.md` — prior operative decision; this note narrows its M4.6/M6.12/M6.13 gating **for branch-local code-completion only**.
- `docs/operations/2026-07-05_2a_c_5e_safety_gate_harness.md` — 2A-C.5E harness note (gate remains open).
- `docs/operations/2026-07-05_fable_roadmap_completion_experiment_log.md` — running slice log for this experiment.
