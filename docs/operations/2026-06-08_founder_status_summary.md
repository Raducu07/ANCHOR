# ANCHOR Founder Status Summary â€” 2026-06-08

> **Plain-English orientation note** for the founder, after the recent backend operational-resilience hardening chain. This is **not** an engineering audit. The detailed engineering evidence lives in `docs/operations/security_audits/`; the deep checkpoint is in [`2026-06-08_operational_resilience_checkpoint.md`](./security_audits/2026-06-08_operational_resilience_checkpoint.md). This summary exists so the founder can reread it quickly and stay oriented without rereading the audit trail. Documentation only â€” no code, dependency, deploy, DB, Render, or secret change in this note.

---

## 1. Where ANCHOR stands now

- **Backend operational-resilience hardening has reached a meaningful checkpoint.** The long sequence of dependency, reproducibility, deploy-smoke, and observability patches is complete.
- **Dependency / CVE scanning is PASS** for the post-Alembic 34-package locked scanned dependency set (CI `pip-audit` confirmed no known vulnerabilities found).
- **Runtime dependencies are locked and hash-pinned** â€” every wheel that installs on Render is verified against a recorded SHA256.
- **The Docker base image is digest-pinned**, so upstream can't silently change what we build.
- **GitHub Actions are SHA-pinned** across every active workflow, removing mutable-tag drift in CI.
- **The stale retention workflow was removed.** It had been firing daily against a non-existent endpoint with a real admin bearer; the manual operator runbook is now the single retention control.
- **Alembic / Mako / MarkupSafe were removed** from runtime dependencies; they were dead weight (no imports anywhere).
- **Render deploys and production smoke tests have passed** â€” twice (`cd9d966` after the dependency stack, `7451357` after the observability fix).
- **`/v1/version` now exposes the deployed git SHA in production**, so future smoke checks can confirm what's actually running without having to cross-reference the Render dashboard.
- **Live Workspace generation remains production-off.**
- **Paid pilot / real clinic data is still not authorised.**

---

## 2. What was materially improved

In founder language:

- **Lower dependency risk.** The set of third-party packages we ship is smaller, fully pinned, hash-verified, and CI-audited. Known-vulnerable packages are gone from the dependency CVE scan for this set.
- **Better reproducibility.** Two builds from the same commit will install exactly the same set of packages from exactly the same base image. There is no longer a "well, it might resolve differently next week" risk in our deploy path.
- **Stronger deployment evidence.** We now have a documented chain showing what was built, what was scanned, what was deployed, and what came back from production after the deploy. That chain is the kind of evidence an advisor, pilot conversation, or future external review can actually look at.
- **Cleaner operational posture.** A scheduled workflow that did nothing useful and emitted noise daily has been deleted; the runbooks remain authoritative.
- **Less noisy / contradictory automation.** What runs is what's supposed to run; what runs is documented; what's documented matches what runs.
- **Better production observability.** Production now tells us its own deployed commit when we ask `/v1/version` â€” a small but real upgrade to operational confidence.
- **Better confidence that the backend can be rebuilt and smoked safely.** This is the kind of confidence that matters more for the next conversation about a pilot than for any one feature change.

This is real improvement to the backend's operational posture. It is **not** a security certification, a compliance status, a regulator endorsement, or a green light for paid pilots or real clinic data.

---

## 3. What this does not mean

- **This does not mean ANCHOR is certified or compliant.** ANCHOR is aligned to RCVS principles and EU AI Act articles where it can be; it is not compliant with them, not RCVS-approved, not regulator-endorsed.
- **This does not mean all security risk is gone.** A clean `pip-audit` PASS records the absence of *known* vulnerabilities for the scanned set at the time of scan. It is not a proof of security; it is one important hygiene check.
- **This does not authorise real clinic data.** No clinic data should be onboarded.
- **This does not authorise paid pilots.** No paid pilot should be initiated.
- **This does not enable live Workspace generation.** Live generation remains production-off.
- **This does not make ANCHOR a clinical decision-making AI system.** ANCHOR remains governance, trust, learning, intelligence, and readiness infrastructure for safe AI use in veterinary clinics. Not a diagnostic tool. Not an EHR. Not a replacement for veterinary judgement.

---

## 4. Current hard stop conditions

These are the lines that must not be crossed without an explicit founder decision and matching evidence:

- **No live Workspace generation in production.** Anthropic becomes a subprocessor the moment live generation is enabled; the local/staging safety gate and the hard-refusal harness must pass on the live path first.
- **No real clinic data** in production.
- **No paid pilots.**
- **No compliance / certification / RCVS approval / regulator endorsement claims** in copy, on the site, in pitches, in conversations.
- **No destructive retention outside the approved runbook** â€” dry-run first, founder approval, exact `I-UNDERSTAND` confirm literal, 50 000-row hard cap, evidence template.
- **No bypassing backup, incident-response, or retention procedures** to "save time" â€” the runbooks are the controls.
- **No clinical decision-making AI positioning** in any external surface.

---

## 5. What is still open

### Engineering hygiene â€” optional

- `httpx<2` / Starlette TestClient deprecation warning (persistent one-line warning in tests).
- Explicit Dockerfile `--require-hashes` flag (per-wheel verification is already in effect; the flag only adds refusal of any future un-hashed entry).
- Base-image digest refresh cadence (operational habit, not a code change).
- Dependabot / GitHub Actions SHA refresh workflow (automation for SHA-pin refresh PRs).
- Additional dependency audit cadence (current audits are manual).

None of these is urgent. Each is a small, deliberate cleanup.

### Operational evidence â€” useful

- Second backup/restore drill (first PASS was 2026-06-07).
- Second intake-retention dry-run (first PASS was 2026-06-07; monthly pre-pilot cadence applies).
- Additional incident-response tabletop scenarios (first tabletop was 2026-06-07).
- Continued evidence packaging â€” operator-facing summary of the standing evidence trail.

These build the standing evidence record. They are not gates the engineering side can self-clear; they are habits the operator runs on a cadence.

### Commercial / legal readiness â€” required before pilots

- Pilot agreement.
- DPA (data processing agreement).
- Terms of service.
- VAT / payment flow clarity.
- Legal / commercial pack (per Addendum v1.3).
- Founder decision on pilot timing.

**Until all six are in place, no paid pilot / no real clinic data.** This is the actual gate now â€” the engineering side has done what it can do for the paid-pilot conversation; the next move is non-engineering.

---

## 6. Recommended next move

Recommended order:

1. **Pause engineering briefly.** There is no open CVE, no broken workflow, no observability gap forcing an immediate code change. This is a deliberate pause, not abandonment.
2. **Complete the legal/commercial pack outline** (per Addendum v1.3). This is the highest-leverage work that can actually move the paid-pilot gate. Engineering hygiene alone cannot.
3. **Then choose one** of:
   - one optional engineering hygiene patch (e.g. `httpx<2` cleanup, Dockerfile `--require-hashes` flip);
   - one operational drill (second backup/restore drill, second intake-retention dry-run, an incident-response tabletop);
   - founder / pilot readiness planning (operator-side, not code).

The shift this checkpoint makes possible: **the engineering chain has moved from reactive hardening to deliberate choice**. There is no failing CI, no broken endpoint, no missing evidence trail pushing the next patch onto the operator. The next highest-leverage work is **not another backend patch by default**. The paid-pilot gate is now **more commercial / legal / operational than purely technical**.

---

## 7. Founder-readable one-paragraph summary

ANCHOR's backend operational-resilience work has reached a meaningful checkpoint. The dependency and reproducibility chain has been tightened, audited, deployed, and smoke-tested in production: third-party packages are locked and hash-verified, the Docker base image is digest-pinned, GitHub Actions are SHA-pinned, a stale scheduled workflow has been removed, dead-weight dependencies (Alembic + transitives) have been dropped, and two Render deploys have passed production smoke. The backend can now report its deployed revision through `/v1/version`, which improves future operational confidence and makes future deploy checks self-sufficient without cross-referencing the Render dashboard. However, this does not authorise real clinic data, paid pilots, or compliance claims; it does not enable live Workspace generation in production; and it does not change ANCHOR's positioning â€” ANCHOR remains governance, trust, learning, intelligence, and readiness infrastructure, not clinical decision-making AI. The next major gate is no longer purely engineering; it is **legal / commercial readiness plus continued operational evidence**, and the most useful next move is to pause the engineering surface and pick up the legal / commercial pack work, with engineering hygiene and operational drills available as deliberate follow-ups rather than reactive ones.
