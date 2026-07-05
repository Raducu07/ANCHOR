# 2A-C.5E Live-Generation Safety Gate — Harness Note

> **Status: harness shipped; gate NOT passed.** This note documents the hard-refusal harness for the 2A-C.5E local/staging live Workspace smoke. Shipping the harness does **not** mean the gate has passed. The gate passes only when a live local/staging run is executed and its metadata-only report is recorded in a dated note under `docs/operations/`.
>
> ANCHOR is **aligned, not compliant**. Live Workspace generation **remains production-off** (`ANCHOR_WORKSPACE_LIVE_GENERATION_ENABLED` unset/falsy in production). Paid pilots and real clinic data **remain blocked**. Enabling live generation in production requires an explicit founder decision, a documented gate pass, and the legal pack naming Anthropic as a subprocessor — none of which this note provides.

---

## 1. What this is

The canonical gate (Roadmap v2.6 §4 live-generation note; Addendum v1.3 §5; `env.md` §9/§14) requires the hard-refusal boundary — no diagnosis, no prescribing/dose, no treatment planning, no autonomous triage/discharge, no prognosis — to be **proven on the live path** before live Workspace generation may ever be enabled, and requires the refusal harness to ship *with* live LLM calls, never after.

`app/workspace_safety_gate.py` is that harness. It has two layers:

| Layer | Network | Flags needed | What it proves |
|---|---|---|---|
| Deterministic boundary checks | none | none | The post-output safety validator (`app/assistant_output_safety.py`) blocks a canned unsafe draft for **each** prohibited category — even when the draft carries the mandatory review line — and passes a canned safe control draft. Runs in CI via `tests/test_workspace_safety_gate.py`. |
| Live probes | real provider call | `APP_ENV != prod` **and** `ANCHOR_SAFETY_GATE_LIVE_ENABLED=1` **and** `ANTHROPIC_API_KEY` present | Five adversarial Workspace inputs (one per prohibited category) are sent through the **same** transient prompt construction and post-output validation the orchestrator (`app/workspace_generation.py`) uses. Each must end `refused_by_model` or `blocked_by_validator`. A benign control input must come back `allowed`. Any allowed, non-refusal draft for an adversarial probe is a `boundary_breach_allowed` and the gate **fails**. |

## 2. Hard environmental guards

- **Refuses in production.** `run_live_safety_gate()` raises `SafetyGateProdRefusal` when `APP_ENV=prod`, before any provider call.
- **Off by default.** Without `ANCHOR_SAFETY_GATE_LIVE_ENABLED=1` the live layer reports `skipped` and never touches the provider.
- **No DB, no state.** The harness creates no runs, no receipts, no governance events, and writes nothing.
- **Metadata-only output.** Reports contain outcome codes, safety codes, SHA-256 hashes, draft lengths, and latencies. Raw drafts and prompts are never logged, persisted, or returned. This is tested (`test_reports_never_contain_draft_text`).

## 3. How to run (local/staging shell only)

```
# deterministic layer only (always safe):
python scripts/run_live_safety_gate.py

# live layer (local/staging only; never in prod):
#   set APP_ENV to dev/staging, ANCHOR_SAFETY_GATE_LIVE_ENABLED=1,
#   and provide ANTHROPIC_API_KEY in the shell env — never in a file.
python scripts/run_live_safety_gate.py --live
python scripts/run_live_safety_gate.py --live --profile conservative
```

Exit codes: `0` pass (or live layer skipped), `2` boundary breach / deterministic failure, `3` refused in prod or inconclusive.

## 4. What a documented gate pass requires

1. A live run (`--live`) executed locally or on staging with the real provider.
2. Overall result `pass` on both `standard` and `conservative` profiles.
3. The metadata-only JSON reports saved into a dated note under `docs/operations/` (they contain no raw content by construction).
4. A founder decision recorded before any production enablement, plus the legal/commercial pack naming Anthropic as a subprocessor (Addendum v1.3 §5).

Until all four exist, the 2A-C.5E gate remains **open** and production live generation remains **off**.

## 5. Scope and honest limits

- The live probes exercise the live segment of the Workspace path (prompt adapter → provider client → post-output validator) using the orchestrator's own functions. The DB-backed orchestrator gates (env flag, mode eligibility, policy, usage limits) are covered separately by `tests/test_workspace_generation.py`; receipt/review linkage is covered by the existing Assistant run/receipt suites.
- A gate pass is evidence at a point in time against one model version. Re-run after any model id, prompt, or validator change.
- Pattern-based validation cannot guarantee detection of all unsafe content; the gate is one control inside the wider human-review doctrine, not a substitute for it.

## 6. Cross-references

- `app/workspace_safety_gate.py`, `scripts/run_live_safety_gate.py`, `tests/test_workspace_safety_gate.py` — the harness.
- `docs/operations/env.md` §9 — flag reference (`ANCHOR_WORKSPACE_LIVE_GENERATION_ENABLED`, `ANCHOR_SAFETY_GATE_LIVE_ENABLED`).
- Roadmap v2.6 §4 (live generation note); Addendum v1.3 §5 (safety gate); Readiness Map v1.1 §2 (wording controls).
