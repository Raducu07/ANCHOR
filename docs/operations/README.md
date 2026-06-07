# ANCHOR Operations Docs

Operator-facing runbooks and references for the ANCHOR backend.

These documents do **not** grant compliance, certification, RCVS approval, regulator endorsement, or guaranteed protection. ANCHOR is aligned to RCVS principles and EU AI Act articles where it can be; it is not compliant with them.

## Current

- [`env.md`](./env.md) — Backend environment variable reference. Categories (required / functional / tuning / bootstrap / danger), startup fail-closed behaviour, smoke commands, stop conditions.
- [`backup_restore.md`](./backup_restore.md) — Render Postgres restore-to-new drill runbook. Inventory checklist, restore procedure, drill env table, smoke set, migration-checksum evidence, teardown, failure-mode playbook, cadence, and a per-drill evidence template. Drills are operator-driven; the runbook is in place, the first restore-to-new drill was executed on 2026-06-07 and passed; future drills follow the cadence in the runbook.
- [`intake_retention.md`](./intake_retention.md) — Operator runbook for `POST /v1/admin/intake/prune`. Data boundary, endpoint contract, recommended retention defaults (90 / 365 / 365), pre-run checklist, dry-run procedure, dry-run evidence template, destructive procedure (founder-approval-gated, confirm literal `I-UNDERSTAND`), destructive evidence template, failure-mode playbook, cadence, first-run plan. First production dry-run executed on 2026-06-07 and passed; no destructive prune has been executed.
- [`incident_response.md`](./incident_response.md) — Operator runbook for operational, security, privacy, governance, availability, migration, and AI-governance incidents on the ANCHOR backend. Severity ladder (SEV-0 through SEV-3), first-15-minutes checklist, role/responsibility split (solo-operator and future multi-operator), communication rules with safe / avoid wording lists, evidence capture rules (with explicit never-capture list), eleven per-class containment playbooks, recovery checklist, post-incident review template, evidence log template, closure criteria, cadence and tabletop scenarios. Runbook is written; **no real incident has been simulated or executed**. **First tabletop drill completed on 2026-06-07** using the migration checksum mismatch scenario (`incident_response.md §16`); result: PASS. Remaining tabletop scenarios pending.

- [`security_audits/`](./security_audits/) — Append-only directory of dated dependency / CVE / security audit artefacts. First artefact created 2026-06-07 — see [`2026-06-07_dependency_cve_audit.md`](./security_audits/2026-06-07_dependency_cve_audit.md). That audit recorded process findings and an **INCONCLUSIVE** CVE scan (the `pip-audit` tool was not available locally at the time and was not auto-installed). Second artefact created 2026-06-07 — see [`2026-06-07_pip_audit_scan.md`](./security_audits/2026-06-07_pip_audit_scan.md). The follow-up scan installed `pip-audit` as a user-level tool and attempted both the PyPI advisory and OSV sources; both attempts failed with a workstation-side TLS certificate verification error, so the result is **INCONCLUSIVE (new reason: TLS path)** rather than PASS or FINDINGS. Third artefact created 2026-06-07 — see [`2026-06-07_pip_audit_ci_workflow_note.md`](./security_audits/2026-06-07_pip_audit_ci_workflow_note.md). That implementation note records the creation of `.github/workflows/dependency-audit.yml` as the reproducible execution path: `workflow_dispatch` only (not scheduled, not push-blocking), Python `3.11` matching the Render runtime base image, read-only permissions, no secrets referenced, no project dependencies installed. **No CVE scan result yet exists** — the workflow must be triggered manually from the Actions tab and the result captured in a new dated artefact. The next recommended operator action is that manual run. This directory does not claim ANCHOR is secure, compliant, certified, or vulnerability-free.

## Planned

To be added as the 2A-D.2 operational resilience track lands. None of these exist yet — they are listed here so the folder's shape is predictable.

*(All Patch 7–10B docs are now Current; the next planned operational artefact is the Patch 11B follow-up — see the dependency/CVE audit for the recommended split.)*

## Doctrine pointers

For non-operational questions, the operative canon lives elsewhere:

- `../canonical/ANCHOR_Roadmap_v2_6_June_2026_CORRECTED.md`
- `../canonical/ANCHOR_RCVS_EU_AI_Act_Readiness_Map_v1_1_COMPLETE.md`
- `../canonical/ANCHOR_Phase_2A_Build_Order_Decision_Memo_Addendum_v1_3.md`
