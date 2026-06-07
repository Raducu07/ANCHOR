# ANCHOR Operations Docs

Operator-facing runbooks and references for the ANCHOR backend.

These documents do **not** grant compliance, certification, RCVS approval, regulator endorsement, or guaranteed protection. ANCHOR is aligned to RCVS principles and EU AI Act articles where it can be; it is not compliant with them.

## Current

- [`env.md`](./env.md) — Backend environment variable reference. Categories (required / functional / tuning / bootstrap / danger), startup fail-closed behaviour, smoke commands, stop conditions.
- [`backup_restore.md`](./backup_restore.md) — Render Postgres restore-to-new drill runbook. Inventory checklist, restore procedure, drill env table, smoke set, migration-checksum evidence, teardown, failure-mode playbook, cadence, and a per-drill evidence template. Drills are operator-driven; the runbook is in place, the first restore-to-new drill was executed on 2026-06-07 and passed; future drills follow the cadence in the runbook.

## Planned

To be added as the 2A-D.2 operational resilience track lands. None of these exist yet — they are listed here so the folder's shape is predictable.

- `intake_retention.md` — Operator runbook for `POST /v1/admin/intake/prune` (dry-run, confirm-on-destructive, cap, recommended `older_than_days` per kind, evidence capture).
- `incident_response.md` — Severity ladder, contact/escalation flow, first-15-minutes evidence checklist, containment actions by failure class, post-incident review template.
- `security_audits/` — Append-only directory of dated audit / CVE-scan artefacts.

## Doctrine pointers

For non-operational questions, the operative canon lives elsewhere:

- `../canonical/ANCHOR_Roadmap_v2_6_June_2026_CORRECTED.md`
- `../canonical/ANCHOR_RCVS_EU_AI_Act_Readiness_Map_v1_1_COMPLETE.md`
- `../canonical/ANCHOR_Phase_2A_Build_Order_Decision_Memo_Addendum_v1_3.md`
