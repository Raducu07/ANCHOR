# Control-to-Evidence Matrix — 2026-06-21

> **Internal documentation-only evidence consolidation artefact.** This matrix maps existing ANCHOR doctrine, product boundaries, operational controls, legal/commercial gates, and trust evidence to the artefacts that already exist in this repository. It **creates no new authority** and **changes no product behaviour**.
>
> **Not** legal advice. **Not** final legal terms. **Not** commercial release. **Not** paid pilot approval. **Not** real clinic data approval. **Not** customer onboarding approval. **Not** live generation approval. **Not** billing / Stripe approval. **Not** connector approval. **Not** compliance / certification / regulator approval.
>
> **This artefact does not claim ANCHOR uses Vanta and does not claim ANCHOR is "Vanta-equivalent."** A read-only trust/compliance framing audit used common SaaS trust-platform patterns only as a generic structural lens; no third-party platform is used, integrated, or endorsed, and no compliance posture is implied.
>
> ANCHOR is **aligned, not compliant** — not RCVS-approved, not regulator-endorsed, not certified, no protection from enforcement. Metadata-only by default. Live Workspace generation **remains production-off**.

---

## 1. Title

**Control-to-Evidence Matrix — 2026-06-21**

A single internal index that consolidates evidence currently distributed across `docs/commercial/`, `docs/operations/`, `docs/operations/security_audits/`, and (by reference) the `anchor-portal` frontend repository.

## 2. Status

- Internal documentation-only evidence consolidation artefact.
- **Not** legal advice.
- **Not** final legal terms.
- **Not** commercial release.
- **Not** paid pilot approval.
- **Not** real clinic data approval.
- **Not** customer onboarding approval.
- **Not** live generation approval.
- **Not** billing / Stripe approval.
- **Not** connector approval.
- **Not** compliance / certification / regulator approval.
- **Does not** claim ANCHOR uses Vanta or is Vanta-equivalent.

Nothing in this matrix is solicitor-reviewed or solicitor-approved. The founder remains the decision-maker on commercial and product risk; this artefact only makes the existing evidence easier to read.

## 3. Purpose

This matrix consolidates existing evidence so that a founder, solicitor, security reviewer, or future procurement reviewer can see, in one place, for each control or doctrine point:

- the **control / doctrine point**;
- the **evidence artefact(s)** that already record it;
- the **current status**;
- the **remaining caveat or gate**.

It exists because the underlying evidence is strong but distributed across many files. It is a **map of what already exists** — it **creates no new authority** and **does not change product behaviour, doctrine, or status**. It does not finalise any legal document, unlock any gate, or make any external claim.

## 4. Scope

- **Internal evidence map only.**
- Covers **backend operational evidence**, **commercial / legal preparation evidence**, **frontend / public evidence by reference**, and **hard-stop evidence**.
- Does **not** create public claims, customer-facing terms, or marketing copy.
- Does **not** duplicate doctrine; doctrine lives in the operative canon (`docs/canonical/` — Roadmap v2.6, Readiness Map v1.1, Decision Memo Addendum v1.3) and in `CLAUDE.md`.
- Frontend / public facts are recorded in the `anchor-portal` repository and are referenced here only; this backend / canonical operations repo did not change them.

## 5. Matrix methodology

The matrix uses five columns:

- **Control / doctrine point** — the doctrine line, product boundary, operational control, legal/commercial gate, or trust-evidence point being tracked.
- **Evidence artefact(s)** — the existing file(s) (or cross-referenced frontend evidence) that record the control. Paths are relative to this file's directory unless otherwise noted.
- **Current status** — an honest statement of what exists today. "Evidence exists" means internal evidence exists, **not** external approval and **not** a security / compliance guarantee.
- **Remaining caveat / gate** — what is still open, still gated, or must not be over-read from the evidence.
- **Review value** — why a founder / solicitor / security / procurement reviewer would look at this row.

Status vocabulary is deliberately conservative: *Evidence exists*, *Outline only (pre-legal review)*, *Production-off / gated*, *Blocked (hard stop)*, *By reference (frontend)*. No row asserts compliance, certification, approval, or guarantee.

## 6. Control-to-evidence matrix

### A. Product and clinical boundary

| Control / doctrine point | Evidence artefact(s) | Current status | Remaining caveat / gate | Review value |
|---|---|---|---|---|
| ANCHOR is not diagnostic / prescribing / treatment-planning / autonomous clinical decision-making AI | `2026-06-21_final_internal_rc_signoff_note.md §3`; `../../commercial/2026-06-21_solicitor_external_review_handoff_pack_v2.md §5`; `../../commercial/2026-06-08_legal_commercial_pack_outline.md §2`; `CLAUDE.md` doctrine | Evidence exists; stated consistently across RC notes and commercial outlines | Boundary must be preserved in every future surface; not solicitor-reviewed as external copy | Clinical / product boundary confirmation |
| ANCHOR is not clinical decision-support software, ambient scribe, EHR / PMS, GPAI provider, or replacement for veterinary judgement | `2026-06-20_founder_rc_review_decision_note.md §3`; `../../commercial/2026-06-08_acceptable_use_policy_outline.md §3`; `../../commercial/2026-06-08_privacy_data_boundary_outline.md §2` | Evidence exists; downstream-integrator (not GPAI) position stated | Must remain stated; AUP / Pilot Agreement remain outline-only | Product-category and regulatory-scope clarity |
| Receipts do not prove clinical correctness, patient safety, staff competence, or clinical safety | `../../commercial/2026-06-21_solicitor_external_review_handoff_pack_v2.md §12`; `../../commercial/2026-06-08_acceptable_use_policy_outline.md §16`; `2026-06-16_rc_coherence_closure.md` | Evidence exists; receipt non-claims stated | Receipt-evidence wording must stay aligned-not-compliant on any clinic-facing surface | Prevents over-reading of governance receipts |

### B. Internal RC / release authority

| Control / doctrine point | Evidence artefact(s) | Current status | Remaining caveat / gate | Review value |
|---|---|---|---|---|
| Final internal RC sign-off is controlled founder / internal review and demo / test-data demonstration only | `2026-06-21_final_internal_rc_signoff_note.md §2`, `§8`; `2026-06-20_founder_rc_review_decision_note.md §2` | Evidence exists (`00fd492`, `576c216`) | Internal milestone only; must never be surfaced externally as approval/release | Confirms the precise, limited meaning of "sign-off" |
| No commercial release | `2026-06-21_final_internal_rc_signoff_note.md §9`; `2026-06-20_rc_signoff_readiness_checklist.md §8` | Blocked (hard stop) | Remains blocked until a future dated approval artefact unlocks it | Prevents accidental commercial-release inference |
| No paid pilot | `2026-06-21_final_internal_rc_signoff_note.md §9`–`§10`; `../../commercial/2026-06-08_commercial_legal_readiness_checkpoint.md §6` | Blocked (hard stop) | Requires solicitor-reviewed pack + founder approval | Gate confirmation for commercial reviewer |
| No customer onboarding | `2026-06-21_final_internal_rc_signoff_note.md §9`; `../../commercial/2026-06-08_personal_data_data_flow_inventory.md §8` | Blocked (hard stop) | Requires DPA + Privacy Notice + AUP + Pilot Agreement (even for synthetic-content + real staff accounts) | Onboarding-permission clarity |
| No real clinic data | `2026-06-21_final_internal_rc_signoff_note.md §9`; `../../commercial/2026-06-08_dpa_outline.md §21` | Blocked (hard stop) | Requires DPA + privacy/data-boundary review + founder approval | Data-permission clarity |

### C. Data boundary

| Control / doctrine point | Evidence artefact(s) | Current status | Remaining caveat / gate | Review value |
|---|---|---|---|---|
| Metadata-only clinic-governance accountability by default | `env.md §9`–`§10`; `../../commercial/2026-06-08_privacy_data_boundary_outline.md §6`; `CLAUDE.md` doctrine | Evidence exists; metadata-only posture documented | Engineering doctrine; not a legal guarantee | Core data-boundary posture |
| Metadata-only does not mean no personal data | `../../commercial/2026-06-08_personal_data_data_flow_inventory.md §2`, `§7`; `../../commercial/2026-06-21_solicitor_external_review_handoff_pack_v2.md §7` | Evidence exists; central correction recorded | Solicitor must confirm controller/processor role **by surface** | The key data-protection nuance for legal review |
| Real clinic / client / patient data blocked | `../../commercial/2026-06-08_privacy_data_boundary_outline.md §16`, `§20`; `../../commercial/2026-06-08_personal_data_data_flow_inventory.md §14` | Blocked (hard stop) | Prohibited-data list applies until executed DPA/pack | Prevents accidental real-data unlock |
| Public intake vs clinic-governance data boundaries | `intake_retention.md §2`; `env.md §10`; `../../commercial/2026-06-08_privacy_data_boundary_outline.md §12` | Evidence exists; public intake bounded + retention runbook | Public-intake Privacy Notice still required; bounded today via runbook | Distinguishes pre-clinic marketing PII from clinic data |
| Staff / user metadata as possible personal data | `../../commercial/2026-06-08_personal_data_data_flow_inventory.md §3`–`§6`; `../../commercial/2026-06-08_dpa_outline.md §5`–`§6` | Evidence exists; staff-attributable metadata flagged as personal data | DPA / Privacy Notice wording for staff/CPD records pending solicitor review | Surfaces personal-data scope before clinical data |

### D. AI-provider and live-generation boundary

| Control / doctrine point | Evidence artefact(s) | Current status | Remaining caveat / gate | Review value |
|---|---|---|---|---|
| Live Workspace generation remains production-off | `env.md §9`, `§14`; `../../commercial/2026-06-08_privacy_data_boundary_outline.md §7`; `2026-06-21_final_internal_rc_signoff_note.md §6` | Production-off / gated | Stays off until 2A-C.5E local/staging safety gate + hard-refusal boundary proven on live path | Single most consequential operational flag |
| Current live-generation path is Anthropic-only where developed | `env.md §9`; `../../commercial/2026-06-08_personal_data_data_flow_inventory.md §4` (Assistant row) | Evidence exists; code path present, not enabled for production real clinic use | Present-tense provider-neutrality **not** claimed | Provider-posture honesty |
| Anthropic production subprocessor activation blocked until legal/subprocessor approval + live-generation safety gate | `../../commercial/2026-06-08_dpa_outline.md §9`, `§17`; `../../commercial/2026-06-21_solicitor_external_review_handoff_pack_v2.md §8` | Blocked (hard stop) | Anthropic becomes a subprocessor the moment live generation is enabled; DPA/sub-processor/privacy/pilot/AUP/onboarding must update first | Subprocessor-trigger control |
| No provider-neutral production-operation claim | `env.md §9`; `../../commercial/2026-06-08_privacy_data_boundary_outline.md §14` | Evidence exists; "architected for vendor-neutrality / vendor-neutral over time" framing only | Do not assert present-tense vendor-neutrality / provider-agnostic | Prevents a prohibited capability claim |

### E. Human review and governance workflow

| Control / doctrine point | Evidence artefact(s) | Current status | Remaining caveat / gate | Review value |
|---|---|---|---|---|
| Human review before operational use | `../../commercial/2026-06-08_pilot_agreement_outline.md §13`; `../../commercial/2026-06-08_acceptable_use_policy_outline.md §7`; `CLAUDE.md` doctrine | Evidence exists; human-review-mandatory stated | Allocation of review responsibility to clinic remains outline-only | Confirms human-in-the-loop posture |
| Governance receipts / receipt-backed review | `2026-06-16_rc_coherence_closure.md`; `../../commercial/2026-06-08_personal_data_data_flow_inventory.md §4` (governance rows) | Evidence exists; metadata-only receipts + Trust Pack aggregate sourced from real counts | Receipts are governance evidence, not clinical correctness certificates | Confirms accountability trail |
| Policy traceability | `../../commercial/2026-06-08_privacy_data_boundary_outline.md §3` (policies/attestations zone); `../../commercial/2026-06-08_personal_data_data_flow_inventory.md §4` | Evidence exists; policy version + attestation metadata | Content-hash / version coherence is an RC-hardening watch item | Policy-evidence integrity |
| Review / handoff accountability | `incident_response.md §5`; `../../commercial/2026-06-08_pilot_agreement_outline.md §13` | Evidence exists; reviewer attribution + named-operator discipline | Reviewer attribution is personal data (see C) | Accountability evidence |
| No raw-content archive posture | `env.md §9`; `incident_response.md §2`, `§7.2`; `CLAUDE.md` doctrine | Evidence exists; no raw prompts/outputs/transcripts/clinical content; hashes only | Any future raw-content storage requires a doctrine-level decision | Confirms storage-minimisation posture |

### F. Tenant isolation and access control

| Control / doctrine point | Evidence artefact(s) | Current status | Remaining caveat / gate | Review value |
|---|---|---|---|---|
| Hard multi-tenancy / RLS / FORCE RLS | `env.md §13` (verify-force-rls script); `incident_response.md §8.4`; `../../commercial/2026-06-08_dpa_outline.md §11` | Evidence exists; RLS/FORCE RLS posture + verification script | Technical evidence, not a legal guarantee | Tenant-safety confirmation |
| Protected portal dashboard unauthenticated 401 smoke | `2026-06-08_render_deploy_smoke_cd9d966.md`; `2026-06-08_version_metadata_deploy_smoke_7451357.md`; `2026-06-21_final_internal_rc_signoff_note.md §6` | Evidence exists; `GET /v1/portal/dashboard` → 401 unauthenticated (PASS) | Re-smoke after any app-behaviour deploy | Access-control evidence |
| Admin token / auth hardening | `env.md §3`, `§6`; `incident_response.md §8.5` | Evidence exists; DB-backed admin tokens prod default; env-mode refused in prod | `INVITE_TOKEN_SALT` fail-closed assert is a flagged follow-up (`env.md §16`) | Auth-posture confirmation |
| RBAC / role awareness where documented | `env.md §5` (`ANCHOR_AUTH_STRICT_DB_CHECK`, `ANCHOR_ROLE_ALLOWLIST`); `../../commercial/2026-06-08_personal_data_data_flow_inventory.md §4` (roles row) | Evidence exists; role allow-list + per-request DB re-validation | No periodic **access-review log** yet (see §8) | Role-control evidence |

### G. Operational resilience

| Control / doctrine point | Evidence artefact(s) | Current status | Remaining caveat / gate | Review value |
|---|---|---|---|---|
| Backup / restore evidence | `backup_restore.md`; `2026-06-08_operational_resilience_checkpoint.md` | Evidence exists; restore-to-new drill PASS 2026-06-07 | Cadence applies; second drill recommended; backup retention is Render-controlled | Recoverability evidence |
| Intake retention dry-run | `intake_retention.md §7` (Dry-run 2026-06-07) | Evidence exists; first production dry-run PASS, all counts 0 | Monthly pre-pilot cadence; no destructive prune executed | Data-minimisation evidence |
| Incident-response runbook | `incident_response.md` | Evidence exists; SEV ladder, never-capture list, 11 containment playbooks | Operational evidence only, not a compliance claim | Incident-readiness evidence |
| Tabletop drill evidence | `incident_response.md §16` (Migration-checksum tabletop 2026-06-07 PASS) | Evidence exists; 1 of 6 suggested scenarios complete | Tabletops #2–#6 pending (see §9) | Incident-rehearsal evidence |
| Env / operations documentation | `env.md`; `README.md` (operations index) | Evidence exists; env var reference + operator runbooks | Some CORS/method values hardcoded (`env.md §16`) | Operator-reference baseline |

### H. Dependency / vulnerability / supply-chain evidence

| Control / doctrine point | Evidence artefact(s) | Current status | Remaining caveat / gate | Review value |
|---|---|---|---|---|
| CI pip-audit clean state | `2026-06-07_post_alembic_ci_audit.md` (run #5 vs `de966a9`); `2026-06-08_operational_resilience_checkpoint.md` | Evidence exists; PASS for scanned locked 34-package set | **Absence of known vulnerabilities at scan time, not a security guarantee** | Dependency-hygiene evidence |
| PyJWT and Starlette remediation | `2026-06-07_pyjwt_remediation.md`; `2026-06-07_fastapi_starlette_remediation.md`; `2026-06-07_post_starlette_ci_audit.md` | Evidence exists; both remediated, cleared in CI | Point-in-time remediation | Remediation trail |
| Hashed runtime lockfile | `2026-06-07_lockfile_implementation.md` | Evidence exists; `pip-compile --generate-hashes`, install-time hash verification | Dockerfile explicit `--require-hashes` flag still deferred | Reproducibility evidence |
| Docker base digest pin | `2026-06-07_docker_base_digest_pin.md` | Evidence exists; `python:3.11-slim@sha256:a3ab0b96…49ac0` | Base-image digest refresh cadence is hygiene, not done | Supply-chain pin evidence |
| GitHub Actions SHA pinning | `2026-06-07_github_actions_sha_pin_implementation.md` | Evidence exists; all active-workflow `uses:` refs SHA-pinned | `github-actions` Dependabot config deferred | CI supply-chain evidence |
| Alembic removal | `2026-06-07_alembic_removal.md` | Evidence exists; `alembic`+`mako`+`markupsafe` removed (34 vs 37 pkgs) | n/a | Attack-surface reduction evidence |
| Known ongoing caveat | `2026-06-07_dependency_cve_audit.md` (non-claims); operations `README.md` | Standing caveat recorded | Evidence is **at scan time**, not an ongoing security guarantee; no documented vuln-management SLA yet (see §9) | Honest framing of CVE evidence |

### I. Deployment / change evidence

| Control / doctrine point | Evidence artefact(s) | Current status | Remaining caveat / gate | Review value |
|---|---|---|---|---|
| Render deploy smoke evidence | `2026-06-08_render_deploy_smoke_cd9d966.md`; `2026-06-08_version_metadata_deploy_smoke_7451357.md`; `2026-06-16_rc_coherence_deploy_smoke_6074f1f.md` | Evidence exists; multiple PASS deploy/smoke records | Re-smoke after any app-behaviour deploy | Deployment-verification evidence |
| `/health` 200 | smoke records above; `env.md §13` | Evidence exists; liveness PASS | n/a | Liveness evidence |
| `/v1/version` 200 with non-null `git_sha` after metadata fallback | `2026-06-08_version_metadata_implementation.md`; `2026-06-08_version_metadata_deploy_smoke_7451357.md` | Evidence exists; `git_sha` populated via `GIT_SHA` → `RENDER_GIT_COMMIT` fallback | `build` remains null without `BUILD_ID` (honest) | Revision-observability evidence |
| Protected `/v1/portal/dashboard` 401 | smoke records above | Evidence exists; 401 unauthenticated (PASS) | Re-smoke after behaviour deploys | Access-control-at-deploy evidence |
| Migration checksum discipline | `env.md §11`; `incident_response.md §8.3`, `§16` | Evidence exists; checksum verification on in prod; restore-then-forward doctrine | `=0` is emergency-only; never steady state | Change-integrity evidence |
| Production smoke expectations after behaviour deploys | `env.md §13`; `2026-06-21_final_internal_rc_signoff_note.md §11` | Evidence exists; smoke set documented | Operator-driven; must be run each behaviour deploy | Change-management expectation |

### J. Commercial / legal preparation evidence

| Control / doctrine point | Evidence artefact(s) | Current status | Remaining caveat / gate | Review value |
|---|---|---|---|---|
| Legal / commercial pack outline | `../../commercial/2026-06-08_legal_commercial_pack_outline.md` | Outline only (pre-legal review) | Every required document `Required — not finalised` | Document-set completeness |
| Privacy / data-boundary outline | `../../commercial/2026-06-08_privacy_data_boundary_outline.md` | Outline only (pre-legal review) | Feeds Privacy Notice + DPA | Data-boundary preparation |
| DPA outline | `../../commercial/2026-06-08_dpa_outline.md` | Outline only (pre-legal review) | Controller/processor role solicitor-confirmation required | Processing-structure preparation |
| Pilot Agreement outline | `../../commercial/2026-06-08_pilot_agreement_outline.md` | Outline only (pre-legal review) | Controls clinic access; not drafted as clauses | Pilot-relationship preparation |
| AUP outline | `../../commercial/2026-06-08_acceptable_use_policy_outline.md` | Outline only (pre-legal review) | Enforcement wording solicitor-drafted | Permitted/prohibited-use preparation |
| Personal data / data-flow inventory | `../../commercial/2026-06-08_personal_data_data_flow_inventory.md` | Evidence exists (inventory; pre-legal review) | Not a RoPA / DPIA | Grounds DPA / privacy / sub-processor review |
| Solicitor handoff preparation pack v1 | `../../commercial/2026-06-15_solicitor_handoff_preparation_pack.md` | Evidence exists (index + review brief; internal) | Not solicitor-reviewed | Solicitor-orientation aid |
| Solicitor / external review handoff pack v2 | `../../commercial/2026-06-21_solicitor_external_review_handoff_pack_v2.md` | Evidence exists (orientation pack; internal) | Authorises nothing | Reviewer-facing evidence pack |
| Solicitor review not complete | `2026-06-21_final_internal_rc_signoff_note.md §7`; `../../commercial/2026-06-08_commercial_legal_readiness_checkpoint.md §2` | Blocked (hard stop) | Required before any external use of any commercial document | Legal-status honesty |
| Final customer terms not approved | `2026-06-20_rc_signoff_readiness_checklist.md §7`; `../../commercial/README.md` | Blocked (hard stop) | Requires solicitor draft + founder approval | Prevents finalised-terms inference |

### K. Frontend / public evidence (by reference)

| Control / doctrine point | Evidence artefact(s) | Current status | Remaining caveat / gate | Review value |
|---|---|---|---|---|
| Frontend RC polish checkpoint | `2026-06-20_rc_signoff_readiness_checklist.md §4`–`§5` (refs `anchor-portal` `1c6ba5b`) | By reference (frontend) | Recorded in `anchor-portal`; not changed here | Frontend-state context |
| Public screenshots refreshed | `2026-06-21_final_internal_rc_signoff_note.md §5` (`5cc03f1`, `bbeff48`) | By reference (frontend) | Asset-only; not a release | Public-evidence freshness |
| Stale screenshot gate closed | `2026-06-21_final_internal_rc_signoff_note.md §5` | By reference (frontend) | Public visual mismatch gate closed | Public-consistency evidence |
| Demo / walkthrough QA checkpoint | `2026-06-21_final_internal_rc_signoff_note.md §5` (`78c5524`) | By reference (frontend) | No Critical / High / Medium findings | Demo-readiness evidence |
| Public site visually verified | `2026-06-21_final_internal_rc_signoff_note.md §5` | By reference (frontend) | Founder/operator verification | Public-state confirmation |
| Public screenshots / demo materials are not a legal / commercial release | `2026-06-21_final_internal_rc_signoff_note.md §9`, `§14` | Blocked (hard stop) | Must not be read as commercial release / approval | Prevents release inference from public assets |

### L. Trust Centre / buyer-readiness evidence

| Control / doctrine point | Evidence artefact(s) | Current status | Remaining caveat / gate | Review value |
|---|---|---|---|---|
| Trust Centre and public legal pages informational only | `../../commercial/2026-06-15_solicitor_handoff_preparation_pack.md §10`; `2026-06-15_wording_copy_scan_closure.md` | Evidence exists; public copy scanned (PASS WITH WATCH ITEMS); informational framing | Solicitor must confirm pages can remain public; not external-cleared | Public-copy-safety posture |
| Trust Pack / trust posture evidence | `2026-06-16_rc_coherence_closure.md`; `../../commercial/2026-06-08_privacy_data_boundary_outline.md §11` | Evidence exists; metadata-only / counts-only aggregate | Does not create compliance/certification/approval | Trust-surface integrity |
| Request-access conservative boundary | `../../commercial/2026-06-15_solicitor_handoff_preparation_pack.md §10` | Evidence exists; conservative framing recorded | Whether request-access pages create obligations is a solicitor question | Buyer-intake boundary |
| No support / SLA or procurement obligation claim unless separately agreed | `../../commercial/2026-06-08_pilot_agreement_outline.md §17`; `../../commercial/2026-06-08_legal_commercial_pack_outline.md §3` (Support SLA row) | Evidence exists; founder-operated, best-effort, explicitly not a staffed desk / SLA | No security-questionnaire response bank yet (see §8) | Prevents implied-SLA / obligation claims |

### M. Hard stops and approval gates

| Control / doctrine point | Evidence artefact(s) | Current status | Remaining caveat / gate | Review value |
|---|---|---|---|---|
| Paid pilots blocked | `2026-06-21_final_internal_rc_signoff_note.md §10`; `../../commercial/2026-06-08_commercial_legal_readiness_checkpoint.md §6` | Blocked (hard stop) | Unlock requires future dated approval artefact | Gate register |
| Real clinic data blocked | `../../commercial/2026-06-08_dpa_outline.md §21`; `../../commercial/2026-06-08_privacy_data_boundary_outline.md §20` | Blocked (hard stop) | DPA + privacy review + founder approval | Gate register |
| Live generation blocked | `env.md §14`; `2026-06-21_final_internal_rc_signoff_note.md §10` | Blocked (hard stop) | Safety gate + hard-refusal boundary on live path | Gate register |
| Billing / Stripe blocked | `../../commercial/2026-06-08_pilot_agreement_outline.md §7`; `env.md §9` (no payment provider wired) | Blocked (hard stop) | Subprocessor + DPA/privacy update before activation | Gate register |
| Connectors blocked | `2026-06-21_final_internal_rc_signoff_note.md §10`, `§12` (M6.12 future/gated) | Blocked (hard stop) | Future / gated; founder decision required | Gate register |
| Ambient integrations blocked | `2026-06-21_final_internal_rc_signoff_note.md §10`, `§12` (M6.13 future/gated) | Blocked (hard stop) | Future / gated; founder decision required | Gate register |
| Customer onboarding blocked | `2026-06-21_final_internal_rc_signoff_note.md §9`; `../../commercial/2026-06-08_personal_data_data_flow_inventory.md §8` | Blocked (hard stop) | Full pack + founder approval | Gate register |
| Compliance / certification / regulator approval claims blocked | `env.md §14`; `../../commercial/README.md`; `incident_response.md §6.4` | Blocked (hard stop) | "Aligned, not compliant" is the controlling wording everywhere | Claims-discipline register |

### N. Future framework-readiness discussions only

> The rows below are **readiness-discussion mapping only**. They record which existing artefacts *could later support a readiness discussion* under a given framework. **No framework readiness is achieved, asserted, or claimed.** No compliance claim is made.

| Control / doctrine point | Evidence artefact(s) | Current status | Remaining caveat / gate | Review value |
|---|---|---|---|---|
| Cyber Essentials — readiness discussion only | §H rows (lockfile, digest pin, Actions SHA); `env.md` (secret discipline, secure config) | Discussion-support only | No assessment undertaken; no claim | Future readiness conversation |
| ISO 27001 — readiness discussion only | §F, §G, §H, §I rows (access control, incident, backup, change mgmt, supplier evidence) | Discussion-support only | No certification; no claim | Future readiness conversation |
| SOC 2 — readiness discussion only | §F, §G, §I rows (security / availability / confidentiality controls + audit logging + RLS) | Discussion-support only | No attestation; no claim | Future readiness conversation |
| UK GDPR / DPA 2018 — solicitor review only | §C, §J rows (data-flow inventory, DPA outline, privacy boundary, retention runbook) | Solicitor-review-input only | Not legal advice; controller/processor role unconfirmed | Future legal review input |
| ISO 42001 / NIST AI RMF-style — future mapping only | §A, §D, §E rows (AI governance boundary, metadata-only, human-review, gated hard-refusal harness, receipts) | Future-mapping only | No AI-management-system claim | Future AI-governance mapping |
| EU AI Act — conditional / future-readiness only | Readiness Map v1.1 §4 (canonical); Article 4 as readiness theme | Conditional / future only | Regulation (EU) 2024/1689; Article 113 for dates; UK applicability depends on EU nexus / legal analysis; amendment watch | Future conditional-readiness framing |
| No compliance claim | this entire section + §2 status block | Standing caveat | None of §N asserts compliance, certification, or approval | Claims-discipline guard |

## 7. Summary of strengths

ANCHOR has strong, consistent evidence discipline for:

- **Claims boundaries** — "aligned, not compliant" is carried across operations, commercial, and RC artefacts; prohibited-claim terms appear in negated form only.
- **Hard stops** — paid pilot, real clinic data, live generation, billing, connectors, and compliance/approval claims are blocked consistently across every artefact.
- **Metadata-only-aware data framing** — the data-flow inventory records the key nuance that metadata-only does not mean no personal data.
- **Operational resilience** — backup/restore drill, intake-retention dry-run, incident-response runbook, and a first tabletop drill all have dated evidence.
- **Dependency / security evidence** — CI pip-audit PASS for the scanned locked set, PyJWT/Starlette remediation, hashed lockfile, Docker digest pin, Actions SHA pinning, Alembic removal.
- **Legal / commercial preparation** — a complete outline spine plus a solicitor handoff pack v1 and external review handoff pack v2.
- **Frontend / public evidence** — RC polish checkpoint, refreshed screenshots, closed visual-mismatch gate, demo/walkthrough QA (all recorded in `anchor-portal`, referenced here).

## 8. Consolidation gaps still remaining

This matrix is an **index**, not a certification or compliance artefact. It does **not** create:

- a formal **risk register** (risk / likelihood / impact / mitigation / owner) — still not created;
- a standalone **subprocessor / vendor register** — still distributed across privacy / DPA / data-flow outlines;
- a consolidated **asset / data-store inventory** — still not consolidated;
- an **access-review log** (periodic who-has-access attestation) — still not created;
- a **security-questionnaire response bank** — still not created;
- a formal **policy register** (policy / owner / version / review-state) — still not created.

This matrix is a map of existing evidence; it is **not** a certification, attestation, audit opinion, or compliance artefact, and it does not substitute for solicitor review.

## 9. Recommended next optional artefacts

In rough order of review value (all internal, documentation-only, authorising nothing):

1. **Legal / commercial document register + hard-stop / approval-gate register** — one table of doc / status / owner / review-state, plus a canonical home for the hard stops and gates currently repeated across files.
2. **Subprocessor / vendor register** — single source of truth for DPA Schedule 5 and any future trust questionnaire.
3. **Formal risk register** — distinct from the hard-stop lists, with owner and mitigation.
4. **Asset / data-store inventory** — consolidated from `env.md` + the data-flow inventory.
5. **Access-review log** — periodic attestation that admin / clinic access is current.
6. **Security-questionnaire response bank** — internal draft answers to common SIG/CAIQ-style questions (no publication).
7. **Vulnerability-management cadence note** — documents an ongoing scan/triage cadence (CVE evidence is currently point-in-time).
8. **Additional incident tabletop drills** — scenarios #2–#6 from `incident_response.md §13.2`.

## 10. Prohibited inferences

Reviewers must **not** infer any of the following from this matrix or from the evidence it indexes:

- that ANCHOR uses Vanta;
- that ANCHOR is "Vanta-equivalent";
- solicitor approval;
- finalised legal terms;
- compliance;
- certification;
- RCVS approval;
- regulator endorsement;
- GDPR compliance;
- SOC 2 / ISO readiness achieved;
- paid pilot permission;
- real-data permission;
- customer onboarding permission;
- live-generation approval;
- clinical safety / correctness / competence proof.

## 11. Final conclusion

- This matrix **improves internal evidence readability and future review readiness** by consolidating existing artefacts into a single index.
- It **does not change ANCHOR's product status, doctrine, or behaviour**, and it grants no authority that did not already exist.
- ANCHOR remains **internally signed off only for controlled founder / internal review and demo / test-data demonstration**.
- The **commercial, legal, real-data, billing, connector, and live-generation gates remain closed**, and all hard stops remain in force unless and until a future dated approval artefact explicitly unlocks them.

## 12. Cross-references

- [`2026-06-21_final_internal_rc_signoff_note.md`](./2026-06-21_final_internal_rc_signoff_note.md) — final internal RC sign-off note (`00fd492`).
- [`2026-06-20_founder_rc_review_decision_note.md`](./2026-06-20_founder_rc_review_decision_note.md) — founder RC review decision note (`576c216`).
- [`2026-06-20_rc_signoff_readiness_checklist.md`](./2026-06-20_rc_signoff_readiness_checklist.md) — RC sign-off readiness checklist (`6f0ca99`).
- [`2026-06-16_2a_d_current_status_checkpoint.md`](./2026-06-16_2a_d_current_status_checkpoint.md) — 2A-D current status checkpoint.
- [`2026-06-16_rc_coherence_closure.md`](./2026-06-16_rc_coherence_closure.md) — RC coherence lane closure.
- [`2026-06-08_operational_resilience_checkpoint.md`](./2026-06-08_operational_resilience_checkpoint.md) — operational resilience checkpoint.
- [`../incident_response.md`](../incident_response.md), [`../intake_retention.md`](../intake_retention.md), [`../env.md`](../env.md) — operations runbooks / reference.
- [`../../commercial/README.md`](../../commercial/README.md) — commercial / legal readiness directory index.
- [`../../commercial/2026-06-21_solicitor_external_review_handoff_pack_v2.md`](../../commercial/2026-06-21_solicitor_external_review_handoff_pack_v2.md) — solicitor / external review handoff pack v2.
- Operative canon: `../../canonical/` (Roadmap v2.6, Readiness Map v1.1, Decision Memo Addendum v1.3). For any clinic-facing wording, check Readiness Map v1.1 §2 first.
