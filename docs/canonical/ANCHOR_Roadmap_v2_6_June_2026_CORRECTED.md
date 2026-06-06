# ANCHOR

## Official Canonical Roadmap v2.6

Governance, trust, learning, intelligence, and readiness infrastructure for safe AI use in veterinary clinics

*Confidential internal strategy reference | As-built reconciliation | 6 June 2026*

# Version basis

| Field | v2.6 position |
| --- | --- |
| Version basis | Roadmap v2.5 reconciled to as-built per Phase 2A Build-Order Decision Memo Addendum v1.3 (6 June 2026) and the current build tracker. |
| Canonical one-line | ANCHOR is governance, trust, learning, intelligence, and readiness infrastructure for safe AI use in veterinary clinics. |
| Current maturity | Phase 2A regulatory conversion wedge complete (2A-1 through 2A-5) and presentation-hardened (2A-C). Readiness discipline R1–R4 complete. Both honest M6 gaps closed. Now entering Phase 2A-D release-candidate hardening. |
| Active phase | 2A-D.0 canonical documentation reconciliation (this document), then security audit + operational resilience, legal/commercial pack, RC coherence fixes, wording scan, RC sign-off. |
| Build stance | Building proceeds on regulatory and professional-governance conviction. No buyer-conversation gate and no buyer-discovery requirement (Addendum v1.3). |
| Deployment | Backend: Render. Frontend: Vercel. Domain: anchorvet.co.uk. |

## What changed since v2.5 (reconciliation summary)

- Phase 2A-1 through 2A-5 moved from "next" to **Complete**.
- Phase 2A-C Presentation Hardening recorded as **Complete** (2A-C.4 backend Trust Pack polish and 2A-C.5E live Workspace smoke deferred).
- Phase 2A-D Release-Candidate Hardening **added as the active phase**.
- M6.10 and M6.11 moved from Open / Optional to **Complete**.
- Both honest M6 gaps (formal evaluation / golden-test set; why-flagged → Learn linkage) **closed** (via R3 and integration polish).
- Readiness discipline **R1–R4 recorded**.
- M5.6 reframed: buyer conversations removed; building on conviction (Addendum v1.3).
- Live Workspace generation recorded as **Anthropic-coupled and production-off** pending the safety gate.
- M6.12 and M6.13 retained as **gated future** milestones with explicit preconditions (§9).
- M6-S retains a **dedicated section** (§8); Residential reduced to a single pointer line.
- M4.6 recorded as **deferred by decision**.
- EU AI Act wording softened to "from August 2026" with an Article 4 amendment watch (§13; see Readiness Map v1.1).
- Nothing from v2.5 deleted; superseded items are marked, not dropped.

# 1. Non-Negotiable Product Doctrine

These principles govern every milestone. No feature should override them.

| Doctrine | Meaning |
| --- | --- |
| Governance-first | The product exists to make AI use safe, reviewable, institutionally accountable, and operationally governed. |
| Metadata-only by default | Avoid storing raw prompts, outputs, transcripts, clinical content, or identifiable case material unless deliberately designed with appropriate controls. |
| Not clinical decision-making AI | ANCHOR must not become a diagnosis, prescribing, treatment-planning, or autonomous clinical decision engine. |
| Human-review based | AI outputs remain subject to professional judgement and explicit human review before operational use. |
| Receipt-backed | Governed interactions must be explainable through a governance receipt, traceability record, or equivalent metadata trail. |
| Trust-surface oriented | Governance evidence should become visible leadership trust surfaces, not hidden backend logs only. |
| Multi-tenant and privacy-aware | Clinic separation, RLS, FORCE RLS, access control, retention, auditability, and privacy posture remain core infrastructure. |
| Veterinary wedge first | Veterinary clinics remain the first market, proof of value, and design anchor before wider expansion. |
| Standalone now, integrable later | ANCHOR works as a standalone governed workspace now, while remaining structurally ready for external AI, ambient, EHR, and workflow connectors later. |
| Vendor-neutral over time | ANCHOR should govern around many AI tools and vendors, not depend on one AI provider. Present-tense vendor-neutrality must not be claimed while only one provider is wired (see §4). |
| Assistant is governed, not generic | The Assistant must operate under explicit contracts, storage policy, safety boundaries, and ANCHOR governance rules. |
| Aligned, not compliant | ANCHOR positions itself as governance and readiness infrastructure. It evidences responsible AI practice aligned with emerging professional and regulatory expectations. It never claims to make a clinic compliant with any specific regulation, certified by any regulator, or guaranteed against enforcement. |
| Sustainability is governed, not a dashboard widget | Any Sustainability module must follow the same metadata-only, receipt-backed, RLS-enforced doctrine as the core platform. |

# 2. Canonical Milestone State — June 2026

| Ref | Milestone | Status | Interpretation |
| --- | --- | --- | --- |
| M1 | Foundation | Complete | Backend and governance infrastructure established. |
| M2 | Observability / Trust Surface | Complete | Operational trust, metrics, logging, and reviewability established. |
| M3 | Security Hardening | Complete | Multi-tenant credibility, RLS, auth, invite flow, and isolation achieved. |
| M4 | Portal / Workspace Baseline | Complete | Clinic-facing product surfaces exist and are navigable. |
| M4.5 | ANCHOR Learn Baseline | Complete | Learning reinforcement and AI-use guidance baseline visible. |
| M4.6 | Learn Maturity & Enablement | Deferred by decision | Knowledge checks, scenarios, role paths, renewal, dashboards — future. Not pre-RC. |
| M5 | ANCHOR Trust | Complete | Trust surfaces and leadership-facing governance posture established. |
| M5.5 | Visible Product v1 | Complete | Public site, Workspace, Dashboard, Receipts, Trust, Learn, Intelligence, navigation coherent as a v1 product. |
| M5.6 | Pilot Readiness | Reframed | Demo/walkthrough materials built under 2A-C. Buyer-conversation step removed (Addendum v1.3); building on conviction. |
| M5.7 | Assisted Onboarding | Future / post-RC | Manual provisioning, clinic setup, invite acceptance. Gated behind security + legal. |
| M5.8 | Billing and Activation Foundations | Future / post-RC | Pilot pricing, Stripe/payment foundations. Gated behind security + legal. |
| M6.1–M6.9.4 | Governed Assistant Evidence Loop | Complete | Assistant run → traceability → review → receipt → central Receipts → Intelligence → Trust evidence. |
| M6.10 | Assistant Policy Admin Maturity | Complete | Role-safe admin edit controls, policy history UI, audit/readability polish, admin-only gating. |
| M6.11 | Assistant Receipt Data Maturity | Complete | Receipts section polish, backend pagination contract, frontend Load more. |
| M6.12 | Vendor-Neutral Connector Layer | Future / gated | See §9 preconditions. Partly a refactor of the existing Anthropic-coupled live path. |
| M6.13 | Ambient Governance Integration | Future / gated | See §9 preconditions. Highest-sensitivity surface; security/legal + clinical-content boundary spec required first. |
| Phase 2A-0 | RCVS + EU AI Act Readiness Map | Complete | Readiness Map v1 issued; v1.1 as-built reconciliation pending in this cycle. |
| Phase 2A | Regulatory Conversion Wedge | Complete | 2A-1 CPD Literacy, 2A-2 Policy Library + Attestation, 2A-3 Self-Assessment, 2A-4 Client Transparency, 2A-5 Incident/Near-Miss all built. |
| Phase 2A-C | Presentation Hardening / Demo Readiness | Complete | Mojibake/wording scan, demo curation, presentation audit, walkthrough prep, screenshots, founder script. 2A-C.4 and 2A-C.5E deferred. |
| Phase 2A-D | Release-Candidate Hardening | **Active** | Canonical reconciliation, security audit + operational resilience, legal/commercial pack, RC coherence fixes, wording scan, RC sign-off. |
| Readiness discipline | R1–R4 | Complete | R1 Public Copy Audit, R2 Retention/Memory-Consent Note, R3 Evaluation/Golden-Test Registry, R4 Official EU AI Act Source Note. |
| Phase 2B | Commercial Leverage Extensions | Future | Mobile near-miss, Locum governance, Solo Professional SKU, AI Tool Governance Notes, Acquisition/Insurer Packs, Peer Benchmarking. |
| M6-S | Sustainability Governance Module | Designed, schema-reviewed, queued | Dedicated section §8. Schema corrections must be applied and re-validated before any code. |
| Future product | Residential Sustainability Evidence | Future spinout / licensing | Separate product opportunity, outside ANCHOR core. Do not lump with Digital Legacy / Soul Sculpting. |
| Optional | Digital Legacy / Soul Sculpting | Long-range optional | Separate initiative. Not ANCHOR core. |
| M7 | Embedded / Institutional Deployment | Future | Sidecar, panel, EHR/workflow integration, institutional deployment patterns. |
| M8 | Cross-Institution Expansion | Long-range | Beyond veterinary into NHS-adjacent, wider health/care, regulated institutions. |

# 3. Completed and Materially Achieved Milestones

| Milestone | Built state |
| --- | --- |
| M1 – Foundation | FastAPI backend, Postgres persistence, metadata-only governance model, governance event and receipt persistence, policy versioning, admin and operational endpoints. |
| M2 – Observability / Trust Surface | Structured logging, hashed IP/user-agent discipline, governance metrics, trust-state concepts, ops health and timeseries support. |
| M3 – Security Hardening | FORCE RLS, request-scoped tenant context, clinic/user isolation, clinic/admin authentication, invite-based onboarding, tenant-isolation testing. |
| M4 – Portal / Workspace Baseline | Login, dashboard, receipts, governance events, exports, privacy/policy surfaces, trust surfaces, integrated portal shell. |
| M4.5 – Learn Baseline | Learn landing page, microlearning cards, privacy-safe AI-use guidance, why-flagged explainers, learning links from governance/receipts/dashboard. |
| M5 – Trust | Trust profile, governance posture, trust materials, Trust Pack concept, leadership-facing governance narrative. |
| M5.5 – Visible Product v1 | Visible product baseline complete: public site, Workspace, Dashboard, Receipts, Trust, Learn, Intelligence, navigation. |
| M6 – Governed Assistant Evidence Loop | Metadata-only evidence from run to review to receipt to Intelligence and Trust. |
| Phase 2A-1 – CPD-Recordable AI Literacy | Learn CPD schema + seed, endpoints, Trust learning-delta, catalogue/detail/completion/JSON export, Trust posture Learning Evidence tile. |
| Phase 2A-2 – Policy Library + Staff Attestation | Schema + seed templates, Policy Library and Attestation endpoints, Trust delta governance_policy block, admin and staff attest flows. |
| Phase 2A-3 – RCVS Self-Assessment | Schema + seeded template/questions, admin endpoints, Trust delta, admin page, evidence tile, Regulatory Readiness Evidence Closure. |
| Phase 2A-4 – Client-Facing Transparency Layer | Schema + seed, templates/profiles endpoints, publish surface, Trust posture client_transparency block, admin profile and publish/preview UI. |
| Phase 2A-5 – Incident / Near-Miss Logging | Schema, vocabulary + create/list, review/close/void workflow + summary, Trust incident evidence, full UI. |
| Phase 2A-C – Presentation Hardening | Artefact/mojibake/wording scan, demo data curation, presentation audit, frontend Trust Pack sanitisation, Workspace output enrichment, screenshot/walkthrough prep, founder script. |
| Readiness discipline R1–R4 | Public Copy Audit Checklist v1; Retention and Memory-Consent Note v1; Assistant Evaluation / Golden-Test Registry v1; Official EU AI Act Source Note v1. |

# 4. M6 Assistant Track — As-Built Numbering

| Ref | Milestone | Status | Purpose / key deliverables |
| --- | --- | --- | --- |
| M6.1 | Assistant contract / governed mode baseline | Complete | Contracts, governed mode framing, explicit permitted/prohibited use. |
| M6.2 | Frontend/backend payload alignment | Complete | Aligned Assistant run payloads. |
| M6.3 | Traceability / evidence surface | Complete | Recent runs, run detail metadata, no raw content. |
| M6.4 | Human review-state workflow | Complete | Review status, decision, reviewed_at/by metadata. |
| M6.5 | Assistant receipt linkage | Complete | Reviewed runs generate metadata-only receipts. |
| M6.6 | Post-output safety validation | Complete | Output safety gate, output-blocked state, hard clinical boundaries. |
| M6.6.1 | Pydantic warning cleanup | Complete | Protected namespace warnings cleaned. |
| M6.7 | Policy controls / tuning first pass | Complete | Clinic-scoped policy controls, validation profile, policy metadata. |
| M6.7.1 | Policy metadata in traceability/receipts | Complete | Policy version/profile surfaced. |
| M6.8 | Assistant analytics into Intelligence | Complete | Assistant Intelligence summary. |
| M6.8.1 | Frontend lint cleanup | Complete | Lint baseline clean except custom-font warning. |
| M6.9 | Evidence / receipt UX polish | Complete | Copy buttons, hash truncation, reviewer labels, not-chat-history notices. |
| M6.9.1–M6.9.4 | Central Receipts integration; layout polish; receipt-ID lookup; Trust aggregation | Complete | Central Receipts integration and Trust posture Assistant receipt counts. |
| M6.10 | Assistant Policy Admin Maturity | Complete | M6.10.1 role-safe admin edit controls (+ backend audit insert fix); M6.10.2 policy history UI; M6.10.3 change audit/readability; M6.10.4 admin-only gating hardening. |
| M6.11 | Assistant Receipt Data Maturity | Complete | M6.11.1 receipts section polish; M6.11.2 backend pagination contract; M6.11.3 frontend Load more. |
| M6 / 2A integration | Why-flagged → Learn linkage | Complete | Assistant refusal/safety reasons deep-link into Learn cards. |

## Honest M6 gaps — now CLOSED

| Gap | Status | Closure |
| --- | --- | --- |
| Formal evaluation / golden-test set | Closed | R3 — Assistant Evaluation / Golden-Test Registry v1. Maintained regression record; Trust Pack artefact. |
| Why-flagged → Learn linkage | Closed | Reason/safety codes deep-link into the Learn module catalogue created in Phase 2A-1. |

## Safe and prohibited use cases

| Use case | Status | Framing |
| --- | --- | --- |
| Explain a governance receipt | Good | Reinforces transparency and learning. |
| Explain why something was flagged | Good | Why-flagged → Learn linkage now shipped. |
| Rewrite client communication from clinician-confirmed facts | Good with human review | No unsupported clinical claims; output remains transient. |
| Prepare internal summary | Good if source-bound | No invented facts; non-inventive only. |
| Explain clinic AI policy | Good | Policy-aware Assistant behaviour. |
| Diagnose a patient | No – hard refusal | Outside product doctrine. |
| Recommend treatment or prescribing | No – hard refusal | Outside product doctrine. |
| Replace veterinary judgement | No – hard refusal | Explicit non-negotiable boundary. |

**Live generation note.** The live Workspace integration (2A-C.5B / 5C) is built directly on the Anthropic API and is **production-off**. It remains off until the local/staging safety gate (2A-C.5E) passes and the hard-refusal boundary is proven on the live path; the hard-refusal harness ships *with* live LLM calls, never after. Anthropic is a subprocessor the moment live generation is enabled. Until then, ANCHOR is presented as deterministic governed generation only.

# 5. Phase 2A-0 — RCVS + EU AI Act Readiness Map

| Element | v2.6 position |
| --- | --- |
| Status | Complete. Readiness Map v1 issued. Readiness Map v1.1 as-built reconciliation pending in this cycle. |
| Purpose | Map RCVS professional expectations and EU AI Act readiness themes to ANCHOR product surfaces and evidence artefacts. |
| Positioning | Aligned, not compliant. Supports readiness and defensibility; not legal certification. |
| v1.1 reconciliation tasks | Update Phase 2A surface statuses to built; apply the EU AI Act date softening and Article 4 amendment watch (§13); re-audit public copy against §2 wording table. |
| Review cadence | Every six months or after material regulatory change. |
| Owner | Founder / product owner. |

# 6. Phase 2A — Regulatory Conversion Wedge (BUILT)

All Phase 2A features are built. Final ordering followed Memo v1.1 for the original Phase 2A sequence, with Addendum v1.3 now operative where it supersedes buyer-conversation and release-candidate ordering.

| Feature | Status | Built state |
| --- | --- | --- |
| CPD-Recordable AI Literacy | Built (2A-1) | Module catalogue, completion tracking, JSON export, Trust learning-delta, bias-detection module signal. |
| Governance Policy Library | Built (2A-2) | Editable AI-use policy templates; clinic policy drafts/versions; Trust governance_policy block. |
| Staff Attestation Layer | Built (2A-2) | Staff confirm policy understanding; metadata-only attestation evidence; admin status view. |
| RCVS AI Governance Self-Assessment | Built (2A-3) | Templates/questions, assessment instances, submitted report snapshot, evidence closure. |
| Client-Facing Transparency Layer | Built (2A-4) | Disclosure templates/profiles, publish surface, client-safe preview, Trust client_transparency block. |
| Basic Incident / Near-Miss Logging | Built (2A-5) | Incident vocabulary, create/list, review/close/void workflow, Trust incident evidence. |

# 7. Commercial readiness milestones

| Ref | Milestone | Scope |
| --- | --- | --- |
| M5.6 | Pilot Readiness | Walkthrough script, screenshots, demo narrative built under 2A-C. Buyer-conversation step removed (Addendum v1.3); ANCHOR proceeds on regulatory/professional-governance conviction. |
| M5.7 | Assisted Onboarding | Manual provisioning first, clinic creation, invite acceptance, setup token expiry. **Gated behind security audit + legal pack.** |
| M5.8 | Billing and Activation Foundations | Pilot pricing, plan structure, Stripe webhook discipline, active_limited → active_verified. **Gated behind security audit + legal pack.** |

**Standing position.** Commercial-validation conversations were deliberately not used as a gate. ANCHOR proceeds on founder regulatory and professional-governance conviction. Security, operational resilience, and legal readiness remain mandatory gates before paid pilots or real clinic data.

# 8. M6-S Sustainability Governance & Evidence Module

M6-S is designed, schema-reviewed, and queued. It is **not current build** and **not a release-candidate blocker**. It is not a dashboard widget; it extends ANCHOR governance/receipt/trust architecture into clinic-level sustainability evidence, under the same metadata-only, receipt-backed, RLS-enforced doctrine.

| Item | v2.6 status |
| --- | --- |
| Concept and seven-step build sequence | Designed and reviewed. Strategic logic accepted. |
| Schema modifications | Not yet applied. Must be applied **and re-validated against the current post-Phase-2A schema** before any M6-S code. |
| Build timing | Queued behind release-candidate sign-off and commercial validation. |
| Data sensitivity | Processes clinic operational evidence; sits behind the same security/legal gates as any real clinic-data feature. |

## Schema corrections required before M6-S code

These corrections are preserved from v2.5 and must survive into any future M6-S build. Several now have proven precedents in shipped Phase 2A code, so the list is to be **re-checked, not lifted unchanged** — some items may already be satisfied.

- Fix rolling 12-month carbon view: aggregate energy, waste, and footprint separately before joining.
- Add explicit WITH CHECK to RLS policies. *(Now the house standard — shipped across 2A-1 to 2A-5.)*
- Reconcile user table naming with the live clinic_users model. *(May be partly resolved via the Engineering Brief §4.3 role-taxonomy reconciliation.)*
- Replace supplier_display_name with clinic-controlled supplier_label.
- Add amendment/supersession fields for evidence records. *(Precedents now exist: policy versions, client-transparency retire flow, learning-completion void.)*
- Rename sustainability_footprint_estimates to sustainability_workflow_footprint_estimates.
- Add factor provenance table later; v1 may store simple factor source text.

## Gating preconditions for M6-S build

1. Schema corrections applied and re-validated against current schema.
2. Release-candidate sign-off complete.
3. Security audit + operational resilience and legal/commercial pack complete (M6-S handles clinic data).
4. AI-governance core commercially validated.

## Residential Sustainability Evidence

Separate future spinout / licensing opportunity, outside ANCHOR core. Do not lump with Digital Legacy / Soul Sculpting. Not a milestone in the core build sequence.

# 9. Future milestone families

| Ref | Family | Status / scope |
| --- | --- | --- |
| M4.6 | Learn Maturity and Enablement | Deferred by decision. Knowledge checks, scenarios, role-based paths, renewal cycles, leadership reporting, adaptive recommendations. Not pre-RC. |
| M6.12 | Vendor-Neutral Connector Layer | Future / gated. Provider-neutral generation interface, Anthropic + OpenAI adapters, provider selection policy, per-clinic config, cost/latency metadata, fallback routing, consistent output governance validation, metadata-only Trust surfaces. **Preconditions:** local/staging live-generation safety gate passed; hard-refusal harness proven on the live path; security audit + legal/subprocessor coverage complete; production live generation remains off until the safety gate passes. Partly a refactor of the existing Anthropic-coupled live path. May be brought forward only by an explicit founder decision (recorded as a memo addendum) if vendor-neutrality is deemed pre-launch-essential. |
| M6.13 | Ambient Governance Integration | Future / gated. Review-gate around transcript-to-note workflows; ANCHOR remains the governance layer, not the scribe. **Preconditions:** security audit + legal pack complete; clinical-content boundary specification completed; normalised ambient event schema and metadata-only review-gate model defined; no real transcript storage by default; no vendor integration until legal/security review. Buyer-discovery removal (Addendum v1.3) means demand is unvalidated; building requires a deliberate founder decision. |
| M7 | Embedded / Institutional Deployment | Future. Sidecar, embedded panel, institutional deployment patterns. |
| M8 | Cross-Institution Expansion | Long-range. NHS-adjacent, wider health/care, regulated institutions. |

# 10. Clean Master Roadmap

| When | Focus | Detail |
| --- | --- | --- |
| Now | 2A-D.0 Canonical reconciliation | Roadmap v2.6 (this document), Readiness Map v1.1, both CLAUDE.md patched to reference Addendum v1.3, Engineering Brief v1.1 retired as current target. |
| Next | 2A-D.1 Security audit + operational resilience | Auth/JWT, admin token, RLS/FORCE RLS, route protection, RBAC, CORS, rate limiting, export/receipt access limits, dependency + secret scan; backups, tested restore, breach runbook. Mandatory before real clinic data. |
| Next | 2A-D.2 Legal / commercial pack | ToS, Privacy Policy, DPA, subprocessor list (naming Anthropic), AUP, disclaimers, pilot agreement — with solicitor review. Mandatory before paid pilots. |
| Next | 2A-D.3 RC coherence fixes | Trust Pack backend source-of-truth polish (2A-C.4 reclassified should-fix); Workspace ↔ Receipt review-state coherence; "Content hash: None"; incident demo-state cleanup; tech-debt classification (TD-BE-1/2, TD-FE-1/2). |
| Next | 2A-D.4 Final wording / copy scan | Against Readiness Map v1.1 §2 across website, deck, Trust Pack, Learn/CPD, client transparency, social bios, pilot copy, demo script, legal surfaces. |
| Then | 2A-D.5 Release-candidate sign-off | — |
| Then | Paid pilots / onboarding / billing | M5.7, M5.8 after security + legal gates. |
| Later | M6-S Sustainability | After RC sign-off, commercial validation, and schema re-validation. |
| Later | M6.12 / M6.13 platform expansion | Gated future per §9. |
| Long range | M7 / M8 | Embedded/institutional deployment and cross-institution expansion. |

# 11. Strategic Success Gaps

| Gap | Meaning | Roadmap answer |
| --- | --- | --- |
| Assistant safety gap | Assistant must not become an unsafe generic chatbot. | Contracts, policy controls, refusal tests, output safety, receipts, metadata-only evidence (built). |
| Evaluation evidence gap | Testing must be a formal evidence artefact. | Closed — R3 evaluation / golden-test registry. |
| Buyer-legibility gap | Buyers must understand the problem instantly. | Public site, walkthrough script, Trust narrative, Readiness Map, self-assessment (built). Note: Addressed through a conviction-led product story and presentation pack; buyer conversations were deliberately not used as a gate under Addendum v1.3. |
| Regulatory-alignment gap | RCVS/EU-style principles must be demonstrably addressed. | Readiness Map, staff attestation, CPD-recordable AI literacy, policy library (built). |
| Activation gap | First use must be easy for any practice. | Assisted onboarding (M5.7, post-RC), guided first run, policy templates. |
| Economic-proof gap | Value must be visible. | Trust Pack, CPD, near-miss reporting, leadership reports (built/partly built). |
| Deployment-model gap | Direct use works; integrated use must remain structurally possible. | M6.12 connector layer, M6.13 ambient review-gate, M7 embedded modes (gated future). |
| Floor-signal gap | Risk signals happen in clinical reality, not only dashboards. | Incident / near-miss logging (built); mobile capture (Phase 2B). |
| Security/legal gap | Cannot handle real clinic data without it. | 2A-D.1 security audit + operational resilience; 2A-D.2 legal/commercial pack. Mandatory before paid pilots. |

# 12. Metadata-Only Data Model Appendix

All entities are metadata-only by doctrine. Phase 2A entities are now built.

| Feature | Metadata-only entities / linkage | State |
| --- | --- | --- |
| Assistant Foundation | assistant_contracts, assistant_runs, assistant_events, assistant_policy_checks, assistant_storage_decisions, assistant_eval_results | Built |
| Assistant Receipts / Traceability | assistant_trace_events, receipt_assistant_links, assistant_reason_codes, assistant_safety_flags, assistant_run_receipts | Built |
| Assistant Intelligence | Aggregated assistant_runs metadata, review status, receipt counts, refusal/safety code counts, validation profile counts | Built |
| RCVS / EU AI Readiness Map | Document-first (v1, v1.1) | Document artefact |
| CPD Integration (2A-1) | learning_modules, learning_completions, v_cpd_records (view), cpd_exports | Built |
| Governance Policy Library (2A-2) | policy_templates, clinic_policy_drafts, clinic_policy_versions | Built |
| Staff Attestation (2A-2) | policy_attestations, policy_attestation_events, admin_audit_events | Built |
| Self-Assessment (2A-3) | self_assessments, self_assessment_answers, self_assessment_reports linked to trust_pack_artifacts | Built |
| Client Transparency (2A-4) | client_transparency_profiles, client_disclosure_versions | Built |
| Near-Miss Logging (2A-5) | ai_incidents, incident_reviews, incident_actions | Built |
| Sustainability v1 core (M6-S) | sustainability_config, sustainability_energy_readings, sustainability_waste_events, sustainability_reports (+ §8 corrections) | Designed / queued |

# 13. Source notes and non-claims

This roadmap is an internal strategy reference, not legal advice.

**RCVS source basis:** RCVS joint statement on AI in health and care education, 11 February 2026, with the General Chiropractic Council, General Optical Council, General Osteopathic Council, General Pharmaceutical Council, and Health and Care Professions Council.

**EU AI Act source basis:** Regulation (EU) 2024/1689. AI literacy (Article 4) entered into application 2 February 2025. Use "from August 2026" for the supervision/enforcement framework rather than asserting a single day: the Commission's own AI Literacy Q&A carries both "from 3 August 2026 onwards" and "as of 2 August 2026", while the main AI Act page and EUR-Lex Article 113 give 2 August 2026 for full applicability. **Article 4 amendment watch:** the Commission's Digital Omnibus (presented 19 November 2025) proposes shifting the obligation to *promote* AI literacy onto Member States and the Commission rather than enforcing an unspecific obligation on organisations; if adopted this softens the organisational obligation for non-high-risk deployers. Treat the Digital Omnibus as provisional and adoption-status-sensitive. Lean commercial framing on RCVS professional expectations and good-governance conviction. Use readiness/alignment language because timelines and implementing guidance can change. See Readiness Map v1.1 for the full article map.

**Internal source basis:** Roadmap v2.5; Phase 2A Build-Order Decision Memo Addendum v1.3; current build tracker; M6 Assistant evidence loop; readiness discipline R1–R4.

**Do not claim:** RCVS approval, EU AI Act compliance, certification, regulator endorsement, clinical decision support, high-risk AI compliance, present-tense vendor-neutrality, or guaranteed protection from enforcement.

---

*Roadmap v2.6 — 6 June 2026 — as-built reconciliation of v2.5 per Addendum v1.3. Phase 2A complete; 2A-D release-candidate hardening active; M6-S dedicated and queued; M6.12/M6.13 gated future; M4.6 deferred by decision; build on regulatory/professional-governance conviction with no buyer-discovery requirement.*
