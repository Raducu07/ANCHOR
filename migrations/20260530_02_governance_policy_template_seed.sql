-- ============================================================
-- 20260530_02_governance_policy_template_seed.sql
--
-- Phase 2A-2.1 - initial v1 Governance Policy Library template seed.
--
-- Four ANCHOR-curated organisational AI-use policy templates.
-- Metadata only:
--   * Each row carries title/summary/category/role_applicability/
--     jurisdiction_tags/source_basis as catalogue metadata.
--   * `content_reference` points at markdown shipped in
--     docs/governance/policies/<slug>-<version>.md.
--   * `content_sha256` is intentionally left NULL in this slice. A
--     follow-up verification utility / test will compute and reconcile
--     hashes from the on-disk markdown stubs (deferred per 2A-2.1
--     spec - schema must not block on hash automation).
--   * `role_applicability` is AUDIENCE METADATA, not access-control.
--
-- Wording: catalogue copy is neutral and makes no accreditation /
-- compliance / certification / RCVS approval claim (Readiness Map
-- Section 2 / Phase 2A-1 wording controls carry over).
--
-- Idempotent: ON CONFLICT (template_slug) DO NOTHING. This targets the
-- explicit UNIQUE constraint on policy_templates.template_slug created
-- in 20260530_01 - NOT a partial index, so no production
-- InvalidColumnReference risk (cf. M6.10.1B / TD-BE).
-- ============================================================

BEGIN;

INSERT INTO public.policy_templates (
    template_slug,
    template_version,
    title,
    summary,
    category,
    role_applicability,
    jurisdiction_tags,
    source_basis,
    content_reference,
    content_sha256,
    is_active
) VALUES (
    'ai_use_policy',
    '1.0.0',
    'AI Use Policy for Veterinary Teams',
    'Practice-wide template describing how AI may be used in clinic workflows, the boundaries of acceptable use, and where human review is required.',
    'ai_use_policy',
    ARRAY['vet','nurse','practice_manager','admin','reception','locum'],
    ARRAY['UK_RCVS','EU_AI_ACT_READINESS'],
    ARRAY['RCVS_AI_literacy','RCVS_accountability','EU_AI_Act_Article_4'],
    'docs/governance/policies/ai_use_policy-1.0.0.md',
    NULL,
    true
)
ON CONFLICT (template_slug) DO NOTHING;

INSERT INTO public.policy_templates (
    template_slug,
    template_version,
    title,
    summary,
    category,
    role_applicability,
    jurisdiction_tags,
    source_basis,
    content_reference,
    content_sha256,
    is_active
) VALUES (
    'client_disclosure_when_ai_assists',
    '1.0.0',
    'Client Disclosure When AI Assists',
    'Template for transparent client communication when AI has assisted in producing materials such as discharge notes, summaries, or client-facing text.',
    'transparency',
    ARRAY['vet','nurse','practice_manager','admin','reception','locum'],
    ARRAY['UK_RCVS','EU_AI_ACT_READINESS'],
    ARRAY['RCVS_transparency','EU_AI_Act_Article_50'],
    'docs/governance/policies/client_disclosure_when_ai_assists-1.0.0.md',
    NULL,
    true
)
ON CONFLICT (template_slug) DO NOTHING;

INSERT INTO public.policy_templates (
    template_slug,
    template_version,
    title,
    summary,
    category,
    role_applicability,
    jurisdiction_tags,
    source_basis,
    content_reference,
    content_sha256,
    is_active
) VALUES (
    'incident_and_near_miss_reporting_for_ai',
    '1.0.0',
    'Incident and Near-Miss Reporting for AI Use',
    'Template covering how clinic staff should record and report AI-related incidents and near-misses for internal review and continuous improvement.',
    'incident_near_miss',
    ARRAY['vet','nurse','practice_manager','admin','reception','locum'],
    ARRAY['UK_RCVS','EU_AI_ACT_READINESS'],
    ARRAY['RCVS_accountability','RCVS_patient_safety','EU_AI_Act_monitoring_readiness'],
    'docs/governance/policies/incident_and_near_miss_reporting_for_ai-1.0.0.md',
    NULL,
    true
)
ON CONFLICT (template_slug) DO NOTHING;

INSERT INTO public.policy_templates (
    template_slug,
    template_version,
    title,
    summary,
    category,
    role_applicability,
    jurisdiction_tags,
    source_basis,
    content_reference,
    content_sha256,
    is_active
) VALUES (
    'data_handling_when_using_ai',
    '1.0.0',
    'Data Handling When Using AI',
    'Template covering what client and patient information may or may not be entered into AI tools, retention, sharing, and confidentiality expectations.',
    'data_handling',
    ARRAY['vet','nurse','practice_manager','admin','reception','locum'],
    ARRAY['UK_RCVS','UK_GDPR_READINESS','EU_AI_ACT_READINESS'],
    ARRAY['RCVS_confidentiality','data_protection_readiness','EU_AI_Act_Article_4'],
    'docs/governance/policies/data_handling_when_using_ai-1.0.0.md',
    NULL,
    true
)
ON CONFLICT (template_slug) DO NOTHING;

COMMIT;
