-- ------------------------------------------------------------
-- 20260531_02_self_assessment_template_seed.sql
--
-- Phase 2A-3.1 - initial v1 RCVS-aligned AI Governance Self-Assessment
-- template + question seed.
--
-- One ANCHOR-curated self-assessment template plus ten questions, one
-- per theme defined in the 20260531_01 schema CHECK constraint.
--
-- Metadata only:
--   * Each row carries title/summary/prompt_text/theme/mappings/
--     evidence_link_hints as catalogue metadata.
--   * `guidance_reference` points at markdown shipped in
--     docs/governance/self_assessment/<slug>-<version>.md.
--   * `rcvs_principle_mappings` and `eu_ai_act_article_mappings` are
--     catalogue audience metadata, NOT legal or regulator-status claims about
--     those principles or articles.
--
-- Wording: catalogue copy is neutral. It makes no accreditation,
-- legal sufficiency,
-- clinical-safety, or guaranteed-outcome claim. Self-assessment is a
-- dated metadata-only governance artefact that supports governance
-- review. Human professional review remains required.
--
-- Question slug stability contract:
--   * The ten question slugs below are STABLE across template
--     versions. Future template bumps (e.g. 1.0.1) MUST reuse these
--     slugs for the same conceptual question so longitudinal Trust
--     deltas remain interpretable. Adding a new conceptual question
--     requires a new slug.
--
-- Idempotent:
--   * The template insert targets the explicit UNIQUE constraint on
--     self_assessment_templates.template_slug
--     (NOT a partial index - safe; no M6.10.1B / TD-BE
--     InvalidColumnReference risk).
--   * Question inserts target the explicit UNIQUE constraint
--     self_assessment_questions_template_slug_unique
--     (NOT a partial index - safe).
-- ------------------------------------------------------------

BEGIN;

-- ------------------------------------------------------------
-- Template
-- ------------------------------------------------------------
INSERT INTO public.self_assessment_templates (
    template_slug,
    template_version,
    title,
    summary,
    rcvs_principle_mappings,
    eu_ai_act_article_mappings,
    is_active
) VALUES (
    'rcvs_ai_governance_self_assessment',
    '1.0.0',
    'RCVS-aligned AI Governance Self-Assessment',
    'Structured self-assessment of a practice''s AI governance posture. Supports governance review and produces a dated metadata-only readiness artefact. Human professional review remains required.',
    ARRAY[
        'RCVS_AI_literacy',
        'RCVS_accountability',
        'RCVS_professional_judgement',
        'RCVS_transparency',
        'RCVS_client_interest'
    ],
    ARRAY[
        'EU_AI_Act_Article_4',
        'EU_AI_Act_Article_14',
        'EU_AI_Act_Article_26',
        'EU_AI_Act_Article_50'
    ],
    true
)
ON CONFLICT (template_slug) DO NOTHING;

-- ------------------------------------------------------------
-- Questions (10) - inserted via SELECT against the template so we
-- resolve template_id without requiring a separate CTE/round-trip.
-- ------------------------------------------------------------

-- Q1
INSERT INTO public.self_assessment_questions (
    template_id, question_slug, question_order, theme,
    prompt_text, guidance_reference, evidence_link_hints,
    rcvs_principle_mappings, eu_ai_act_article_mappings
)
SELECT
    t.template_id,
    'governance_owner_named',
    1,
    'governance_ownership',
    'Is there a named individual responsible for AI-use governance at this practice?',
    'docs/governance/self_assessment/governance_owner_named-1.0.0.md',
    ARRAY['manual_review'],
    ARRAY['RCVS_accountability'],
    ARRAY['EU_AI_Act_Article_26']
FROM public.self_assessment_templates t
WHERE t.template_slug = 'rcvs_ai_governance_self_assessment'
ON CONFLICT ON CONSTRAINT self_assessment_questions_template_slug_unique DO NOTHING;

-- Q2
INSERT INTO public.self_assessment_questions (
    template_id, question_slug, question_order, theme,
    prompt_text, guidance_reference, evidence_link_hints,
    rcvs_principle_mappings, eu_ai_act_article_mappings
)
SELECT
    t.template_id,
    'ai_use_policy_active',
    2,
    'policy_availability',
    'Is an AI-use policy currently active for this clinic?',
    'docs/governance/self_assessment/ai_use_policy_active-1.0.0.md',
    ARRAY['policy_library'],
    ARRAY['RCVS_accountability'],
    ARRAY['EU_AI_Act_Article_26']
FROM public.self_assessment_templates t
WHERE t.template_slug = 'rcvs_ai_governance_self_assessment'
ON CONFLICT ON CONSTRAINT self_assessment_questions_template_slug_unique DO NOTHING;

-- Q3
INSERT INTO public.self_assessment_questions (
    template_id, question_slug, question_order, theme,
    prompt_text, guidance_reference, evidence_link_hints,
    rcvs_principle_mappings, eu_ai_act_article_mappings
)
SELECT
    t.template_id,
    'staff_ai_literacy_recorded',
    3,
    'staff_literacy',
    'Have staff who use AI tools completed AI-literacy learning recorded in ANCHOR?',
    'docs/governance/self_assessment/staff_ai_literacy_recorded-1.0.0.md',
    ARRAY['learn_cpd'],
    ARRAY['RCVS_AI_literacy'],
    ARRAY['EU_AI_Act_Article_4']
FROM public.self_assessment_templates t
WHERE t.template_slug = 'rcvs_ai_governance_self_assessment'
ON CONFLICT ON CONSTRAINT self_assessment_questions_template_slug_unique DO NOTHING;

-- Q4
INSERT INTO public.self_assessment_questions (
    template_id, question_slug, question_order, theme,
    prompt_text, guidance_reference, evidence_link_hints,
    rcvs_principle_mappings, eu_ai_act_article_mappings
)
SELECT
    t.template_id,
    'staff_acknowledged_policy',
    4,
    'staff_acknowledgement',
    'Have staff acknowledged the active AI-use policy?',
    'docs/governance/self_assessment/staff_acknowledged_policy-1.0.0.md',
    ARRAY['staff_attestation'],
    ARRAY['RCVS_accountability'],
    ARRAY['EU_AI_Act_Article_26']
FROM public.self_assessment_templates t
WHERE t.template_slug = 'rcvs_ai_governance_self_assessment'
ON CONFLICT ON CONSTRAINT self_assessment_questions_template_slug_unique DO NOTHING;

-- Q5
INSERT INTO public.self_assessment_questions (
    template_id, question_slug, question_order, theme,
    prompt_text, guidance_reference, evidence_link_hints,
    rcvs_principle_mappings, eu_ai_act_article_mappings
)
SELECT
    t.template_id,
    'human_review_required',
    5,
    'human_review',
    'Does the practice require human review of AI outputs before clinical or client use?',
    'docs/governance/self_assessment/human_review_required-1.0.0.md',
    ARRAY['manual_review','policy_library'],
    ARRAY['RCVS_professional_judgement'],
    ARRAY['EU_AI_Act_Article_14']
FROM public.self_assessment_templates t
WHERE t.template_slug = 'rcvs_ai_governance_self_assessment'
ON CONFLICT ON CONSTRAINT self_assessment_questions_template_slug_unique DO NOTHING;

-- Q6
INSERT INTO public.self_assessment_questions (
    template_id, question_slug, question_order, theme,
    prompt_text, guidance_reference, evidence_link_hints,
    rcvs_principle_mappings, eu_ai_act_article_mappings
)
SELECT
    t.template_id,
    'data_handling_boundaries_set',
    6,
    'data_handling',
    'Are boundaries set for what client or clinical data may be entered into AI tools?',
    'docs/governance/self_assessment/data_handling_boundaries_set-1.0.0.md',
    ARRAY['policy_library','manual_review'],
    ARRAY['RCVS_client_interest'],
    ARRAY['EU_AI_Act_Article_26']
FROM public.self_assessment_templates t
WHERE t.template_slug = 'rcvs_ai_governance_self_assessment'
ON CONFLICT ON CONSTRAINT self_assessment_questions_template_slug_unique DO NOTHING;

-- Q7
INSERT INTO public.self_assessment_questions (
    template_id, question_slug, question_order, theme,
    prompt_text, guidance_reference, evidence_link_hints,
    rcvs_principle_mappings, eu_ai_act_article_mappings
)
SELECT
    t.template_id,
    'client_transparency_practice',
    7,
    'transparency_to_clients',
    'Does the practice have a stated approach for explaining AI assistance to clients when relevant?',
    'docs/governance/self_assessment/client_transparency_practice-1.0.0.md',
    ARRAY['policy_library','manual_review'],
    ARRAY['RCVS_transparency'],
    ARRAY['EU_AI_Act_Article_50']
FROM public.self_assessment_templates t
WHERE t.template_slug = 'rcvs_ai_governance_self_assessment'
ON CONFLICT ON CONSTRAINT self_assessment_questions_template_slug_unique DO NOTHING;

-- Q8
INSERT INTO public.self_assessment_questions (
    template_id, question_slug, question_order, theme,
    prompt_text, guidance_reference, evidence_link_hints,
    rcvs_principle_mappings, eu_ai_act_article_mappings
)
SELECT
    t.template_id,
    'incident_reporting_path',
    8,
    'incident_readiness',
    'Is there a documented path for staff to report AI-related incidents or near-misses?',
    'docs/governance/self_assessment/incident_reporting_path-1.0.0.md',
    ARRAY['policy_library','manual_review'],
    ARRAY['RCVS_accountability'],
    ARRAY['EU_AI_Act_Article_26']
FROM public.self_assessment_templates t
WHERE t.template_slug = 'rcvs_ai_governance_self_assessment'
ON CONFLICT ON CONSTRAINT self_assessment_questions_template_slug_unique DO NOTHING;

-- Q9
INSERT INTO public.self_assessment_questions (
    template_id, question_slug, question_order, theme,
    prompt_text, guidance_reference, evidence_link_hints,
    rcvs_principle_mappings, eu_ai_act_article_mappings
)
SELECT
    t.template_id,
    'tool_vendor_inventory',
    9,
    'tool_vendor_awareness',
    'Does the practice maintain awareness of which AI tools and vendors are in use?',
    'docs/governance/self_assessment/tool_vendor_inventory-1.0.0.md',
    ARRAY['manual_review'],
    ARRAY['RCVS_accountability'],
    ARRAY['EU_AI_Act_Article_26']
FROM public.self_assessment_templates t
WHERE t.template_slug = 'rcvs_ai_governance_self_assessment'
ON CONFLICT ON CONSTRAINT self_assessment_questions_template_slug_unique DO NOTHING;

-- Q10
INSERT INTO public.self_assessment_questions (
    template_id, question_slug, question_order, theme,
    prompt_text, guidance_reference, evidence_link_hints,
    rcvs_principle_mappings, eu_ai_act_article_mappings
)
SELECT
    t.template_id,
    'evidence_audit_ready',
    10,
    'evidence_audit_readiness',
    'Can the practice retrieve dated evidence of its AI governance activity if asked?',
    'docs/governance/self_assessment/evidence_audit_ready-1.0.0.md',
    ARRAY['trust_posture','assistant_receipts','policy_library','staff_attestation','learn_cpd'],
    ARRAY['RCVS_accountability'],
    ARRAY['EU_AI_Act_Article_26']
FROM public.self_assessment_templates t
WHERE t.template_slug = 'rcvs_ai_governance_self_assessment'
ON CONFLICT ON CONSTRAINT self_assessment_questions_template_slug_unique DO NOTHING;

COMMIT;
