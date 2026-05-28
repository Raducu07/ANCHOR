-- ============================================================
-- 20260528_02_learn_module_seed.sql
--
-- Phase 2A-1 - initial v1 learning module catalogue seed.
--
-- Five ANCHOR-curated modules. Metadata only:
--   * summary / learning_objectives are catalogue descriptors, not teaching content.
--   * content_reference points at markdown shipped in docs/learn/modules/<slug>.md.
--   * role_applicability is AUDIENCE METADATA, not access-control roles.
--
-- Wording: catalogue copy is neutral and makes no accreditation/compliance claim
-- (Readiness Map Section 2 / Engineering Brief Section 3.4). No "RCVS-certified" / "compliant".
--
-- Idempotent: ON CONFLICT (module_slug) DO NOTHING.
-- This file intentionally contains no dollar-quoted blocks so the migration
-- runner splits it statement-by-statement on ';'.
-- ============================================================

BEGIN;

INSERT INTO public.learning_modules (
    module_slug, version, title, summary, learning_objectives,
    role_applicability, cpd_minutes, category,
    rcvs_principle_mappings, eu_ai_act_article_mappings, content_reference, is_active
) VALUES (
    'ai-literacy-foundations-v1',
    '1.0.0',
    'AI Literacy Foundations for Veterinary Teams',
    'Introduces what AI is, where it appears in clinic workflows, and the basics of using it safely and accountably.',
    ARRAY[
        'Describe what AI is and is not in a veterinary context',
        'Identify where AI may appear in everyday clinic workflows',
        'Recognise why human review and accountability remain essential'
    ],
    ARRAY['vet','nurse','practice_manager','admin','reception','locum'],
    30,
    'literacy',
    ARRAY['accountability','ai_literacy','preparation_for_practice'],
    ARRAY['article_4'],
    'docs/learn/modules/ai-literacy-foundations-v1.md',
    true
)
ON CONFLICT (module_slug) DO NOTHING;

INSERT INTO public.learning_modules (
    module_slug, version, title, summary, learning_objectives,
    role_applicability, cpd_minutes, category,
    rcvs_principle_mappings, eu_ai_act_article_mappings, content_reference, is_active
) VALUES (
    'bias-detection-in-ai-outputs-v1',
    '1.0.0',
    'Recognising Biased, Inaccurate, or Misleading AI Outputs',
    'Helps you recognise biased, inaccurate, or misleading AI outputs.',
    ARRAY[
        'Recognise common patterns of bias and inaccuracy in AI outputs',
        'Apply a practical check before relying on an AI-generated result',
        'Know when to escalate or discard an AI output'
    ],
    ARRAY['vet','nurse','practice_manager','admin','reception','locum'],
    25,
    'bias_detection',
    ARRAY['ai_literacy','bias_detection'],
    ARRAY['article_4'],
    'docs/learn/modules/bias-detection-in-ai-outputs-v1.md',
    true
)
ON CONFLICT (module_slug) DO NOTHING;

INSERT INTO public.learning_modules (
    module_slug, version, title, summary, learning_objectives,
    role_applicability, cpd_minutes, category,
    rcvs_principle_mappings, eu_ai_act_article_mappings, content_reference, is_active
) VALUES (
    'ethical-and-safe-ai-use-v1',
    '1.0.0',
    'Ethical and Safe Use of AI in Clinical Workflows',
    'Covers the ethical principles and practical guardrails for using AI safely alongside professional judgement.',
    ARRAY[
        'Describe the ethical principles that govern AI use in practice',
        'Apply guardrails that keep AI use safe and within professional scope',
        'Distinguish appropriate from inappropriate uses of AI in clinical workflows'
    ],
    ARRAY['vet','nurse','practice_manager','admin','reception','locum'],
    20,
    'ethical_use',
    ARRAY['ethical_safe_use','academic_integrity'],
    ARRAY['article_4'],
    'docs/learn/modules/ethical-and-safe-ai-use-v1.md',
    true
)
ON CONFLICT (module_slug) DO NOTHING;

INSERT INTO public.learning_modules (
    module_slug, version, title, summary, learning_objectives,
    role_applicability, cpd_minutes, category,
    rcvs_principle_mappings, eu_ai_act_article_mappings, content_reference, is_active
) VALUES (
    'confidentiality-and-ai-v1',
    '1.0.0',
    'Confidentiality and Data Protection When Using AI',
    'Explains how to protect client and practice data when using AI tools, and what should never be shared.',
    ARRAY[
        'Identify data that must not be entered into AI tools',
        'Apply confidentiality and data-protection practices when using AI',
        'Recognise the privacy risks specific to AI workflows'
    ],
    ARRAY['vet','nurse','practice_manager','admin','reception','locum'],
    20,
    'confidentiality',
    ARRAY['confidentiality_data_protection'],
    ARRAY['article_4'],
    'docs/learn/modules/confidentiality-and-ai-v1.md',
    true
)
ON CONFLICT (module_slug) DO NOTHING;

INSERT INTO public.learning_modules (
    module_slug, version, title, summary, learning_objectives,
    role_applicability, cpd_minutes, category,
    rcvs_principle_mappings, eu_ai_act_article_mappings, content_reference, is_active
) VALUES (
    'explaining-ai-to-clients-v1',
    '1.0.0',
    'Explaining AI Use to Pet Owners',
    'Helps you explain AI use to pet owners clearly and transparently, supporting informed trust.',
    ARRAY[
        'Explain in plain language how AI may be used in the clinic',
        'Respond to common pet-owner questions about AI transparently',
        'Support informed trust without overstating what AI does'
    ],
    ARRAY['vet','nurse','practice_manager','admin','reception','locum'],
    15,
    'transparency',
    ARRAY['explainability'],
    ARRAY['article_4','article_50'],
    'docs/learn/modules/explaining-ai-to-clients-v1.md',
    true
)
ON CONFLICT (module_slug) DO NOTHING;

COMMIT;
