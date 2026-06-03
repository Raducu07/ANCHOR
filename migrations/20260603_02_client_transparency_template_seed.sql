-- ------------------------------------------------------------
-- 20260603_02_client_transparency_template_seed.sql
--
-- Phase 2A-4.1 - initial v1 Client-Facing Transparency template seed.
--
-- One ANCHOR-curated client AI-use transparency template. Metadata
-- only:
--   * `default_sections` is a bounded JSON catalogue of section
--     headings only. No clinical content, no client identifiers, no
--     patient identifiers, no Assistant outputs.
--   * `default_permitted_categories` and `default_prohibited_categories`
--     define the canonical enums the 2A-4.2 endpoint slice will
--     validate clinic-side category selections against.
--   * `content_reference` points at markdown shipped in
--     docs/governance/client_transparency/<slug>-<version>.md.
--   * `content_sha256` is intentionally NULL in this slice. A later
--     verification utility / test will compute and reconcile the
--     hash from the on-disk markdown stub. The schema must not block
--     on hash automation (consistent with 2A-2.1 / 2A-3.1).
--
-- Wording: catalogue copy is neutral and makes no accreditation /
-- compliance / certification / regulator-endorsement claim
-- (Readiness Map Section 2 / 2A-2.1B wording controls carry over).
-- The closing disclaimer wording lives in the markdown stub.
--
-- Idempotent: ON CONFLICT (template_slug) DO NOTHING. This targets
-- the explicit UNIQUE constraint on
-- client_transparency_templates.template_slug created in 20260603_01
-- (NOT a partial index, so no production InvalidColumnReference risk;
-- cf. M6.10.1B / TD-BE).
-- ------------------------------------------------------------

BEGIN;

INSERT INTO public.client_transparency_templates (
    template_slug,
    template_version,
    title,
    summary,
    default_sections,
    default_permitted_categories,
    default_prohibited_categories,
    rcvs_principle_mappings,
    eu_ai_act_article_mappings,
    content_reference,
    content_sha256,
    is_active
) VALUES (
    'client_ai_use_transparency_v1',
    '1.0.0',
    'Client AI Use Transparency Statement',
    'Plain-language client-facing explanation of bounded, human-reviewed AI use in the clinic.',
    CAST('{
      "sections": [
        {
          "key": "what_ai_may_be_used_for",
          "heading": "What AI may be used for"
        },
        {
          "key": "what_ai_is_not_used_for",
          "heading": "What AI is not used for"
        },
        {
          "key": "human_review",
          "heading": "Human review"
        },
        {
          "key": "privacy_and_confidentiality",
          "heading": "Privacy and confidentiality"
        },
        {
          "key": "questions_from_clients",
          "heading": "Questions from clients"
        }
      ]
    }' AS jsonb),
    ARRAY[
      'draft_client_communication',
      'internal_summarisation',
      'administrative_support',
      'governance_and_learning_support'
    ],
    ARRAY[
      'diagnosis',
      'prescribing',
      'treatment_planning',
      'autonomous_clinical_decisions',
      'replacing_veterinary_judgement'
    ],
    ARRAY[
      'RCVS_transparency',
      'RCVS_accountability',
      'RCVS_professional_judgement'
    ],
    ARRAY[
      'EU_AI_Act_Article_50',
      'EU_AI_Act_Article_4'
    ],
    'docs/governance/client_transparency/client_ai_use_transparency_v1-1.0.0.md',
    NULL,
    true
)
ON CONFLICT (template_slug) DO NOTHING;

COMMIT;
