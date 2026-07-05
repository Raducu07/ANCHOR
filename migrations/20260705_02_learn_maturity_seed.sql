-- ============================================================
-- 20260705_02_learn_maturity_seed.sql
--
-- M4.6 - self-check / scenario question seed + role-based path seed.
--
-- Non-certifying wording doctrine: prompts, options, and explanations
-- are reinforcement content. Nothing here states or implies pass/fail
-- competence, certified CPD, RCVS accreditation, or regulator approval.
--
-- Metadata-only: ANCHOR-authored global educational content; no clinic
-- data, no clinical case content, no identifiable details.
--
-- Idempotent: ON CONFLICT (check_slug / path_slug) DO NOTHING.
-- This file intentionally contains no dollar-quoted blocks so the
-- migration runner splits it statement-by-statement on ';'.
-- ============================================================

BEGIN;

-- ---------- ai-literacy-foundations-v1 ----------

INSERT INTO public.learning_module_checks (
    module_id, check_slug, version, kind, prompt, options,
    correct_option_index, explanation, display_order, is_active
) VALUES (
    (SELECT module_id FROM public.learning_modules WHERE module_slug = 'ai-literacy-foundations-v1'),
    'ai-literacy-review-before-use-v1',
    '1.0.0',
    'knowledge_check',
    'Before an AI-drafted client message is used, what must happen?',
    ARRAY[
        'It can be sent as long as it reads well',
        'A veterinary professional reviews it against the clinical record',
        'It only needs review if the client asks',
        'AI drafts never need review'
    ],
    1,
    'Every AI-assisted output remains subject to professional review before operational use. ANCHOR records review evidence; it does not replace the review.',
    1,
    true
)
ON CONFLICT (check_slug) DO NOTHING;

INSERT INTO public.learning_module_checks (
    module_id, check_slug, version, kind, prompt, options,
    correct_option_index, explanation, display_order, is_active
) VALUES (
    (SELECT module_id FROM public.learning_modules WHERE module_slug = 'ai-literacy-foundations-v1'),
    'ai-literacy-already-checked-scenario-v1',
    '1.0.0',
    'scenario',
    'A colleague says an AI tool already checked a draft, so nobody needs to read it before sending. What is the safest response?',
    ARRAY[
        'Agree - the tool validated it',
        'Send it but keep a copy just in case',
        'Explain that human review is still required and review it against the record',
        'Ask the client to check it instead'
    ],
    2,
    'Automated checks support, but never replace, professional review. Human review before operational use is a standing boundary of governed AI use.',
    2,
    true
)
ON CONFLICT (check_slug) DO NOTHING;

-- ---------- bias-detection-in-ai-outputs-v1 ----------

INSERT INTO public.learning_module_checks (
    module_id, check_slug, version, kind, prompt, options,
    correct_option_index, explanation, display_order, is_active
) VALUES (
    (SELECT module_id FROM public.learning_modules WHERE module_slug = 'bias-detection-in-ai-outputs-v1'),
    'bias-detection-warning-signs-v1',
    '1.0.0',
    'knowledge_check',
    'Which of these is a warning sign that an AI output may be unreliable?',
    ARRAY[
        'It is fluent and confident',
        'It includes details nobody provided',
        'It is shorter than expected',
        'It uses UK spelling'
    ],
    1,
    'Fluency is not accuracy. Details that were never provided are invented content and a key sign the output must not be relied on.',
    1,
    true
)
ON CONFLICT (check_slug) DO NOTHING;

INSERT INTO public.learning_module_checks (
    module_id, check_slug, version, kind, prompt, options,
    correct_option_index, explanation, display_order, is_active
) VALUES (
    (SELECT module_id FROM public.learning_modules WHERE module_slug = 'bias-detection-in-ai-outputs-v1'),
    'bias-detection-invented-detail-scenario-v1',
    '1.0.0',
    'scenario',
    'An AI summary states a patient is doing well post-op, but no post-operative information was ever entered. What should you do?',
    ARRAY[
        'Accept it - it sounds plausible',
        'Discard or correct the invented detail and flag the output',
        'Send it to the client quickly before it changes',
        'Assume the system has access to more data'
    ],
    1,
    'Content that was never provided is invented. Correct or discard it, and use the clinic flagging path so the event becomes governance evidence.',
    2,
    true
)
ON CONFLICT (check_slug) DO NOTHING;

-- ---------- confidentiality-and-ai-v1 ----------

INSERT INTO public.learning_module_checks (
    module_id, check_slug, version, kind, prompt, options,
    correct_option_index, explanation, display_order, is_active
) VALUES (
    (SELECT module_id FROM public.learning_modules WHERE module_slug = 'confidentiality-and-ai-v1'),
    'confidentiality-minimum-data-v1',
    '1.0.0',
    'knowledge_check',
    'What is the safest default when using AI tools with client or patient information?',
    ARRAY[
        'Paste the full record for the best results',
        'Share only the minimum information needed, per clinic policy',
        'Include contact details so the tool can personalise',
        'Use a personal account to keep work accounts clean'
    ],
    1,
    'Data minimisation is the safe default. Clinic policy governs what may be shared with any AI tool, and identifiable details need particular care.',
    1,
    true
)
ON CONFLICT (check_slug) DO NOTHING;

INSERT INTO public.learning_module_checks (
    module_id, check_slug, version, kind, prompt, options,
    correct_option_index, explanation, display_order, is_active
) VALUES (
    (SELECT module_id FROM public.learning_modules WHERE module_slug = 'confidentiality-and-ai-v1'),
    'confidentiality-locum-chatbot-scenario-v1',
    '1.0.0',
    'scenario',
    'A locum wants to paste a full clinical history, including the owner phone number, into a general-purpose chatbot. What applies?',
    ARRAY[
        'It is fine if it saves time',
        'Only the phone number is a problem',
        'The clinic AI-use and data-handling policy applies - identifiable details must not be shared with ungoverned tools',
        'Nothing - chatbot conversations are private'
    ],
    2,
    'Confidentiality and data-protection expectations apply to AI tools exactly as to any other channel. The clinic policy and data-handling boundaries govern what may be shared.',
    2,
    true
)
ON CONFLICT (check_slug) DO NOTHING;

-- ---------- ethical-and-safe-ai-use-v1 ----------

INSERT INTO public.learning_module_checks (
    module_id, check_slug, version, kind, prompt, options,
    correct_option_index, explanation, display_order, is_active
) VALUES (
    (SELECT module_id FROM public.learning_modules WHERE module_slug = 'ethical-and-safe-ai-use-v1'),
    'ethical-outside-safe-use-v1',
    '1.0.0',
    'knowledge_check',
    'Which task is OUTSIDE safe AI use in a veterinary clinic?',
    ARRAY[
        'Drafting a reminder message from confirmed facts',
        'Explaining a governance policy in plain language',
        'Recommending a drug dose',
        'Summarising a team meeting'
    ],
    2,
    'Diagnosis, prescribing, dosing, and treatment planning are outside safe AI use. They remain matters of professional clinical judgement.',
    1,
    true
)
ON CONFLICT (check_slug) DO NOTHING;

INSERT INTO public.learning_module_checks (
    module_id, check_slug, version, kind, prompt, options,
    correct_option_index, explanation, display_order, is_active
) VALUES (
    (SELECT module_id FROM public.learning_modules WHERE module_slug = 'ethical-and-safe-ai-use-v1'),
    'ethical-treatment-suggestion-scenario-v1',
    '1.0.0',
    'scenario',
    'While drafting a client update, an AI tool suggests changing the treatment. What is the correct handling?',
    ARRAY[
        'Adopt the suggestion - it may be right',
        'Ignore the whole message and start again silently',
        'Do not act on the suggestion, keep clinical content out of the draft, and log the event as a near-miss',
        'Forward the suggestion to the client for their view'
    ],
    2,
    'Clinical recommendations from a drafting tool are out of bounds. Near-miss logging turns the event into reviewable governance evidence.',
    2,
    true
)
ON CONFLICT (check_slug) DO NOTHING;

-- ---------- explaining-ai-to-clients-v1 ----------

INSERT INTO public.learning_module_checks (
    module_id, check_slug, version, kind, prompt, options,
    correct_option_index, explanation, display_order, is_active
) VALUES (
    (SELECT module_id FROM public.learning_modules WHERE module_slug = 'explaining-ai-to-clients-v1'),
    'explaining-ai-discharge-question-v1',
    '1.0.0',
    'knowledge_check',
    'A client asks whether AI wrote their discharge summary. What is the best framing?',
    ARRAY[
        'Deny any AI involvement',
        'Explain that AI may help draft wording, and a veterinary professional reviews everything before it is used',
        'Say the AI decides the content',
        'Avoid the question'
    ],
    1,
    'A clear, honest, bounded explanation maintains trust: AI assists with drafting; professionals stay accountable for everything that is used.',
    1,
    true
)
ON CONFLICT (check_slug) DO NOTHING;

INSERT INTO public.learning_module_checks (
    module_id, check_slug, version, kind, prompt, options,
    correct_option_index, explanation, display_order, is_active
) VALUES (
    (SELECT module_id FROM public.learning_modules WHERE module_slug = 'explaining-ai-to-clients-v1'),
    'explaining-ai-robot-worry-scenario-v1',
    '1.0.0',
    'scenario',
    'A client is worried that a robot is treating their dog. Which response fits the clinic transparency commitments?',
    ARRAY[
        'Tell them not to worry about it',
        'Explain that AI tools never make clinical decisions here - they help with drafting and admin under professional review',
        'Say it is too technical to explain',
        'Promise that AI is never used for anything'
    ],
    1,
    'The transparency layer commits the clinic to plain-language, honest, bounded explanations of where AI does and does not appear.',
    2,
    true
)
ON CONFLICT (check_slug) DO NOTHING;

-- ---------- role-based learning paths ----------

INSERT INTO public.learning_role_paths (
    path_slug, version, title, summary, role_applicability,
    module_slugs, display_order, is_active
) VALUES (
    'clinical-team-ai-foundations-v1',
    '1.0.0',
    'Clinical Team AI Foundations',
    'A recommended sequence for clinical team members covering AI literacy, output reliability, confidentiality, and safe-use boundaries.',
    ARRAY['vet','nurse','locum'],
    ARRAY[
        'ai-literacy-foundations-v1',
        'bias-detection-in-ai-outputs-v1',
        'confidentiality-and-ai-v1',
        'ethical-and-safe-ai-use-v1'
    ],
    1,
    true
)
ON CONFLICT (path_slug) DO NOTHING;

INSERT INTO public.learning_role_paths (
    path_slug, version, title, summary, role_applicability,
    module_slugs, display_order, is_active
) VALUES (
    'practice-leadership-governance-v1',
    '1.0.0',
    'Practice Leadership and Client Communication',
    'A recommended sequence for leadership and client-facing roles covering AI literacy, confidentiality, client explanation, and safe-use boundaries.',
    ARRAY['practice_manager','admin','owner','reception'],
    ARRAY[
        'ai-literacy-foundations-v1',
        'confidentiality-and-ai-v1',
        'explaining-ai-to-clients-v1',
        'ethical-and-safe-ai-use-v1'
    ],
    2,
    true
)
ON CONFLICT (path_slug) DO NOTHING;

COMMIT;
