-- ------------------------------------------------------------
-- 20260603_01_client_transparency_schema.sql
--
-- Phase 2A-4.1 - Client-Facing Transparency Layer schema.
--
-- Creates three objects:
--   * client_transparency_templates
--       - ANCHOR-curated GLOBAL catalogue of client-facing AI-use
--         transparency templates. NOT clinic-scoped. No RLS.
--   * clinic_client_transparency_profiles
--       - per-clinic adoption of a template at a chosen version,
--         with status (draft / active / superseded / archived).
--         RLS ENABLED + FORCED.
--   * client_transparency_public_versions
--       - immutable per-clinic client-safe publication snapshot.
--         RLS ENABLED + FORCED.
--
-- IMPORTANT v1 rule (founder decision after 2A-4.0 audit):
--   At most ONE active client transparency profile per clinic. The
--   partial unique index is on (clinic_id) WHERE status = 'active'
--   (NOT on (clinic_id, template_id)). A clinic that wants to switch
--   to a different template must first activate the new draft, which
--   supersedes the existing active profile.
--
-- IMPORTANT distinctions:
--   * Assistant runtime policy (`assistant_policy_settings`),
--     governance AI-use policy (`clinic_policy_versions`), and
--     client-facing transparency (this slice) are three DELIBERATELY
--     SEPARATE surfaces. They do not share tables.
--   * Client transparency is metadata-only. It is not a consent form,
--     legal advice, regulatory approval, certification, or clinical
--     record.
--
-- Metadata-only doctrine:
--   * Template body text is NOT stored in the DB. Templates carry
--     only a `content_reference` pointing at markdown shipped under
--     docs/governance/client_transparency/<slug>-<version>.md.
--   * Clinic profiles carry two bounded clinic-authored public
--     disclosure fields (`display_title`, `plain_language_summary`)
--     with hard length caps enforced by CHECK constraints. These
--     fields are PUBLIC DISCLOSURE TEXT, not clinical content. The
--     handler layer (added in 2A-4.2) will additionally apply
--     blocklist heuristics for identifier-shaped tokens.
--   * Permitted / prohibited use categories are stored as text[]
--     and validated against the catalogue enum at the handler layer.
--   * `client_transparency_public_versions.generated_public_payload`
--     is a frozen client-safe snapshot. It contains no clinical
--     content, no client identifiers, no patient identifiers, no
--     telemetry, and no Assistant outputs. The payload contents are
--     bounded by the schema of the profile it was published from.
--   * Corrections use append-only retire-with-actor (publication
--     status = 'retired'); rows are never deleted or overwritten.
--   * No `ON CONFLICT (clinic_id, action, idempotency_key)` against
--     the partial admin_audit_events_idem_uq index anywhere in this
--     slice (M6.10.1B / TD-BE postmortem). 2A-4.1 does NOT insert
--     into admin_audit_events.
--
-- Tenancy:
--   * Clinic-scoped tables use `app_current_clinic_id()` (defined in
--     app/schema.sql), matching learning_completions /
--     clinic_policy_versions / policy_attestations /
--     clinic_self_assessments.
--   * RLS policies created inside DO $$ pg_policies guards (idempotent).
--
-- This migration must remain idempotent and boot-safe.
-- ------------------------------------------------------------

BEGIN;

-- ------------------------------------------------------------
-- 2A-4.1.a - client_transparency_templates: GLOBAL catalogue (NO RLS)
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.client_transparency_templates (
    template_id                     uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    template_slug                   text        NOT NULL UNIQUE,
    template_version                text        NOT NULL,
    title                           text        NOT NULL,
    summary                         text        NOT NULL,
    default_sections                jsonb       NOT NULL,
    default_permitted_categories    text[]      NOT NULL,
    default_prohibited_categories   text[]      NOT NULL,
    rcvs_principle_mappings         text[]      NOT NULL,
    eu_ai_act_article_mappings      text[]      NOT NULL,
    content_reference               text        NOT NULL,
    content_sha256                  text        NULL,
    is_active                       boolean     NOT NULL DEFAULT true,
    superseded_by                   uuid        NULL
        REFERENCES public.client_transparency_templates(template_id) ON DELETE SET NULL,
    created_at                      timestamptz NOT NULL DEFAULT now(),
    updated_at                      timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_client_transparency_templates_active
    ON public.client_transparency_templates (is_active);

CREATE INDEX IF NOT EXISTS idx_client_transparency_templates_slug
    ON public.client_transparency_templates (template_slug);


-- ------------------------------------------------------------
-- 2A-4.1.b - clinic_client_transparency_profiles (RLS + FORCE)
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.clinic_client_transparency_profiles (
    clinic_profile_id                       uuid        PRIMARY KEY DEFAULT gen_random_uuid(),

    clinic_id                               uuid        NOT NULL
        REFERENCES public.clinics(clinic_id) ON DELETE RESTRICT,
    client_transparency_template_id         uuid        NOT NULL
        REFERENCES public.client_transparency_templates(template_id) ON DELETE RESTRICT,

    template_version_snapshot               text        NOT NULL,
    clinic_profile_version                  integer     NOT NULL,

    status                                  text        NOT NULL
        CHECK (status IN ('draft','active','superseded','archived')),

    display_title                           text        NOT NULL
        CHECK (char_length(display_title) BETWEEN 1 AND 120),
    plain_language_summary                  text        NOT NULL
        CHECK (char_length(plain_language_summary) BETWEEN 1 AND 1500),

    permitted_use_categories                text[]      NOT NULL,
    prohibited_use_categories               text[]      NOT NULL,

    human_review_statement_enabled          boolean     NOT NULL DEFAULT true,
    privacy_statement_enabled               boolean     NOT NULL DEFAULT true,
    client_explanation_statement_enabled    boolean     NOT NULL DEFAULT true,

    content_sha256_snapshot                 text        NULL,

    created_by_user_id                      uuid        NOT NULL
        REFERENCES public.clinic_users(user_id) ON DELETE RESTRICT,
    activated_by_user_id                    uuid        NULL
        REFERENCES public.clinic_users(user_id) ON DELETE SET NULL,
    activated_at                            timestamptz NULL,
    superseded_at                           timestamptz NULL,
    effective_from                          timestamptz NULL,

    created_at                              timestamptz NOT NULL DEFAULT now(),
    updated_at                              timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT clinic_client_transparency_profiles_unique
        UNIQUE (clinic_id, client_transparency_template_id, clinic_profile_version)
);

-- v1 founder decision: ONE active client transparency profile per
-- clinic (NOT one per template). A clinic switching templates must
-- first activate the new draft, which supersedes the existing active
-- profile via the partial unique index below.
CREATE UNIQUE INDEX IF NOT EXISTS clinic_client_transparency_one_active
    ON public.clinic_client_transparency_profiles (clinic_id)
    WHERE status = 'active';

CREATE INDEX IF NOT EXISTS idx_clinic_client_transparency_profiles_clinic_status
    ON public.clinic_client_transparency_profiles (clinic_id, status);

CREATE INDEX IF NOT EXISTS idx_clinic_client_transparency_profiles_clinic_activated_at
    ON public.clinic_client_transparency_profiles (clinic_id, activated_at DESC);

CREATE INDEX IF NOT EXISTS idx_clinic_client_transparency_profiles_clinic_template_version
    ON public.clinic_client_transparency_profiles
        (clinic_id, client_transparency_template_id, clinic_profile_version DESC);

ALTER TABLE public.clinic_client_transparency_profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.clinic_client_transparency_profiles FORCE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename = 'clinic_client_transparency_profiles'
          AND policyname = 'rls_clinic_client_transparency_profiles_tenant'
    ) THEN
        EXECUTE $policy$
            CREATE POLICY rls_clinic_client_transparency_profiles_tenant
            ON public.clinic_client_transparency_profiles
            FOR ALL
            USING (clinic_id = app_current_clinic_id())
            WITH CHECK (clinic_id = app_current_clinic_id())
        $policy$;
    END IF;
END
$$;


-- ------------------------------------------------------------
-- 2A-4.1.c - client_transparency_public_versions (RLS + FORCE)
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.client_transparency_public_versions (
    public_version_id           uuid        PRIMARY KEY DEFAULT gen_random_uuid(),

    clinic_id                   uuid        NOT NULL
        REFERENCES public.clinics(clinic_id) ON DELETE RESTRICT,
    clinic_profile_id           uuid        NOT NULL
        REFERENCES public.clinic_client_transparency_profiles(clinic_profile_id)
        ON DELETE RESTRICT,

    public_version              integer     NOT NULL,

    publication_status          text        NOT NULL
        CHECK (publication_status IN ('published','retired')),

    generated_public_payload    jsonb       NOT NULL,
    content_hash                text        NOT NULL,

    published_at                timestamptz NOT NULL DEFAULT now(),
    published_by_user_id        uuid        NOT NULL
        REFERENCES public.clinic_users(user_id) ON DELETE RESTRICT,

    retired_at                  timestamptz NULL,
    retired_by_user_id          uuid        NULL
        REFERENCES public.clinic_users(user_id) ON DELETE SET NULL,

    created_at                  timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT client_transparency_public_versions_unique
        UNIQUE (clinic_id, public_version)
);

CREATE INDEX IF NOT EXISTS idx_client_transparency_public_versions_clinic_published_at
    ON public.client_transparency_public_versions (clinic_id, published_at DESC);

CREATE INDEX IF NOT EXISTS idx_client_transparency_public_versions_clinic_status
    ON public.client_transparency_public_versions (clinic_id, publication_status);

ALTER TABLE public.client_transparency_public_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.client_transparency_public_versions FORCE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename = 'client_transparency_public_versions'
          AND policyname = 'rls_client_transparency_public_versions_tenant'
    ) THEN
        EXECUTE $policy$
            CREATE POLICY rls_client_transparency_public_versions_tenant
            ON public.client_transparency_public_versions
            FOR ALL
            USING (clinic_id = app_current_clinic_id())
            WITH CHECK (clinic_id = app_current_clinic_id())
        $policy$;
    END IF;
END
$$;

COMMIT;
