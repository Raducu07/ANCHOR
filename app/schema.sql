-- =========================
-- ANCHOR schema.sql (ready copy/paste)
-- PostgreSQL
-- Includes: core tables, memories, memory_offers handshake/audit, governance audit + config,
-- ops time-series buckets (aggregated, mode-aware), and safe performance indexes.
-- Idempotent: safe to run repeatedly.
-- =========================

-- Needed for gen_random_uuid()
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- =========================
-- Core tables
-- =========================

CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS sessions (
  id UUID PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  mode TEXT NOT NULL DEFAULT 'witness',
  question_used BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS messages (
  id UUID PRIMARY KEY,
  session_id UUID NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
  role TEXT NOT NULL CHECK (role IN ('user','assistant','system')),
  content TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Useful indexes for common queries
CREATE INDEX IF NOT EXISTS idx_sessions_user_created_at
  ON sessions(user_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_sessions_created_at
  ON sessions(created_at DESC);

CREATE INDEX IF NOT EXISTS idx_messages_session_created_at
  ON messages(session_id, created_at ASC);

CREATE INDEX IF NOT EXISTS idx_messages_created_at
  ON messages(created_at DESC);

-- =========================
-- Memories
-- =========================

CREATE TABLE IF NOT EXISTS memories (
  id UUID PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,

  kind TEXT NOT NULL CHECK (kind IN (
    'recurring_tension',
    'unexpressed_axis',
    'values_vs_emphasis',
    'decision_posture',
    'negative_space'
  )),

  statement TEXT NOT NULL,
  evidence_session_ids JSONB NOT NULL DEFAULT '[]'::jsonb,

  confidence TEXT NOT NULL CHECK (confidence IN ('tentative','emerging','consistent')),
  active BOOLEAN NOT NULL DEFAULT TRUE,

  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_memories_user_active
  ON memories(user_id, active);

CREATE INDEX IF NOT EXISTS idx_memories_user_kind
  ON memories(user_id, kind);

CREATE INDEX IF NOT EXISTS idx_memories_user_active_created
  ON memories(user_id, active, created_at DESC);

-- =========================
-- Memory offers (handshake + audit)
-- =========================

CREATE TABLE IF NOT EXISTS memory_offers (
  id UUID PRIMARY KEY,                      -- offer_id
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,

  kind TEXT NOT NULL CHECK (kind IN (
    'recurring_tension',
    'unexpressed_axis',
    'values_vs_emphasis',
    'decision_posture',
    'negative_space'
  )),

  statement TEXT NOT NULL,
  evidence_session_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
  confidence TEXT NOT NULL CHECK (confidence IN ('tentative','emerging','consistent')),

  -- minimal explainability; never store raw user messages here
  basis JSONB NOT NULL DEFAULT '{}'::jsonb,

  status TEXT NOT NULL CHECK (status IN ('proposed','accepted','rejected','expired'))
    DEFAULT 'proposed',

  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  decided_at TIMESTAMPTZ NULL
);

CREATE INDEX IF NOT EXISTS idx_memory_offers_user_created
  ON memory_offers(user_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_memory_offers_user_status_created
  ON memory_offers(user_id, status, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_memory_offers_user_id_status
  ON memory_offers(user_id, status);

-- =========================
-- Governance audit table (A3/A4)
-- =========================

CREATE TABLE IF NOT EXISTS governance_events (
  id UUID PRIMARY KEY,

  user_id UUID REFERENCES users(id) ON DELETE SET NULL,
  session_id UUID REFERENCES sessions(id) ON DELETE SET NULL,

  mode TEXT NOT NULL DEFAULT 'witness',

  allowed BOOLEAN NOT NULL,
  replaced BOOLEAN NOT NULL,
  score INT NOT NULL,
  grade TEXT NOT NULL,
  reason TEXT NOT NULL,

  findings JSONB NOT NULL DEFAULT '[]'::jsonb,
  audit JSONB NOT NULL DEFAULT '{}'::jsonb,

  -- A4: versioning + deterministic decision trace
  policy_version TEXT NOT NULL DEFAULT 'gov-v1.0',
  neutrality_version TEXT NOT NULL DEFAULT 'n-v1.1',
  decision_trace JSONB NOT NULL DEFAULT '{}'::jsonb,

  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_governance_events_user_created
  ON governance_events(user_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_governance_events_session_created
  ON governance_events(session_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_governance_events_created
  ON governance_events(created_at DESC);

CREATE INDEX IF NOT EXISTS brin_governance_events_created_at
  ON governance_events USING BRIN (created_at);

CREATE INDEX IF NOT EXISTS idx_governance_events_policy_version
  ON governance_events(policy_version, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_governance_events_neutrality_version
  ON governance_events(neutrality_version, created_at DESC);

-- Optional performance: GIN index on decision_trace (safe + idempotent)
CREATE INDEX IF NOT EXISTS idx_governance_events_decision_trace_gin
  ON governance_events
  USING GIN (decision_trace);

-- =========================
-- Governance config (institution-friendly, auditable settings)
-- =========================

CREATE TABLE IF NOT EXISTS governance_config (
  id UUID PRIMARY KEY,
  policy_version TEXT NOT NULL,
  neutrality_version TEXT NOT NULL,

  min_score_allow INT NOT NULL DEFAULT 75,

  hard_block_rules JSONB NOT NULL DEFAULT '["jailbreak","therapy","promise"]'::jsonb,
  soft_rules JSONB NOT NULL DEFAULT '["direct_advice","coercion"]'::jsonb,

  max_findings INT NOT NULL DEFAULT 10,

  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_governance_config_updated
  ON governance_config(updated_at DESC);

-- Seed: ensure at least one policy row exists (idempotent)
INSERT INTO governance_config (
  id,
  policy_version,
  neutrality_version,
  min_score_allow,
  hard_block_rules,
  soft_rules,
  max_findings
)
SELECT
  gen_random_uuid(),
  'gov-v1.0',
  'n-v1.1',
  75,
  '["jailbreak","therapy","promise"]'::jsonb,
  '["direct_advice","coercion"]'::jsonb,
  10
WHERE NOT EXISTS (SELECT 1 FROM governance_config);

-- ===========================
-- Ops time-series buckets (M2.4b/M2.5) — mode-aware
-- Aggregated only. No content.
-- ===========================

CREATE TABLE IF NOT EXISTS ops_timeseries_buckets (
  id UUID PRIMARY KEY,
  bucket_start TIMESTAMPTZ NOT NULL,
  bucket_sec INT NOT NULL,
  route TEXT NOT NULL DEFAULT '__all__',
  mode TEXT NOT NULL DEFAULT '__all__',

  request_count INT NOT NULL DEFAULT 0,
  rate_5xx DOUBLE PRECISION NOT NULL DEFAULT 0,
  p95_latency_ms INT NOT NULL DEFAULT 0,
  avg_latency_ms DOUBLE PRECISION NOT NULL DEFAULT 0,

  gov_events_total INT NOT NULL DEFAULT 0,
  gov_replaced_rate DOUBLE PRECISION NOT NULL DEFAULT 0,
  gov_avg_score DOUBLE PRECISION NOT NULL DEFAULT 0,

  policy_version TEXT,
  neutrality_version TEXT,
  min_score_allow INT,
  hard_rules_count INT,
  soft_rules_count INT,
  strictness_score DOUBLE PRECISION NOT NULL DEFAULT 0,

  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Uniqueness for bucket aggregation (mode-aware)
CREATE UNIQUE INDEX IF NOT EXISTS idx_ops_timeseries_unique_mode
  ON ops_timeseries_buckets (bucket_start, bucket_sec, route, mode);

-- Query helpers
CREATE INDEX IF NOT EXISTS idx_ops_timeseries_bucket_start
  ON ops_timeseries_buckets (bucket_start DESC);

CREATE INDEX IF NOT EXISTS idx_ops_timeseries_bucket_route_mode_sec_start
  ON ops_timeseries_buckets (bucket_sec, route, mode, bucket_start DESC);

CREATE INDEX IF NOT EXISTS idx_ops_timeseries_bucket_mode_sec_start
  ON ops_timeseries_buckets (bucket_sec, mode, bucket_start DESC);

CREATE INDEX IF NOT EXISTS brin_ops_timeseries_bucket_start
  ON ops_timeseries_buckets USING BRIN (bucket_start);

-- ===========================
-- Back-compat upgrades (safe if running on older DBs)
-- ===========================

-- If ops_timeseries_buckets existed without mode before, ensure column exists + backfill
ALTER TABLE ops_timeseries_buckets
  ADD COLUMN IF NOT EXISTS mode TEXT NOT NULL DEFAULT '__all__';

UPDATE ops_timeseries_buckets
SET mode = '__all__'
WHERE mode IS NULL;

-- If old unique index exists (bucket_start, bucket_sec, route) drop it
DO $$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM pg_indexes
    WHERE schemaname = 'public'
      AND indexname = 'idx_ops_timeseries_unique'
  ) THEN
    EXECUTE 'DROP INDEX IF EXISTS idx_ops_timeseries_unique';
  END IF;
END $$;

-- If old helper index exists (bucket_sec, route, bucket_start) drop it
DO $$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM pg_indexes
    WHERE schemaname = 'public'
      AND indexname = 'idx_ops_timeseries_bucket_route_sec_start'
  ) THEN
    EXECUTE 'DROP INDEX IF EXISTS idx_ops_timeseries_bucket_route_sec_start';
  END IF;
END $$;

-- schema.sql — ANCHOR Portal Blueprint v1 (DDL + RLS)
-- PostgreSQL 13+ recommended.

BEGIN;

-- ---------- Extensions ----------
-- gen_random_uuid()
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ---------- Helper: tenant context ----------
-- Your app should run, per request:
--   SELECT set_config('app.clinic_id', '<uuid>', true);
--   SELECT set_config('app.user_id',   '<uuid>', true);
--
-- We use current_setting(..., true) so missing settings don't error.
CREATE OR REPLACE FUNCTION app_current_clinic_id()
RETURNS uuid
LANGUAGE sql
STABLE
AS $$
  SELECT NULLIF(current_setting('app.clinic_id', true), '')::uuid;
$$;

CREATE OR REPLACE FUNCTION app_current_user_id()
RETURNS uuid
LANGUAGE sql
STABLE
AS $$
  SELECT NULLIF(current_setting('app.user_id', true), '')::uuid;
$$;

-- ---------- Controlled vocab (v1 via CHECK constraints) ----------
-- NOTE: You can evolve to ENUMs later if you want hard typing.
-- Keeping TEXT + CHECK is easiest for migrations.

-- ---------- Core tables ----------
CREATE TABLE IF NOT EXISTS clinics (
  clinic_id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  clinic_name           text NOT NULL,
  subscription_tier     text NOT NULL DEFAULT 'starter',
  active_status         boolean NOT NULL DEFAULT true,
  policy_version_locked boolean NOT NULL DEFAULT false,
  usage_limit_monthly   integer,
  rate_limit_per_min    integer,
  created_at            timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS users (
  user_id       uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  clinic_id     uuid NOT NULL REFERENCES clinics(clinic_id) ON DELETE CASCADE,
  role          text NOT NULL CHECK (role IN ('admin','staff')),
  email         text NOT NULL,
  password_hash text NOT NULL,
  active_status boolean NOT NULL DEFAULT true,
  created_at    timestamptz NOT NULL DEFAULT now(),
  UNIQUE (clinic_id, email)
);

CREATE TABLE IF NOT EXISTS user_invites (
  invite_id   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  clinic_id   uuid NOT NULL REFERENCES clinics(clinic_id) ON DELETE CASCADE,
  email       text NOT NULL,
  role        text NOT NULL CHECK (role IN ('admin','staff')),
  token_hash  text NOT NULL,
  expires_at  timestamptz NOT NULL,
  used_at     timestamptz,
  created_by  uuid REFERENCES users(user_id) ON DELETE SET NULL,
  created_at  timestamptz NOT NULL DEFAULT now(),
  UNIQUE (clinic_id, email, token_hash)
);

-- ---------- Policy versioning ----------
-- Immutable history (append-only)
CREATE TABLE IF NOT EXISTS clinic_policies (
  clinic_id     uuid NOT NULL REFERENCES clinics(clinic_id) ON DELETE CASCADE,
  policy_version integer NOT NULL,
  policy_json   jsonb NOT NULL,
  created_by    uuid NOT NULL REFERENCES users(user_id) ON DELETE RESTRICT,
  created_at    timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (clinic_id, policy_version)
);

-- Pointer to active version
CREATE TABLE IF NOT EXISTS clinic_policy_state (
  clinic_id             uuid PRIMARY KEY REFERENCES clinics(clinic_id) ON DELETE CASCADE,
  active_policy_version integer NOT NULL,
  updated_by            uuid NOT NULL REFERENCES users(user_id) ON DELETE RESTRICT,
  updated_at            timestamptz NOT NULL DEFAULT now()
);

-- ---------- Privacy profile / retention ----------
CREATE TABLE IF NOT EXISTS clinic_privacy_profile (
  clinic_id               uuid PRIMARY KEY REFERENCES clinics(clinic_id) ON DELETE CASCADE,
  data_region             text NOT NULL CHECK (data_region IN ('UK','EU')),
  retention_days_governance integer NOT NULL DEFAULT 90 CHECK (retention_days_governance BETWEEN 1 AND 3650),
  retention_days_ops        integer NOT NULL DEFAULT 30 CHECK (retention_days_ops BETWEEN 1 AND 3650),
  export_enabled          boolean NOT NULL DEFAULT false,
  dpa_accepted_at         timestamptz,
  subprocessor_ack_at     timestamptz,
  updated_at              timestamptz NOT NULL DEFAULT now()
);

-- ---------- Governance events (metadata-only) ----------
CREATE TABLE IF NOT EXISTS governance_events (
  event_id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  clinic_id        uuid NOT NULL REFERENCES clinics(clinic_id) ON DELETE CASCADE,
  request_id       uuid NOT NULL,
  user_id          uuid NOT NULL REFERENCES users(user_id) ON DELETE RESTRICT,

  mode             text NOT NULL CHECK (mode IN ('clinical_note','client_comm','internal_summary')),

  pii_detected     boolean NOT NULL DEFAULT false,
  pii_action       text NOT NULL CHECK (pii_action IN ('allow','warn','block','redact')),
  pii_types        text[], -- categories only (e.g. name,email,phone,address,microchip,client_id)

  decision         text NOT NULL CHECK (decision IN ('allowed','blocked','replaced','modified')),
  risk_grade       text NOT NULL CHECK (risk_grade IN ('low','med','high')),

  reason_code      text NOT NULL CHECK (
                    reason_code IN (
                      'PII_DETECTED_BLOCKED',
                      'PII_DETECTED_WARNED',
                      'MODE_NOT_ALLOWED',
                      'CLIENT_FACING_TEMPLATE_APPLIED',
                      'UNCERTAINTY_REQUIRED_ADDED',
                      'MEDICAL_OVERCONFIDENCE_SOFTENED',
                      'DISALLOWED_CONTENT_REPLACED'
                    )
                  ),

  governance_score   double precision,
  policy_version     integer NOT NULL,
  neutrality_version text NOT NULL DEFAULT 'v1.1',

  created_at       timestamptz NOT NULL DEFAULT now()
);

-- ---------- Ops metrics events (telemetry-only) ----------
-- Note: keep clinic_id NOT NULL to preserve strict tenant scoping via RLS.
-- For non-tenant routes (/health), write a reserved "system clinic_id" in your app.
CREATE TABLE IF NOT EXISTS ops_metrics_events (
  event_id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  clinic_id           uuid NOT NULL REFERENCES clinics(clinic_id) ON DELETE CASCADE,
  request_id          uuid NOT NULL,
  route               text NOT NULL,
  status_code         integer NOT NULL CHECK (status_code BETWEEN 100 AND 599),
  latency_ms          integer NOT NULL CHECK (latency_ms >= 0),
  mode                text CHECK (mode IN ('clinical_note','client_comm','internal_summary')),
  governance_replaced boolean NOT NULL DEFAULT false,
  created_at          timestamptz NOT NULL DEFAULT now()
);

-- ---------- Admin audit events (content-free) ----------
CREATE TABLE IF NOT EXISTS admin_audit_events (
  event_id       uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  clinic_id      uuid NOT NULL REFERENCES clinics(clinic_id) ON DELETE CASCADE,
  admin_user_id  uuid NOT NULL REFERENCES users(user_id) ON DELETE RESTRICT,
  action         text NOT NULL CHECK (
                  action IN (
                    'created_user',
                    'disabled_user',
                    'changed_policy',
                    'exported_csv',
                    'changed_retention',
                    'created_invite',
                    'revoked_invite'
                  )
                ),
  target_id      uuid,
  ip_hash        text,
  created_at     timestamptz NOT NULL DEFAULT now()
);

-- ---------- Indexes ----------
-- Events: tenant + time
CREATE INDEX IF NOT EXISTS idx_governance_events_clinic_created_at
  ON governance_events (clinic_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_governance_events_clinic_request
  ON governance_events (clinic_id, request_id);

CREATE INDEX IF NOT EXISTS idx_governance_events_clinic_user_created_at
  ON governance_events (clinic_id, user_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_ops_metrics_events_clinic_created_at
  ON ops_metrics_events (clinic_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_ops_metrics_events_route_created_at
  ON ops_metrics_events (route, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_admin_audit_events_clinic_created_at
  ON admin_audit_events (clinic_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_users_clinic_role
  ON users (clinic_id, role);

CREATE INDEX IF NOT EXISTS idx_user_invites_clinic_expires
  ON user_invites (clinic_id, expires_at DESC);

-- ---------- Row Level Security (RLS) ----------
-- Enable RLS for tenant-scoped tables.
ALTER TABLE clinics               ENABLE ROW LEVEL SECURITY;
ALTER TABLE users                 ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_invites          ENABLE ROW LEVEL SECURITY;
ALTER TABLE clinic_policies       ENABLE ROW LEVEL SECURITY;
ALTER TABLE clinic_policy_state   ENABLE ROW LEVEL SECURITY;
ALTER TABLE clinic_privacy_profile ENABLE ROW LEVEL SECURITY;
ALTER TABLE governance_events     ENABLE ROW LEVEL SECURITY;
ALTER TABLE ops_metrics_events    ENABLE ROW LEVEL SECURITY;
ALTER TABLE admin_audit_events    ENABLE ROW LEVEL SECURITY;

-- Optional: force RLS even for table owners (recommended in production)
ALTER TABLE clinics               FORCE ROW LEVEL SECURITY;
ALTER TABLE users                 FORCE ROW LEVEL SECURITY;
ALTER TABLE user_invites          FORCE ROW LEVEL SECURITY;
ALTER TABLE clinic_policies       FORCE ROW LEVEL SECURITY;
ALTER TABLE clinic_policy_state   FORCE ROW LEVEL SECURITY;
ALTER TABLE clinic_privacy_profile FORCE ROW LEVEL SECURITY;
ALTER TABLE governance_events     FORCE ROW LEVEL SECURITY;
ALTER TABLE ops_metrics_events    FORCE ROW LEVEL SECURITY;
ALTER TABLE admin_audit_events    FORCE ROW LEVEL SECURITY;

-- Policy pattern: only allow rows where clinic_id == app_current_clinic_id()
-- NOTE: For INSERT/UPDATE, WITH CHECK enforces tenant binding as well.

-- clinics
DROP POLICY IF EXISTS rls_clinics_tenant ON clinics;
CREATE POLICY rls_clinics_tenant ON clinics
  USING (clinic_id = app_current_clinic_id())
  WITH CHECK (clinic_id = app_current_clinic_id());

-- users
DROP POLICY IF EXISTS rls_users_tenant ON users;
CREATE POLICY rls_users_tenant ON users
  USING (clinic_id = app_current_clinic_id())
  WITH CHECK (clinic_id = app_current_clinic_id());

-- user_invites
DROP POLICY IF EXISTS rls_user_invites_tenant ON user_invites;
CREATE POLICY rls_user_invites_tenant ON user_invites
  USING (clinic_id = app_current_clinic_id())
  WITH CHECK (clinic_id = app_current_clinic_id());

-- clinic_policies
DROP POLICY IF EXISTS rls_clinic_policies_tenant ON clinic_policies;
CREATE POLICY rls_clinic_policies_tenant ON clinic_policies
  USING (clinic_id = app_current_clinic_id())
  WITH CHECK (clinic_id = app_current_clinic_id());

-- clinic_policy_state
DROP POLICY IF EXISTS rls_clinic_policy_state_tenant ON clinic_policy_state;
CREATE POLICY rls_clinic_policy_state_tenant ON clinic_policy_state
  USING (clinic_id = app_current_clinic_id())
  WITH CHECK (clinic_id = app_current_clinic_id());

-- clinic_privacy_profile
DROP POLICY IF EXISTS rls_privacy_profile_tenant ON clinic_privacy_profile;
CREATE POLICY rls_privacy_profile_tenant ON clinic_privacy_profile
  USING (clinic_id = app_current_clinic_id())
  WITH CHECK (clinic_id = app_current_clinic_id());

-- governance_events
DROP POLICY IF EXISTS rls_governance_events_tenant ON governance_events;
CREATE POLICY rls_governance_events_tenant ON governance_events
  USING (clinic_id = app_current_clinic_id())
  WITH CHECK (clinic_id = app_current_clinic_id());

-- ops_metrics_events
DROP POLICY IF EXISTS rls_ops_metrics_events_tenant ON ops_metrics_events;
CREATE POLICY rls_ops_metrics_events_tenant ON ops_metrics_events
  USING (clinic_id = app_current_clinic_id())
  WITH CHECK (clinic_id = app_current_clinic_id());

-- admin_audit_events
DROP POLICY IF EXISTS rls_admin_audit_events_tenant ON admin_audit_events;
CREATE POLICY rls_admin_audit_events_tenant ON admin_audit_events
  USING (clinic_id = app_current_clinic_id())
  WITH CHECK (clinic_id = app_current_clinic_id());

COMMIT;

-- ---------- Important implementation notes ----------
-- 1) Login/Auth with RLS:
--    Because RLS requires app.clinic_id, your login flow should either:
--      A) take clinic identifier first (subdomain/clinic code), set app.clinic_id, then query users, OR
--      B) perform the login query via a SECURITY DEFINER function that checks credentials and returns clinic_id/user_id.
--
-- 2) Always set app.clinic_id at the start of each request handler before hitting tenant tables.
--
-- 3) For background jobs (retention pruning), set app.clinic_id in the DB session per clinic before deleting rows.

BEGIN;

-- 1) Add a human-friendly unique clinic code / subdomain slug
ALTER TABLE clinics
  ADD COLUMN IF NOT EXISTS clinic_slug text;

-- 2) Backfill for existing rows (optional; you can do this in app code instead)
-- UPDATE clinics SET clinic_slug = lower(regexp_replace(clinic_name, '[^a-zA-Z0-9]+', '-', 'g'))
-- WHERE clinic_slug IS NULL;

-- 3) Enforce slug presence + uniqueness (once you’ve backfilled)
-- If you already have clinics in prod, do this in two steps:
--   (a) backfill
--   (b) then set NOT NULL
ALTER TABLE clinics
  ALTER COLUMN clinic_slug SET NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS ux_clinics_slug
  ON clinics (clinic_slug);

-- Helpful index for login
CREATE INDEX IF NOT EXISTS idx_users_clinic_email
  ON users (clinic_id, email);

COMMIT;
