-- =========================
-- ANCHOR schema.sql (BOOT-SAFE for Render startup)
-- PostgreSQL
-- Idempotent: safe to run repeatedly.
--
-- IMPORTANT:
--  - NO DO $$ blocks at startup
--  - NO RLS ENABLE / POLICIES at startup (apply once via security.sql)
--  - NO SECURITY DEFINER at startup (apply once via security.sql)
-- =========================

-- Extensions
CREATE EXTENSION IF NOT EXISTS pgcrypto; -- gen_random_uuid()
CREATE EXTENSION IF NOT EXISTS citext;

-- =========================
-- Core tables (v0)
-- =========================

CREATE TABLE IF NOT EXISTS users (
  id uuid PRIMARY KEY,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS sessions (
  id uuid PRIMARY KEY,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  mode text NOT NULL DEFAULT 'witness',
  question_used boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS messages (
  id uuid PRIMARY KEY,
  session_id uuid NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
  role text NOT NULL CHECK (role IN ('user','assistant','system')),
  content text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

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
  id uuid PRIMARY KEY,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,

  kind text NOT NULL CHECK (kind IN (
    'recurring_tension',
    'unexpressed_axis',
    'values_vs_emphasis',
    'decision_posture',
    'negative_space'
  )),

  statement text NOT NULL,
  evidence_session_ids jsonb NOT NULL DEFAULT '[]'::jsonb,

  confidence text NOT NULL CHECK (confidence IN ('tentative','emerging','consistent')),
  active boolean NOT NULL DEFAULT true,

  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_memories_user_active
  ON memories(user_id, active);

CREATE INDEX IF NOT EXISTS idx_memories_user_kind
  ON memories(user_id, kind);

CREATE INDEX IF NOT EXISTS idx_memories_user_active_created
  ON memories(user_id, active, created_at DESC);

-- =========================
-- Memory offers
-- =========================

CREATE TABLE IF NOT EXISTS memory_offers (
  id uuid PRIMARY KEY,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,

  kind text NOT NULL CHECK (kind IN (
    'recurring_tension',
    'unexpressed_axis',
    'values_vs_emphasis',
    'decision_posture',
    'negative_space'
  )),

  statement text NOT NULL,
  evidence_session_ids jsonb NOT NULL DEFAULT '[]'::jsonb,
  confidence text NOT NULL CHECK (confidence IN ('tentative','emerging','consistent')),

  basis jsonb NOT NULL DEFAULT '{}'::jsonb,

  status text NOT NULL CHECK (status IN ('proposed','accepted','rejected','expired'))
    DEFAULT 'proposed',

  created_at timestamptz NOT NULL DEFAULT now(),
  decided_at timestamptz NULL
);

CREATE INDEX IF NOT EXISTS idx_memory_offers_user_created
  ON memory_offers(user_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_memory_offers_user_status_created
  ON memory_offers(user_id, status, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_memory_offers_user_id_status
  ON memory_offers(user_id, status);

-- =========================
-- Governance events (v0)
-- =========================

CREATE TABLE IF NOT EXISTS governance_events (
  id uuid PRIMARY KEY,

  user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  session_id uuid REFERENCES sessions(id) ON DELETE SET NULL,

  mode text NOT NULL DEFAULT 'witness',

  allowed boolean NOT NULL,
  replaced boolean NOT NULL,
  score int NOT NULL,
  grade text NOT NULL,
  reason text NOT NULL,

  findings jsonb NOT NULL DEFAULT '[]'::jsonb,
  audit jsonb NOT NULL DEFAULT '{}'::jsonb,

  policy_version text NOT NULL DEFAULT 'gov-v1.0',
  neutrality_version text NOT NULL DEFAULT 'n-v1.1',
  decision_trace jsonb NOT NULL DEFAULT '{}'::jsonb,

  created_at timestamptz NOT NULL DEFAULT now()
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

CREATE INDEX IF NOT EXISTS idx_governance_events_decision_trace_gin
  ON governance_events USING GIN (decision_trace);

-- =========================
-- Governance config
-- =========================

CREATE TABLE IF NOT EXISTS governance_config (
  id uuid PRIMARY KEY,
  policy_version text NOT NULL,
  neutrality_version text NOT NULL,

  min_score_allow int NOT NULL DEFAULT 75,

  hard_block_rules jsonb NOT NULL DEFAULT '["jailbreak","therapy","promise"]'::jsonb,
  soft_rules jsonb NOT NULL DEFAULT '["direct_advice","coercion"]'::jsonb,

  max_findings int NOT NULL DEFAULT 10,

  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_governance_config_updated
  ON governance_config(updated_at DESC);

INSERT INTO governance_config (
  id, policy_version, neutrality_version, min_score_allow,
  hard_block_rules, soft_rules, max_findings
)
SELECT
  gen_random_uuid(), 'gov-v1.0', 'n-v1.1', 75,
  '["jailbreak","therapy","promise"]'::jsonb,
  '["direct_advice","coercion"]'::jsonb,
  10
WHERE NOT EXISTS (SELECT 1 FROM governance_config);

-- =========================
-- Ops time-series buckets (mode-aware)
-- =========================

CREATE TABLE IF NOT EXISTS ops_timeseries_buckets (
  id uuid PRIMARY KEY,
  bucket_start timestamptz NOT NULL,
  bucket_sec int NOT NULL,
  route text NOT NULL DEFAULT '__all__',
  mode text NOT NULL DEFAULT '__all__',

  request_count int NOT NULL DEFAULT 0,
  rate_5xx double precision NOT NULL DEFAULT 0,
  p95_latency_ms int NOT NULL DEFAULT 0,
  avg_latency_ms double precision NOT NULL DEFAULT 0,

  gov_events_total int NOT NULL DEFAULT 0,
  gov_replaced_rate double precision NOT NULL DEFAULT 0,
  gov_avg_score double precision NOT NULL DEFAULT 0,

  policy_version text,
  neutrality_version text,
  min_score_allow int,
  hard_rules_count int,
  soft_rules_count int,
  strictness_score double precision NOT NULL DEFAULT 0,

  created_at timestamptz NOT NULL DEFAULT now()
);

-- Ensure mode exists (back-compat)
ALTER TABLE ops_timeseries_buckets
  ADD COLUMN IF NOT EXISTS mode text NOT NULL DEFAULT '__all__';

-- Drop old indexes safely (no DO blocks)
DROP INDEX IF EXISTS idx_ops_timeseries_unique;
DROP INDEX IF EXISTS idx_ops_timeseries_bucket_route_sec_start;

CREATE UNIQUE INDEX IF NOT EXISTS idx_ops_timeseries_unique_mode
  ON ops_timeseries_buckets (bucket_start, bucket_sec, route, mode);

CREATE INDEX IF NOT EXISTS idx_ops_timeseries_bucket_start
  ON ops_timeseries_buckets (bucket_start DESC);

CREATE INDEX IF NOT EXISTS idx_ops_timeseries_bucket_route_mode_sec_start
  ON ops_timeseries_buckets (bucket_sec, route, mode, bucket_start DESC);

CREATE INDEX IF NOT EXISTS idx_ops_timeseries_bucket_mode_sec_start
  ON ops_timeseries_buckets (bucket_sec, mode, bucket_start DESC);

CREATE INDEX IF NOT EXISTS brin_ops_timeseries_bucket_start
  ON ops_timeseries_buckets USING BRIN (bucket_start);

-- =========================
-- Portal V1: tenant context helpers
-- =========================

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

-- =========================
-- Portal V1: tenant tables
-- =========================

CREATE TABLE IF NOT EXISTS clinics (
  clinic_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  clinic_name text NOT NULL,
  clinic_slug citext UNIQUE NOT NULL,
  subscription_tier text NOT NULL DEFAULT 'starter',
  active_status boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS clinic_users (
  user_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  clinic_id uuid NOT NULL REFERENCES clinics(clinic_id) ON DELETE CASCADE,
  role text NOT NULL CHECK (role IN ('admin','staff')),
  email citext NOT NULL,
  password_hash text NOT NULL,
  active_status boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (clinic_id, email)
);

CREATE INDEX IF NOT EXISTS idx_clinic_users_clinic_email
  ON clinic_users (clinic_id, email);

CREATE TABLE IF NOT EXISTS clinic_user_invites (
  invite_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  clinic_id uuid NOT NULL REFERENCES clinics(clinic_id) ON DELETE CASCADE,
  email citext NOT NULL,
  role text NOT NULL CHECK (role IN ('admin','staff')),
  token_hash text NOT NULL,
  expires_at timestamptz NOT NULL,
  used_at timestamptz,
  created_by uuid REFERENCES clinic_users(user_id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_clinic_user_invites_clinic_expires
  ON clinic_user_invites (clinic_id, expires_at DESC);

CREATE TABLE IF NOT EXISTS clinic_policies (
  clinic_id uuid NOT NULL REFERENCES clinics(clinic_id) ON DELETE CASCADE,
  policy_version integer NOT NULL,
  policy_json jsonb NOT NULL,
  created_by uuid NOT NULL REFERENCES clinic_users(user_id) ON DELETE RESTRICT,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (clinic_id, policy_version)
);

CREATE TABLE IF NOT EXISTS clinic_policy_state (
  clinic_id uuid PRIMARY KEY REFERENCES clinics(clinic_id) ON DELETE CASCADE,
  active_policy_version integer NOT NULL,
  updated_by uuid NOT NULL REFERENCES clinic_users(user_id) ON DELETE RESTRICT,
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS clinic_privacy_profile (
  clinic_id uuid PRIMARY KEY REFERENCES clinics(clinic_id) ON DELETE CASCADE,
  data_region text NOT NULL CHECK (data_region IN ('UK','EU')),
  retention_days_governance integer NOT NULL DEFAULT 90 CHECK (retention_days_governance BETWEEN 1 AND 3650),
  retention_days_ops integer NOT NULL DEFAULT 30 CHECK (retention_days_ops BETWEEN 1 AND 3650),
  export_enabled boolean NOT NULL DEFAULT false,
  dpa_accepted_at timestamptz,
  subprocessor_ack_at timestamptz,
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS clinic_governance_events (
  event_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  clinic_id uuid NOT NULL REFERENCES clinics(clinic_id) ON DELETE CASCADE,
  request_id uuid NOT NULL,
  user_id uuid NOT NULL REFERENCES clinic_users(user_id) ON DELETE RESTRICT,
  mode text NOT NULL CHECK (mode IN ('clinical_note','client_comm','internal_summary')),

  pii_detected boolean NOT NULL DEFAULT false,
  pii_action text NOT NULL CHECK (pii_action IN ('allow','warn','block','redact')),
  pii_types text[] NOT NULL DEFAULT ARRAY[]::text[],

  decision text NOT NULL CHECK (decision IN ('allowed','blocked','replaced','modified')),
  risk_grade text NOT NULL CHECK (risk_grade IN ('low','med','high')),
  reason_code text NOT NULL,

  governance_score double precision,
  policy_version integer NOT NULL,
  neutrality_version text NOT NULL DEFAULT 'v1.1',
  created_at timestamptz NOT NULL DEFAULT now()
);

-- ============================================================
-- Portal R1–R3 (tenant table): AI usage + review + override log
-- Table: clinic_governance_events
-- Boot-safe + idempotent
-- ============================================================

ALTER TABLE IF EXISTS clinic_governance_events
  ADD COLUMN IF NOT EXISTS ai_assisted boolean;

ALTER TABLE IF EXISTS clinic_governance_events
  ADD COLUMN IF NOT EXISTS user_confirmed_review boolean;

ALTER TABLE IF EXISTS clinic_governance_events
  ADD COLUMN IF NOT EXISTS override_flag boolean;

ALTER TABLE IF EXISTS clinic_governance_events
  ADD COLUMN IF NOT EXISTS override_reason text;

ALTER TABLE IF EXISTS clinic_governance_events
  ADD COLUMN IF NOT EXISTS override_at timestamptz;

-- Defaults (safe; does not rewrite old rows)
ALTER TABLE IF EXISTS clinic_governance_events
  ALTER COLUMN ai_assisted SET DEFAULT false;

ALTER TABLE IF EXISTS clinic_governance_events
  ALTER COLUMN user_confirmed_review SET DEFAULT true;

ALTER TABLE IF EXISTS clinic_governance_events
  ALTER COLUMN override_flag SET DEFAULT false;

CREATE UNIQUE INDEX IF NOT EXISTS uq_cge_clinic_request
  ON clinic_governance_events (clinic_id, request_id);

CREATE INDEX IF NOT EXISTS idx_clinic_gov_events_clinic_created_at
  ON clinic_governance_events (clinic_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_cge_clinic_created_request
  ON clinic_governance_events (clinic_id, created_at DESC, request_id DESC);

-- ============================================================
-- M2.7 Hardening: explainability + tamper evidence
-- Table: clinic_governance_events
-- Boot-safe + idempotent
-- ============================================================

ALTER TABLE IF EXISTS clinic_governance_events
  ADD COLUMN IF NOT EXISTS policy_sha256 text;

ALTER TABLE IF EXISTS clinic_governance_events
  ADD COLUMN IF NOT EXISTS rules_fired jsonb;

-- Optional: app can populate a hash of canonical event JSON
ALTER TABLE IF EXISTS clinic_governance_events
  ADD COLUMN IF NOT EXISTS event_sha256 text;

CREATE TABLE IF NOT EXISTS ops_metrics_events (
  event_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  clinic_id uuid NOT NULL REFERENCES clinics(clinic_id) ON DELETE CASCADE,
  request_id uuid NOT NULL,
  route text NOT NULL,
  status_code integer NOT NULL CHECK (status_code BETWEEN 100 AND 599),
  latency_ms integer NOT NULL CHECK (latency_ms >= 0),
  mode text CHECK (mode IN ('clinical_note','client_comm','internal_summary')),
  governance_replaced boolean NOT NULL DEFAULT false,
  pii_warned boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_ome_clinic_request
  ON ops_metrics_events (clinic_id, request_id);

CREATE INDEX IF NOT EXISTS idx_ops_metrics_events_clinic_created_at
  ON ops_metrics_events (clinic_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_ome_clinic_created_request
  ON ops_metrics_events (clinic_id, created_at DESC, request_id DESC);

CREATE INDEX IF NOT EXISTS idx_ome_clinic_route_created
  ON ops_metrics_events (clinic_id, route, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_ome_clinic_mode_created
  ON ops_metrics_events (clinic_id, mode, created_at DESC);

CREATE TABLE IF NOT EXISTS admin_audit_events (
  event_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  clinic_id uuid NOT NULL REFERENCES clinics(clinic_id) ON DELETE CASCADE,
  admin_user_id uuid NOT NULL REFERENCES clinic_users(user_id) ON DELETE RESTRICT,
  action text NOT NULL,
  target_id uuid,
  ip_hash text,
  created_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE IF EXISTS admin_audit_events
  ADD COLUMN IF NOT EXISTS meta jsonb NOT NULL DEFAULT '{}'::jsonb;

-- ============================================================
-- M2.7 Hardening: DB-enforced idempotency for admin actions
-- Table: admin_audit_events
-- Boot-safe + idempotent
-- ============================================================

ALTER TABLE IF EXISTS admin_audit_events
  ADD COLUMN IF NOT EXISTS idempotency_key text;

-- DB-enforced idempotency (partial unique index allows NULL)
CREATE UNIQUE INDEX IF NOT EXISTS admin_audit_events_idem_uq
  ON admin_audit_events (clinic_id, action, idempotency_key)
  WHERE idempotency_key IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_admin_audit_events_clinic_created_at
  ON admin_audit_events (clinic_id, created_at DESC);

-- Needed for fast "latest override" LATERAL join by target_id
CREATE INDEX IF NOT EXISTS idx_admin_audit_events_clinic_target_created
  ON admin_audit_events (clinic_id, target_id, created_at DESC);

-- Helpful for filtering/timelines by action
CREATE INDEX IF NOT EXISTS idx_admin_audit_events_clinic_action_created
  ON admin_audit_events (clinic_id, action, created_at DESC);

-- =========================
-- Safe public lookup view (boot-safe)
-- =========================

CREATE OR REPLACE VIEW clinics_public AS
SELECT clinic_slug, active_status
FROM clinics;

-- ============================================================
-- M3: Platform admin tokens (hashed-at-rest) + platform audit
-- (DO NOT collide with existing clinic-scoped admin_audit_events)
-- ============================================================

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS platform_admin_tokens (
  token_id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  token_hash       text NOT NULL UNIQUE, -- sha256 hex
  label            text NOT NULL DEFAULT '',
  created_at       timestamptz NOT NULL DEFAULT now(),
  expires_at       timestamptz NULL,
  disabled_at      timestamptz NULL,
  last_used_at     timestamptz NULL,
  last_used_ip_hash text NULL
);

CREATE INDEX IF NOT EXISTS idx_platform_admin_tokens_active
  ON platform_admin_tokens (disabled_at, expires_at);

CREATE TABLE IF NOT EXISTS platform_admin_audit_events (
  event_id       uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  created_at     timestamptz NOT NULL DEFAULT now(),

  admin_token_id uuid NULL REFERENCES platform_admin_tokens(token_id) ON DELETE SET NULL,

  action         text NOT NULL,        -- e.g. "admin.auth", "admin.tokens.create"
  method         text NOT NULL,
  route          text NOT NULL,
  status_code    int  NOT NULL,

  request_id     text NULL,
  ip_hash        text NULL,
  ua_hash        text NULL,

  meta           jsonb NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_platform_admin_audit_created_at
  ON platform_admin_audit_events (created_at DESC);

CREATE INDEX IF NOT EXISTS idx_platform_admin_audit_action
  ON platform_admin_audit_events (action, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_platform_admin_audit_token
  ON platform_admin_audit_events (admin_token_id, created_at DESC);
