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
