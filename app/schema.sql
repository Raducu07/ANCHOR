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

-- =========================
-- ANCHOR v1: memories table
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

CREATE INDEX IF NOT EXISTS idx_memories_user_active ON memories(user_id, active);
CREATE INDEX IF NOT EXISTS idx_memories_user_kind ON memories(user_id, kind);

-- =========================
-- ANCHOR A3: governance audit table
-- =========================

CREATE TABLE IF NOT EXISTS governance_events (
  id UUID PRIMARY KEY,

  user_id UUID REFERENCES users(id) ON DELETE SET NULL,
  session_id UUID REFERENCES sessions(id) ON DELETE SET NULL,

  mode TEXT NOT NULL DEFAULT 'witness',

  -- Flattened decision fields (easy queries)
  allowed BOOLEAN NOT NULL,
  replaced BOOLEAN NOT NULL,
  score INT NOT NULL,
  grade TEXT NOT NULL,
  reason TEXT NOT NULL,

  -- Scorer findings (small, structured)
  findings JSONB NOT NULL DEFAULT '[]'::jsonb,

  -- Full audit payload (optional, but useful for forensics)
  audit JSONB NOT NULL DEFAULT '{}'::jsonb,

  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_governance_events_user_created
  ON governance_events(user_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_governance_events_session_created
  ON governance_events(session_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_governance_events_created
  ON governance_events(created_at DESC);

-- =========================
-- A4: policy/versioning + deterministic decision trace
-- (safe, idempotent upgrades)
-- =========================

ALTER TABLE governance_events
  ADD COLUMN IF NOT EXISTS policy_version TEXT NOT NULL DEFAULT 'gov-v1.0';

ALTER TABLE governance_events
  ADD COLUMN IF NOT EXISTS neutrality_version TEXT NOT NULL DEFAULT 'n-v1.1';

-- Compact deterministic explanation:
-- {
--   "min_score_allow": 75,
--   "hard_block_rules": ["jailbreak","therapy","promise"],
--   "soft_rules": ["direct_advice","coercion"],
--   "triggered_rule_ids": ["direct_advice"],
--   "score": 92,
--   "grade": "pass",
--   "replaced": false,
--   "reason": "allowed"
-- }
ALTER TABLE governance_events
  ADD COLUMN IF NOT EXISTS decision_trace JSONB NOT NULL DEFAULT '{}'::jsonb;

-- Helpful index for audits by policy / neutrality versions
CREATE INDEX IF NOT EXISTS idx_governance_events_policy_version
  ON governance_events(policy_version, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_governance_events_neutrality_version
  ON governance_events(neutrality_version, created_at DESC);

-- =========================
-- A4: governance config (institution-friendly, auditable settings)
-- =========================

CREATE TABLE IF NOT EXISTS governance_config (
  id UUID PRIMARY KEY,
  policy_version TEXT NOT NULL,
  neutrality_version TEXT NOT NULL,

  min_score_allow INT NOT NULL DEFAULT 75,

  hard_block_rules JSONB NOT NULL DEFAULT '["jailbreak","therapy","promise"]'::jsonb,
  soft_rules JSONB NOT NULL DEFAULT '["direct_advice","coercion"]'::jsonb,

  -- optional future knobs
  max_findings INT NOT NULL DEFAULT 10,

  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Ensure we only have one active config row by convention (not strict constraint)
CREATE INDEX IF NOT EXISTS idx_governance_config_updated
  ON governance_config(updated_at DESC);
