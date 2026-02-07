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

CREATE INDEX IF NOT EXISTS idx_messages_session_created
  ON messages(session_id, created_at ASC);

CREATE INDEX IF NOT EXISTS idx_messages_session_role_created
  ON messages(session_id, role, created_at ASC);

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

CREATE INDEX IF NOT EXISTS idx_memories_user_active
  ON memories(user_id, active);

CREATE INDEX IF NOT EXISTS idx_memories_user_kind
  ON memories(user_id, kind);

CREATE INDEX IF NOT EXISTS idx_memories_user_created
  ON memories(user_id, created_at DESC);

-- ==================================
-- A3: governance audit events table
-- ==================================

CREATE TABLE IF NOT EXISTS governance_events (
  id UUID PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  session_id UUID REFERENCES sessions(id) ON DELETE SET NULL,

  mode TEXT NOT NULL DEFAULT 'witness',

  allowed BOOLEAN NOT NULL,
  replaced BOOLEAN NOT NULL,

  score INTEGER NOT NULL,
  grade TEXT NOT NULL,
  reason TEXT NOT NULL,

  findings JSONB NOT NULL DEFAULT '[]'::jsonb,
  decision JSONB NOT NULL DEFAULT '{}'::jsonb,
  notes JSONB NOT NULL DEFAULT '{}'::jsonb,

  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_governance_events_user_created
  ON governance_events(user_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_governance_events_session_created
  ON governance_events(session_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_governance_events_created
  ON governance_events(created_at DESC);
;
