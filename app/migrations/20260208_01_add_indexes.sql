-- Governance events: window queries + ordered pagination + retention
CREATE INDEX IF NOT EXISTS ix_governance_events_created_at
  ON governance_events (created_at);

CREATE INDEX IF NOT EXISTS ix_governance_events_created_at_id
  ON governance_events (created_at DESC, id DESC);

CREATE INDEX IF NOT EXISTS ix_governance_events_user_created
  ON governance_events (user_id, created_at DESC);

CREATE INDEX IF NOT EXISTS ix_governance_events_session_created
  ON governance_events (session_id, created_at DESC);

-- Messages: session listing + retention deletes
CREATE INDEX IF NOT EXISTS ix_messages_session_created
  ON messages (session_id, created_at ASC);

CREATE INDEX IF NOT EXISTS ix_messages_created_at
  ON messages (created_at);

-- Sessions: per-user and retention/orphan pruning
CREATE INDEX IF NOT EXISTS ix_sessions_user_created
  ON sessions (user_id, created_at DESC);

CREATE INDEX IF NOT EXISTS ix_sessions_created_at
  ON sessions (created_at);
