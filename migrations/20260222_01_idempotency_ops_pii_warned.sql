-- 20260222_01_idempotency_ops_pii_warned.sql
-- Enforces idempotency per clinic + request_id
-- Safe to run repeatedly.

-- 1) Ensure ops_metrics_events has pii_warned (schema sync)
ALTER TABLE ops_metrics_events
  ADD COLUMN IF NOT EXISTS pii_warned boolean NOT NULL DEFAULT false;

-- 2) DEDUPE any existing duplicates BEFORE adding unique indexes
-- Keep the earliest created_at row per (clinic_id, request_id)
WITH ranked AS (
  SELECT
    ctid,
    clinic_id,
    request_id,
    created_at,
    row_number() OVER (
      PARTITION BY clinic_id, request_id
      ORDER BY created_at ASC, ctid ASC
    ) AS rn
  FROM ops_metrics_events
)
DELETE FROM ops_metrics_events o
USING ranked r
WHERE o.ctid = r.ctid
  AND r.rn > 1;

WITH ranked AS (
  SELECT
    ctid,
    clinic_id,
    request_id,
    created_at,
    row_number() OVER (
      PARTITION BY clinic_id, request_id
      ORDER BY created_at ASC, ctid ASC
    ) AS rn
  FROM clinic_governance_events
)
DELETE FROM clinic_governance_events g
USING ranked r
WHERE g.ctid = r.ctid
  AND r.rn > 1;

-- 3) Enforce idempotency (hard guarantee)
CREATE UNIQUE INDEX IF NOT EXISTS uq_cge_clinic_request
  ON clinic_governance_events (clinic_id, request_id);

CREATE UNIQUE INDEX IF NOT EXISTS uq_ome_clinic_request
  ON ops_metrics_events (clinic_id, request_id);

-- 4) Optional performance helpers for KPI aggregation
CREATE INDEX IF NOT EXISTS idx_ome_clinic_route_created
  ON ops_metrics_events (clinic_id, route, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_ome_clinic_mode_created
  ON ops_metrics_events (clinic_id, mode, created_at DESC);
