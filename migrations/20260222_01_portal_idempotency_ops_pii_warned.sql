-- 20260222_01_portal_idempotency_ops_pii_warned.sql
-- Portal V1: schema sync + idempotency guarantees

ALTER TABLE ops_metrics_events
  ADD COLUMN IF NOT EXISTS pii_warned boolean NOT NULL DEFAULT false;

CREATE UNIQUE INDEX IF NOT EXISTS uq_cge_clinic_request
  ON clinic_governance_events (clinic_id, request_id);

CREATE UNIQUE INDEX IF NOT EXISTS uq_ome_clinic_request
  ON ops_metrics_events (clinic_id, request_id);
