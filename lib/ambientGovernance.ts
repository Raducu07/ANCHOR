// lib/ambientGovernance.ts
//
// M6.13 - Ambient Governance shell API client (internal preview,
// extreme caution surface).
//
// Backend contract: docs/operations/fable_frontend_experiment/
// 2026-07-05_backend_contract_map.md.
//
// Hard boundaries:
//   * ANCHOR is the governance layer around ambient/scribe workflows.
//     It is not the scribe: no transcript, no audio, no note content
//     exists anywhere in this contract, and no create/upload UI is
//     built in this experiment. This client exposes list, review-gate,
//     and summary reads only.
//   * Every backend endpoint returns 503 ambient_governance_disabled
//     unless the backend flag is enabled. The UI treats 503 as the
//     normal, expected "ingestion disabled" posture - not an error.
//   * Review decisions are bounded categories; never note content.

import { apiFetch } from "@/lib/api";

export type AmbientEventType =
  | "consult_recorded"
  | "note_generated"
  | "note_reviewed_externally"
  | "other";

export type AmbientReviewStatus = "pending_review" | "reviewed" | "discarded";

export type AmbientReviewDecision =
  | "approved_for_record"
  | "amended_before_use"
  | "rejected";

export const AMBIENT_REVIEW_DECISIONS: {
  value: AmbientReviewDecision;
  label: string;
  description: string;
}[] = [
  {
    value: "approved_for_record",
    label: "Approved for record",
    description:
      "The clinic reviewed the externally produced output and accepted it into the clinic's own systems.",
  },
  {
    value: "amended_before_use",
    label: "Amended before use",
    description:
      "The clinic amended the externally produced output before using it. The amendment lives in the clinic's own systems.",
  },
  {
    value: "rejected",
    label: "Rejected",
    description:
      "The clinic rejected the externally produced output. The event is recorded as discarded.",
  },
];

export type AmbientEvent = {
  ambient_event_id: string;
  source_label: string;
  event_type: AmbientEventType;
  occurred_at: string;
  duration_seconds: number | null;
  workflow_reference_hash: string | null;
  review_status: AmbientReviewStatus;
  review_decision: AmbientReviewDecision | null;
  reviewed_at: string | null;
  created_at: string;
  ambient_note: string;
};

export type AmbientEventListResponse = {
  events: AmbientEvent[];
  ambient_note: string;
};

export type AmbientSummaryResponse = {
  pending_review_count: number;
  reviewed_count: number;
  discarded_count: number;
  latest_event_at: string | null;
  ambient_note: string;
};

const BASE = "/v1/portal/ambient";

export function listAmbientEvents(
  reviewStatus?: AmbientReviewStatus,
): Promise<AmbientEventListResponse> {
  const url = reviewStatus
    ? `${BASE}/events?review_status=${encodeURIComponent(reviewStatus)}`
    : `${BASE}/events`;
  return apiFetch<AmbientEventListResponse>(url);
}

export function reviewAmbientEvent(
  ambientEventId: string,
  decision: AmbientReviewDecision,
): Promise<AmbientEvent> {
  return apiFetch<AmbientEvent>(
    `${BASE}/events/${encodeURIComponent(ambientEventId)}/review`,
    {
      method: "POST",
      body: JSON.stringify({ review_decision: decision }),
    },
  );
}

export function getAmbientSummary(): Promise<AmbientSummaryResponse> {
  return apiFetch<AmbientSummaryResponse>(`${BASE}/summary`);
}
