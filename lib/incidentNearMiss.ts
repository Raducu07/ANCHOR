// lib/incidentNearMiss.ts
//
// Phase 2A-5 - Incident / Near-Miss Logging API client.
//
// Doctrine:
//   * Metadata-only. The frontend never carries free-text narratives,
//     clinical content, transcripts, identifiers, or raw prompts and
//     outputs. Records are bounded enums + structural links only.
//   * Endpoints are clinic-scoped on the backend (RLS); the frontend
//     does not pass clinic_id explicitly.
//   * Query string parameter names mirror the backend snake_case
//     contract.
//   * Standard apiFetch flow; standard ApiError propagation.

import { apiFetch } from "@/lib/api";
import type {
  IncidentNearMissCategory,
  IncidentNearMissCreateRequest,
  IncidentNearMissRecordListResponse,
  IncidentNearMissRecordResponse,
  IncidentNearMissReviewRequest,
  IncidentNearMissSeverity,
  IncidentNearMissSource,
  IncidentNearMissStatus,
  IncidentNearMissSummaryResponse,
  IncidentNearMissUpdateRequest,
  IncidentNearMissVocabularyResponse,
  IncidentNearMissVoidRequest,
} from "@/lib/types";

const BASE = "/v1/governance/incidents";

type ListOpts = {
  status?: IncidentNearMissStatus;
  severity?: IncidentNearMissSeverity;
  category?: IncidentNearMissCategory;
  source?: IncidentNearMissSource;
  linkedReceiptId?: string;
  limit?: number;
};

function buildListQuery(opts: ListOpts): string {
  const query = new URLSearchParams();
  if (opts.status) query.set("status", opts.status);
  if (opts.severity) query.set("severity", opts.severity);
  if (opts.category) query.set("category", opts.category);
  if (opts.source) query.set("source", opts.source);
  if (opts.linkedReceiptId) query.set("linked_receipt_id", opts.linkedReceiptId);
  if (typeof opts.limit === "number") query.set("limit", String(opts.limit));
  return query.toString();
}

// ----- Vocabulary -----------------------------------------------------

export function getIncidentNearMissVocabulary(): Promise<IncidentNearMissVocabularyResponse> {
  return apiFetch<IncidentNearMissVocabularyResponse>(`${BASE}/vocabulary`);
}

// ----- Records --------------------------------------------------------

export function createIncidentNearMissRecord(
  input: IncidentNearMissCreateRequest,
): Promise<IncidentNearMissRecordResponse> {
  return apiFetch<IncidentNearMissRecordResponse>(`${BASE}/records`, {
    method: "POST",
    body: JSON.stringify(input),
  });
}

export function listIncidentNearMissRecords(
  opts: ListOpts = {},
): Promise<IncidentNearMissRecordListResponse> {
  const qs = buildListQuery(opts);
  const url = qs ? `${BASE}/records?${qs}` : `${BASE}/records`;
  return apiFetch<IncidentNearMissRecordListResponse>(url);
}

export function listMyIncidentNearMissRecords(
  opts: ListOpts = {},
): Promise<IncidentNearMissRecordListResponse> {
  const qs = buildListQuery(opts);
  const url = qs ? `${BASE}/records/mine?${qs}` : `${BASE}/records/mine`;
  return apiFetch<IncidentNearMissRecordListResponse>(url);
}

export function getIncidentNearMissRecord(
  incidentId: string,
): Promise<IncidentNearMissRecordResponse> {
  return apiFetch<IncidentNearMissRecordResponse>(
    `${BASE}/records/${encodeURIComponent(incidentId)}`,
  );
}

export function updateIncidentNearMissRecord(
  incidentId: string,
  input: IncidentNearMissUpdateRequest,
): Promise<IncidentNearMissRecordResponse> {
  return apiFetch<IncidentNearMissRecordResponse>(
    `${BASE}/records/${encodeURIComponent(incidentId)}`,
    {
      method: "PATCH",
      body: JSON.stringify(input),
    },
  );
}

export function reviewIncidentNearMissRecord(
  incidentId: string,
  input: IncidentNearMissReviewRequest = {},
): Promise<IncidentNearMissRecordResponse> {
  return apiFetch<IncidentNearMissRecordResponse>(
    `${BASE}/records/${encodeURIComponent(incidentId)}/review`,
    {
      method: "POST",
      body: JSON.stringify(input),
    },
  );
}

export function closeIncidentNearMissRecord(
  incidentId: string,
): Promise<IncidentNearMissRecordResponse> {
  return apiFetch<IncidentNearMissRecordResponse>(
    `${BASE}/records/${encodeURIComponent(incidentId)}/close`,
    {
      method: "POST",
      body: JSON.stringify({}),
    },
  );
}

export function voidIncidentNearMissRecord(
  incidentId: string,
  input: IncidentNearMissVoidRequest,
): Promise<IncidentNearMissRecordResponse> {
  return apiFetch<IncidentNearMissRecordResponse>(
    `${BASE}/records/${encodeURIComponent(incidentId)}/void`,
    {
      method: "POST",
      body: JSON.stringify(input),
    },
  );
}

// ----- Summary --------------------------------------------------------

export function getIncidentNearMissSummary(
  opts: { windowDays?: number } = {},
): Promise<IncidentNearMissSummaryResponse> {
  const query = new URLSearchParams();
  if (typeof opts.windowDays === "number") {
    query.set("window_days", String(opts.windowDays));
  }
  const qs = query.toString();
  const url = qs ? `${BASE}/summary?${qs}` : `${BASE}/summary`;
  return apiFetch<IncidentNearMissSummaryResponse>(url);
}
