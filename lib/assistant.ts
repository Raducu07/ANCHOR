import { apiFetch } from "@/lib/api";
import type {
  AssistantContractResponse,
  AssistantPolicyHistoryResponse,
  AssistantPolicyResponse,
  AssistantPolicyUpdatePayload,
  AssistantReviewStatusInput,
  AssistantRunDetailResponse,
  AssistantRunEnvelope,
  AssistantRunListResponse,
  AssistantRunReceiptResponse,
  AssistantRunRecord,
  AssistantRunReviewUpdateRequest,
  AssistantRunReviewUpdateResponse,
  AssistantRunTraceItem,
} from "@/lib/types";

export function getAssistantContract() {
  return apiFetch<AssistantContractResponse>("/v1/assistant/contracts");
}

// Backend contract (PR 2A + PR 2B):
//   POST /v1/assistant/runs accepts only:
//     mode = "client_communication"
//     input.communication_goal       (non-empty)
//     input.clinician_confirmed_facts (non-empty)
//
//   Persistence is metadata-only (input_sha256, output_sha256, field keys,
//   PII flags, safety flags, governance pointers). Raw input, prompts, and
//   the generated draft are NEVER stored.
//
//   Safe requests may return a transient draft (run_status =
//   "generation_succeeded"). Unsafe clinical requests return
//   run_status = "generation_refused" without invoking the model. Provider
//   failure returns 503.
export const ASSISTANT_MODE_CLIENT_COMMUNICATION = "client_communication" as const;

export type ClientCommunicationInput = {
  communication_goal: string;
  clinician_confirmed_facts: string;
};

export type AssistantRunRequest = {
  mode: typeof ASSISTANT_MODE_CLIENT_COMMUNICATION;
  input: ClientCommunicationInput;
};

export async function submitAssistantRun(req: AssistantRunRequest): Promise<AssistantRunRecord> {
  const result = await apiFetch<AssistantRunEnvelope>("/v1/assistant/runs", {
    method: "POST",
    body: JSON.stringify(req),
  });
  const envelope = result as Record<string, unknown>;
  const run = (envelope.run ?? envelope.record) as AssistantRunRecord | undefined;
  return run ?? (result as unknown as AssistantRunRecord);
}

// M6.3 — Assistant traceability / evidence surface (metadata only).
//
// GET /v1/assistant/runs        — recent metadata records for the clinic
// GET /v1/assistant/runs/:id    — single metadata record by id
//
// Neither endpoint returns raw input, prompts, or draft output. The
// detail response carries explicit storage_policy + draft_stored=false
// assertions for governance evidence.

export type ListAssistantRunsParams = {
  limit?: number;
  run_status?:
    | "created"
    | "generation_succeeded"
    | "generation_refused"
    | "generation_failed";
  mode?: typeof ASSISTANT_MODE_CLIENT_COMMUNICATION;
};

export async function listAssistantRuns(
  params: ListAssistantRunsParams = {},
): Promise<AssistantRunListResponse> {
  const query = new URLSearchParams();
  if (typeof params.limit === "number") query.set("limit", String(params.limit));
  if (params.run_status) query.set("run_status", params.run_status);
  if (params.mode) query.set("mode", params.mode);
  const qs = query.toString();
  const url = qs ? `/v1/assistant/runs?${qs}` : "/v1/assistant/runs";
  return apiFetch<AssistantRunListResponse>(url);
}

export async function getAssistantRun(runId: string): Promise<AssistantRunDetailResponse> {
  return apiFetch<AssistantRunDetailResponse>(
    `/v1/assistant/runs/${encodeURIComponent(runId)}`,
  );
}

export type { AssistantRunTraceItem };

// M6.5 — create-or-return / fetch a metadata-only Assistant receipt.
//
// Receipts are idempotent per (clinic, run): a second POST returns the
// same receipt. The frontend never sends raw input, prompt, or draft —
// the backend snapshots metadata from the existing assistant_runs row.

export async function createAssistantRunReceipt(
  runId: string,
): Promise<AssistantRunReceiptResponse> {
  return apiFetch<AssistantRunReceiptResponse>(
    `/v1/assistant/runs/${encodeURIComponent(runId)}/receipt`,
    {
      method: "POST",
      body: JSON.stringify({}),
    },
  );
}

export async function getAssistantRunReceipt(
  runId: string,
): Promise<AssistantRunReceiptResponse> {
  return apiFetch<AssistantRunReceiptResponse>(
    `/v1/assistant/runs/${encodeURIComponent(runId)}/receipt`,
  );
}

// M6.9.3 — identifier-keyed lookup: accepts either an Assistant receipt
// UUID or an Assistant run UUID, returns the same metadata-only receipt
// response shape plus a `matched_by` discriminator. Clinic-scoped on the
// backend; cross-clinic identifiers 404.
export async function getAssistantReceiptByIdentifier(
  identifier: string,
): Promise<AssistantRunReceiptResponse> {
  return apiFetch<AssistantRunReceiptResponse>(
    `/v1/assistant/receipts/${encodeURIComponent(identifier)}`,
  );
}

// M6.4 — record a metadata-only human review outcome for a single run.
// Reviewer identity comes from the authenticated clinic_user context on
// the backend; this function never sends notes, draft text, or reviewer
// overrides.
export async function updateAssistantRunReview(
  runId: string,
  reviewStatus: AssistantReviewStatusInput,
): Promise<AssistantRunReviewUpdateResponse> {
  const body: AssistantRunReviewUpdateRequest = { review_status: reviewStatus };
  return apiFetch<AssistantRunReviewUpdateResponse>(
    `/v1/assistant/runs/${encodeURIComponent(runId)}/review`,
    {
      method: "PATCH",
      body: JSON.stringify(body),
    },
  );
}

// M6.7 — Assistant policy / settings.
// Metadata-only governance configuration. Hard safety prohibitions
// (no diagnosis, no prescribing, no dosing, no autonomous triage) are
// NOT configurable and are enforced server-side.

export function getAssistantPolicy(): Promise<AssistantPolicyResponse> {
  return apiFetch<AssistantPolicyResponse>("/v1/assistant/policy");
}

export function updateAssistantPolicy(
  payload: AssistantPolicyUpdatePayload,
): Promise<AssistantPolicyResponse> {
  return apiFetch<AssistantPolicyResponse>("/v1/assistant/policy", {
    method: "PATCH",
    body: JSON.stringify(payload),
  });
}

export function getAssistantPolicyHistory(
  limit?: number,
): Promise<AssistantPolicyHistoryResponse> {
  const url =
    typeof limit === "number"
      ? `/v1/assistant/policy/history?limit=${encodeURIComponent(String(limit))}`
      : "/v1/assistant/policy/history";
  return apiFetch<AssistantPolicyHistoryResponse>(url);
}

// M6.8 — Assistant analytics into Intelligence.
// Metadata-only aggregation of assistant_runs evidence. The endpoint
// lives under /v1/portal/intelligence/ to match existing Intelligence
// routes; the wire shape is owned by AssistantIntelligenceSummaryResponse.
export function getAssistantIntelligenceSummary(
  days?: number,
): Promise<import("@/lib/types").AssistantIntelligenceSummaryResponse> {
  const url =
    typeof days === "number"
      ? `/v1/portal/intelligence/assistant-summary?days=${encodeURIComponent(String(days))}`
      : "/v1/portal/intelligence/assistant-summary";
  return apiFetch<import("@/lib/types").AssistantIntelligenceSummaryResponse>(url);
}
