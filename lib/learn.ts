import { apiFetch } from "@/lib/api";
import type {
  CPDExport,
  CPDExportPayload,
  CPDRecord,
  LearningCompletion,
  LearningCompletionCreate,
  LearningCompletionVoid,
  LearningModule,
  TrustPackLearningDelta,
} from "@/lib/types";

// Phase 2A-1 - Learn / CPD API client (Slice F1).
//
// Backend contract (Engineering Brief v1.1 Section 2.3):
//   Learn endpoints are served under /v1/learn.
//   The Trust learning-delta aggregate is served under the existing
//   portal trust prefix: /v1/portal/trust/posture/learning-delta.
//
// All responses are metadata-only. No raw learning content, prompts,
// drafts, or clinical content is sent or received. Auth, error handling,
// and tenant scoping follow the existing apiFetch/ApiError conventions.

// ----- Module catalogue -------------------------------------------------

export function listLearningModules(params: {
  category?: string;
  role?: string;
} = {}): Promise<LearningModule[]> {
  const query = new URLSearchParams();
  if (params.category) query.set("category", params.category);
  if (params.role) query.set("role", params.role);
  const qs = query.toString();
  const url = qs ? `/v1/learn/modules?${qs}` : "/v1/learn/modules";
  return apiFetch<LearningModule[]>(url);
}

export function getLearningModule(moduleId: string): Promise<LearningModule> {
  return apiFetch<LearningModule>(
    `/v1/learn/modules/${encodeURIComponent(moduleId)}`,
  );
}

// Slug-based lookup is resolved client-side: the backend module detail
// endpoint is ID-based, while the frontend route (/learn/[moduleSlug]) is
// slug-based. We list the catalogue and match on module_slug. Returns null
// when no active module matches.
export async function findLearningModuleBySlug(
  moduleSlug: string,
): Promise<LearningModule | null> {
  const modules = await listLearningModules();
  return modules.find((module) => module.module_slug === moduleSlug) ?? null;
}

// ----- Completions ------------------------------------------------------

export function recordLearningCompletion(
  input: LearningCompletionCreate,
): Promise<LearningCompletion> {
  return apiFetch<LearningCompletion>("/v1/learn/completions", {
    method: "POST",
    body: JSON.stringify(input),
  });
}

export function voidLearningCompletion(
  completionId: string,
  input: LearningCompletionVoid,
): Promise<LearningCompletion> {
  return apiFetch<LearningCompletion>(
    `/v1/learn/completions/${encodeURIComponent(completionId)}/void`,
    {
      method: "POST",
      body: JSON.stringify(input),
    },
  );
}

export function listMyLearningCompletions(): Promise<LearningCompletion[]> {
  return apiFetch<LearningCompletion[]>("/v1/learn/completions/me");
}

export function listUserLearningCompletions(
  userId: string,
): Promise<LearningCompletion[]> {
  return apiFetch<LearningCompletion[]>(
    `/v1/learn/completions/users/${encodeURIComponent(userId)}`,
  );
}

// ----- CPD records ------------------------------------------------------

export function getMyCPDRecord(): Promise<CPDRecord> {
  return apiFetch<CPDRecord>("/v1/learn/cpd/me");
}

export function getUserCPDRecord(userId: string): Promise<CPDRecord> {
  return apiFetch<CPDRecord>(
    `/v1/learn/cpd/users/${encodeURIComponent(userId)}`,
  );
}

// ----- CPD exports ------------------------------------------------------

export function createUserCPDExport(userId: string): Promise<CPDExport> {
  return apiFetch<CPDExport>(
    `/v1/learn/cpd/users/${encodeURIComponent(userId)}/exports`,
    {
      method: "POST",
      body: JSON.stringify({}),
    },
  );
}

export function listUserCPDExports(userId: string): Promise<CPDExport[]> {
  return apiFetch<CPDExport[]>(
    `/v1/learn/cpd/users/${encodeURIComponent(userId)}/exports`,
  );
}

export function getCPDExport(exportId: string): Promise<CPDExport> {
  return apiFetch<CPDExport>(
    `/v1/learn/cpd/exports/${encodeURIComponent(exportId)}`,
  );
}

export function getCPDExportPayload(
  exportId: string,
): Promise<CPDExportPayload> {
  return apiFetch<CPDExportPayload>(
    `/v1/learn/cpd/exports/${encodeURIComponent(exportId)}/payload`,
  );
}

// ----- Trust Pack learning delta ----------------------------------------

export function getTrustLearningDelta(): Promise<TrustPackLearningDelta> {
  return apiFetch<TrustPackLearningDelta>(
    "/v1/portal/trust/posture/learning-delta",
  );
}

// ----- JSON download helper ---------------------------------------------

// Mirrors the existing receipt export pattern (lib/receipts/export.ts):
// serialise a metadata-only payload to a Blob and trigger a browser
// download. Browser-only; only invoked from a client handler.
export function exportCpdPayloadAsJson(
  payload: CPDExportPayload,
  filename?: string,
): void {
  const blob = new Blob([JSON.stringify(payload, null, 2)], {
    type: "application/json",
  });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download =
    filename ?? `anchor-cpd-${payload.user_id}-${payload.export_version}.json`;
  anchor.click();
  URL.revokeObjectURL(url);
}
