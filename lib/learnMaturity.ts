// lib/learnMaturity.ts
//
// M4.6 - Learn Maturity and Enablement API client (internal preview).
//
// Backend contract: docs/operations/fable_frontend_experiment/
// 2026-07-05_backend_contract_map.md. Additive to lib/learn.ts, which
// is untouched.
//
// Non-certifying doctrine: self-checks are learning reinforcement, not
// competence assessment. There is no pass/fail, no grade, and no
// certificate; every response carries self_check_note saying so and the
// UI displays it verbatim. Attempts are stored aggregate-only on the
// backend (never per-question answers). Metadata-only throughout.

import { apiFetch } from "@/lib/api";

export type SelfCheckQuestion = {
  check_id: string;
  check_slug: string;
  kind: string;
  prompt: string;
  options: string[];
  display_order: number;
};

export type SelfCheckListResponse = {
  module_id: string;
  questions: SelfCheckQuestion[];
  self_check_note: string;
};

export type SelfCheckAnswer = {
  check_id: string;
  selected_option_index: number;
};

export type SelfCheckFeedback = {
  check_id: string;
  correct: boolean;
  correct_option_index: number;
  explanation: string;
};

export type SelfCheckAttemptResponse = {
  attempt_id: string;
  module_id: string;
  module_version: string;
  questions_total: number;
  questions_correct: number;
  completed_at: string;
  feedback: SelfCheckFeedback[];
  self_check_note: string;
};

export type LearningPathProgress = {
  path_id: string;
  path_slug: string;
  version: string;
  title: string;
  summary: string;
  role_applicability: string[];
  module_slugs: string[];
  completed_module_slugs: string[];
  completed_count: number;
  total_count: number;
};

export type LearningPathListResponse = {
  paths: LearningPathProgress[];
  self_check_note: string;
};

export type RenewalStatus = "current" | "due_soon" | "overdue";

export type RenewalEntry = {
  module_id: string;
  module_slug: string;
  title: string;
  latest_completed_at: string;
  due_at: string;
  status: RenewalStatus;
};

export type MyRenewalsResponse = {
  renewal_months: number;
  entries: RenewalEntry[];
  self_check_note: string;
};

export type RenewalOverviewUser = {
  user_id: string;
  modules_completed: number;
  current_count: number;
  due_soon_count: number;
  overdue_count: number;
};

export type RenewalOverviewResponse = {
  renewal_months: number;
  users: RenewalOverviewUser[];
  total_current: number;
  total_due_soon: number;
  total_overdue: number;
  self_check_note: string;
};

export type RenewalPolicyResponse = {
  renewal_months: number;
  updated_at: string | null;
  self_check_note: string;
};

const BASE = "/v1/learn";

export function listModuleSelfChecks(
  moduleId: string,
): Promise<SelfCheckListResponse> {
  return apiFetch<SelfCheckListResponse>(
    `${BASE}/checks/modules/${encodeURIComponent(moduleId)}`,
  );
}

export function submitSelfCheckAttempt(
  moduleId: string,
  answers: SelfCheckAnswer[],
): Promise<SelfCheckAttemptResponse> {
  return apiFetch<SelfCheckAttemptResponse>(
    `${BASE}/checks/modules/${encodeURIComponent(moduleId)}/attempts`,
    {
      method: "POST",
      body: JSON.stringify({ answers }),
    },
  );
}

export function listLearningPaths(): Promise<LearningPathListResponse> {
  return apiFetch<LearningPathListResponse>(`${BASE}/paths`);
}

export function getMyRenewals(): Promise<MyRenewalsResponse> {
  return apiFetch<MyRenewalsResponse>(`${BASE}/renewals/me`);
}

export function getRenewalOverview(): Promise<RenewalOverviewResponse> {
  return apiFetch<RenewalOverviewResponse>(`${BASE}/renewals/overview`);
}

export function setRenewalPolicy(
  renewalMonths: number,
): Promise<RenewalPolicyResponse> {
  return apiFetch<RenewalPolicyResponse>(`${BASE}/renewal-policy`, {
    method: "PUT",
    body: JSON.stringify({ renewal_months: renewalMonths }),
  });
}
