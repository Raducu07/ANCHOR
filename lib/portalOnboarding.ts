// lib/portalOnboarding.ts
//
// M5.7 - Assisted Onboarding foundations API client (internal preview).
//
// Backend contract: docs/operations/fable_frontend_experiment/
// 2026-07-05_backend_contract_map.md. Both endpoints are read-only and
// metadata-only: counts, timestamps, statuses, and guidance strings.
// Invite responses never contain token material - only lifecycle
// status. Tenant scoping and auth follow the standard apiFetch flow.

import { apiFetch } from "@/lib/api";

export type OnboardingChecklistItem = {
  key: string;
  title: string;
  done: boolean;
  available: boolean;
  count: number | null;
  guidance: string;
};

export type OnboardingChecklistResponse = {
  generated_at: string;
  completed_count: number;
  total_count: number;
  items: OnboardingChecklistItem[];
  governance_note: string;
};

export type OnboardingInviteStatus = "pending" | "used" | "expired";

export type OnboardingInvite = {
  invite_id: string;
  email: string;
  role: string;
  status: OnboardingInviteStatus;
  created_at: string | null;
  expires_at: string | null;
  used_at: string | null;
};

export type OnboardingInviteListResponse = {
  invites: OnboardingInvite[];
  pending_count: number;
  used_count: number;
  expired_count: number;
  governance_note: string;
};

const BASE = "/v1/portal/onboarding";

export function getOnboardingChecklist(): Promise<OnboardingChecklistResponse> {
  return apiFetch<OnboardingChecklistResponse>(`${BASE}/checklist`);
}

export function listOnboardingInvites(): Promise<OnboardingInviteListResponse> {
  return apiFetch<OnboardingInviteListResponse>(`${BASE}/invites`);
}
