// lib/billingFoundations.ts
//
// M5.8 - Billing and Activation Foundations API client (internal
// preview, sandbox-only).
//
// Backend contract: docs/operations/fable_frontend_experiment/
// 2026-07-05_backend_contract_map.md.
//
// Hard boundaries mirrored from the backend:
//   * No live billing, no charge capability, no payment instrument
//     fields, no checkout. Plan prices are deliberately null in the
//     sandbox catalogue.
//   * The API can only set activation_status internal_demo or
//     pilot_candidate; active_limited / active_verified are refused
//     server-side (403) because they require the security + legal
//     gates and a founder decision.
//   * stripe_mode is read-only here and can never be "live" at the
//     schema level.

import { apiFetch } from "@/lib/api";

export type BillingPlan = {
  plan_slug: string;
  version: string;
  title: string;
  summary: string;
  monthly_price_pence: number | null;
  currency: string;
  display_order: number;
};

export type BillingStateResponse = {
  plan_slug: string;
  activation_status: string;
  billing_readiness: string;
  stripe_mode: string;
  updated_at: string | null;
  plans: BillingPlan[];
  sandbox_note: string;
};

export type BillingStateUpdate = {
  plan_slug?: string;
  activation_status?: string;
  billing_readiness?: string;
};

// The only activation states the API will accept; the gated states are
// listed separately so the UI can show them as visibly unavailable.
export const API_SETTABLE_ACTIVATION = ["internal_demo", "pilot_candidate"] as const;
export const GATED_ACTIVATION = ["active_limited", "active_verified"] as const;
export const API_SETTABLE_READINESS = [
  "not_ready",
  "sandbox_only",
  "ready_pending_gates",
] as const;

const BASE = "/v1/portal/billing";

export function getBillingState(): Promise<BillingStateResponse> {
  return apiFetch<BillingStateResponse>(`${BASE}/state`);
}

export function updateBillingState(
  input: BillingStateUpdate,
): Promise<BillingStateResponse> {
  return apiFetch<BillingStateResponse>(`${BASE}/state`, {
    method: "PUT",
    body: JSON.stringify(input),
  });
}
