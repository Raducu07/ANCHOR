// lib/sustainability.ts
//
// M6-S - Sustainability Governance & Evidence API client (internal
// preview).
//
// Backend contract: docs/operations/fable_frontend_experiment/
// 2026-07-05_backend_contract_map.md.
//
// Doctrine:
//   * Metadata-only: quantities (kWh, kg, kg CO2e), dates, and
//     clinic-controlled labels. No clinical content, no client data.
//   * Evidence rows are corrected by void-with-reason, never edited or
//     deleted. Reports are immutable hashed rows with supersession.
//   * Governance-evidence wording only: not an accredited carbon audit
//     and not a compliance certification (backend note shown verbatim).

import { apiFetch } from "@/lib/api";

export type SustainabilityConfig = {
  reporting_enabled: boolean;
  baseline_year: number | null;
  electricity_factor_g_co2e_per_kwh: number | null;
  gas_factor_g_co2e_per_kwh: number | null;
  waste_factor_g_co2e_per_kg: number | null;
  factor_source_text: string | null;
};

export type SustainabilityConfigResponse = SustainabilityConfig & {
  updated_at: string | null;
  sustainability_note: string;
};

export type EnergyType = "electricity" | "gas" | "other";

export type EnergyReading = {
  reading_id: string;
  energy_type: EnergyType;
  period_start: string;
  period_end: string;
  consumption_kwh: number;
  supplier_label: string | null;
  is_voided: boolean;
  created_at: string;
};

export type EnergyReadingListResponse = {
  readings: EnergyReading[];
  sustainability_note: string;
};

export type EnergyReadingCreate = {
  energy_type: EnergyType;
  period_start: string;
  period_end: string;
  consumption_kwh: number;
  supplier_label?: string | null;
};

export type WasteStream =
  | "clinical"
  | "offensive"
  | "domestic"
  | "recycling"
  | "other";

export type WasteEvent = {
  waste_event_id: string;
  waste_stream: WasteStream;
  occurred_on: string;
  weight_kg: number;
  supplier_label: string | null;
  is_voided: boolean;
  created_at: string;
};

export type WasteEventListResponse = {
  waste_events: WasteEvent[];
  sustainability_note: string;
};

export type WasteEventCreate = {
  waste_stream: WasteStream;
  occurred_on: string;
  weight_kg: number;
  supplier_label?: string | null;
};

export type FootprintEstimate = {
  estimate_id: string;
  workflow_label: string;
  period_start: string;
  period_end: string;
  estimated_kg_co2e: number;
  factor_source_text: string | null;
  is_voided: boolean;
  created_at: string;
};

export type FootprintEstimateListResponse = {
  estimates: FootprintEstimate[];
  sustainability_note: string;
};

export type FootprintEstimateCreate = {
  workflow_label: string;
  period_start: string;
  period_end: string;
  estimated_kg_co2e: number;
  factor_source_text?: string | null;
};

export type RollingMonth = {
  month: string;
  energy_kwh: number | null;
  waste_kg: number | null;
  estimated_kg_co2e: number | null;
};

export type RollingResponse = {
  months: RollingMonth[];
  sustainability_note: string;
};

export type SustainabilityReport = {
  report_id: string;
  report_version: number;
  period_start: string;
  period_end: string;
  energy_kwh_total: number;
  waste_kg_total: number;
  estimated_kg_co2e_total: number;
  report_hash: string;
  superseded_at: string | null;
  generated_at: string;
};

export type ReportListResponse = {
  reports: SustainabilityReport[];
  sustainability_note: string;
};

export type SustainabilityTrustSummary = {
  reporting_enabled: boolean;
  energy_reading_count: number;
  waste_event_count: number;
  footprint_estimate_count: number;
  report_count: number;
  latest_report_generated_at: string | null;
  sustainability_note: string;
};

const BASE = "/v1/portal/sustainability";

// ----- Config ---------------------------------------------------------

export function getSustainabilityConfig(): Promise<SustainabilityConfigResponse> {
  return apiFetch<SustainabilityConfigResponse>(`${BASE}/config`);
}

export function putSustainabilityConfig(
  input: SustainabilityConfig,
): Promise<SustainabilityConfigResponse> {
  return apiFetch<SustainabilityConfigResponse>(`${BASE}/config`, {
    method: "PUT",
    body: JSON.stringify(input),
  });
}

// ----- Evidence streams -------------------------------------------------

export function listEnergyReadings(): Promise<EnergyReadingListResponse> {
  return apiFetch<EnergyReadingListResponse>(`${BASE}/energy-readings`);
}

export function createEnergyReading(
  input: EnergyReadingCreate,
): Promise<{ reading_id: string }> {
  return apiFetch<{ reading_id: string }>(`${BASE}/energy-readings`, {
    method: "POST",
    body: JSON.stringify(input),
  });
}

export function voidEnergyReading(
  readingId: string,
  voidReason: string,
): Promise<{ voided: boolean }> {
  return apiFetch<{ voided: boolean }>(
    `${BASE}/energy-readings/${encodeURIComponent(readingId)}/void`,
    {
      method: "POST",
      body: JSON.stringify({ void_reason: voidReason }),
    },
  );
}

export function listWasteEvents(): Promise<WasteEventListResponse> {
  return apiFetch<WasteEventListResponse>(`${BASE}/waste-events`);
}

export function createWasteEvent(
  input: WasteEventCreate,
): Promise<{ waste_event_id: string }> {
  return apiFetch<{ waste_event_id: string }>(`${BASE}/waste-events`, {
    method: "POST",
    body: JSON.stringify(input),
  });
}

export function voidWasteEvent(
  wasteEventId: string,
  voidReason: string,
): Promise<{ voided: boolean }> {
  return apiFetch<{ voided: boolean }>(
    `${BASE}/waste-events/${encodeURIComponent(wasteEventId)}/void`,
    {
      method: "POST",
      body: JSON.stringify({ void_reason: voidReason }),
    },
  );
}

export function listFootprintEstimates(): Promise<FootprintEstimateListResponse> {
  return apiFetch<FootprintEstimateListResponse>(`${BASE}/footprint-estimates`);
}

export function createFootprintEstimate(
  input: FootprintEstimateCreate,
): Promise<{ estimate_id: string }> {
  return apiFetch<{ estimate_id: string }>(`${BASE}/footprint-estimates`, {
    method: "POST",
    body: JSON.stringify(input),
  });
}

export function voidFootprintEstimate(
  estimateId: string,
  voidReason: string,
): Promise<{ voided: boolean }> {
  return apiFetch<{ voided: boolean }>(
    `${BASE}/footprint-estimates/${encodeURIComponent(estimateId)}/void`,
    {
      method: "POST",
      body: JSON.stringify({ void_reason: voidReason }),
    },
  );
}

// ----- Rolling view / reports / trust summary ---------------------------

export function getRolling12m(): Promise<RollingResponse> {
  return apiFetch<RollingResponse>(`${BASE}/rolling-12m`);
}

export function generateSustainabilityReport(): Promise<SustainabilityReport> {
  return apiFetch<SustainabilityReport>(`${BASE}/reports`, {
    method: "POST",
    body: JSON.stringify({}),
  });
}

export function listSustainabilityReports(): Promise<ReportListResponse> {
  return apiFetch<ReportListResponse>(`${BASE}/reports`);
}

export function getSustainabilityTrustSummary(): Promise<SustainabilityTrustSummary> {
  return apiFetch<SustainabilityTrustSummary>(`${BASE}/trust-summary`);
}
