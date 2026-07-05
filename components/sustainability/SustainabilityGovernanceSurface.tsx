"use client";

// Fable roadmap-completion experiment - Slice F5 (M6-S Sustainability
// Governance & Evidence, internal preview).
//
// Doctrine:
//   * Metadata-only governance evidence: quantities, dates, and
//     clinic-controlled labels. No clinical content, no client data.
//   * Evidence rows are corrected by void-with-reason (admin), never
//     edited or deleted. Reports are immutable hashed rows with
//     supersession.
//   * Governance-evidence wording only: this is not an accredited
//     carbon audit, not verified carbon accounting, and not an ESG
//     compliance claim. The backend note is displayed verbatim.

import { useCallback, useEffect, useState, useSyncExternalStore } from "react";
import { Button } from "@/components/ui/Button";
import { Card } from "@/components/ui/Card";
import { StatusBadge } from "@/components/ui/StatusBadge";
import {
  InternalPreviewBadge,
  InternalPreviewGate,
} from "@/components/experiment/InternalPreviewGate";
import {
  SESSION_SERVER_SNAPSHOT,
  getSessionUserSnapshot,
  subscribeSessionStorage,
} from "@/lib/auth";
import {
  createEnergyReading,
  createFootprintEstimate,
  createWasteEvent,
  generateSustainabilityReport,
  getRolling12m,
  getSustainabilityConfig,
  listEnergyReadings,
  listFootprintEstimates,
  listSustainabilityReports,
  listWasteEvents,
  putSustainabilityConfig,
  voidEnergyReading,
  voidFootprintEstimate,
  voidWasteEvent,
} from "@/lib/sustainability";
import type {
  EnergyReadingListResponse,
  EnergyType,
  FootprintEstimateListResponse,
  ReportListResponse,
  RollingResponse,
  SustainabilityConfigResponse,
  WasteEventListResponse,
  WasteStream,
} from "@/lib/sustainability";

const ADMIN_ROLES = new Set(["admin", "owner", "practice_manager"]);

const ENERGY_TYPES: { value: EnergyType; label: string }[] = [
  { value: "electricity", label: "Electricity" },
  { value: "gas", label: "Gas" },
  { value: "other", label: "Other" },
];

const WASTE_STREAMS: { value: WasteStream; label: string }[] = [
  { value: "clinical", label: "Clinical" },
  { value: "offensive", label: "Offensive" },
  { value: "domestic", label: "Domestic" },
  { value: "recycling", label: "Recycling" },
  { value: "other", label: "Other" },
];

function formatDate(value?: string | null): string {
  if (!value) return "—";
  try {
    return new Date(value).toLocaleDateString();
  } catch {
    return value;
  }
}

function formatDateTime(value?: string | null): string {
  if (!value) return "—";
  try {
    return new Date(value).toLocaleString();
  } catch {
    return value;
  }
}

function formatMonth(value: string): string {
  try {
    return new Date(value).toLocaleDateString(undefined, {
      year: "numeric",
      month: "short",
    });
  } catch {
    return value;
  }
}

function formatQuantity(value: number | null): string {
  if (value === null) return "—";
  return value.toLocaleString(undefined, { maximumFractionDigits: 2 });
}

function numOrNull(raw: string): number | null {
  const trimmed = raw.trim();
  if (!trimmed) return null;
  const value = Number(trimmed);
  return Number.isFinite(value) ? value : null;
}

export function SustainabilityGovernanceSurface() {
  return (
    <InternalPreviewGate title="Sustainability governance">
      <SustainabilityContent />
    </InternalPreviewGate>
  );
}

function SustainabilityContent() {
  const user = useSyncExternalStore(
    subscribeSessionStorage,
    getSessionUserSnapshot,
    SESSION_SERVER_SNAPSHOT,
  );
  const isAdmin = Boolean(user && ADMIN_ROLES.has(user.role));

  return (
    <div className="space-y-6">
      <div>
        <div className="flex flex-wrap items-center gap-3">
          <p className="text-sm font-medium text-slate-500">Clinic administration</p>
          <InternalPreviewBadge />
        </div>
        <h1 className="text-2xl font-semibold tracking-tight text-slate-900">
          Sustainability governance
        </h1>
        <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-600">
          Metadata-only sustainability governance evidence for this clinic: energy readings,
          waste events, workflow footprint estimates, and hashed evidence reports. This is
          governance evidence under clinic control — not an accredited carbon audit, not
          verified carbon accounting, and not an ESG compliance claim.
        </p>
      </div>

      <ConfigSection isAdmin={isAdmin} />
      <EnergySection isAdmin={isAdmin} />
      <WasteSection isAdmin={isAdmin} />
      <FootprintSection isAdmin={isAdmin} />
      <RollingSection />
      <ReportsSection isAdmin={isAdmin} />
    </div>
  );
}

// ---------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------

function ConfigSection({ isAdmin }: { isAdmin: boolean }) {
  const [config, setConfig] = useState<SustainabilityConfigResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [reportingEnabled, setReportingEnabled] = useState(false);
  const [baselineYear, setBaselineYear] = useState("");
  const [electricityFactor, setElectricityFactor] = useState("");
  const [gasFactor, setGasFactor] = useState("");
  const [wasteFactor, setWasteFactor] = useState("");
  const [factorSource, setFactorSource] = useState("");
  const [saving, setSaving] = useState(false);
  const [feedback, setFeedback] = useState<
    { kind: "success" | "error"; message: string } | null
  >(null);

  useEffect(() => {
    let active = true;

    async function load() {
      setLoading(true);
      setError(null);
      try {
        const response = await getSustainabilityConfig();
        if (!active) return;
        setConfig(response);
        setReportingEnabled(response.reporting_enabled);
        setBaselineYear(response.baseline_year !== null ? String(response.baseline_year) : "");
        setElectricityFactor(
          response.electricity_factor_g_co2e_per_kwh !== null
            ? String(response.electricity_factor_g_co2e_per_kwh)
            : "",
        );
        setGasFactor(
          response.gas_factor_g_co2e_per_kwh !== null
            ? String(response.gas_factor_g_co2e_per_kwh)
            : "",
        );
        setWasteFactor(
          response.waste_factor_g_co2e_per_kg !== null
            ? String(response.waste_factor_g_co2e_per_kg)
            : "",
        );
        setFactorSource(response.factor_source_text ?? "");
      } catch (err: unknown) {
        if (!active) return;
        setConfig(null);
        setError(
          err instanceof Error ? err.message : "Unable to load the sustainability configuration.",
        );
      } finally {
        if (active) setLoading(false);
      }
    }

    void load();
    return () => {
      active = false;
    };
  }, []);

  async function handleSave() {
    setSaving(true);
    setFeedback(null);
    try {
      const response = await putSustainabilityConfig({
        reporting_enabled: reportingEnabled,
        baseline_year: baselineYear.trim() ? Number(baselineYear) : null,
        electricity_factor_g_co2e_per_kwh: numOrNull(electricityFactor),
        gas_factor_g_co2e_per_kwh: numOrNull(gasFactor),
        waste_factor_g_co2e_per_kg: numOrNull(wasteFactor),
        factor_source_text: factorSource.trim() || null,
      });
      setConfig(response);
      setFeedback({ kind: "success", message: "Sustainability configuration saved." });
    } catch (err: unknown) {
      setFeedback({
        kind: "error",
        message:
          err instanceof Error ? err.message : "Unable to save the sustainability configuration.",
      });
    } finally {
      setSaving(false);
    }
  }

  return (
    <Card variant="native">
      <SectionTitle
        title="Configuration"
        description="Reporting posture and clinic-recorded conversion factors, with the factor source recorded for provenance."
      />

      {loading ? (
        <Notice tone="neutral">Loading sustainability configuration…</Notice>
      ) : error ? (
        <Notice tone="error">{error}</Notice>
      ) : config ? (
        <>
          <div className="mt-4 grid gap-2 md:grid-cols-[1fr_auto]">
            <p className="text-sm leading-6 text-slate-600">
              Sustainability reporting is{" "}
              <span className="font-semibold text-slate-900">
                {config.reporting_enabled ? "enabled" : "not enabled"}
              </span>{" "}
              for this clinic. It defaults to off; enabling it is a deliberate clinic decision.
            </p>
            <div className="md:text-right">
              <StatusBadge value={config.reporting_enabled ? "ready" : "pending"} />
            </div>
          </div>

          {isAdmin ? (
            <div className="mt-4 border-t border-slate-100 pt-4">
              <label className="flex items-start gap-3 text-sm leading-6 text-slate-700">
                <input
                  type="checkbox"
                  checked={reportingEnabled}
                  onChange={(event) => setReportingEnabled(event.target.checked)}
                  className="mt-1 h-4 w-4 rounded border-slate-300"
                />
                <span>Enable sustainability reporting for this clinic</span>
              </label>

              <div className="mt-4 grid gap-4 md:grid-cols-2 xl:grid-cols-4">
                <LabelledInput
                  label="Baseline year"
                  value={baselineYear}
                  onChange={setBaselineYear}
                  type="number"
                  placeholder="e.g. 2025"
                />
                <LabelledInput
                  label="Electricity factor (g CO2e/kWh)"
                  value={electricityFactor}
                  onChange={setElectricityFactor}
                  type="number"
                  placeholder="Optional"
                />
                <LabelledInput
                  label="Gas factor (g CO2e/kWh)"
                  value={gasFactor}
                  onChange={setGasFactor}
                  type="number"
                  placeholder="Optional"
                />
                <LabelledInput
                  label="Waste factor (g CO2e/kg)"
                  value={wasteFactor}
                  onChange={setWasteFactor}
                  type="number"
                  placeholder="Optional"
                />
              </div>
              <div className="mt-4">
                <LabelledInput
                  label="Factor source (provenance, e.g. published conversion factor set and year)"
                  value={factorSource}
                  onChange={setFactorSource}
                  placeholder="Where these conversion factors come from"
                  wide
                />
              </div>
              <div className="mt-4">
                <Button onClick={handleSave} loading={saving} variant="secondary">
                  Save configuration
                </Button>
              </div>
              {feedback ? <FeedbackNotice feedback={feedback} /> : null}
            </div>
          ) : (
            <p className="mt-3 text-xs leading-5 text-slate-500">
              Configuration changes require a clinic admin role.
            </p>
          )}

          <p className="mt-4 max-w-3xl text-xs leading-5 text-slate-500">
            {config.sustainability_note}
          </p>
        </>
      ) : null}
    </Card>
  );
}

// ---------------------------------------------------------------------
// Evidence: energy readings
// ---------------------------------------------------------------------

function EnergySection({ isAdmin }: { isAdmin: boolean }) {
  const [data, setData] = useState<EnergyReadingListResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [energyType, setEnergyType] = useState<EnergyType>("electricity");
  const [periodStart, setPeriodStart] = useState("");
  const [periodEnd, setPeriodEnd] = useState("");
  const [consumption, setConsumption] = useState("");
  const [supplierLabel, setSupplierLabel] = useState("");
  const [creating, setCreating] = useState(false);
  const [feedback, setFeedback] = useState<
    { kind: "success" | "error"; message: string } | null
  >(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await listEnergyReadings();
      setData(response);
    } catch (err: unknown) {
      setData(null);
      setError(err instanceof Error ? err.message : "Unable to load energy readings.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  async function handleCreate() {
    const kwh = numOrNull(consumption);
    if (!periodStart || !periodEnd || kwh === null || kwh < 0) {
      setFeedback({
        kind: "error",
        message: "A period start, period end, and non-negative kWh value are required.",
      });
      return;
    }
    setCreating(true);
    setFeedback(null);
    try {
      await createEnergyReading({
        energy_type: energyType,
        period_start: periodStart,
        period_end: periodEnd,
        consumption_kwh: kwh,
        supplier_label: supplierLabel.trim() || null,
      });
      setFeedback({ kind: "success", message: "Energy reading recorded as evidence." });
      setConsumption("");
      setSupplierLabel("");
      await load();
    } catch (err: unknown) {
      setFeedback({
        kind: "error",
        message: err instanceof Error ? err.message : "Unable to record the energy reading.",
      });
    } finally {
      setCreating(false);
    }
  }

  return (
    <Card variant="native">
      <SectionTitle
        title="Energy evidence"
        description="Metered consumption periods recorded as metadata-only governance evidence."
      />

      <div className="mt-4 grid gap-3 md:grid-cols-2 xl:grid-cols-5">
        <label className="flex flex-col text-xs font-medium text-slate-500">
          Energy type
          <select
            value={energyType}
            onChange={(event) => setEnergyType(event.target.value as EnergyType)}
            className="mt-1 rounded-xl border border-slate-300 bg-white px-3 py-2 text-sm font-normal text-slate-900"
          >
            {ENERGY_TYPES.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>
        </label>
        <LabelledInput label="Period start" value={periodStart} onChange={setPeriodStart} type="date" />
        <LabelledInput label="Period end" value={periodEnd} onChange={setPeriodEnd} type="date" />
        <LabelledInput
          label="Consumption (kWh)"
          value={consumption}
          onChange={setConsumption}
          type="number"
          placeholder="0"
        />
        <LabelledInput
          label="Supplier label (optional)"
          value={supplierLabel}
          onChange={setSupplierLabel}
          placeholder="Clinic-controlled label"
        />
      </div>
      <div className="mt-3">
        <Button onClick={handleCreate} loading={creating} variant="secondary">
          Record energy reading
        </Button>
      </div>
      {feedback ? <FeedbackNotice feedback={feedback} /> : null}

      {loading ? (
        <Notice tone="neutral">Loading energy readings…</Notice>
      ) : error ? (
        <Notice tone="error">{error}</Notice>
      ) : data && data.readings.length > 0 ? (
        <div className="mt-4 overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead>
              <tr className="border-b border-slate-200 text-xs uppercase tracking-wide text-slate-500">
                <th className="py-2 pr-4 font-semibold">Type</th>
                <th className="py-2 pr-4 font-semibold">Period</th>
                <th className="py-2 pr-4 font-semibold">kWh</th>
                <th className="py-2 pr-4 font-semibold">Supplier label</th>
                <th className="py-2 pr-4 font-semibold">Status</th>
                {isAdmin ? <th className="py-2 font-semibold">Correction</th> : null}
              </tr>
            </thead>
            <tbody>
              {data.readings.map((reading) => (
                <EvidenceRow
                  key={reading.reading_id}
                  cells={[
                    <span key="type" className="capitalize">{reading.energy_type}</span>,
                    `${formatDate(reading.period_start)} – ${formatDate(reading.period_end)}`,
                    formatQuantity(reading.consumption_kwh),
                    reading.supplier_label || "—",
                  ]}
                  isVoided={reading.is_voided}
                  isAdmin={isAdmin}
                  onVoid={(reason) => voidEnergyReading(reading.reading_id, reason)}
                  onVoided={load}
                />
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <Notice tone="neutral">No energy readings recorded yet.</Notice>
      )}
    </Card>
  );
}

// ---------------------------------------------------------------------
// Evidence: waste events
// ---------------------------------------------------------------------

function WasteSection({ isAdmin }: { isAdmin: boolean }) {
  const [data, setData] = useState<WasteEventListResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [wasteStream, setWasteStream] = useState<WasteStream>("clinical");
  const [occurredOn, setOccurredOn] = useState("");
  const [weight, setWeight] = useState("");
  const [supplierLabel, setSupplierLabel] = useState("");
  const [creating, setCreating] = useState(false);
  const [feedback, setFeedback] = useState<
    { kind: "success" | "error"; message: string } | null
  >(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await listWasteEvents();
      setData(response);
    } catch (err: unknown) {
      setData(null);
      setError(err instanceof Error ? err.message : "Unable to load waste events.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  async function handleCreate() {
    const kg = numOrNull(weight);
    if (!occurredOn || kg === null || kg < 0) {
      setFeedback({
        kind: "error",
        message: "A collection date and non-negative weight are required.",
      });
      return;
    }
    setCreating(true);
    setFeedback(null);
    try {
      await createWasteEvent({
        waste_stream: wasteStream,
        occurred_on: occurredOn,
        weight_kg: kg,
        supplier_label: supplierLabel.trim() || null,
      });
      setFeedback({ kind: "success", message: "Waste event recorded as evidence." });
      setWeight("");
      setSupplierLabel("");
      await load();
    } catch (err: unknown) {
      setFeedback({
        kind: "error",
        message: err instanceof Error ? err.message : "Unable to record the waste event.",
      });
    } finally {
      setCreating(false);
    }
  }

  return (
    <Card variant="native">
      <SectionTitle
        title="Waste evidence"
        description="Waste collections by stream recorded as metadata-only governance evidence."
      />

      <div className="mt-4 grid gap-3 md:grid-cols-2 xl:grid-cols-4">
        <label className="flex flex-col text-xs font-medium text-slate-500">
          Waste stream
          <select
            value={wasteStream}
            onChange={(event) => setWasteStream(event.target.value as WasteStream)}
            className="mt-1 rounded-xl border border-slate-300 bg-white px-3 py-2 text-sm font-normal text-slate-900"
          >
            {WASTE_STREAMS.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>
        </label>
        <LabelledInput label="Collection date" value={occurredOn} onChange={setOccurredOn} type="date" />
        <LabelledInput
          label="Weight (kg)"
          value={weight}
          onChange={setWeight}
          type="number"
          placeholder="0"
        />
        <LabelledInput
          label="Supplier label (optional)"
          value={supplierLabel}
          onChange={setSupplierLabel}
          placeholder="Clinic-controlled label"
        />
      </div>
      <div className="mt-3">
        <Button onClick={handleCreate} loading={creating} variant="secondary">
          Record waste event
        </Button>
      </div>
      {feedback ? <FeedbackNotice feedback={feedback} /> : null}

      {loading ? (
        <Notice tone="neutral">Loading waste events…</Notice>
      ) : error ? (
        <Notice tone="error">{error}</Notice>
      ) : data && data.waste_events.length > 0 ? (
        <div className="mt-4 overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead>
              <tr className="border-b border-slate-200 text-xs uppercase tracking-wide text-slate-500">
                <th className="py-2 pr-4 font-semibold">Stream</th>
                <th className="py-2 pr-4 font-semibold">Collected</th>
                <th className="py-2 pr-4 font-semibold">Weight (kg)</th>
                <th className="py-2 pr-4 font-semibold">Supplier label</th>
                <th className="py-2 pr-4 font-semibold">Status</th>
                {isAdmin ? <th className="py-2 font-semibold">Correction</th> : null}
              </tr>
            </thead>
            <tbody>
              {data.waste_events.map((event) => (
                <EvidenceRow
                  key={event.waste_event_id}
                  cells={[
                    <span key="stream" className="capitalize">{event.waste_stream}</span>,
                    formatDate(event.occurred_on),
                    formatQuantity(event.weight_kg),
                    event.supplier_label || "—",
                  ]}
                  isVoided={event.is_voided}
                  isAdmin={isAdmin}
                  onVoid={(reason) => voidWasteEvent(event.waste_event_id, reason)}
                  onVoided={load}
                />
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <Notice tone="neutral">No waste events recorded yet.</Notice>
      )}
    </Card>
  );
}

// ---------------------------------------------------------------------
// Evidence: workflow footprint estimates
// ---------------------------------------------------------------------

function FootprintSection({ isAdmin }: { isAdmin: boolean }) {
  const [data, setData] = useState<FootprintEstimateListResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [workflowLabel, setWorkflowLabel] = useState("");
  const [periodStart, setPeriodStart] = useState("");
  const [periodEnd, setPeriodEnd] = useState("");
  const [estimate, setEstimate] = useState("");
  const [factorSource, setFactorSource] = useState("");
  const [creating, setCreating] = useState(false);
  const [feedback, setFeedback] = useState<
    { kind: "success" | "error"; message: string } | null
  >(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await listFootprintEstimates();
      setData(response);
    } catch (err: unknown) {
      setData(null);
      setError(err instanceof Error ? err.message : "Unable to load footprint estimates.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  async function handleCreate() {
    const kg = numOrNull(estimate);
    if (!workflowLabel.trim() || !periodStart || !periodEnd || kg === null || kg < 0) {
      setFeedback({
        kind: "error",
        message:
          "A workflow label, period start, period end, and non-negative kg CO2e estimate are required.",
      });
      return;
    }
    setCreating(true);
    setFeedback(null);
    try {
      await createFootprintEstimate({
        workflow_label: workflowLabel.trim(),
        period_start: periodStart,
        period_end: periodEnd,
        estimated_kg_co2e: kg,
        factor_source_text: factorSource.trim() || null,
      });
      setFeedback({ kind: "success", message: "Workflow footprint estimate recorded." });
      setEstimate("");
      await load();
    } catch (err: unknown) {
      setFeedback({
        kind: "error",
        message:
          err instanceof Error ? err.message : "Unable to record the footprint estimate.",
      });
    } finally {
      setCreating(false);
    }
  }

  return (
    <Card variant="native">
      <SectionTitle
        title="Workflow footprint estimates"
        description="Clinic-labelled workflow estimates in kg CO2e, with the factor source recorded for provenance. Estimates, not measurements."
      />

      <div className="mt-4 grid gap-3 md:grid-cols-2 xl:grid-cols-5">
        <LabelledInput
          label="Workflow label"
          value={workflowLabel}
          onChange={setWorkflowLabel}
          placeholder="Clinic-controlled label"
        />
        <LabelledInput label="Period start" value={periodStart} onChange={setPeriodStart} type="date" />
        <LabelledInput label="Period end" value={periodEnd} onChange={setPeriodEnd} type="date" />
        <LabelledInput
          label="Estimated kg CO2e"
          value={estimate}
          onChange={setEstimate}
          type="number"
          placeholder="0"
        />
        <LabelledInput
          label="Factor source (optional)"
          value={factorSource}
          onChange={setFactorSource}
          placeholder="Provenance of the estimate"
        />
      </div>
      <div className="mt-3">
        <Button onClick={handleCreate} loading={creating} variant="secondary">
          Record footprint estimate
        </Button>
      </div>
      {feedback ? <FeedbackNotice feedback={feedback} /> : null}

      {loading ? (
        <Notice tone="neutral">Loading footprint estimates…</Notice>
      ) : error ? (
        <Notice tone="error">{error}</Notice>
      ) : data && data.estimates.length > 0 ? (
        <div className="mt-4 overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead>
              <tr className="border-b border-slate-200 text-xs uppercase tracking-wide text-slate-500">
                <th className="py-2 pr-4 font-semibold">Workflow</th>
                <th className="py-2 pr-4 font-semibold">Period</th>
                <th className="py-2 pr-4 font-semibold">Estimated kg CO2e</th>
                <th className="py-2 pr-4 font-semibold">Factor source</th>
                <th className="py-2 pr-4 font-semibold">Status</th>
                {isAdmin ? <th className="py-2 font-semibold">Correction</th> : null}
              </tr>
            </thead>
            <tbody>
              {data.estimates.map((row) => (
                <EvidenceRow
                  key={row.estimate_id}
                  cells={[
                    row.workflow_label,
                    `${formatDate(row.period_start)} – ${formatDate(row.period_end)}`,
                    formatQuantity(row.estimated_kg_co2e),
                    row.factor_source_text || "—",
                  ]}
                  isVoided={row.is_voided}
                  isAdmin={isAdmin}
                  onVoid={(reason) => voidFootprintEstimate(row.estimate_id, reason)}
                  onVoided={load}
                />
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <Notice tone="neutral">No workflow footprint estimates recorded yet.</Notice>
      )}
    </Card>
  );
}

// ---------------------------------------------------------------------
// Rolling 12-month view
// ---------------------------------------------------------------------

function RollingSection() {
  const [data, setData] = useState<RollingResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;

    async function load() {
      setLoading(true);
      setError(null);
      try {
        const response = await getRolling12m();
        if (!active) return;
        setData(response);
      } catch (err: unknown) {
        if (!active) return;
        setData(null);
        setError(
          err instanceof Error ? err.message : "Unable to load the rolling 12-month view.",
        );
      } finally {
        if (active) setLoading(false);
      }
    }

    void load();
    return () => {
      active = false;
    };
  }, []);

  return (
    <Card variant="native">
      <SectionTitle
        title="Rolling 12-month view"
        description="Monthly aggregation of non-voided evidence, per stream. This is also the basis every generated report is hashed against."
      />

      {loading ? (
        <Notice tone="neutral">Loading the rolling view…</Notice>
      ) : error ? (
        <Notice tone="error">{error}</Notice>
      ) : data && data.months.length > 0 ? (
        <div className="mt-4 overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead>
              <tr className="border-b border-slate-200 text-xs uppercase tracking-wide text-slate-500">
                <th className="py-2 pr-4 font-semibold">Month</th>
                <th className="py-2 pr-4 font-semibold">Energy (kWh)</th>
                <th className="py-2 pr-4 font-semibold">Waste (kg)</th>
                <th className="py-2 font-semibold">Estimated kg CO2e</th>
              </tr>
            </thead>
            <tbody>
              {data.months.map((month) => (
                <tr key={month.month} className="border-b border-slate-100 last:border-b-0">
                  <td className="py-2.5 pr-4 text-slate-900">{formatMonth(month.month)}</td>
                  <td className="py-2.5 pr-4 text-slate-600">{formatQuantity(month.energy_kwh)}</td>
                  <td className="py-2.5 pr-4 text-slate-600">{formatQuantity(month.waste_kg)}</td>
                  <td className="py-2.5 text-slate-600">
                    {formatQuantity(month.estimated_kg_co2e)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <Notice tone="neutral">No evidence in the rolling 12-month window yet.</Notice>
      )}
    </Card>
  );
}

// ---------------------------------------------------------------------
// Reports
// ---------------------------------------------------------------------

function ReportsSection({ isAdmin }: { isAdmin: boolean }) {
  const [data, setData] = useState<ReportListResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [generating, setGenerating] = useState(false);
  const [feedback, setFeedback] = useState<
    { kind: "success" | "error"; message: string } | null
  >(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await listSustainabilityReports();
      setData(response);
    } catch (err: unknown) {
      setData(null);
      setError(err instanceof Error ? err.message : "Unable to load sustainability reports.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  async function handleGenerate() {
    setGenerating(true);
    setFeedback(null);
    try {
      const report = await generateSustainabilityReport();
      setFeedback({
        kind: "success",
        message: `Report version ${report.report_version} generated and hashed. Any prior report is now marked superseded.`,
      });
      await load();
    } catch (err: unknown) {
      setFeedback({
        kind: "error",
        message: err instanceof Error ? err.message : "Unable to generate a report.",
      });
    } finally {
      setGenerating(false);
    }
  }

  return (
    <Card variant="native">
      <SectionTitle
        title="Evidence reports"
        description="Immutable, hashed snapshots of the rolling 12-month view. New reports supersede prior ones; nothing is edited or deleted."
      />

      {isAdmin ? (
        <div className="mt-4">
          <Button onClick={handleGenerate} loading={generating} variant="secondary">
            Generate evidence report
          </Button>
        </div>
      ) : (
        <p className="mt-3 text-xs leading-5 text-slate-500">
          Generating a report requires a clinic admin role.
        </p>
      )}
      {feedback ? <FeedbackNotice feedback={feedback} /> : null}

      {loading ? (
        <Notice tone="neutral">Loading sustainability reports…</Notice>
      ) : error ? (
        <Notice tone="error">{error}</Notice>
      ) : data && data.reports.length > 0 ? (
        <div className="mt-4 space-y-4">
          {data.reports.map((report) => (
            <div
              key={report.report_id}
              className="grid gap-2 border-b border-slate-100 pb-4 last:border-b-0 last:pb-0 md:grid-cols-[1fr_auto]"
            >
              <div>
                <p className="text-sm font-semibold text-slate-900">
                  Report v{report.report_version} · {formatDate(report.period_start)} –{" "}
                  {formatDate(report.period_end)}
                </p>
                <p className="mt-1 text-sm leading-6 text-slate-600">
                  {formatQuantity(report.energy_kwh_total)} kWh ·{" "}
                  {formatQuantity(report.waste_kg_total)} kg waste ·{" "}
                  {formatQuantity(report.estimated_kg_co2e_total)} kg CO2e estimated · generated{" "}
                  {formatDateTime(report.generated_at)}
                </p>
                <p className="mt-1 font-mono text-xs text-slate-500" title={report.report_hash}>
                  SHA-256 {report.report_hash.slice(0, 16)}…
                </p>
              </div>
              <div className="md:text-right">
                <StatusBadge value={report.superseded_at ? "replaced" : "current"} />
              </div>
            </div>
          ))}
        </div>
      ) : (
        <Notice tone="neutral">No evidence reports generated yet.</Notice>
      )}

      {data ? (
        <p className="mt-4 max-w-3xl text-xs leading-5 text-slate-500">
          {data.sustainability_note}
        </p>
      ) : null}
    </Card>
  );
}

// ---------------------------------------------------------------------
// Shared row with void-with-reason correction flow
// ---------------------------------------------------------------------

function EvidenceRow({
  cells,
  isVoided,
  isAdmin,
  onVoid,
  onVoided,
}: {
  cells: React.ReactNode[];
  isVoided: boolean;
  isAdmin: boolean;
  onVoid: (reason: string) => Promise<{ voided: boolean }>;
  onVoided: () => Promise<void>;
}) {
  const [voidOpen, setVoidOpen] = useState(false);
  const [reason, setReason] = useState("");
  const [working, setWorking] = useState(false);
  const [voidError, setVoidError] = useState<string | null>(null);

  async function handleConfirmVoid() {
    if (reason.trim().length < 3) {
      setVoidError("A short correction reason (at least 3 characters) is required.");
      return;
    }
    setWorking(true);
    setVoidError(null);
    try {
      await onVoid(reason.trim());
      setVoidOpen(false);
      setReason("");
      await onVoided();
    } catch (err: unknown) {
      setVoidError(err instanceof Error ? err.message : "Unable to void this record.");
    } finally {
      setWorking(false);
    }
  }

  const columnCount = cells.length + 1 + (isAdmin ? 1 : 0);

  return (
    <>
      <tr className={`border-b border-slate-100 last:border-b-0 ${isVoided ? "opacity-60" : ""}`}>
        {cells.map((cell, index) => (
          <td key={index} className="py-2.5 pr-4 text-slate-700">
            {cell}
          </td>
        ))}
        <td className="py-2.5 pr-4">
          <StatusBadge value={isVoided ? "voided" : "recorded"} />
        </td>
        {isAdmin ? (
          <td className="py-2.5">
            {isVoided ? (
              <span className="text-xs text-slate-400">—</span>
            ) : voidOpen ? (
              <button
                type="button"
                onClick={() => {
                  setVoidOpen(false);
                  setVoidError(null);
                }}
                className="text-xs font-medium text-slate-500 underline underline-offset-4"
              >
                Cancel
              </button>
            ) : (
              <button
                type="button"
                onClick={() => setVoidOpen(true)}
                className="text-xs font-medium text-slate-900 underline underline-offset-4"
              >
                Void with reason
              </button>
            )}
          </td>
        ) : null}
      </tr>
      {voidOpen ? (
        <tr className="border-b border-slate-100">
          <td colSpan={columnCount} className="pb-3 pt-1">
            <div className="flex flex-wrap items-end gap-3 rounded-xl border border-slate-200 bg-slate-50 px-3 py-2.5">
              <label className="flex min-w-64 flex-1 flex-col text-xs font-medium text-slate-500">
                Correction reason (kept on the voided record)
                <input
                  type="text"
                  value={reason}
                  maxLength={500}
                  onChange={(event) => setReason(event.target.value)}
                  className="mt-1 rounded-xl border border-slate-300 bg-white px-3 py-2 text-sm font-normal text-slate-900"
                />
              </label>
              <Button onClick={handleConfirmVoid} loading={working} variant="secondary">
                Confirm void
              </Button>
              {voidError ? <p className="w-full text-xs text-rose-700">{voidError}</p> : null}
            </div>
          </td>
        </tr>
      ) : null}
    </>
  );
}

// ---------------------------------------------------------------------
// Small shared pieces
// ---------------------------------------------------------------------

function SectionTitle({
  title,
  description,
}: {
  title: string;
  description?: string;
}) {
  return (
    <div>
      <h2 className="text-base font-semibold text-slate-900">{title}</h2>
      {description ? (
        <p className="mt-1 text-sm leading-6 text-slate-600">{description}</p>
      ) : null}
    </div>
  );
}

function Notice({
  tone,
  children,
}: {
  tone: "neutral" | "error";
  children: React.ReactNode;
}) {
  const toneClass =
    tone === "error"
      ? "border-rose-200 bg-rose-50 text-rose-700"
      : "border-slate-200 bg-slate-50 text-slate-600";
  return (
    <div className={`mt-4 rounded-xl border px-4 py-3 text-sm ${toneClass}`}>{children}</div>
  );
}

function FeedbackNotice({
  feedback,
}: {
  feedback: { kind: "success" | "error"; message: string };
}) {
  return (
    <div
      className={[
        "mt-3 rounded-xl border px-4 py-3 text-sm",
        feedback.kind === "success"
          ? "border-emerald-200 bg-emerald-50 text-emerald-700"
          : "border-rose-200 bg-rose-50 text-rose-700",
      ].join(" ")}
    >
      {feedback.message}
    </div>
  );
}

function LabelledInput({
  label,
  value,
  onChange,
  type = "text",
  placeholder,
  wide = false,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  type?: string;
  placeholder?: string;
  wide?: boolean;
}) {
  return (
    <label
      className={`flex flex-col text-xs font-medium text-slate-500 ${wide ? "max-w-2xl" : ""}`}
    >
      {label}
      <input
        type={type}
        value={value}
        placeholder={placeholder}
        onChange={(event) => onChange(event.target.value)}
        className="mt-1 rounded-xl border border-slate-300 bg-white px-3 py-2 text-sm font-normal text-slate-900"
      />
    </label>
  );
}
