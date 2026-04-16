"use client";

import { useEffect, useState } from "react";
import { AppShell } from "@/components/shell/AppShell";
import { Card } from "@/components/ui/Card";
import { StatusBadge } from "@/components/ui/StatusBadge";
import { apiFetch, ApiError } from "@/lib/api";

type IntelligenceHotspot = {
  dimension: string;
  key: string;
  event_count: number;
  event_share: number;
  intervention_count: number;
  intervention_rate: number;
  pii_warned_count: number;
  pii_warned_rate: number;
  recency_spike_ratio: number;
  share_of_all_interventions?: number;
  severity_score: number;
  severity: "low" | "medium" | "high";
  summary: string;
};

type IntelligenceHotspotsResponse = {
  generated_at: string;
  window: "7d" | "30d";
  limit: number;
  items: IntelligenceHotspot[];
};

export default function IntelligenceHotspotsPage() {
  const [windowValue, setWindowValue] = useState<"7d" | "30d">("30d");
  const [dimension, setDimension] = useState("all");
  const [data, setData] = useState<IntelligenceHotspotsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function load(
    selectedWindow: "7d" | "30d",
    selectedDimension: string,
    showRefreshState = false
  ) {
    try {
      if (showRefreshState) {
        setRefreshing(true);
      } else {
        setLoading(true);
      }

      const response = await apiFetch<IntelligenceHotspotsResponse>(
        `/v1/portal/intelligence/hotspots?window=${selectedWindow}&dimension=${selectedDimension}&limit=20`
      );

      setData(response);
      setError(null);
    } catch (err) {
      const message = err instanceof ApiError ? err.message : "Unable to load hotspot analysis.";
      setError(message);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }

  useEffect(() => {
    void load(windowValue, dimension, false);
  }, [windowValue, dimension]);

  return (
    <AppShell>
      <div className="space-y-6">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
          <div>
            <p className="text-sm font-medium text-slate-500">Hotspots</p>
            <h1 className="text-2xl font-semibold tracking-tight text-slate-900">
              Governance hotspot analysis
            </h1>
            <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-600">
              Identify where governance friction, privacy warnings, and intervention signals are
              concentrating across supported operational dimensions.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <WindowTabs value={windowValue} onChange={setWindowValue} />
            <select
              value={dimension}
              onChange={(e) => setDimension(e.target.value)}
              className="rounded-2xl border border-slate-200 bg-white px-4 py-2.5 text-sm font-medium text-slate-900 shadow-sm outline-none"
            >
              <option value="all">All dimensions</option>
              <option value="mode">Mode</option>
              <option value="route">Route</option>
              <option value="reason_code">Reason code</option>
              <option value="risk_grade">Risk grade</option>
              <option value="pii_action">PII action</option>
            </select>

            <button
              onClick={() => void load(windowValue, dimension, true)}
              disabled={loading}
              className="inline-flex items-center rounded-2xl border border-slate-200 bg-white px-4 py-2.5 text-sm font-medium text-slate-900 shadow-sm transition hover:border-slate-300 disabled:cursor-not-allowed disabled:opacity-60"
            >
              {refreshing ? "Refreshing..." : "Refresh"}
            </button>
          </div>
        </div>

        {loading ? (
          <div className="grid gap-4">
            {Array.from({ length: 4 }).map((_, index) => (
              <Card key={index} className="h-40 animate-pulse bg-slate-100" />
            ))}
          </div>
        ) : error ? (
          <Card>
            <p className="text-sm font-medium text-rose-700">Hotspot analysis unavailable</p>
            <p className="mt-2 text-sm leading-6 text-slate-600">{error}</p>
          </Card>
        ) : (
          <>
            <Card>
              <SectionTitle
                title="Current filter view"
                description="A quick readout of the active analysis scope."
              />
              <dl className="mt-4 space-y-4 text-sm">
                <Detail label="Window" value={data?.window ?? windowValue} />
                <Detail label="Dimension" value={dimension === "all" ? "All dimensions" : formatDimension(dimension)} />
                <Detail label="Generated at" value={formatDateTime(data?.generated_at)} />
                <Detail label="Returned items" value={String(data?.items.length ?? 0)} />
              </dl>
            </Card>

            <div className="space-y-4">
              {data?.items.length ? (
                data.items.map((item, index) => (
                  <Card key={`${item.dimension}-${item.key}-${index}`}>
                    <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
                      <div className="min-w-0">
                        <div className="flex flex-wrap items-center gap-3">
                          <StatusBadge value={item.severity} />
                          <p className="text-sm font-semibold uppercase tracking-wide text-slate-500">
                            {formatDimension(item.dimension)}
                          </p>
                        </div>

                        <p className="mt-3 text-lg font-semibold text-slate-900">{item.key}</p>
                        <p className="mt-2 text-sm leading-6 text-slate-600">{item.summary}</p>
                      </div>

                      <div className="shrink-0 rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3 text-right">
                        <p className="text-xs uppercase tracking-wide text-slate-500">Severity score</p>
                        <p className="mt-2 text-xl font-semibold tracking-tight text-slate-900">
                          {item.severity_score}
                        </p>
                      </div>
                    </div>

                    <div className="mt-5 grid gap-4 md:grid-cols-2 xl:grid-cols-5">
                      <MetricCard
                        label="Events"
                        value={item.event_count}
                        helper="Privacy-aware thresholded hotspot volume."
                      />
                      <MetricCard
                        label="Event share"
                        value={formatPercent(item.event_share)}
                        helper="Share of filtered hotspot activity."
                      />
                      <MetricCard
                        label="Intervention rate"
                        value={formatPercent(item.intervention_rate)}
                        helper="Share ending in intervention."
                      />
                      <MetricCard
                        label="PII warned rate"
                        value={formatPercent(item.pii_warned_rate)}
                        helper="Privacy signal intensity."
                      />
                      <MetricCard
                        label="Recency spike"
                        value={`${item.recency_spike_ratio}x`}
                        helper="Recent period versus baseline."
                      />
                    </div>
                  </Card>
                ))
              ) : (
                <Card>
                  <p className="text-sm font-medium text-slate-900">No hotspots were returned</p>
                  <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-600">
                    This can happen when there is not yet enough clinic activity, or when no
                    segments pass the privacy-aware display threshold.
                  </p>
                </Card>
              )}
            </div>
          </>
        )}
      </div>
    </AppShell>
  );
}

function WindowTabs({
  value,
  onChange,
}: {
  value: "7d" | "30d";
  onChange: (value: "7d" | "30d") => void;
}) {
  return (
    <div className="inline-flex rounded-2xl border border-slate-200 bg-white p-1 shadow-sm">
      {(["7d", "30d"] as const).map((option) => {
        const active = value === option;
        return (
          <button
            key={option}
            onClick={() => onChange(option)}
            className={[
              "rounded-xl px-3 py-2 text-sm font-medium transition",
              active ? "bg-slate-900 text-white" : "text-slate-600 hover:text-slate-900",
            ].join(" ")}
          >
            {option}
          </button>
        );
      })}
    </div>
  );
}

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
      {description ? <p className="mt-1 text-sm leading-6 text-slate-600">{description}</p> : null}
    </div>
  );
}

function MetricCard({
  label,
  value,
  helper,
}: {
  label: string;
  value: string | number;
  helper: string;
}) {
  return (
    <div className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
      <p className="text-xs uppercase tracking-wide text-slate-500">{label}</p>
      <p className="mt-2 text-xl font-semibold tracking-tight text-slate-900">{value}</p>
      <p className="mt-2 text-sm leading-6 text-slate-600">{helper}</p>
    </div>
  );
}

function Detail({
  label,
  value,
}: {
  label: string;
  value: string;
}) {
  return (
    <div className="grid grid-cols-[140px_1fr] gap-4 border-b border-slate-100 pb-4 last:border-b-0 last:pb-0">
      <dt className="text-slate-500">{label}</dt>
      <dd className="text-slate-900">{value}</dd>
    </div>
  );
}

function formatPercent(value: number | null | undefined) {
  if (typeof value !== "number") return "—";
  return `${(value * 100).toFixed(1)}%`;
}

function formatDateTime(value?: string | null) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat("en-GB", {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(date);
}

function formatDimension(value: string) {
  return value.replace(/_/g, " ").replace(/\b\w/g, (match) => match.toUpperCase());
}