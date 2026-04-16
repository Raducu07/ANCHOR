"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { AppShell } from "@/components/shell/AppShell";
import { Card } from "@/components/ui/Card";
import { StatusBadge } from "@/components/ui/StatusBadge";
import { apiFetch, ApiError } from "@/lib/api";

type IntelligenceRecommendation = {
  type: "learning" | "policy_review" | "privacy_training" | "workflow_guidance";
  priority: "low" | "medium" | "high";
  title: string;
  why: string;
  based_on: {
    dimension: string;
    key: string;
  };
  target_path: string | null;
};

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

type IntelligenceSummary = {
  generated_at: string;
  window: "7d" | "30d";
  overall: {
    events: number;
    intervention_rate: number;
    pii_warned_rate: number;
    top_mode: string | null;
    top_route: string | null;
    top_reason_code: string | null;
  };
  headline_hotspot: IntelligenceHotspot | null;
  headline_action: IntelligenceRecommendation | null;
};

type IntelligenceRecommendationsResponse = {
  generated_at: string;
  window: "7d" | "30d";
  items: IntelligenceRecommendation[];
};

export default function IntelligencePage() {
  const [windowValue, setWindowValue] = useState<"7d" | "30d">("30d");
  const [summary, setSummary] = useState<IntelligenceSummary | null>(null);
  const [recommendations, setRecommendations] = useState<IntelligenceRecommendationsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function load(selectedWindow: "7d" | "30d", showRefreshState = false) {
    try {
      if (showRefreshState) {
        setRefreshing(true);
      } else {
        setLoading(true);
      }

      const [summaryResp, recommendationsResp] = await Promise.all([
        apiFetch<IntelligenceSummary>(`/v1/portal/intelligence/summary?window=${selectedWindow}`),
        apiFetch<IntelligenceRecommendationsResponse>(
          `/v1/portal/intelligence/recommendations?window=${selectedWindow}`
        ),
      ]);

      setSummary(summaryResp);
      setRecommendations(recommendationsResp);
      setError(null);
    } catch (err) {
      const message = err instanceof ApiError ? err.message : "Unable to load intelligence overview.";
      setError(message);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }

  useEffect(() => {
    void load(windowValue, false);
  }, [windowValue]);

  const hotspot = summary?.headline_hotspot ?? null;
  const action = summary?.headline_action ?? null;
  const topRecommendations = recommendations?.items?.slice(0, 3) ?? [];

  return (
    <AppShell>
      <div className="space-y-6">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
          <div>
            <p className="text-sm font-medium text-slate-500">Intelligence</p>
            <h1 className="text-2xl font-semibold tracking-tight text-slate-900">
              Governance intelligence overview
            </h1>
            <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-600">
              A metadata-driven view of governance hotspots, recurring friction, and recommended
              next actions for safer AI use across clinic workflows.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <WindowTabs value={windowValue} onChange={setWindowValue} />
            <button
              onClick={() => void load(windowValue, true)}
              disabled={loading}
              className="inline-flex items-center rounded-2xl border border-slate-200 bg-white px-4 py-2.5 text-sm font-medium text-slate-900 shadow-sm transition hover:border-slate-300 disabled:cursor-not-allowed disabled:opacity-60"
            >
              {refreshing ? "Refreshing..." : "Refresh"}
            </button>
          </div>
        </div>

        {loading ? (
          <div className="grid gap-4 xl:grid-cols-3">
            {Array.from({ length: 3 }).map((_, index) => (
              <Card key={index} className="h-44 animate-pulse bg-slate-100" />
            ))}
          </div>
        ) : error ? (
          <Card>
            <p className="text-sm font-medium text-rose-700">Intelligence unavailable</p>
            <p className="mt-2 text-sm leading-6 text-slate-600">{error}</p>
          </Card>
        ) : (
          <>
            <div className="grid gap-4 xl:grid-cols-4">
              <MetricCard
                label="Events"
                value={summary?.overall.events ?? 0}
                helper={`Governed events in the last ${windowValue === "7d" ? "7" : "30"} days.`}
              />
              <MetricCard
                label="Intervention rate"
                value={formatPercent(summary?.overall.intervention_rate)}
                helper="Share of events ending in governed intervention."
              />
              <MetricCard
                label="PII warned rate"
                value={formatPercent(summary?.overall.pii_warned_rate)}
                helper="Privacy warning intensity in the selected window."
              />
              <MetricCard
                label="Top mode"
                value={summary?.overall.top_mode ?? "—"}
                helper="Most concentrated workflow mode in current view."
              />
            </div>

            <div className="grid gap-4 xl:grid-cols-[1.1fr_0.9fr]">
              <Card>
                <SectionTitle
                  title="Headline hotspot"
                  description="The strongest currently surfaced governance concentration signal."
                />

                {hotspot ? (
                  <div className="mt-4 space-y-4">
                    <div className="flex items-center gap-3">
                      <StatusBadge value={hotspot.severity} />
                      <p className="text-sm font-semibold text-slate-900">
                        {hotspot.dimension}: {hotspot.key}
                      </p>
                    </div>

                    <p className="text-sm leading-6 text-slate-600">{hotspot.summary}</p>

                    <div className="grid grid-cols-2 gap-4">
                      <MiniMetric label="Events" value={hotspot.event_count} />
                      <MiniMetric label="Intervention rate" value={formatPercent(hotspot.intervention_rate)} />
                      <MiniMetric label="PII warned rate" value={formatPercent(hotspot.pii_warned_rate)} />
                      <MiniMetric label="Recency spike" value={`${hotspot.recency_spike_ratio}x`} />
                    </div>

                    <div className="pt-1">
                      <Link
                        href="/intelligence/hotspots"
                        className="text-sm font-medium text-slate-900 underline underline-offset-4"
                      >
                        Open hotspot analysis
                      </Link>
                    </div>
                  </div>
                ) : (
                  <EmptyState
                    title="No hotspot available"
                    description="Once intelligence signals are available for this clinic, the strongest concentration pattern will appear here."
                  />
                )}
              </Card>

              <Card>
                <SectionTitle
                  title="Recommended next action"
                  description="A deterministic action derived from the current hotspot profile."
                />

                {action ? (
                  <div className="mt-4 space-y-4">
                    <div className="flex items-center gap-3">
                      <StatusBadge value={action.priority} />
                      <p className="text-sm font-semibold text-slate-900">
                        {action.type.replace(/_/g, " ")}
                      </p>
                    </div>

                    <div className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
                      <p className="text-sm font-semibold text-slate-900">{action.title}</p>
                      <p className="mt-2 text-sm leading-6 text-slate-600">{action.why}</p>

                      <dl className="mt-4 space-y-3 text-sm">
                        <Detail label="Based on" value={`${action.based_on.dimension}: ${action.based_on.key}`} />
                        <Detail label="Priority" value={capitalize(action.priority)} />
                        <Detail label="Window" value={summary?.window ?? windowValue} />
                      </dl>

                      <div className="mt-4">
                        <Link
                          href={action.target_path || "/intelligence/recommendations"}
                          className="text-sm font-medium text-slate-900 underline underline-offset-4"
                        >
                          Open recommended destination
                        </Link>
                      </div>
                    </div>
                  </div>
                ) : (
                  <EmptyState
                    title="No recommendation available"
                    description="When hotspot concentration is available, a recommended next action will appear here."
                  />
                )}
              </Card>
            </div>

            <div className="grid gap-4 xl:grid-cols-[0.9fr_1.1fr]">
              <Card>
                <SectionTitle
                  title="Signal summary"
                  description="A concise readout of current intelligence-level concentration indicators."
                />
                <dl className="mt-4 space-y-4 text-sm">
                  <Detail label="Top route" value={summary?.overall.top_route ?? "—"} />
                  <Detail label="Top reason code" value={summary?.overall.top_reason_code ?? "—"} />
                  <Detail label="Generated at" value={formatDateTime(summary?.generated_at)} />
                  <Detail label="Window" value={summary?.window ?? windowValue} />
                </dl>
              </Card>

              <Card>
                <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
                  <div>
                    <SectionTitle
                      title="Top recommendations"
                      description="Learning, privacy, workflow, or policy actions tied to current metadata patterns."
                    />
                  </div>
                  <Link
                    href="/intelligence/recommendations"
                    className="text-sm font-medium text-slate-900 underline underline-offset-4"
                  >
                    View all
                  </Link>
                </div>

                <div className="mt-4 space-y-3">
                  {topRecommendations.length ? (
                    topRecommendations.map((item, index) => (
                      <div key={`${item.type}-${item.based_on.dimension}-${item.based_on.key}-${index}`} className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
                        <div className="flex items-center gap-3">
                          <StatusBadge value={item.priority} />
                          <p className="text-sm font-semibold text-slate-900">
                            {item.type.replace(/_/g, " ")}
                          </p>
                        </div>

                        <p className="mt-3 text-sm font-semibold text-slate-900">{item.title}</p>
                        <p className="mt-2 text-sm leading-6 text-slate-600">{item.why}</p>

                        <div className="mt-3">
                          <Link
                            href={item.target_path || "/intelligence/recommendations"}
                            className="text-sm font-medium text-slate-900 underline underline-offset-4"
                          >
                            Open
                          </Link>
                        </div>
                      </div>
                    ))
                  ) : (
                    <EmptyState
                      title="No recommendations returned"
                      description="Recommendations will appear here once concentration patterns are available for the clinic."
                    />
                  )}
                </div>
              </Card>
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
    <Card>
      <p className="text-xs uppercase tracking-wide text-slate-500">{label}</p>
      <p className="mt-2 text-2xl font-semibold tracking-tight text-slate-900">{value}</p>
      <p className="mt-2 text-sm leading-6 text-slate-600">{helper}</p>
    </Card>
  );
}

function MiniMetric({
  label,
  value,
}: {
  label: string;
  value: string | number;
}) {
  return (
    <div className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
      <p className="text-xs uppercase tracking-wide text-slate-500">{label}</p>
      <p className="mt-2 text-lg font-semibold tracking-tight text-slate-900">{value}</p>
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

function EmptyState({
  title,
  description,
}: {
  title: string;
  description: string;
}) {
  return (
    <div className="mt-4 rounded-2xl border border-slate-200 bg-slate-50 p-4">
      <p className="text-sm font-semibold text-slate-900">{title}</p>
      <p className="mt-2 text-sm leading-6 text-slate-600">{description}</p>
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

function capitalize(value: string) {
  if (!value) return "—";
  return value.charAt(0).toUpperCase() + value.slice(1);
}