"use client";

import Link from "next/link";
import { useEffect, useMemo, useState } from "react";
import { AppShell } from "@/components/shell/AppShell";
import { Button } from "@/components/ui/Button";
import { Card } from "@/components/ui/Card";
import { StatusBadge } from "@/components/ui/StatusBadge";
import { apiFetch, ApiError } from "@/lib/api";
import type { GovernanceEventListEnvelope, GovernanceEventSummary } from "@/lib/types";

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

type IntelligenceRecommendationsResponse = {
  generated_at: string;
  window: "7d" | "30d";
  items: IntelligenceRecommendation[];
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
  headline_hotspot: {
    dimension: string;
    key: string;
    event_count: number;
    event_share: number;
    intervention_count: number;
    intervention_rate: number;
    pii_warned_count: number;
    pii_warned_rate: number;
    recency_spike_ratio: number;
    share_of_all_interventions: number;
    summary: string;
    severity_score: number;
    severity: "low" | "medium" | "high";
  } | null;
  headline_action: IntelligenceRecommendation | null;
};

export default function GovernanceEventsPage() {
  const [items, setItems] = useState<GovernanceEventSummary[]>([]);
  const [intelligenceSummary, setIntelligenceSummary] = useState<IntelligenceSummary | null>(null);
  const [recommendations, setRecommendations] = useState<IntelligenceRecommendation[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [loadingIntelligence, setLoadingIntelligence] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function load(showRefreshState = false) {
    try {
      if (showRefreshState) {
        setRefreshing(true);
      } else {
        setLoading(true);
      }

      setLoadingIntelligence(true);

      const [eventsResponse, summaryResponse, recommendationsResponse] = await Promise.all([
        apiFetch<GovernanceEventListEnvelope | GovernanceEventSummary[]>(
          "/v1/portal/governance-events?limit=50",
        ),
        apiFetch<IntelligenceSummary>("/v1/portal/intelligence/summary?window=30d"),
        apiFetch<IntelligenceRecommendationsResponse>("/v1/portal/intelligence/recommendations?window=30d"),
      ]);

      const normalizedEvents = Array.isArray(eventsResponse)
        ? eventsResponse
        : eventsResponse.events ?? eventsResponse.items ?? eventsResponse.rows ?? [];

      setItems(normalizedEvents);
      setIntelligenceSummary(summaryResponse);
      setRecommendations(recommendationsResponse.items ?? []);
      setError(null);
    } catch (err) {
      const message = err instanceof ApiError ? err.message : "Unable to load governance events.";
      setError(message);
      setIntelligenceSummary(null);
      setRecommendations([]);
    } finally {
      setLoading(false);
      setRefreshing(false);
      setLoadingIntelligence(false);
    }
  }

  useEffect(() => {
    void load(false);
  }, []);

  const summary = useMemo(() => {
    return {
      total: items.length,
      allowed: items.filter((item) => (item.decision ?? "").toLowerCase() === "allowed").length,
      flagged: items.filter((item) =>
        ["replaced", "modified", "blocked"].includes((item.decision ?? "").toLowerCase()),
      ).length,
      pii: items.filter((item) => item.pii_detected).length,
    };
  }, [items]);

  const topRecommendation = useMemo(() => recommendations[0] ?? null, [recommendations]);

  return (
    <AppShell>
      <div className="space-y-6">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
          <div>
            <p className="text-sm font-medium text-slate-500">Governance activity</p>
            <h1 className="text-2xl font-semibold tracking-tight text-slate-900">Governance events</h1>
            <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-600">
              Clinic-scoped governance activity surface for operational review, follow-up, receipt navigation,
              and lightweight intelligence-aware learning cues.
            </p>
          </div>

          <div className="flex items-center gap-3">
            <Button onClick={() => void load(true)} disabled={loading || refreshing} loading={refreshing}>
              Refresh
            </Button>
          </div>
        </div>

        <div className="grid gap-4 md:grid-cols-4">
          <MetricCard label="Events in view" value={String(summary.total)} helper="Most recent clinic-scoped governance activity." />
          <MetricCard label="Allowed" value={String(summary.allowed)} helper="Events that remained allowed within current policy." />
          <MetricCard label="Flagged" value={String(summary.flagged)} helper="Replaced, modified, or blocked events." />
          <MetricCard label="PII detected" value={String(summary.pii)} helper="Events where PII detection was present." />
        </div>

        <div className="grid gap-4 xl:grid-cols-[1.05fr_0.95fr]">
          <Card variant="native">
            <div className="flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between">
              <div>
                <h2 className="text-base font-semibold text-slate-900">Current intelligence context</h2>
                <p className="mt-1 text-sm leading-6 text-slate-600">
                  A lightweight reading of the clinic’s current intelligence layer, shown alongside event review.
                </p>
              </div>
              {loadingIntelligence ? (
                <div className="text-xs text-slate-500">Refreshing intelligence…</div>
              ) : null}
            </div>

            {intelligenceSummary ? (
              <div className="mt-4 space-y-4">
                <div className="grid gap-4 md:grid-cols-3">
                  <InlineMetric
                    label="Top mode"
                    value={intelligenceSummary.overall.top_mode ?? "—"}
                  />
                  <InlineMetric
                    label="Top route"
                    value={intelligenceSummary.overall.top_route ?? "—"}
                  />
                  <InlineMetric
                    label="PII warned rate"
                    value={formatPercent(intelligenceSummary.overall.pii_warned_rate)}
                  />
                </div>

                {intelligenceSummary.headline_hotspot ? (
                  <div className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
                    <div className="flex items-center gap-3">
                      <StatusBadge value={intelligenceSummary.headline_hotspot.severity} />
                      <p className="text-sm font-semibold text-slate-900">
                        Current hotspot: {intelligenceSummary.headline_hotspot.dimension}:{" "}
                        {intelligenceSummary.headline_hotspot.key}
                      </p>
                    </div>
                    <p className="mt-2 text-sm leading-6 text-slate-600">
                      {intelligenceSummary.headline_hotspot.summary}
                    </p>
                    <div className="mt-3">
                      <Link
                        href="/intelligence/hotspots"
                        className="text-sm font-medium text-slate-900 underline underline-offset-4"
                      >
                        Open hotspot analysis
                      </Link>
                    </div>
                  </div>
                ) : (
                  <div className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
                    <p className="text-sm text-slate-600">
                      No current hotspot is available for this clinic view yet.
                    </p>
                  </div>
                )}
              </div>
            ) : (
              <div className="mt-4 rounded-2xl border border-slate-200 bg-slate-50 p-4">
                <p className="text-sm text-slate-600">
                  Intelligence context is not currently available. The governance activity table still
                  remains fully usable.
                </p>
              </div>
            )}
          </Card>

          <Card variant="native">
            <div className="flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between">
              <div>
                <h2 className="text-base font-semibold text-slate-900">Recommended next action</h2>
                <p className="mt-1 text-sm leading-6 text-slate-600">
                  Use the current recommendation as a light operational bridge into learning or workflow guidance.
                </p>
              </div>
            </div>

            {topRecommendation ? (
              <div className="mt-4 rounded-2xl border border-slate-200 bg-slate-50 p-4">
                <div className="flex items-center gap-3">
                  <StatusBadge value={topRecommendation.priority} />
                  <p className="text-sm font-semibold text-slate-900">
                    {topRecommendation.title}
                  </p>
                </div>
                <p className="mt-2 text-sm leading-6 text-slate-600">{topRecommendation.why}</p>
                <dl className="mt-4 space-y-3 text-sm">
                  <DetailRow
                    label="Based on"
                    value={`${topRecommendation.based_on.dimension}: ${topRecommendation.based_on.key}`}
                  />
                  <DetailRow label="Type" value={topRecommendation.type.replace(/_/g, " ")} />
                </dl>
                <div className="mt-4 flex flex-wrap gap-4">
                  <Link
                    href={topRecommendation.target_path || "/intelligence"}
                    className="text-sm font-medium text-slate-900 underline underline-offset-4"
                  >
                    Open recommended destination
                  </Link>
                  <Link
                    href="/intelligence/recommendations"
                    className="text-sm font-medium text-slate-900 underline underline-offset-4"
                  >
                    View all recommendations
                  </Link>
                </div>
              </div>
            ) : (
              <div className="mt-4 rounded-2xl border border-slate-200 bg-slate-50 p-4">
                <p className="text-sm text-slate-600">
                  No active recommendation is currently available for this clinic view.
                </p>
              </div>
            )}
          </Card>
        </div>

        <Card variant="native">
          <div className="flex flex-col gap-2 border-b border-slate-100 pb-4 sm:flex-row sm:items-start sm:justify-between">
            <div>
              <h2 className="text-base font-semibold text-slate-900">Operational review queue</h2>
              <p className="mt-1 text-sm leading-6 text-slate-600">
                This table is metadata-only. Use request IDs to move directly into governance receipts without exposing raw prompt or output content.
              </p>
            </div>
            <div className="text-xs text-slate-500">
              Showing up to 50 recent records
            </div>
          </div>

          {loading ? (
            <div className="py-8">
              <p className="text-sm text-slate-500">Loading governance events…</p>
            </div>
          ) : error ? (
            <div className="py-8">
              <p className="text-sm font-medium text-rose-700">Unable to load governance activity</p>
              <p className="mt-2 text-sm leading-6 text-slate-600">{error}</p>
            </div>
          ) : items.length === 0 ? (
            <div className="py-8">
              <p className="text-sm font-medium text-slate-900">No governance events are available yet</p>
              <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-600">
                New governed activity will appear here for clinic-scoped operational review and receipt access.
                Once a submission is processed through the backend, its metadata record should become visible in this table.
              </p>
              <div className="mt-4 flex flex-wrap gap-4">
                <Link
                  href="/receipts"
                  className="text-sm font-medium text-slate-900 underline underline-offset-4"
                >
                  Open receipt viewer
                </Link>
                <Link
                  href="/learn"
                  className="text-sm font-medium text-slate-900 underline underline-offset-4"
                >
                  Open Learn
                </Link>
              </div>
            </div>
          ) : (
            <div className="mt-4 overflow-x-auto">
              <table className="min-w-full divide-y divide-slate-200 text-sm">
                <thead>
                  <tr className="text-left text-slate-500">
                    <th className="py-3 pr-4 font-medium">Created</th>
                    <th className="py-3 pr-4 font-medium">Request</th>
                    <th className="py-3 pr-4 font-medium">Mode</th>
                    <th className="py-3 pr-4 font-medium">Decision</th>
                    <th className="py-3 pr-4 font-medium">Risk</th>
                    <th className="py-3 pr-4 font-medium">Reason</th>
                    <th className="py-3 pr-4 font-medium">Context</th>
                    <th className="py-3 pr-0 font-medium">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {items.map((item) => {
                    const requestId = item.request_id ?? "";
                    const receiptHref = `/receipts?request_id=${encodeURIComponent(requestId)}`;

                    const rowContext = getRowContext(item, intelligenceSummary, recommendations);
                    const rowLearningHref = getRowLearningHref(item, recommendations);

                    return (
                      <tr key={`${item.request_id}-${item.created_at ?? item.created_at_utc ?? ""}`} className="align-top">
                        <td className="py-4 pr-4 text-slate-600">
                          {formatDate(item.created_at ?? item.created_at_utc)}
                        </td>
                        <td className="py-4 pr-4">
                          <Link
                            href={receiptHref}
                            className="font-medium text-slate-900 underline underline-offset-4"
                          >
                            {requestId || "—"}
                          </Link>
                        </td>
                        <td className="py-4 pr-4">
                          <StatusBadge value={item.mode ?? "unknown"} />
                        </td>
                        <td className="py-4 pr-4">
                          <StatusBadge value={item.decision ?? "unknown"} />
                        </td>
                        <td className="py-4 pr-4">
                          <StatusBadge value={item.risk_grade ?? "unknown"} />
                        </td>
                        <td className="py-4 pr-4 text-slate-600">{item.reason_code ?? "—"}</td>
                        <td className="py-4 pr-4">
                          {rowContext ? (
                            <div className="space-y-2">
                              {rowContext.badge ? (
                                <div>
                                  <StatusBadge value={rowContext.badge} />
                                </div>
                              ) : null}
                              <p className="max-w-xs text-sm leading-6 text-slate-600">
                                {rowContext.text}
                              </p>
                            </div>
                          ) : (
                            <span className="text-slate-400">—</span>
                          )}
                        </td>
                        <td className="py-4 pr-0">
                          <div className="flex flex-col gap-2">
                            <Link
                              href={receiptHref}
                              className="text-sm font-medium text-slate-900 underline underline-offset-4"
                            >
                              Open receipt
                            </Link>
                            <Link
                              href={rowLearningHref}
                              className="text-sm font-medium text-slate-900 underline underline-offset-4"
                            >
                              Related learning
                            </Link>
                            <Link
                              href="/intelligence"
                              className="text-sm font-medium text-slate-900 underline underline-offset-4"
                            >
                              Open Intelligence
                            </Link>
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </Card>

        <Card variant="native">
          <div className="flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between">
            <div>
              <h2 className="text-base font-semibold text-slate-900">Learning tie-in</h2>
              <p className="mt-1 max-w-3xl text-sm leading-6 text-slate-600">
                Governance events show what happened. ANCHOR Learn helps staff understand why patterns matter and how safer AI use can be strengthened over time.
              </p>
            </div>
            <div className="mt-2 sm:mt-0">
              <Link
                href="/learn/explainers"
                className="text-sm font-medium text-slate-900 underline underline-offset-4"
              >
                Open explainers
              </Link>
            </div>
          </div>
        </Card>
      </div>
    </AppShell>
  );
}

function MetricCard({
  label,
  value,
  helper,
}: {
  label: string;
  value: string;
  helper: string;
}) {
  return (
    <Card variant="native">
      <p className="text-sm font-medium text-slate-500">{label}</p>
      <p className="mt-2 text-2xl font-semibold tracking-tight text-slate-900">{value}</p>
      <p className="mt-2 text-sm leading-6 text-slate-600">{helper}</p>
    </Card>
  );
}

function InlineMetric({
  label,
  value,
}: {
  label: string;
  value: string;
}) {
  return (
    <div className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
      <p className="text-xs uppercase tracking-wide text-slate-500">{label}</p>
      <p className="mt-2 text-lg font-semibold tracking-tight text-slate-900">{value}</p>
    </div>
  );
}

function DetailRow({
  label,
  value,
}: {
  label: string;
  value: string;
}) {
  return (
    <div className="grid grid-cols-[110px_1fr] gap-4 border-b border-slate-100 pb-3 last:border-b-0 last:pb-0">
      <dt className="text-slate-500">{label}</dt>
      <dd className="text-slate-900">{value}</dd>
    </div>
  );
}

function formatDate(value?: string | null) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat("en-GB", {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(date);
}

function formatPercent(value?: number | null) {
  if (typeof value !== "number") return "—";
  return `${(value * 100).toFixed(1)}%`;
}

function getRowLearningHref(
  item: GovernanceEventSummary,
  recommendations: IntelligenceRecommendation[],
) {
  if (item.pii_action === "warn") {
    return "/learn/cards/privacy-safe-ai-use";
  }

  const matchingRecommendation = recommendations.find(
    (rec) =>
      rec.type === "learning" &&
      rec.based_on.dimension === "mode" &&
      rec.based_on.key === String(item.mode ?? ""),
  );

  if (matchingRecommendation?.target_path) {
    return matchingRecommendation.target_path;
  }

  if (item.mode === "client_comm") {
    return "/learn/explainers/client-communication-safety";
  }

  if (item.mode === "clinical_note") {
    return "/learn/explainers/clinical-note-governance";
  }

  return "/learn";
}

function getRowContext(
  item: GovernanceEventSummary,
  intelligenceSummary: IntelligenceSummary | null,
  recommendations: IntelligenceRecommendation[],
) {
  if (item.pii_action === "warn") {
    return {
      badge: "medium",
      text: "Privacy warning present. This event is a strong candidate for privacy-safe AI-use reinforcement.",
    };
  }

  const headlineHotspot = intelligenceSummary?.headline_hotspot;
  if (
    headlineHotspot &&
    ((headlineHotspot.dimension === "mode" && headlineHotspot.key === String(item.mode ?? "")) ||
      (headlineHotspot.dimension === "reason_code" &&
        headlineHotspot.key === String(item.reason_code ?? "")))
  ) {
    return {
      badge: headlineHotspot.severity,
      text: `Matches current hotspot: ${headlineHotspot.summary}`,
    };
  }

  const matchingRecommendation = recommendations.find(
    (rec) =>
      rec.based_on.dimension === "mode" &&
      rec.based_on.key === String(item.mode ?? ""),
  );

  if (matchingRecommendation) {
    return {
      badge: matchingRecommendation.priority,
      text: matchingRecommendation.title,
    };
  }

  if (item.mode === intelligenceSummary?.overall.top_mode) {
    return {
      badge: "low",
      text: "This event sits inside the clinic’s currently most active governed workflow mode.",
    };
  }

  return null;
}