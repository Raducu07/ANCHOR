"use client";

import Link from "next/link";
import { useEffect, useMemo, useState } from "react";
import { AppShell } from "@/components/shell/AppShell";
import { Button } from "@/components/ui/Button";
import { Card } from "@/components/ui/Card";
import { StatusBadge } from "@/components/ui/StatusBadge";
import { apiFetch, ApiError } from "@/lib/api";
import type { DashboardResponse } from "@/lib/types";

export default function DashboardPage() {
  const [data, setData] = useState<DashboardResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function load(showRefreshState = false) {
    try {
      if (showRefreshState) {
        setRefreshing(true);
      } else {
        setLoading(true);
      }

      const response = await apiFetch<DashboardResponse>("/v1/portal/dashboard");
      setData(response);
      setError(null);
    } catch (err) {
      const message = err instanceof ApiError ? err.message : "Unable to load dashboard.";
      setError(message);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }

  useEffect(() => {
    void load(false);
  }, []);

  const trustState = data?.trust_state?.health_state ?? "unknown";
  const trustReasons = data?.trust_state?.reasons ?? [];
  const kpis = data?.kpis_24h;
  const recent = data?.recent_submissions ?? [];

  const summary = useMemo(() => {
    return {
      events: kpis?.events_24h ?? 0,
      interventions: kpis?.interventions_24h ?? 0,
      piiWarned: kpis?.pii_warned_24h ?? 0,
      topMode: kpis?.top_mode_24h ?? "—",
      topRoute: kpis?.top_route_24h ?? "—",
      eventsPerHour: kpis?.events_per_hour ?? 0,
      interventionRate: kpis?.intervention_rate_24h ?? 0,
      piiWarnedRate: kpis?.pii_warned_rate_24h ?? 0,
    };
  }, [kpis]);

  return (
    <AppShell>
      <div className="space-y-6">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
          <div>
            <p className="text-sm font-medium text-slate-500">Dashboard</p>
            <h1 className="text-2xl font-semibold tracking-tight text-slate-900">
              Trust-oriented clinic overview
            </h1>
            <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-600">
              A calm operational summary of governance posture, bounded activity, and clinic-scoped
              accountability surfaces.
            </p>
          </div>

          <div className="flex justify-start lg:justify-end">
            <div className="flex items-center gap-4 rounded-2xl border border-slate-200 bg-white/80 px-4 py-3 shadow-sm">
              <div className="min-w-[160px]">
                <p className="text-[11px] font-semibold uppercase tracking-[0.14em] text-slate-500">
                  Current trust state
                </p>
                <div className="mt-2">
                  <TrustPill value={trustState} />
                </div>
              </div>

              <div className="hidden h-10 w-px bg-slate-200 sm:block" />

              <Button
                variant="secondary"
                onClick={() => void load(true)}
                loading={refreshing}
                disabled={loading}
                className="shrink-0"
              >
                Refresh
              </Button>
            </div>
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
            <p className="text-sm font-medium text-rose-700">Dashboard unavailable</p>
            <p className="mt-2 text-sm leading-6 text-slate-600">{error}</p>
          </Card>
        ) : (
          <>
            <div className="grid gap-4 xl:grid-cols-3">
              <Card>
                <SectionTitle
                  title="Trust posture"
                  description="Current clinic-facing trust signal derived from the backend surface."
                />
                <div className="mt-4 flex items-center gap-3">
                  <TrustPill value={trustState} />
                </div>
                <div className="mt-4 space-y-2">
                  {trustReasons.length ? (
                    trustReasons.map((reason, index) => (
                      <p key={`${reason}-${index}`} className="text-sm leading-6 text-slate-600">
                        • {reason}
                      </p>
                    ))
                  ) : (
                    <p className="text-sm leading-6 text-slate-600">
                      No trust-state reasons were returned. The clinic appears stable under the current
                      dashboard surface.
                    </p>
                  )}
                </div>
              </Card>

              <Card>
                <SectionTitle
                  title="24-hour governance activity"
                  description="A compact view of operational volume and bounded intervention signals."
                />
                <div className="mt-4 grid grid-cols-2 gap-4">
                  <Metric label="Events" value={summary.events} helper="Governed requests in the last 24 hours." />
                  <Metric
                    label="Interventions"
                    value={summary.interventions}
                    helper="Modified, replaced, or blocked outcomes."
                  />
                  <Metric label="PII warned" value={summary.piiWarned} helper="Events with privacy warning signals." />
                  <Metric label="Top mode" value={summary.topMode} helper="Most active workflow mode in view." />
                </div>
              </Card>

              <Card>
                <SectionTitle
                  title="Quick actions"
                  description="Move directly into the strongest operational surfaces."
                />
                <div className="mt-4 space-y-3">
                  <QuickLink
                    href="/receipts"
                    title="Open receipt viewer"
                    description="Inspect governance receipts by request ID."
                  />
                  <QuickLink
                    href="/governance-events"
                    title="Review governance events"
                    description="See recent clinic-scoped governance activity."
                  />
                  <QuickLink
                    href="/exports"
                    title="Export governance data"
                    description="Generate a metadata-only CSV export."
                  />
                  <QuickLink
                    href="/learn"
                    title="Open Learn"
                    description="Build safe AI-use literacy through explainers and microlearning."
                  />
                </div>
              </Card>
            </div>

            <div className="grid gap-4 xl:grid-cols-[1.1fr_0.9fr]">
              <Card>
                <SectionTitle
                  title="Operating snapshot"
                  description="A slightly richer reading of current dashboard activity signals."
                />
                <dl className="mt-4 space-y-4 text-sm">
                  <Detail label="Events per hour" value={formatNumber(summary.eventsPerHour)} />
                  <Detail label="Intervention rate" value={formatPercent(summary.interventionRate)} />
                  <Detail label="PII warned rate" value={formatPercent(summary.piiWarnedRate)} />
                  <Detail label="Top route" value={summary.topRoute} />
                  <Detail label="Snapshot time" value={formatDateTime(data?.now_utc)} />
                </dl>
              </Card>

              <Card>
                <SectionTitle
                  title="Recommended learning"
                  description="A lightweight bridge from governance operations into staff learning."
                />
                <div className="mt-4 space-y-4">
                  <div className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
                    <p className="text-sm font-semibold text-slate-900">Why metadata-only governance matters</p>
                    <p className="mt-2 text-sm leading-6 text-slate-600">
                      Reinforce why ANCHOR records governance evidence without turning the product into a raw-content archive.
                    </p>
                    <div className="mt-3">
                      <Link
                        href="/learn/explainers"
                        className="text-sm font-medium text-slate-900 underline underline-offset-4"
                      >
                        Open explainers
                      </Link>
                    </div>
                  </div>

                  <div className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
                    <p className="text-sm font-semibold text-slate-900">Human review responsibility</p>
                    <p className="mt-2 text-sm leading-6 text-slate-600">
                      Strengthen safe AI use by reinforcing that staff remain responsible for review and judgment.
                    </p>
                    <div className="mt-3">
                      <Link
                        href="/learn/cards"
                        className="text-sm font-medium text-slate-900 underline underline-offset-4"
                      >
                        Open microlearning cards
                      </Link>
                    </div>
                  </div>
                </div>
              </Card>
            </div>

            <Card>
              <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
                <div>
                  <p className="text-sm font-medium text-slate-500">Recent items</p>
                  <p className="mt-1 max-w-3xl text-sm leading-6 text-slate-600">
                    A clinic-scoped preview of recent governed activity surfaced through the existing backend
                    dashboard endpoint. Use request IDs to move directly into receipts.
                  </p>
                </div>
                <Link
                  href="/governance-events"
                  className="text-sm font-medium text-slate-900 underline underline-offset-4"
                >
                  View all governance events
                </Link>
              </div>

              <div className="mt-4 overflow-x-auto">
                <table className="min-w-full divide-y divide-slate-200 text-sm">
                  <thead>
                    <tr className="text-left text-slate-500">
                      <th className="py-3 pr-4 font-medium">Request ID</th>
                      <th className="py-3 pr-4 font-medium">Mode</th>
                      <th className="py-3 pr-4 font-medium">Decision</th>
                      <th className="py-3 pr-4 font-medium">PII</th>
                      <th className="py-3 pr-0 font-medium">Receipt</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100">
                    {recent.length ? (
                      recent.map((item) => {
                        const requestId = item.request_id ?? "";
                        const receiptHref = `/receipts?request_id=${encodeURIComponent(requestId)}`;

                        return (
                          <tr key={item.request_id ?? Math.random()} className="align-top">
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
                            <td className="py-4 pr-4 text-slate-600">
                              {item.pii_detected ? "Detected" : "Not detected"}
                            </td>
                            <td className="py-4 pr-0">
                              <Link
                                href={receiptHref}
                                className="text-sm font-medium text-slate-900 underline underline-offset-4"
                              >
                                Open receipt
                              </Link>
                            </td>
                          </tr>
                        );
                      })
                    ) : (
                      <tr>
                        <td colSpan={5} className="py-8">
                          <p className="text-sm font-medium text-slate-900">No recent items were returned</p>
                          <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-600">
                            Once new governed activity is processed for this clinic, recent items should appear here as
                            a bridge into governance events and receipts.
                          </p>
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </Card>
          </>
        )}
      </div>
    </AppShell>
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

function Metric({
  label,
  value,
  helper,
}: {
  label: string;
  value: string | number | null | undefined;
  helper: string;
}) {
  return (
    <div className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
      <p className="text-xs uppercase tracking-wide text-slate-500">{label}</p>
      <p className="mt-2 text-xl font-semibold tracking-tight text-slate-900">{value ?? "—"}</p>
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

function QuickLink({
  href,
  title,
  description,
}: {
  href: string;
  title: string;
  description: string;
}) {
  return (
    <Link
      href={href}
      className="block rounded-2xl border border-slate-200 bg-slate-50 p-4 transition hover:border-slate-300 hover:bg-white"
    >
      <p className="text-sm font-semibold text-slate-900">{title}</p>
      <p className="mt-1 text-sm leading-6 text-slate-600">{description}</p>
    </Link>
  );
}

function TrustPill({ value }: { value: string }) {
  const normalized = String(value || "unknown").toLowerCase().trim();

  const tone =
    normalized === "green"
      ? "border border-emerald-200 bg-emerald-50/70 text-emerald-800"
      : normalized === "amber" || normalized === "yellow"
        ? "border border-amber-200 bg-amber-50/70 text-amber-800"
        : normalized === "red"
          ? "border border-rose-200 bg-rose-50/70 text-rose-800"
          : "border border-slate-200 bg-slate-100 text-slate-700";

  return (
    <span
      className={[
        "inline-flex items-center rounded-full px-3 py-1.5 text-sm font-medium tracking-wide",
        tone,
      ].join(" ")}
    >
      {normalized === "unknown" ? "Unknown" : normalized.charAt(0).toUpperCase() + normalized.slice(1)}
    </span>
  );
}

function formatPercent(value: number | null | undefined) {
  if (typeof value !== "number") return "—";
  return `${(value * 100).toFixed(1)}%`;
}

function formatNumber(value: number | null | undefined) {
  if (typeof value !== "number") return "—";
  return value.toFixed(2);
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