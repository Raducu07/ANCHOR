"use client";

import Link from "next/link";
import { useEffect, useMemo, useState, type ReactNode } from "react";
import { Button, getButtonChromeClasses } from "@/components/ui/Button";
import { apiFetch, ApiError } from "@/lib/api";
import type {
  DashboardResponse,
  IntelligenceRecommendation,
  IntelligenceRecommendationsResponse,
  IntelligenceSummary,
} from "@/lib/types";

const quickActions = [
  { href: "/workspace-live", icon: "clinical_notes", label: "Open Workspace" },
  { href: "/receipts", icon: "receipt_long", label: "Open receipt viewer" },
  { href: "/intelligence", icon: "psychology", label: "Open Intelligence" },
  { href: "/learn", icon: "school", label: "Open Learn" },
  { href: "/exports", icon: "download", label: "Export governance data" },
] as const;

const principles = [
  { title: "Metadata-only accountability", icon: "shield" },
  { title: "Operational clarity", icon: "visibility" },
] as const;

export function DashboardSurface() {
  const [dashboard, setDashboard] = useState<DashboardResponse | null>(null);
  const [intelligence, setIntelligence] = useState<IntelligenceSummary | null>(null);
  const [recommendations, setRecommendations] = useState<IntelligenceRecommendation[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function load(showRefreshing = false) {
    try {
      if (showRefreshing) {
        setRefreshing(true);
      } else {
        setLoading(true);
      }

      const [dashboardResponse, intelligenceResponse, recommendationsResponse] = await Promise.all([
        apiFetch<DashboardResponse>("/v1/portal/dashboard"),
        apiFetch<IntelligenceSummary>("/v1/portal/intelligence/summary?window=30d"),
        apiFetch<IntelligenceRecommendationsResponse>("/v1/portal/intelligence/recommendations?window=30d"),
      ]);

      setDashboard(dashboardResponse);
      setIntelligence(intelligenceResponse);
      setRecommendations(recommendationsResponse.items ?? []);
      setError(null);
    } catch (err) {
      const message = err instanceof ApiError ? err.message : "Unable to load the dashboard.";
      setError(message);
      setDashboard(null);
      setIntelligence(null);
      setRecommendations([]);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }

  useEffect(() => {
    void load(false);
  }, []);

  const view = useMemo(() => {
    const kpis = dashboard?.kpis_24h;
    const recent = dashboard?.recent_submissions ?? [];
    const trustState = dashboard?.trust_state?.health_state ?? "green";
    const trustReasons = dashboard?.trust_state?.reasons ?? [];
    const topRecommendation = recommendations[0] ?? intelligence?.headline_action ?? null;
    const priorityReceipt = recent.find((item) => item.pii_detected) ?? recent[0] ?? null;
    const recommendedLearningHref =
      topRecommendation?.target_path && topRecommendation.target_path.startsWith("/learn")
        ? topRecommendation.target_path
        : "/learn/cards";

    return {
      events: kpis?.events_24h ?? recent.length ?? 0,
      interventions: kpis?.interventions_24h ?? 0,
      piiWarned: kpis?.pii_warned_24h ?? recent.filter((item) => item.pii_detected).length,
      topMode: prettyMode(kpis?.top_mode_24h),
      topRoute: kpis?.top_route_24h ?? "No route surfaced yet",
      eventsPerHour: kpis?.events_per_hour ?? 0,
      interventionRate: kpis?.intervention_rate_24h ?? 0,
      piiWarnedRate: kpis?.pii_warned_rate_24h ?? 0,
      recent,
      trustState,
      trustLetter: trustLetter(trustState),
      trustReasons:
        trustReasons.length > 0
          ? trustReasons
          : [
              "Clinic-scoped governance is active across current portal surfaces.",
              "Receipt-backed accountability remains visible without raw-content storage.",
              "Human review remains assumed before operational use.",
            ],
      headlineHotspot: intelligence?.headline_hotspot ?? null,
      topRecommendation,
      nextActionHref: priorityReceipt?.request_id
        ? `/receipts?request_id=${encodeURIComponent(priorityReceipt.request_id)}`
        : "/receipts",
      nextActionText:
        topRecommendation?.why ??
        (priorityReceipt?.pii_detected
          ? `Review receipt ${priorityReceipt.request_id?.slice(0, 8) ?? ""} for privacy-aware handling before operational use.`
          : "Review recent governance activity and confirm whether any receipt requires follow-up."),
      recommendedLearningTitle:
        topRecommendation && (topRecommendation.type === "learning" || topRecommendation.type === "privacy_training")
          ? topRecommendation.title
          : "Refresh privacy-safe AI use guidance",
      recommendedLearningHref,
      snapshotTime: formatDateTime(dashboard?.now_utc ?? intelligence?.generated_at),
    };
  }, [dashboard, intelligence, recommendations]);

  return (
    <div className="mx-auto max-w-[1480px] space-y-8">
      <section className="space-y-6">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight text-slate-900">Operational governance overview</h1>
          <p className="mt-2 max-w-4xl text-sm leading-6 text-slate-600">
            A calm leadership-facing surface for trust posture, governance activity, receipts, learning signals,
            and intelligence.
          </p>
        </div>

        <div className="flex flex-wrap gap-2">
          <MetaChip label={`Trust state (${view.trustLetter})`} dot />
          <MetaChip label="Mode: clinic-scoped" />
          <MetaChip label={`Events 24h (${formatInteger(view.events)})`} />
        </div>

        <div className="flex flex-wrap gap-3">
          <Button
            variant="ghost"
            onClick={() => void load(true)}
            loading={refreshing}
            disabled={loading || refreshing}
            className="rounded-md px-5 py-2.5"
          >
            Refresh dashboard
          </Button>
          <Link
            href="/workspace-live"
            className={[getButtonChromeClasses("primary"), "rounded-md px-6 py-2.5"].join(" ")}
          >
            Open Workspace
          </Link>
        </div>
      </section>

      {error ? (
        <NativeCard className="border-rose-200 bg-rose-50 text-rose-700">
          <p className="text-sm font-medium">Dashboard unavailable</p>
          <p className="mt-2 text-sm leading-6">{error}</p>
        </NativeCard>
      ) : null}

      <div className="space-y-8">
        <NativeCard>
          <div className="mb-8 flex flex-col gap-4 md:flex-row md:items-start md:justify-between">
            <div>
              <SectionEyebrow>Governance telemetry</SectionEyebrow>
              <h2 className="mt-2 text-base font-semibold text-slate-900">24-hour governance activity</h2>
            </div>
            <div className="flex flex-wrap gap-2">
              <MetaChip label="Clinic-scoped" />
              <MetaChip label="Live surface" tone="success" />
            </div>
          </div>

          <div className="mb-10 grid grid-cols-2 gap-4 md:grid-cols-4">
            <MetricTile label="Events" value={formatInteger(view.events)} />
            <MetricTile label="Interventions" value={formatInteger(view.interventions)} />
            <MetricTile label="PII warned" value={String(view.piiWarned).padStart(2, "0")} tone="danger" />
            <MetricTile label="Top mode" value={view.topMode} compact />
          </div>

          <div className="grid gap-10 md:grid-cols-2">
            <DataList
              title="Operating snapshot"
              rows={[
                ["Events per hour", formatDecimal(view.eventsPerHour, 1)],
                ["Intervention rate", formatPercent(view.interventionRate)],
                ["PII warned rate", formatPercent(view.piiWarnedRate)],
              ]}
            />
            <DataList
              title="Current route picture"
              rows={[
                ["Top route", view.topRoute],
                ["Snapshot time", view.snapshotTime],
                ["Window", "Rolling 24h"],
              ]}
            />
          </div>
        </NativeCard>

        <div className="space-y-6">
          <NativeCard>
            <div className="mb-8">
              <SectionEyebrow>Accountability surfaces</SectionEyebrow>
              <h2 className="mt-2 text-base font-semibold text-slate-900">Recent governance receipts</h2>
            </div>

            {loading ? (
              <EmptyState text="Loading recent governance receipts..." />
            ) : view.recent.length === 0 ? (
              <EmptyState text="No recent governance receipts are available yet." />
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full min-w-[680px] text-left">
                  <thead>
                    <tr className="border-b border-slate-100 text-[10px] font-bold uppercase tracking-[0.16em] text-slate-500">
                      <th className="pb-4">Request ID</th>
                      <th className="pb-4">Mode</th>
                      <th className="pb-4">Decision</th>
                      <th className="pb-4">PII</th>
                      <th className="pb-4 text-right">Receipt</th>
                    </tr>
                  </thead>
                  <tbody>
                    {view.recent.slice(0, 3).map((item, index) => {
                      const requestId = item.request_id ?? `recent-${index}`;
                      const receiptHref = item.request_id
                        ? `/receipts?request_id=${encodeURIComponent(item.request_id)}`
                        : "/receipts";
                      return (
                        <tr
                          key={requestId}
                          className="border-b border-slate-100/80 text-sm text-slate-700 last:border-b-0"
                        >
                          <td className="py-5 font-mono text-xs font-bold text-slate-900">
                            {item.request_id ?? "-"}
                          </td>
                          <td className="py-5 text-xs font-medium text-slate-900">{prettyMode(item.mode)}</td>
                          <td className="py-5">
                            <DecisionBadge decision={item.decision} />
                          </td>
                          <td className="py-5 text-[11px] italic text-slate-500">
                            {item.pii_detected ? (
                              <span className="not-italic font-semibold uppercase text-rose-600">Detected</span>
                            ) : (
                              "Not detected"
                            )}
                          </td>
                          <td className="py-5 text-right">
                            <Link
                              href={receiptHref}
                              className="inline-flex items-center gap-1 text-xs font-bold text-slate-600 hover:text-slate-900 hover:underline"
                            >
                              Open link
                              <span className="material-symbols-outlined text-[14px]">open_in_new</span>
                            </Link>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </NativeCard>

          <div className="space-y-3">
            <div className="grid gap-3 xl:grid-cols-[minmax(0,1.3fr)_minmax(320px,0.7fr)] xl:items-stretch">
              <NativeCard className="relative flex h-full min-h-[228px] flex-col overflow-hidden bg-slate-50/70 p-5">
                <div className="relative mb-4 flex items-start justify-between gap-4">
                  <SectionEyebrow className="pt-1">Recommended next action</SectionEyebrow>
                  <span
                    className={[
                      "shrink-0 rounded-full px-3 py-1 text-[10px] font-semibold uppercase tracking-[0.12em]",
                      priorityTone(view.topRecommendation?.priority ?? "medium"),
                    ].join(" ")}
                  >
                    {humanizeToken(view.topRecommendation?.priority ?? "medium")} priority
                  </span>
                </div>

                <p className="relative max-w-[28rem] text-[1.05rem] font-semibold leading-7 tracking-tight text-slate-900">
                  {view.nextActionText}
                </p>

                <div className="relative mt-auto border-t border-slate-200/80 pt-3.5">
                  <Link
                    href={view.nextActionHref}
                    className={[getButtonChromeClasses("primary"), "rounded-md px-4 py-2"].join(" ")}
                  >
                    Review receipt
                  </Link>
                </div>
              </NativeCard>

              <NativeCard className="p-[14px]">
                <div className="flex items-start gap-3">
                  <div className="flex h-14 w-14 items-center justify-center rounded-2xl border border-slate-200 bg-slate-100 text-[1.75rem] font-extrabold text-slate-700 shadow-[inset_0_1px_0_rgba(255,255,255,0.6)]">
                    {view.trustLetter}
                  </div>
                  <div className="pt-0.5">
                    <SectionEyebrow>Trust posture</SectionEyebrow>
                    <h2 className="mt-1 text-base font-semibold tracking-tight text-slate-900">Clinic-Scoped</h2>
                  </div>
                </div>

                <ul className="mt-3 space-y-2">
                  {view.trustReasons.slice(0, 3).map((reason) => (
                    <li key={reason} className="flex items-start gap-3">
                      <span className="material-symbols-outlined mt-0.5 text-[18px] text-emerald-500">
                        check_circle
                      </span>
                      <span className="text-sm leading-5 text-slate-600">{humanizeToken(reason)}</span>
                    </li>
                  ))}
                </ul>
              </NativeCard>
            </div>

            <div className="grid gap-3 xl:grid-cols-[minmax(0,1.3fr)_minmax(320px,0.7fr)] xl:items-stretch">
              <NativeCard className="h-full p-4">
                <SectionEyebrow>Recommended learning</SectionEyebrow>
                <div className="mt-2.5 divide-y divide-slate-100 rounded-xl border border-slate-200/80 bg-slate-50/70">
                  <Link
                    href={view.recommendedLearningHref}
                    className="group flex items-center gap-3 px-4 py-2.5 transition hover:bg-white/75"
                  >
                    <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-white text-slate-600 shadow-sm">
                      <span className="material-symbols-outlined text-[18px]">book</span>
                    </div>
                    <div className="min-w-0 flex-1">
                      <div className="text-sm font-semibold text-slate-900">{view.recommendedLearningTitle}</div>
                      <div className="mt-0.5 text-sm text-slate-600">Open microlearning card</div>
                    </div>
                    <span className="material-symbols-outlined text-[18px] text-slate-400 transition group-hover:translate-x-0.5">
                      chevron_right
                    </span>
                  </Link>

                  <Link
                    href="/receipts"
                    className="group flex items-center gap-3 px-4 py-2.5 transition hover:bg-white/75"
                  >
                    <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-white text-slate-600 shadow-sm">
                      <span className="material-symbols-outlined text-[18px]">play_circle</span>
                    </div>
                    <div className="min-w-0 flex-1">
                      <div className="text-sm font-semibold text-slate-900">Navigating the Receipt Ledger</div>
                      <div className="mt-0.5 text-sm text-slate-600">Open explainer</div>
                    </div>
                    <span className="material-symbols-outlined text-[18px] text-slate-400 transition group-hover:translate-x-0.5">
                      chevron_right
                    </span>
                  </Link>
                </div>
              </NativeCard>

              <NativeCard className="h-full p-4">
                <div>
                  <SectionEyebrow>Current intelligence context</SectionEyebrow>
                  <h3 className="mt-1.5 text-base font-semibold text-slate-900">
                    {view.headlineHotspot
                      ? hotspotLabel(view.headlineHotspot.dimension, view.headlineHotspot.key)
                      : "No active hotspot"}
                  </h3>
                  <p className="mt-2 text-sm leading-5 text-slate-600">
                    {view.headlineHotspot?.summary ??
                      "No prominent hotspot is surfaced in the selected intelligence window, but the clinic view remains live."}
                  </p>

                  <div className="mt-3 grid grid-cols-2 gap-2.5">
                    <MetricTile
                      label="Event share"
                      value={view.headlineHotspot ? formatPercent(view.headlineHotspot.event_share) : "-"}
                      compact
                    />
                    <MetricTile
                      label="Recency spike"
                      value={
                        view.headlineHotspot
                          ? `${formatDecimal(view.headlineHotspot.recency_spike_ratio, 1)}x`
                          : "-"
                      }
                      compact
                    />
                  </div>
                </div>
              </NativeCard>
            </div>

            <div className="grid gap-4 xl:grid-cols-[minmax(0,1.3fr)_minmax(320px,0.7fr)] xl:items-stretch">
              <NativeCard className="h-full p-5">
                <SectionEyebrow>Quick actions</SectionEyebrow>
                <div className="mt-4 grid gap-2.5 sm:grid-cols-2">
                  {quickActions.map((action) => (
                    <Link
                      key={action.href}
                      href={action.href}
                      className="group flex items-center justify-between rounded-xl border border-slate-200/80 bg-slate-50 px-4 py-3 transition hover:border-slate-300 hover:bg-white"
                    >
                      <div className="flex items-center gap-3">
                        <span className="material-symbols-outlined text-[18px] text-slate-600">{action.icon}</span>
                        <span className="text-sm font-medium text-slate-900">{action.label}</span>
                      </div>
                      <span className="material-symbols-outlined text-[18px] text-slate-400 transition group-hover:translate-x-0.5">
                        chevron_right
                      </span>
                    </Link>
                  ))}
                </div>
              </NativeCard>

              <NativeCard className="h-full p-4">
                <SectionEyebrow>Principles</SectionEyebrow>
                <div className="mt-4 grid gap-2">
                  {principles.map((principle, index) => (
                    <div
                      key={principle.title}
                      className="flex items-center gap-3 rounded-xl border border-slate-200/80 bg-slate-50 px-4 py-3"
                    >
                      <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-white text-slate-600 shadow-sm">
                        <span className="material-symbols-outlined text-[17px]">{principle.icon}</span>
                      </div>
                      <div className="min-w-0">
                        <h4 className="mb-0.5 text-[10px] font-medium uppercase tracking-[0.14em] text-slate-500">
                          Principle {String(index + 1).padStart(2, "0")}
                        </h4>
                        <p className="text-sm font-semibold text-slate-900">{principle.title}</p>
                      </div>
                    </div>
                  ))}
                </div>
              </NativeCard>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

function NativeCard({
  children,
  className = "",
}: {
  children: ReactNode;
  className?: string;
}) {
  return (
    <section
      className={[
        "rounded-xl border border-slate-200/80 bg-white p-8 shadow-[0_18px_40px_rgba(42,52,57,0.07)]",
        className,
      ].join(" ")}
    >
      {children}
    </section>
  );
}

function SectionEyebrow({
  children,
  className = "",
}: {
  children: ReactNode;
  className?: string;
}) {
  return (
    <span
      className={[
        "block text-[10px] font-bold uppercase tracking-[0.18em] text-slate-500",
        className,
      ].join(" ")}
    >
      {children}
    </span>
  );
}

function MetaChip({
  label,
  dot = false,
  tone = "default",
}: {
  label: string;
  dot?: boolean;
  tone?: "default" | "success";
}) {
  return (
    <span
      className={[
        "inline-flex items-center rounded-full border px-3 py-1 text-[11px] font-medium uppercase tracking-[0.12em]",
        tone === "success"
          ? "border-emerald-200 bg-emerald-50 text-emerald-700"
          : "border-slate-200 bg-slate-100 text-slate-500",
      ].join(" ")}
    >
      {dot ? <span className="mr-1.5 h-1.5 w-1.5 rounded-full bg-slate-500" /> : null}
      {label}
    </span>
  );
}

function MetricTile({
  label,
  value,
  tone = "default",
  compact = false,
}: {
  label: string;
  value: string;
  tone?: "default" | "danger";
  compact?: boolean;
}) {
  return (
    <div className="rounded-lg border border-slate-200/70 bg-slate-50 p-4">
      <p className="mb-1 text-xs uppercase tracking-wide text-slate-500">{label}</p>
      <p
        className={[
          compact ? "text-lg leading-tight" : "text-2xl",
          "font-semibold tracking-tight",
          tone === "danger" ? "text-rose-600" : "text-slate-900",
        ].join(" ")}
      >
        {value}
      </p>
    </div>
  );
}

function DataList({
  title,
  rows,
}: {
  title: string;
  rows: Array<[string, string]>;
}) {
  return (
    <div className="space-y-4">
      <h3 className="text-xs uppercase tracking-wide text-slate-500">{title}</h3>
      <div className="space-y-3">
        {rows.map(([label, value]) => (
          <div key={label} className="flex items-center justify-between border-b border-slate-100 py-1 text-sm">
            <span className="text-slate-500">{label}</span>
            <span className="font-medium text-slate-900">{value}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function DecisionBadge({ decision }: { decision?: string }) {
  const normalized = (decision ?? "").toLowerCase();
  const tone =
    normalized === "allowed" || normalized === "verified" || normalized === "pass"
      ? "bg-emerald-50 text-emerald-700"
      : normalized === "modified" || normalized === "warning" || normalized === "warn"
        ? "bg-amber-100 text-amber-800"
        : normalized === "blocked" || normalized === "replaced" || normalized === "flagged"
          ? "bg-rose-50 text-rose-700"
          : "bg-slate-100 text-slate-600";

  return (
    <span
      className={[
        "inline-flex rounded px-2 py-0.5 text-[10px] font-semibold uppercase tracking-[0.12em]",
        tone,
      ].join(" ")}
    >
      {humanizeToken(decision ?? "unknown")}
    </span>
  );
}

function EmptyState({ text }: { text: string }) {
  return <p className="py-8 text-sm text-slate-500">{text}</p>;
}

function trustLetter(value: string | undefined) {
  const normalized = (value ?? "").toLowerCase();
  if (normalized === "green") return "A";
  if (normalized === "yellow" || normalized === "amber") return "B";
  if (normalized === "red") return "C";
  return "A";
}

function priorityTone(priority: string) {
  const normalized = priority.toLowerCase();
  if (normalized === "high") return "bg-rose-500 text-white";
  if (normalized === "low") return "bg-emerald-500 text-white";
  return "bg-amber-400 text-slate-900";
}

function hotspotLabel(dimension?: string | null, key?: string | null) {
  if (!dimension && !key) return "No active hotspot";
  return `${humanizeToken(dimension ?? "signal")} - ${humanizeToken(key ?? "current")}`;
}

function prettyMode(value?: string | null) {
  const raw = (value ?? "").toLowerCase().trim();
  if (raw === "client_comm" || raw === "client_communication") return "Client communication";
  if (raw === "clinical_note") return "Clinical note";
  if (raw === "clinical_note_baseline") return "Clinical note baseline";
  if (raw === "internal_summary") return "Internal summary";
  return humanizeToken(value ?? "-");
}

function humanizeToken(value?: string | null) {
  if (!value) return "-";
  return value.replace(/[_-]+/g, " ").replace(/\b\w/g, (char) => char.toUpperCase());
}

function formatInteger(value: number) {
  return new Intl.NumberFormat("en-GB", { maximumFractionDigits: 0 }).format(value);
}

function formatDecimal(value: number, places = 1) {
  return Number.isFinite(value) ? value.toFixed(places) : "0.0";
}

function formatPercent(value: number) {
  return `${(value * 100).toFixed(2)}%`;
}

function formatDateTime(value?: string | null) {
  if (!value) return "No live snapshot yet";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat("en-GB", {
    day: "2-digit",
    month: "short",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  }).format(date);
}
