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

type IntelligenceRecommendationsResponse = {
  generated_at: string;
  window: "7d" | "30d";
  items: IntelligenceRecommendation[];
};

export default function IntelligenceRecommendationsPage() {
  const [windowValue, setWindowValue] = useState<"7d" | "30d">("30d");
  const [data, setData] = useState<IntelligenceRecommendationsResponse | null>(null);
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

      const response = await apiFetch<IntelligenceRecommendationsResponse>(
        `/v1/portal/intelligence/recommendations?window=${selectedWindow}`
      );

      setData(response);
      setError(null);
    } catch (err) {
      const message = err instanceof ApiError ? err.message : "Unable to load intelligence recommendations.";
      setError(message);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }

  useEffect(() => {
    void load(windowValue, false);
  }, [windowValue]);

  return (
    <AppShell>
      <div className="space-y-6">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
          <div>
            <p className="text-sm font-medium text-slate-500">Recommendations</p>
            <h1 className="text-2xl font-semibold tracking-tight text-slate-900">
              Intelligence recommendations
            </h1>
            <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-600">
              Deterministic actions derived from current metadata patterns across governance,
              privacy, workflow, and learning signals.
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
          <div className="grid gap-4">
            {Array.from({ length: 4 }).map((_, index) => (
              <Card variant="native" key={index} className="h-36 animate-pulse bg-slate-100" />
            ))}
          </div>
        ) : error ? (
          <Card variant="native">
            <p className="text-sm font-medium text-rose-700">Recommendations unavailable</p>
            <p className="mt-2 text-sm leading-6 text-slate-600">{error}</p>
          </Card>
        ) : (
          <>
            <Card variant="native">
              <SectionTitle
                title="Current recommendation view"
                description="A quick readout of the active recommendation scope."
              />
              <dl className="mt-4 space-y-4 text-sm">
                <Detail label="Window" value={data?.window ?? windowValue} />
                <Detail label="Generated at" value={formatDateTime(data?.generated_at)} />
                <Detail label="Returned items" value={String(data?.items.length ?? 0)} />
              </dl>
            </Card>

            <div className="space-y-4">
              {data?.items.length ? (
                data.items.map((item, index) => (
                  <Card variant="native" key={`${item.type}-${item.based_on.dimension}-${item.based_on.key}-${index}`}>
                    <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
                      <div className="min-w-0">
                        <div className="flex flex-wrap items-center gap-3">
                          <StatusBadge value={item.priority} />
                          <p className="text-sm font-semibold uppercase tracking-wide text-slate-500">
                            {item.type.replace(/_/g, " ")}
                          </p>
                        </div>

                        <p className="mt-3 text-lg font-semibold text-slate-900">{item.title}</p>
                        <p className="mt-2 text-sm leading-6 text-slate-600">{item.why}</p>

                        <dl className="mt-4 space-y-3 text-sm">
                          <Detail label="Based on" value={`${item.based_on.dimension}: ${item.based_on.key}`} />
                          <Detail label="Priority" value={capitalize(item.priority)} />
                        </dl>
                      </div>

                      <div className="shrink-0">
                        <Link
                          href={item.target_path || "/intelligence"}
                          className="inline-flex items-center rounded-2xl border border-slate-200 bg-white px-4 py-2.5 text-sm font-medium text-slate-900 shadow-sm transition hover:border-slate-300"
                        >
                          Open destination
                        </Link>
                      </div>
                    </div>
                  </Card>
                ))
              ) : (
                <Card variant="native">
                  <p className="text-sm font-medium text-slate-900">No recommendations were returned</p>
                  <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-600">
                    Recommendations will appear once sufficient governance concentration patterns are
                    available in the selected window.
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