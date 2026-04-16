"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { AppShell } from "@/components/shell/AppShell";
import { getTrustPosture } from "@/lib/trust";
import type { TrustPostureResponse } from "@/lib/types";

function formatDate(value?: string) {
  if (!value) return "—";
  try {
    return new Date(value).toLocaleString();
  } catch {
    return value;
  }
}

function statusTone(status?: string) {
  switch (status) {
    case "attention_required":
      return "bg-rose-100 text-rose-800";
    case "monitoring":
      return "bg-amber-100 text-amber-800";
    case "light_signal":
      return "bg-slate-200 text-slate-800";
    default:
      return "bg-emerald-100 text-emerald-800";
  }
}

export default function TrustPosturePage() {
  const [data, setData] = useState<TrustPostureResponse | null>(null);
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
      setError(null);
      const response = await getTrustPosture();
      setData(response);
    } catch (err: any) {
      setError(err?.message || "Failed to load governance posture.");
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }

  useEffect(() => {
    load();
  }, []);

  return (
    <AppShell>
      <div className="mx-auto max-w-7xl space-y-6 p-6">
        <div className="flex items-start justify-between gap-4">
          <div>
            <p className="text-sm font-medium uppercase tracking-wide text-slate-500">Trust</p>
            <h1 className="text-2xl font-semibold text-slate-900">Governance Posture</h1>
            <p className="mt-2 max-w-3xl text-sm text-slate-600">
              Leadership-readable summary of governance, privacy, tenant isolation, operations, and
              learning readiness generated from ANCHOR’s live metadata-only evidence.
            </p>
          </div>

          <button
            onClick={() => load(true)}
            className="rounded-xl border border-slate-300 px-4 py-2 text-sm font-medium text-slate-700 hover:bg-slate-50"
            disabled={refreshing}
          >
            {refreshing ? "Refreshing..." : "Refresh"}
          </button>
        </div>

        {loading ? (
          <div className="rounded-2xl border border-slate-200 bg-white p-6 text-sm text-slate-600 shadow-sm">
            Loading governance posture...
          </div>
        ) : error ? (
          <div className="rounded-2xl border border-rose-200 bg-rose-50 p-6 text-sm text-rose-700 shadow-sm">
            {error}
          </div>
        ) : data ? (
          <>
            <div className="grid gap-6 xl:grid-cols-[1.4fr_minmax(320px,0.8fr)]">
              <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm">
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <div>
                    <p className="text-xs font-medium uppercase tracking-wide text-slate-500">
                      Posture summary
                    </p>
                    <h2 className="mt-1 text-2xl font-semibold text-slate-900">{data.headline}</h2>
                  </div>

                  <span
                    className={`rounded-full px-3 py-1 text-xs font-medium ${statusTone(
                      data.sections.find((section) => section.id === "operations")?.status
                    )}`}
                  >
                    {data.snapshot.operations.trust_state}
                  </span>
                </div>

                <p className="mt-4 max-w-3xl text-sm leading-7 text-slate-600">{data.summary}</p>

                <div className="mt-5 grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
                  <div className="rounded-xl border border-slate-200 bg-slate-50 p-4">
                    <div className="text-xs uppercase tracking-wide text-slate-500">Generated</div>
                    <div className="mt-2 text-sm font-medium text-slate-900">
                      {formatDate(data.generated_at)}
                    </div>
                  </div>

                  <div className="rounded-xl border border-slate-200 bg-slate-50 p-4">
                    <div className="text-xs uppercase tracking-wide text-slate-500">Policy version</div>
                    <div className="mt-2 text-sm font-medium text-slate-900">
                      v{data.snapshot.governance.policy_version}
                    </div>
                  </div>

                  <div className="rounded-xl border border-slate-200 bg-slate-50 p-4">
                    <div className="text-xs uppercase tracking-wide text-slate-500">Signal quality</div>
                    <div className="mt-2 text-sm font-medium capitalize text-slate-900">
                      {data.snapshot.operations.signal_quality}
                    </div>
                  </div>

                  <div className="rounded-xl border border-slate-200 bg-slate-50 p-4">
                    <div className="text-xs uppercase tracking-wide text-slate-500">Evidence window</div>
                    <div className="mt-2 text-sm font-medium text-slate-900">
                      {data.snapshot.evidence_window.hours}h
                    </div>
                  </div>
                </div>

                <div className="mt-4 flex flex-wrap gap-3">
                  <Link
                    href="/trust/profile"
                    className="rounded-xl bg-slate-900 px-4 py-2 text-sm font-medium text-white hover:bg-slate-800"
                  >
                    Back to trust profile
                  </Link>
                  <Link
                    href="/trust/pack"
                    className="rounded-xl border border-slate-300 px-4 py-2 text-sm font-medium text-slate-700 hover:bg-slate-50"
                  >
                    View trust pack
                  </Link>
                  <Link
                    href="/trust/materials"
                    className="rounded-xl border border-slate-300 px-4 py-2 text-sm font-medium text-slate-700 hover:bg-slate-50"
                  >
                    View trust materials
                  </Link>
                </div>
              </div>

              <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm">
                <p className="text-xs font-medium uppercase tracking-wide text-slate-500">
                  Operating signals
                </p>
                <h2 className="mt-2 text-lg font-semibold text-slate-900">Current evidence view</h2>

                <div className="mt-4 space-y-3">
                  <div className="rounded-xl border border-slate-200 bg-slate-50 p-4">
                    <div className="text-xs uppercase tracking-wide text-slate-500">Events (24h)</div>
                    <div className="mt-1 text-sm font-medium text-slate-900">
                      {data.snapshot.operations.events_24h}
                    </div>
                  </div>

                  <div className="rounded-xl border border-slate-200 bg-slate-50 p-4">
                    <div className="text-xs uppercase tracking-wide text-slate-500">
                      Intervention rate (24h)
                    </div>
                    <div className="mt-1 text-sm font-medium text-slate-900">
                      {(data.snapshot.operations.intervention_rate_24h * 100).toFixed(1)}%
                    </div>
                  </div>

                  <div className="rounded-xl border border-slate-200 bg-slate-50 p-4">
                    <div className="text-xs uppercase tracking-wide text-slate-500">
                      Privacy warning rate (24h)
                    </div>
                    <div className="mt-1 text-sm font-medium text-slate-900">
                      {(data.snapshot.operations.pii_warned_rate_24h * 100).toFixed(1)}%
                    </div>
                  </div>

                  <div className="rounded-xl border border-slate-200 bg-slate-50 p-4">
                    <div className="text-xs uppercase tracking-wide text-slate-500">Top mode (24h)</div>
                    <div className="mt-1 text-sm font-medium text-slate-900">
                      {data.snapshot.operations.top_mode_24h ?? "—"}
                    </div>
                  </div>
                </div>
              </div>
            </div>

            <div className="grid gap-6 xl:grid-cols-2">
              {data.sections.map((section) => (
                <div key={section.id} className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm">
                  <div className="flex items-center justify-between gap-3">
                    <div>
                      <div className="text-xs font-medium uppercase tracking-wide text-slate-500">
                        {section.id.replaceAll("_", " ")}
                      </div>
                      <h2 className="mt-1 text-lg font-semibold text-slate-900">{section.title}</h2>
                    </div>

                    <span
                      className={`rounded-full px-3 py-1 text-xs font-medium ${statusTone(section.status)}`}
                    >
                      {section.status.replaceAll("_", " ")}
                    </span>
                  </div>

                  <div className="mt-4 space-y-3">
                    {section.items.map((item, idx) => (
                      <div key={idx} className="rounded-xl border border-slate-200 bg-slate-50 px-4 py-3">
                        <p className="text-sm leading-6 text-slate-700">{item}</p>
                      </div>
                    ))}
                  </div>
                </div>
              ))}
            </div>

            <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm">
              <p className="text-xs font-medium uppercase tracking-wide text-slate-500">Limitations</p>
              <div className="mt-4 grid gap-3">
                {data.snapshot.limitations.map((item, idx) => (
                  <div key={idx} className="rounded-xl border border-slate-200 bg-slate-50 px-4 py-3">
                    <p className="text-sm leading-6 text-slate-700">{item}</p>
                  </div>
                ))}
              </div>
            </div>
          </>
        ) : null}
      </div>
    </AppShell>
  );
}
