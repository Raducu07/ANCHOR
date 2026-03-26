"use client";

import Link from "next/link";
import { useEffect, useMemo, useState } from "react";
import { AppShell } from "@/components/shell/AppShell";
import { Button } from "@/components/ui/Button";
import { Card } from "@/components/ui/Card";
import { StatusBadge } from "@/components/ui/StatusBadge";
import { apiFetch, ApiError } from "@/lib/api";
import type { GovernanceEventListEnvelope, GovernanceEventSummary } from "@/lib/types";

export default function GovernanceEventsPage() {
  const [items, setItems] = useState<GovernanceEventSummary[]>([]);
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

      const response = await apiFetch<GovernanceEventListEnvelope | GovernanceEventSummary[]>(
        "/v1/portal/governance-events?limit=50",
      );

      const normalized = Array.isArray(response)
        ? response
        : response.events ?? response.items ?? response.rows ?? [];

      setItems(normalized);
      setError(null);
    } catch (err) {
      const message = err instanceof ApiError ? err.message : "Unable to load governance events.";
      setError(message);
    } finally {
      setLoading(false);
      setRefreshing(false);
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

  return (
    <AppShell>
      <div className="space-y-6">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
          <div>
            <p className="text-sm font-medium text-slate-500">Governance activity</p>
            <h1 className="text-2xl font-semibold tracking-tight text-slate-900">Governance events</h1>
            <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-600">
              Clinic-scoped governance activity surface for operational review, follow-up, and receipt navigation.
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

        <Card>
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
              <div className="mt-4">
                <Link
                  href="/receipts"
                  className="text-sm font-medium text-slate-900 underline underline-offset-4"
                >
                  Open receipt viewer
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
                    <th className="py-3 pr-0 font-medium">Receipt</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {items.map((item) => {
                    const requestId = item.request_id ?? "";
                    const receiptHref = `/receipts?request_id=${encodeURIComponent(requestId)}`;

                    return (
                      <tr key={`${item.request_id}-${item.created_at}`} className="align-top">
                        <td className="py-4 pr-4 text-slate-600">{formatDate(item.created_at)}</td>
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
                  })}
                </tbody>
              </table>
            </div>
          )}
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
    <Card>
      <p className="text-sm font-medium text-slate-500">{label}</p>
      <p className="mt-2 text-2xl font-semibold tracking-tight text-slate-900">{value}</p>
      <p className="mt-2 text-sm leading-6 text-slate-600">{helper}</p>
    </Card>
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