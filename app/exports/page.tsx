"use client";

import { useMemo, useState } from "react";
import { AppShell } from "@/components/shell/AppShell";
import { Button } from "@/components/ui/Button";
import { Card } from "@/components/ui/Card";
import { Input } from "@/components/ui/Input";
import { buildApiUrl, getAuthHeaders, normalizeApiErrorMessage } from "@/lib/api";

function toLocalInputValue(date: Date) {
  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, "0");
  const day = String(date.getDate()).padStart(2, "0");
  const hours = String(date.getHours()).padStart(2, "0");
  const minutes = String(date.getMinutes()).padStart(2, "0");
  return `${year}-${month}-${day}T${hours}:${minutes}`;
}

export default function ExportsPage() {
  const [from, setFrom] = useState(toLocalInputValue(new Date(Date.now() - 7 * 24 * 60 * 60 * 1000)));
  const [to, setTo] = useState(toLocalInputValue(new Date()));
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const valid = useMemo(() => Boolean(from && to && new Date(from) < new Date(to)), [from, to]);

  async function handleDownload() {
    if (!valid) return;

    try {
      setLoading(true);
      setError(null);
      setMessage(null);

      const query = new URLSearchParams({
        from: new Date(from).toISOString(),
        to: new Date(to).toISOString(),
      });
      const headers = new Headers({
        Accept: "text/csv",
      });

      for (const [key, value] of Object.entries(getAuthHeaders())) {
        headers.set(key, value);
      }

      const response = await fetch(buildApiUrl(`/v1/portal/export.csv?${query.toString()}`), {
        method: "GET",
        headers,
      });

      if (!response.ok) {
        const text = await response.text();
        throw new Error(normalizeApiErrorMessage(response.status, text));
      }

      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = `anchor-export-${new Date().toISOString().slice(0, 10)}.csv`;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      window.URL.revokeObjectURL(url);

      setMessage("CSV export generated successfully.");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to export CSV.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <AppShell>
      <div className="space-y-6">
        <div>
          <p className="text-sm font-medium text-slate-500">Export controls</p>
          <h1 className="text-2xl font-semibold tracking-tight text-slate-900">Metadata-only exports</h1>
          <p className="mt-2 text-sm leading-6 text-slate-600">
            Generate clinic-scoped CSV exports for governance review. Server-side row caps and window caps remain the source of truth.
          </p>
        </div>

        <Card variant="native">
          <div className="grid gap-4 md:grid-cols-2">
            <Input label="From" type="datetime-local" value={from} onChange={(event) => setFrom(event.target.value)} />
            <Input label="To" type="datetime-local" value={to} onChange={(event) => setTo(event.target.value)} />
          </div>
          <div className="mt-4 flex flex-wrap items-center gap-3">
            <Button onClick={handleDownload} loading={loading} disabled={!valid || loading}>
              Download CSV
            </Button>
            <p className="text-sm text-slate-500">Exports remain metadata-only and clinic-scoped.</p>
          </div>
          {message ? <p className="mt-4 text-sm text-emerald-700">{message}</p> : null}
          {error ? <p className="mt-4 text-sm text-rose-700">{error}</p> : null}
        </Card>
      </div>
    </AppShell>
  );
}
