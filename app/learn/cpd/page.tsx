"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { AppShell } from "@/components/shell/AppShell";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { getSessionUser } from "@/lib/auth";
import {
  createUserCPDExport,
  exportCpdPayloadAsJson,
  getCPDExportPayload,
  getMyCPDRecord,
} from "@/lib/learn";
import type { CPDRecord } from "@/lib/types";

function formatDate(value?: string | null) {
  if (!value) return "—";
  try {
    return new Date(value).toLocaleString();
  } catch {
    return value;
  }
}

type ExportState =
  | { kind: "idle" }
  | { kind: "exporting" }
  | { kind: "done" }
  | { kind: "error"; message: string };

// Clinic-admin roles permitted to generate a CPD export. Mirrors the
// backend LEARN_ADMIN_ROLES on POST /v1/learn/cpd/users/{user_id}/exports,
// which is admin-only. Non-admin users would otherwise receive 403.
const EXPORT_ADMIN_ROLES = new Set(["admin", "owner", "practice_manager"]);

export default function MyCPDRecordPage() {
  const [userId, setUserId] = useState<string | null>(null);
  const [role, setRole] = useState<string | null>(null);
  const [record, setRecord] = useState<CPDRecord | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [exportState, setExportState] = useState<ExportState>({ kind: "idle" });

  useEffect(() => {
    const session = getSessionUser();
    setUserId(session?.clinicUserId ?? null);
    setRole(session?.role ?? null);
  }, []);

  useEffect(() => {
    let active = true;

    async function load() {
      setLoading(true);
      setError(null);
      try {
        const result = await getMyCPDRecord();
        if (!active) return;
        setRecord(result);
      } catch (err: unknown) {
        if (!active) return;
        const message =
          err instanceof Error
            ? err.message
            : "Unable to load your CPD-recordable AI literacy activity.";
        setError(message);
        setRecord(null);
      } finally {
        if (active) setLoading(false);
      }
    }

    void load();

    return () => {
      active = false;
    };
  }, []);

  async function handleExport() {
    if (!userId) return;
    setExportState({ kind: "exporting" });
    try {
      const created = await createUserCPDExport(userId);
      const payload = await getCPDExportPayload(created.export_id);
      exportCpdPayloadAsJson(payload);
      setExportState({ kind: "done" });
    } catch (err: unknown) {
      const message =
        err instanceof Error ? err.message : "Unable to generate the export.";
      setExportState({ kind: "error", message });
    }
  }

  const hasCompletions = Boolean(record && record.total_modules_completed > 0);
  const isExportAdmin = Boolean(role && EXPORT_ADMIN_ROLES.has(role));
  const canExport = Boolean(userId) && hasCompletions && isExportAdmin;

  return (
    <AppShell>
      <div className="mx-auto max-w-4xl space-y-6">
        <div>
          <Link
            href="/learn"
            className="text-sm font-medium text-slate-500 underline underline-offset-4 hover:text-slate-700"
          >
            Back to Learn
          </Link>
        </div>

        <div>
          <p className="text-sm font-medium text-slate-500">ANCHOR Learn</p>
          <h1 className="text-2xl font-semibold tracking-tight text-slate-900">
            Your CPD-recordable AI literacy activity
          </h1>
          <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-600">
            This page shows metadata-only evidence of completed ANCHOR AI literacy modules.
          </p>
          <p className="mt-2 max-w-3xl text-xs leading-5 text-slate-500">
            This is not an RCVS-accredited CPD certificate or an official professional-body record.
          </p>
        </div>

        {loading ? (
          <div className="rounded-xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-600">
            Loading your CPD-recordable AI literacy activity...
          </div>
        ) : error ? (
          <div className="rounded-xl border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-700">
            {error}
          </div>
        ) : record ? (
          <>
            <Card variant="native">
              <div className="flex flex-wrap items-start justify-between gap-3">
                <h2 className="text-base font-semibold text-slate-900">Summary</h2>
                <div className="flex max-w-xs flex-col items-end gap-2">
                  {isExportAdmin ? (
                    <>
                      <Button
                        onClick={handleExport}
                        loading={exportState.kind === "exporting"}
                        disabled={!canExport}
                      >
                        Export as JSON
                      </Button>
                      {!userId ? (
                        <span className="text-xs text-slate-500">
                          Export is unavailable: no signed-in user context.
                        </span>
                      ) : null}
                    </>
                  ) : hasCompletions ? (
                    <span className="text-right text-xs text-slate-500">
                      JSON export is available to clinic administrators. Your completion activity
                      remains recorded as metadata-only evidence.
                    </span>
                  ) : null}
                </div>
              </div>

              <div className="mt-5 grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
                <SummaryTile label="Modules completed" value={String(record.total_modules_completed)} />
                <SummaryTile label="Total CPD minutes" value={String(record.total_cpd_minutes)} />
                <SummaryTile label="First completion" value={formatDate(record.first_completion_at)} />
                <SummaryTile
                  label="Most recent completion"
                  value={formatDate(record.most_recent_completion_at)}
                />
              </div>

              {exportState.kind === "done" ? (
                <div className="mt-4 rounded-xl border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm text-emerald-700">
                  Export generated as a metadata-only JSON record and downloaded.
                </div>
              ) : exportState.kind === "error" ? (
                <div className="mt-4 rounded-xl border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-700">
                  {exportState.message}
                </div>
              ) : null}
            </Card>

            <Card variant="native">
              <h2 className="text-base font-semibold text-slate-900">Completed modules</h2>
              {hasCompletions ? (
                <div className="mt-4 space-y-3">
                  {record.completions.map((completion) => (
                    <div
                      key={completion.completion_id}
                      className="rounded-xl border border-slate-200 bg-slate-50 px-4 py-3"
                    >
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <p className="text-sm font-medium text-slate-900">
                          Module {completion.module_id}
                        </p>
                        <span className="inline-flex items-center rounded-full border border-slate-200 bg-white px-2 py-0.5 text-xs font-medium text-slate-500">
                          v{completion.module_version}
                        </span>
                      </div>
                      <div className="mt-2 flex flex-wrap gap-x-6 gap-y-1 text-xs text-slate-600">
                        <span>Completed: {formatDate(completion.completed_at)}</span>
                        <span>CPD minutes: {completion.cpd_minutes_credited}</span>
                        <span>
                          Acknowledgement:{" "}
                          {completion.acknowledgement_provided ? "Provided" : "Not provided"}
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="mt-4 rounded-xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-600">
                  No completed AI literacy modules yet. Completing modules in Learn will record
                  metadata-only evidence here.
                </div>
              )}
            </Card>
          </>
        ) : null}
      </div>
    </AppShell>
  );
}

function SummaryTile({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-xl border border-slate-200 bg-slate-50 p-4">
      <div className="text-xs uppercase tracking-wide text-slate-500">{label}</div>
      <div className="mt-2 text-sm font-semibold text-slate-900">{value}</div>
    </div>
  );
}

