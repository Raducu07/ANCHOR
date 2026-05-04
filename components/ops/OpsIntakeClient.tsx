"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import { Button } from "@/components/ui/Button";
import { Card } from "@/components/ui/Card";
import { StatusBadge } from "@/components/ui/StatusBadge";

type IntakeSummary = Record<string, number | string | null | Record<string, unknown>>;

type IntakeRecord = {
  id: string;
  type?: "demo" | "start";
  kind?: "demo" | "start";
  created_at?: string;
  clinic_name?: string;
  full_name?: string;
  work_email?: string;
  phone?: string | null;
  role?: string;
  clinic_size?: string | null;
  current_ai_use?: string | null;
  rollout_timing?: string | null;
  site_count?: number | null;
  biggest_concern?: string | null;
  primary_interest?: string | null;
  preferred_plan?: string | null;
  interest_or_plan?: string | null;
  concern_or_timing?: string | null;
  source_page?: string | null;
  utm_source?: string | null;
  utm_medium?: string | null;
  utm_campaign?: string | null;
  message?: string | null;
  notes?: string | null;
  status?: string;
};

type OpsError = {
  message: string;
  unauthorized?: boolean;
  status?: number;
  endpoint?: string;
};

type RequestFilters = {
  type: "all" | "demo" | "start";
  status: string;
};

function formatDate(value: string | undefined) {
  if (!value) return "-";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

function getRecordValue(record: IntakeRecord, ...keys: string[]) {
  const source = record as Record<string, unknown>;

  for (const key of keys) {
    const value = source[key];
    if (typeof value === "string" && value.trim()) return value;
    if (typeof value === "number") return String(value);
  }

  return null;
}

function getRecordKind(record: IntakeRecord): "demo" | "start" {
  const explicitKind = getRecordValue(record, "type", "kind", "request_type");
  if (explicitKind === "start" || explicitKind === "demo") return explicitKind;

  const startSignals = ["preferred_plan", "rollout_timing", "site_count"];
  return startSignals.some((key) => getRecordValue(record, key) !== null) ? "start" : "demo";
}

function getRecordStatus(record: IntakeRecord) {
  return getRecordValue(record, "status", "request_status") ?? "new";
}

function getRecordFocusLabel(record: IntakeRecord, kind: "demo" | "start") {
  if (kind === "start") {
    return getRecordValue(record, "preferred_plan", "interest_or_plan", "plan") ?? "-";
  }
  return getRecordValue(record, "primary_interest", "interest_or_plan", "interest") ?? "-";
}

function getRecordConcernLabel(record: IntakeRecord, kind: "demo" | "start") {
  if (kind === "start") {
    return getRecordValue(record, "rollout_timing", "concern_or_timing") ?? "-";
  }
  return getRecordValue(record, "biggest_concern", "concern_or_timing") ?? "-";
}

function getSummaryNumber(summary: IntakeSummary | null, paths: string[][]) {
  if (!summary) return null;

  for (const path of paths) {
    let current: unknown = summary;

    for (const segment of path) {
      if (!current || typeof current !== "object") {
        current = null;
        break;
      }
      current = (current as Record<string, unknown>)[segment];
    }

    if (typeof current === "number") return current;
    if (typeof current === "string" && current.trim() && !Number.isNaN(Number(current))) {
      return Number(current);
    }
  }

  return null;
}

function mapOpsErrorToUiMessage(error: OpsError) {
  const source = `${error.endpoint ?? ""} ${error.message}`.toLowerCase();

  if (source.includes("requests") || source.includes("admin_intake_requests_failed")) {
    return "Recent intake requests could not be loaded right now.";
  }

  if (source.includes("summary") || source.includes("admin_intake_summary_failed")) {
    return "Intake summary data could not be loaded right now.";
  }

  return "Some intake operations data could not be loaded right now.";
}

function extractErrorMessage(payload: unknown) {
  if (!payload || typeof payload !== "object") return null;
  if ("detail" in payload && typeof payload.detail === "string") return payload.detail;
  if ("error" in payload && typeof payload.error === "string") return payload.error;
  return null;
}

async function fetchOps<T>(path: string) {
  const response = await fetch(path, { method: "GET" });

  const payload = (await response.json().catch(() => null)) as T | null;
  if (!response.ok) {
    const message = extractErrorMessage(payload) ?? "Unable to reach ANCHOR intake operations right now.";
    const error: OpsError = {
      message,
      unauthorized: response.status === 401 || response.status === 403,
      status: response.status,
      endpoint: path,
    };
    throw error;
  }

  return payload as T;
}

function SummaryCard({ label, value }: { label: string; value: string | number }) {
  return (
    <Card className="rounded-[2rem] p-6">
      <p className="text-sm font-bold uppercase tracking-[0.18em] text-slate-500">{label}</p>
      <p className="mt-4 text-3xl font-bold tracking-tight text-slate-950">{value}</p>
    </Card>
  );
}

function RequestDetailRow({
  label,
  value,
}: {
  label: string;
  value: string | null | undefined;
}) {
  return (
    <div className="rounded-2xl border border-slate-200 bg-white px-4 py-3">
      <p className="text-xs font-bold uppercase tracking-[0.18em] text-slate-500">{label}</p>
      <p className="mt-2 break-words text-sm leading-6 text-slate-700">{value || "-"}</p>
    </div>
  );
}

export function OpsIntakeClient() {
  const router = useRouter();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<OpsError | null>(null);
  const [summary, setSummary] = useState<IntakeSummary | null>(null);
  const [requests, setRequests] = useState<IntakeRecord[]>([]);
  const [loggingOut, setLoggingOut] = useState(false);
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [filters, setFilters] = useState<RequestFilters>({
    type: "all",
    status: "all",
  });

  const filteredRequests = useMemo(() => {
    return requests.filter((record) => {
      const kind = getRecordKind(record);
      const matchesType = filters.type === "all" || kind === filters.type;
      const matchesStatus = filters.status === "all" || getRecordStatus(record) === filters.status;
      return matchesType && matchesStatus;
    });
  }, [filters.status, filters.type, requests]);

  const loadData = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);

      const [summaryPayload, requestsPayload] = await Promise.allSettled([
        fetchOps<{ counts?: IntakeSummary; summary?: IntakeSummary } & IntakeSummary>(
          "/api/ops/intake/summary"
        ),
        fetchOps<{ items?: IntakeRecord[]; requests?: IntakeRecord[] }>(
          "/api/ops/intake/requests?type=all&limit=50"
        ),
      ]);

      const failures = [summaryPayload, requestsPayload]
        .filter((result): result is PromiseRejectedResult => result.status === "rejected")
        .map((result) =>
          result.reason && typeof result.reason === "object" && "message" in result.reason
            ? (result.reason as OpsError)
            : ({ message: "Unable to load intake operations." } as OpsError)
        );

      const unauthorizedFailure = failures.find((failure) => failure.unauthorized);
      if (unauthorizedFailure) {
        router.replace("/ops/admin-login");
        return;
      }

      if (summaryPayload.status === "fulfilled") {
        const value = summaryPayload.value as { counts?: IntakeSummary; summary?: IntakeSummary } & IntakeSummary;
        setSummary(value.summary ?? value.counts ?? (value as IntakeSummary));
      } else {
        setSummary(null);
      }

      if (requestsPayload.status === "fulfilled") {
        setRequests(requestsPayload.value.items ?? requestsPayload.value.requests ?? []);
      } else {
        setRequests([]);
      }

      if (failures.length > 0) {
        setError({ message: mapOpsErrorToUiMessage(failures[0]) });
      }
    } finally {
      setLoading(false);
    }
  }, [router]);

  useEffect(() => {
    void loadData();
  }, [loadData]);

  async function handleLogout() {
    try {
      setLoggingOut(true);
      await fetch("/api/ops/admin-session/logout", { method: "POST" });
    } finally {
      router.replace("/ops/admin-login");
    }
  }

  const summaryValues = {
    newDemo:
      getSummaryNumber(summary, [
        ["new_demo_requests"],
        ["demo_requests", "new"],
        ["demo", "new"],
      ]) ??
      requests.filter((record) => getRecordKind(record) === "demo" && getRecordStatus(record) === "new").length,
    newStart:
      getSummaryNumber(summary, [
        ["new_start_requests"],
        ["start_requests", "new"],
        ["start", "new"],
      ]) ??
      requests.filter((record) => getRecordKind(record) === "start" && getRecordStatus(record) === "new").length,
    demoTotal:
      getSummaryNumber(summary, [
        ["demo_requests", "total"],
        ["demo_requests"],
        ["demo", "total"],
      ]) ?? requests.filter((record) => getRecordKind(record) === "demo").length,
    startTotal:
      getSummaryNumber(summary, [
        ["start_requests", "total"],
        ["start_requests"],
        ["start", "total"],
      ]) ?? requests.filter((record) => getRecordKind(record) === "start").length,
  };

  return (
    <main className="min-h-screen bg-slate-50 px-4 py-10 text-slate-800 sm:px-6 lg:px-8">
      <div className="mx-auto max-w-7xl space-y-8">
        <div className="flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
          <div>
            <p className="text-sm font-bold uppercase tracking-[0.18em] text-slate-500">Internal operations</p>
            <h1 className="mt-2 text-4xl font-bold tracking-tight text-slate-950">
              Ops intake <span className="text-slate-500">(read-only)</span>
            </h1>
            <p className="mt-3 max-w-3xl text-lg leading-8 text-slate-600">
              Internal-only review of public demo and onboarding intake requests. This view is read-only.
            </p>
          </div>
          <div className="flex gap-3">
            <Button type="button" variant="secondary" onClick={() => void loadData()} loading={loading}>
              Refresh
            </Button>
            <Button type="button" onClick={() => void handleLogout()} loading={loggingOut}>
              Sign out
            </Button>
          </div>
        </div>

        <Card className="rounded-[2rem] border-amber-200 bg-amber-50/80 p-5 text-sm leading-6 text-amber-900">
          Internal operations view. Do not copy confidential clinical, client-identifiable, or
          patient-identifiable content into external systems.
        </Card>

        {error ? (
          <Card className="rounded-[2rem] border-rose-200 bg-rose-50/80 p-6 text-sm text-rose-700">
            {error.message}
            {error.unauthorized ? (
              <>
                {" "}
                <a className="font-semibold underline" href="/ops/admin-login">
                  Sign in again
                </a>
                .
              </>
            ) : null}
          </Card>
        ) : null}

        <div className="grid gap-4 lg:grid-cols-4">
          <SummaryCard label="New demo requests" value={summaryValues.newDemo} />
          <SummaryCard label="New start requests" value={summaryValues.newStart} />
          <SummaryCard label="Demo requests (total)" value={summaryValues.demoTotal} />
          <SummaryCard label="Start requests (total)" value={summaryValues.startTotal} />
        </div>

        <Card className="rounded-[2rem] p-8">
          <div className="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
            <div>
              <h2 className="text-2xl font-semibold text-slate-900">Recent intake requests</h2>
              <p className="mt-2 text-sm leading-6 text-slate-600">
                Read-only review of recent demo and onboarding requests. Status updates and notes
                editing are not part of this view.
              </p>
            </div>

            <div className="grid gap-3 sm:grid-cols-2">
              <label className="space-y-2 text-sm font-medium text-slate-700">
                <span>Type</span>
                <select
                  value={filters.type}
                  onChange={(event) =>
                    setFilters((current) => ({
                      ...current,
                      type: event.target.value as RequestFilters["type"],
                    }))
                  }
                  className="w-full rounded-2xl border border-slate-300 bg-white px-4 py-3 text-sm text-slate-900 shadow-sm"
                >
                  <option value="all">All</option>
                  <option value="demo">Demo</option>
                  <option value="start">Start</option>
                </select>
              </label>

              <label className="space-y-2 text-sm font-medium text-slate-700">
                <span>Status</span>
                <select
                  value={filters.status}
                  onChange={(event) =>
                    setFilters((current) => ({
                      ...current,
                      status: event.target.value,
                    }))
                  }
                  className="w-full rounded-2xl border border-slate-300 bg-white px-4 py-3 text-sm text-slate-900 shadow-sm"
                >
                  <option value="all">All</option>
                  <option value="new">new</option>
                  <option value="contacted">contacted</option>
                  <option value="booked">booked</option>
                  <option value="onboarding">onboarding</option>
                  <option value="qualified">qualified</option>
                  <option value="closed">closed</option>
                </select>
              </label>
            </div>
          </div>

          <div className="mt-6 space-y-4">
            {loading ? (
              <div className="rounded-2xl border border-slate-200 bg-slate-50 px-4 py-6 text-sm text-slate-600">
                Loading intake requests...
              </div>
            ) : null}

            {!loading && filteredRequests.length === 0 ? (
              <div className="rounded-2xl border border-slate-200 bg-slate-50 px-4 py-6 text-sm text-slate-600">
                No intake requests match the current filters.
              </div>
            ) : null}

            {filteredRequests.map((record) => {
              const kind = getRecordKind(record);
              const isExpanded = expandedId === record.id;
              const summaryLabel = getRecordFocusLabel(record, kind);
              const clinicName = getRecordValue(record, "clinic_name") ?? "Unknown clinic";
              const fullName = getRecordValue(record, "full_name") ?? "-";
              const workEmail = getRecordValue(record, "work_email") ?? "-";
              const role = getRecordValue(record, "role") ?? "-";
              const currentStatus = getRecordStatus(record);

              return (
                <div key={record.id} className="rounded-3xl border border-slate-200 bg-slate-50/80 p-5">
                  <div className="flex flex-col gap-3">
                    <div className="flex flex-wrap items-center gap-2">
                      <StatusBadge value={kind} />
                      <StatusBadge value={currentStatus} />
                      <span className="text-xs font-medium uppercase tracking-[0.18em] text-slate-500">
                        {formatDate(record.created_at)}
                      </span>
                    </div>

                    <div>
                      <h3 className="text-lg font-semibold text-slate-950">{clinicName}</h3>
                      <div className="mt-2 grid gap-x-6 gap-y-1 text-sm text-slate-600 md:grid-cols-2">
                        <p>
                          <span className="font-medium text-slate-800">Name:</span> {fullName}
                        </p>
                        <p>
                          <span className="font-medium text-slate-800">Email:</span> {workEmail}
                        </p>
                        <p>
                          <span className="font-medium text-slate-800">Role:</span> {role}
                        </p>
                        <p>
                          <span className="font-medium text-slate-800">
                            {kind === "start" ? "Preferred plan" : "Primary interest"}:
                          </span>{" "}
                          {summaryLabel}
                        </p>
                      </div>
                    </div>

                    <div>
                      <button
                        type="button"
                        onClick={() => setExpandedId((current) => (current === record.id ? null : record.id))}
                        className="rounded-full border border-slate-200 bg-white px-3 py-1.5 text-xs font-semibold text-slate-700 transition hover:bg-slate-100"
                      >
                        {isExpanded ? "Hide details" : "View details"}
                      </button>
                    </div>
                  </div>

                  {isExpanded ? (
                    <div className="mt-5 grid gap-3 border-t border-slate-200 pt-5 md:grid-cols-2 xl:grid-cols-3">
                      <RequestDetailRow label="Created" value={formatDate(record.created_at)} />
                      <RequestDetailRow label="Full name" value={getRecordValue(record, "full_name")} />
                      <RequestDetailRow label="Work email" value={getRecordValue(record, "work_email")} />
                      <RequestDetailRow label="Phone" value={getRecordValue(record, "phone")} />
                      <RequestDetailRow label="Clinic name" value={getRecordValue(record, "clinic_name")} />
                      <RequestDetailRow label="Role" value={getRecordValue(record, "role")} />
                      <RequestDetailRow
                        label={kind === "start" ? "Preferred plan" : "Primary interest"}
                        value={getRecordFocusLabel(record, kind)}
                      />
                      <RequestDetailRow label="Clinic size" value={getRecordValue(record, "clinic_size")} />
                      <RequestDetailRow label="Current AI use" value={getRecordValue(record, "current_ai_use")} />
                      <RequestDetailRow
                        label={kind === "start" ? "Rollout timing" : "Biggest concern"}
                        value={getRecordConcernLabel(record, kind)}
                      />
                      {kind === "start" ? (
                        <RequestDetailRow
                          label="Number of sites"
                          value={getRecordValue(record, "site_count")}
                        />
                      ) : null}
                      <RequestDetailRow label="Status" value={currentStatus} />
                      <RequestDetailRow label="Message" value={getRecordValue(record, "message")} />
                      <RequestDetailRow label="Source page" value={getRecordValue(record, "source_page")} />
                      <RequestDetailRow label="UTM source" value={getRecordValue(record, "utm_source")} />
                      <RequestDetailRow label="UTM medium" value={getRecordValue(record, "utm_medium")} />
                      <RequestDetailRow label="UTM campaign" value={getRecordValue(record, "utm_campaign")} />
                    </div>
                  ) : null}
                </div>
              );
            })}
          </div>
        </Card>
      </div>
    </main>
  );
}
