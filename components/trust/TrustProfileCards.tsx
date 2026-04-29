// Reference / experimental UI only.
// This file is currently not used by active routes and should not be treated as current source-of-truth UI.
// @ts-nocheck
import Link from "next/link";
import type { ReactNode } from "react";
import type { TrustProfileResponse } from "@/lib/types";

function CardShell({
  title,
  subtitle,
  children,
}: {
  title: string;
  subtitle?: string;
  children: ReactNode;
}) {
  return (
    <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm">
      <div className="mb-4">
        <h2 className="text-lg font-semibold text-slate-900">{title}</h2>
        {subtitle ? <p className="mt-1 text-sm text-slate-600">{subtitle}</p> : null}
      </div>
      {children}
    </div>
  );
}

function Metric({
  label,
  value,
}: {
  label: string;
  value: ReactNode;
}) {
  return (
    <div className="rounded-xl border border-slate-200 bg-slate-50 p-4">
      <div className="text-xs font-medium uppercase tracking-wide text-slate-500">{label}</div>
      <div className="mt-2 text-xl font-semibold text-slate-900">{value}</div>
    </div>
  );
}

function formatPct(value: number) {
  return `${(value * 100).toFixed(1)}%`;
}

function trustPillClass(state: string) {
  if (state === "green") return "bg-emerald-100 text-emerald-800";
  if (state === "yellow") return "bg-amber-100 text-amber-800";
  return "bg-rose-100 text-rose-800";
}

function posturePillClass(state: string) {
  if (state === "strong") return "bg-emerald-100 text-emerald-800";
  if (state === "stable") return "bg-sky-100 text-sky-800";
  if (state === "watch") return "bg-amber-100 text-amber-800";
  return "bg-rose-100 text-rose-800";
}

function displayValue(value: string | null | undefined) {
  const cleaned = (value ?? "").trim();

  if (!cleaned) return "—";

  const lowered = cleaned.toLowerCase();
  if (["null", "none", "undefined", "n/a", "na"].includes(lowered)) {
    return "—";
  }

  return cleaned;
}

export function TrustHeroCard({ data }: { data: TrustProfileResponse }) {
  return (
    <div className="rounded-3xl border border-slate-200 bg-white p-6 shadow-sm">
      <div className="flex flex-col gap-4 md:flex-row md:items-start md:justify-between">
        <div>
          <p className="text-sm font-medium uppercase tracking-wide text-slate-500">Trust Profile</p>
          <h1 className="mt-2 text-3xl font-semibold text-slate-900">Clinic trust posture</h1>
          <p className="mt-2 max-w-2xl text-sm text-slate-600">
            A leadership-facing summary of current governance strength, privacy posture, and operational trust signals.
          </p>
        </div>

        <div className="flex flex-wrap gap-2">
          <span className={`rounded-full px-3 py-1 text-sm font-medium ${trustPillClass(data.trust_state)}`}>
            trust {data.trust_state}
          </span>
          <span className={`rounded-full px-3 py-1 text-sm font-medium ${posturePillClass(data.posture_status)}`}>
            posture {data.posture_status}
          </span>
        </div>
      </div>

      <div className="mt-6 grid gap-4 md:grid-cols-3">
        <Metric label="Posture score" value={data.posture_score} />
        <Metric label="Events (24h)" value={data.operations.events_24h} />
        <Metric label="Generated" value={new Date(data.generated_at).toLocaleString()} />
      </div>

      <div className="mt-6 flex flex-wrap gap-3">
        <Link
          href="/trust/posture"
          className="rounded-xl bg-slate-900 px-4 py-2 text-sm font-medium text-white hover:bg-slate-800"
        >
          View governance posture
        </Link>
        <Link
          href="/trust/pack"
          className="rounded-xl border border-slate-300 px-4 py-2 text-sm font-medium text-slate-700 hover:bg-slate-50"
        >
          Open trust pack
        </Link>
        <Link
          href="/governance-events"
          className="rounded-xl border border-slate-300 px-4 py-2 text-sm font-medium text-slate-700 hover:bg-slate-50"
        >
          Review governed activity
        </Link>
      </div>
    </div>
  );
}

export function ControlsChecklistCard({ data }: { data: TrustProfileResponse }) {
  const items = [
    ["Metadata-only accountability", data.controls.metadata_only_accountability],
    ["Governance receipts", data.controls.governance_receipts],
    ["Policy versioning", data.controls.policy_versioning],
    ["Tenant isolation (RLS)", data.controls.tenant_isolation_rls_forced],
    ["Privacy controls", data.controls.privacy_controls_active],
    ["Export capability", data.controls.export_capability],
    ["Learning layer", data.controls.learning_layer_available],
  ];

  return (
    <CardShell title="Governance controls" subtitle="Core control posture currently visible for this clinic">
      <div className="grid gap-3 md:grid-cols-2">
        {items.map(([label, ok]) => (
          <div
            key={label}
            className="flex items-center justify-between rounded-xl border border-slate-200 bg-slate-50 px-4 py-3"
          >
            <span className="text-sm text-slate-700">{label}</span>
            <span
              className={`rounded-full px-2.5 py-1 text-xs font-medium ${
                ok ? "bg-emerald-100 text-emerald-800" : "bg-slate-200 text-slate-700"
              }`}
            >
              {ok ? "active" : "inactive"}
            </span>
          </div>
        ))}
      </div>
    </CardShell>
  );
}

export function OperationalTrustCard({ data }: { data: TrustProfileResponse }) {
  return (
    <CardShell title="Operational trust indicators" subtitle="Recent activity and governance signals">
      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <Metric label="Intervention rate (24h)" value={formatPct(data.operations.intervention_rate_24h)} />
        <Metric label="PII warned rate (24h)" value={formatPct(data.operations.pii_warned_rate_24h)} />
        <Metric label="Top mode (24h)" value={data.operations.top_mode_24h ? data.operations.top_mode_24h : "—"} />
<Metric label="Top route (24h)" value={data.operations.top_route_24h ? data.operations.top_route_24h : "—"} />
      </div>
    </CardShell>
  );
}

export function LearningReadinessCard({ data }: { data: TrustProfileResponse }) {
  const topics =
    data.learning_readiness.recommended_topics?.length > 0
      ? data.learning_readiness.recommended_topics
      : ["No current recommendation"];

  return (
    <CardShell title="Learning readiness" subtitle="Recommended educational tie-ins from recent governance patterns">
      <div className="grid gap-4 lg:grid-cols-[1.25fr_0.75fr]">
        <div className="rounded-xl border border-slate-200 bg-slate-50 p-4">
          <div className="text-sm font-medium text-slate-900">Recommended topics</div>
          <ul className="mt-3 space-y-2">
            {topics.map((topic) => (
              <li key={topic} className="rounded-lg bg-white px-3 py-2 text-sm text-slate-700 shadow-sm">
                {topic}
              </li>
            ))}
          </ul>
        </div>

        <div className="rounded-xl border border-slate-200 bg-slate-50 p-4">
          <div className="text-sm font-medium text-slate-900">Learning tie-in rate</div>
          <div className="mt-3 text-3xl font-semibold text-slate-900">
            {formatPct(data.learning_readiness.learning_tie_in_rate_24h)}
          </div>
          <p className="mt-2 text-sm text-slate-600">
            Share of recent governed activity that naturally points toward an explanatory or training follow-up.
          </p>
        </div>
      </div>
    </CardShell>
  );
}

export function ExportReadinessCard({ data }: { data: TrustProfileResponse }) {
  return (
    <CardShell title="Export readiness" subtitle="Trust-pack status for leadership and external trust materials">
      <div className="grid gap-4 md:grid-cols-2">
        <div className="rounded-xl border border-slate-200 bg-slate-50 p-4">
          <div className="text-sm font-medium text-slate-900">Trust pack availability</div>
          <div className="mt-3">
            <span
              className={`rounded-full px-3 py-1 text-sm font-medium ${
                data.export_readiness.trust_pack_available
                  ? "bg-emerald-100 text-emerald-800"
                  : "bg-amber-100 text-amber-800"
              }`}
            >
              {data.export_readiness.trust_pack_available ? "available" : "planned"}
            </span>
          </div>
        </div>

        <div className="rounded-xl border border-slate-200 bg-slate-50 p-4">
          <div className="text-sm font-medium text-slate-900">Last pack generated</div>
          <div className="mt-3 text-base font-semibold text-slate-900">
            {data.export_readiness.last_pack_generated_at
              ? new Date(data.export_readiness.last_pack_generated_at).toLocaleString()
              : "Not yet generated"}
          </div>
        </div>
      </div>
    </CardShell>
  );
}

