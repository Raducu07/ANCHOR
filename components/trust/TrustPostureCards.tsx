import type { ReactNode } from "react";
import type { TrustPostureResponse } from "@/lib/types";

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

function posturePillClass(state: string) {
  if (state === "strong") return "bg-emerald-100 text-emerald-800";
  if (state === "stable") return "bg-sky-100 text-sky-800";
  if (state === "watch") return "bg-amber-100 text-amber-800";
  return "bg-rose-100 text-rose-800";
}

export function PostureSummaryHero({ data }: { data: TrustPostureResponse }) {
  return (
    <div className="rounded-3xl border border-slate-200 bg-white p-6 shadow-sm">
      <div className="flex flex-col gap-4 md:flex-row md:items-start md:justify-between">
        <div>
          <p className="text-sm font-medium uppercase tracking-wide text-slate-500">Governance posture</p>
          <h1 className="mt-2 text-3xl font-semibold text-slate-900">Leadership posture summary</h1>
          <p className="mt-2 max-w-3xl text-sm text-slate-600">{data.summary.headline}</p>
        </div>

        <div className="flex flex-wrap gap-2">
          <span className={`rounded-full px-3 py-1 text-sm font-medium ${posturePillClass(data.summary.posture_status)}`}>
            {data.summary.posture_status}
          </span>
        </div>
      </div>

      <div className="mt-6 grid gap-4 md:grid-cols-3">
        <Metric label="Posture score" value={data.summary.posture_score} />
        <Metric label="Events (30d)" value={data.adoption.events_30d} />
        <Metric label="Generated" value={new Date(data.generated_at).toLocaleString()} />
      </div>
    </div>
  );
}

export function AdoptionOverviewCard({ data }: { data: TrustPostureResponse }) {
  return (
    <CardShell title="Adoption overview" subtitle="Usage footprint across the last 30 days">
      <div className="grid gap-4 md:grid-cols-3">
        <Metric label="Events (30d)" value={data.adoption.events_30d} />
        <Metric label="Top mode" value={data.adoption.top_mode || "—"} />
        <Metric label="Active modes" value={data.adoption.active_modes.length} />
      </div>

      <div className="mt-4 flex flex-wrap gap-2">
        {data.adoption.active_modes.map((mode) => (
          <span key={mode} className="rounded-full bg-slate-100 px-3 py-1 text-sm text-slate-700">
            {mode}
          </span>
        ))}
      </div>
    </CardShell>
  );
}

export function GovernancePerformanceCard({ data }: { data: TrustPostureResponse }) {
  return (
    <CardShell title="Governance performance" subtitle="Key governing signals from recent activity">
      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <Metric label="Intervention rate" value={formatPct(data.governance.intervention_rate_30d)} />
        <Metric label="Replacement rate" value={formatPct(data.governance.replacement_rate_30d)} />
        <Metric label="Receipt coverage" value={formatPct(data.governance.receipt_coverage_rate)} />
        <Metric label="Active policy version" value={data.governance.active_policy_version ?? "—"} />
      </div>
    </CardShell>
  );
}

export function PrivacyAccountabilityCard({ data }: { data: TrustPostureResponse }) {
  return (
    <CardShell title="Privacy & accountability" subtitle="Core doctrine and privacy-facing signals">
      <div className="grid gap-4 md:grid-cols-3">
        <Metric
          label="Metadata-only model"
          value={data.privacy.metadata_only_model ? "Active" : "Inactive"}
        />
        <Metric
          label="PII warning rate"
          value={formatPct(data.privacy.pii_warning_rate_30d)}
        />
        <Metric
          label="Raw content storage"
          value={data.privacy.raw_content_storage ? "Enabled" : "Not stored"}
        />
      </div>
    </CardShell>
  );
}

export function LearningSummaryCard({ data }: { data: TrustPostureResponse }) {
  return (
    <CardShell title="Learning & readiness" subtitle="Recommended enablement themes from governance patterns">
      <div className="mb-4">
        <span
          className={`rounded-full px-3 py-1 text-sm font-medium ${
            data.learning.learn_enabled ? "bg-emerald-100 text-emerald-800" : "bg-slate-200 text-slate-700"
          }`}
        >
          {data.learning.learn_enabled ? "Learn enabled" : "Learn inactive"}
        </span>
      </div>

      <ul className="space-y-2">
        {data.learning.top_recommended_topics.map((topic) => (
          <li key={topic} className="rounded-xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-700">
            {topic}
          </li>
        ))}
      </ul>
    </CardShell>
  );
}

export function AttentionAreasCard({ data }: { data: TrustPostureResponse }) {
  return (
    <CardShell title="Attention areas" subtitle="Signals that warrant leadership visibility or follow-up">
      <div className="space-y-3">
        {data.attention_areas.map((area) => (
          <div key={`${area.type}-${area.label}`} className="rounded-xl border border-amber-200 bg-amber-50 p-4">
            <div className="text-xs font-medium uppercase tracking-wide text-amber-700">{area.type}</div>
            <div className="mt-1 text-sm text-amber-900">{area.label}</div>
          </div>
        ))}
      </div>
    </CardShell>
  );
}

export function RecommendedActionsCard({ data }: { data: TrustPostureResponse }) {
  return (
    <CardShell title="Recommended next actions" subtitle="Conservative, governance-safe follow-up actions">
      <ul className="space-y-3">
        {data.recommended_actions.map((action) => (
          <li key={action} className="rounded-xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-700">
            {action}
          </li>
        ))}
      </ul>
    </CardShell>
  );
}