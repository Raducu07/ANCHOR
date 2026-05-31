"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { AppShell } from "@/components/shell/AppShell";
import { getTrustPosture } from "@/lib/trust";
import { getAssistantIntelligenceSummary } from "@/lib/assistant";
import { getTrustLearningDelta } from "@/lib/learn";
import type {
  AssistantIntelligenceSummaryResponse,
  GovernancePolicyTrustActivePolicy,
  GovernancePolicyTrustBlock,
  TrustPackLearningDelta,
  TrustPostureResponse,
  TrustSelfAssessmentBlock,
} from "@/lib/types";

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

  // M6.9.4 — Assistant receipt evidence card. Sourced from the existing
  // Assistant Intelligence summary endpoint (M6.8) — no new backend route.
  // A fetch failure here must NOT block the rest of the posture page.
  const [assistantSummary, setAssistantSummary] =
    useState<AssistantIntelligenceSummaryResponse | null>(null);
  const [assistantSummaryError, setAssistantSummaryError] = useState<string | null>(
    null,
  );

  // Phase 2A-1 (F5) — Learning evidence card. Sourced from the learning
  // delta aggregate. A fetch failure here must NOT block the rest of the
  // posture page; it renders its own isolated error state.
  const [learningDelta, setLearningDelta] = useState<TrustPackLearningDelta | null>(
    null,
  );
  const [learningDeltaError, setLearningDeltaError] = useState<string | null>(null);

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
    } catch (err: unknown) {
      const message =
        err instanceof Error
          ? err.message
          : "Failed to load governance posture.";
      setError(message);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }

  async function loadAssistantSummary() {
    try {
      setAssistantSummaryError(null);
      const result = await getAssistantIntelligenceSummary(30);
      setAssistantSummary(result);
    } catch (err: unknown) {
      const message =
        err instanceof Error
          ? err.message
          : "Unable to load Assistant receipt evidence.";
      setAssistantSummary(null);
      setAssistantSummaryError(message);
    }
  }

  async function loadLearningDelta() {
    try {
      setLearningDeltaError(null);
      const result = await getTrustLearningDelta();
      setLearningDelta(result);
    } catch (err: unknown) {
      const message =
        err instanceof Error
          ? err.message
          : "Unable to load learning evidence.";
      setLearningDelta(null);
      setLearningDeltaError(message);
    }
  }

  useEffect(() => {
    load();
    void loadAssistantSummary();
    void loadLearningDelta();
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

            <AssistantReceiptEvidenceCard
              summary={assistantSummary}
              error={assistantSummaryError}
            />

            <LearningEvidenceCard
              delta={learningDelta}
              error={learningDeltaError}
            />

            <GovernancePolicyEvidenceCard
              block={data.governance_policy ?? data.snapshot.governance_policy ?? null}
            />

            <SelfAssessmentEvidenceCard
              block={data.snapshot.self_assessment ?? null}
            />

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

// M6.9.4 — Assistant receipt evidence card. Surfaces a small,
// metadata-only count of governed Assistant receipts on Trust posture.
// Source: the existing Assistant Intelligence summary endpoint. Wording
// is intentionally governance-only — no clinical-quality or outcome
// language, no new trust score, no certification claim.
function AssistantReceiptEvidenceCard({
  summary,
  error,
}: {
  summary: AssistantIntelligenceSummaryResponse | null;
  error: string | null;
}) {
  const completionPct =
    summary && summary.summary.reviewed > 0
      ? Math.round(summary.rates.receipt_completion_rate * 100)
      : 0;

  return (
    <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <p className="text-xs font-medium uppercase tracking-wide text-slate-500">
            Evidence
          </p>
          <h2 className="mt-1 text-lg font-semibold text-slate-900">
            Assistant receipt evidence
          </h2>
          <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-600">
            Metadata-only receipts from governed Assistant runs. These records
            support governance visibility and review traceability; they are not
            clinical records or chat transcripts.
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          <Link
            href="/receipts"
            className="rounded-xl border border-slate-300 px-3 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-50"
          >
            Open Receipts
          </Link>
          <Link
            href="/intelligence"
            className="rounded-xl border border-slate-300 px-3 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-50"
          >
            Open Intelligence
          </Link>
        </div>
      </div>

      {error ? (
        <p className="mt-4 rounded-xl border border-slate-200 bg-slate-50 px-4 py-3 text-xs leading-5 text-slate-600">
          Assistant receipt evidence is temporarily unavailable. Governance posture
          above remains unaffected.
        </p>
      ) : summary ? (
        <>
          <div className="mt-5 grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
            <div className="rounded-xl border border-slate-200 bg-slate-50 p-4">
              <div className="text-xs uppercase tracking-wide text-slate-500">
                Assistant receipts linked
              </div>
              <div className="mt-2 text-sm font-semibold text-slate-900">
                {summary.summary.receipt_linked}
              </div>
            </div>
            <div className="rounded-xl border border-slate-200 bg-slate-50 p-4">
              <div className="text-xs uppercase tracking-wide text-slate-500">
                Reviewed runs
              </div>
              <div className="mt-2 text-sm font-semibold text-slate-900">
                {summary.summary.reviewed}
              </div>
            </div>
            <div className="rounded-xl border border-slate-200 bg-slate-50 p-4">
              <div className="text-xs uppercase tracking-wide text-slate-500">
                Receipt completion
              </div>
              <div className="mt-2 text-sm font-semibold text-slate-900">
                {completionPct}%
              </div>
            </div>
            <div className="rounded-xl border border-slate-200 bg-slate-50 p-4">
              <div className="text-xs uppercase tracking-wide text-slate-500">
                Window
              </div>
              <div className="mt-2 text-sm font-semibold text-slate-900">
                Last {summary.window.days} days
              </div>
            </div>
          </div>
          <p className="mt-3 text-[11px] leading-5 text-slate-500">
            Metadata evidence. Receipts confirm governance metadata, not clinical
            correctness. Hard clinical safety rules cannot be disabled.
          </p>
        </>
      ) : (
        <p className="mt-4 text-sm text-slate-500">
          Loading Assistant receipt evidence…
        </p>
      )}
    </div>
  );
}

// Phase 2A-1 (F5) — Learning evidence card. Surfaces clinic-level
// aggregates of CPD-recordable AI literacy activity. Aggregate metadata
// only — no per-user data, no clinical content. Wording is governance /
// readiness only: aligned with, not compliant or certified.
function LearningEvidenceCard({
  delta,
  error,
}: {
  delta: TrustPackLearningDelta | null;
  error: string | null;
}) {
  const roleRates = delta ? Object.entries(delta.completion_rate_by_role) : [];
  const hasActivity = Boolean(
    delta &&
      (delta.total_staff_with_completions > 0 ||
        delta.total_cpd_minutes_delivered > 0 ||
        delta.module_catalogue_count > 0),
  );

  return (
    <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <p className="text-xs font-medium uppercase tracking-wide text-slate-500">
            Evidence
          </p>
          <h2 className="mt-1 text-lg font-semibold text-slate-900">
            Learning evidence
          </h2>
          <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-600">
            Metadata-only evidence of completed AI literacy modules across the
            clinic. Aligned with RCVS AI literacy expectations and EU AI Act
            Article 4 readiness. Aggregates only — no per-user records.
          </p>
        </div>
        <Link
          href="/learn"
          className="rounded-xl border border-slate-300 px-3 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-50"
        >
          Open Learn
        </Link>
      </div>

      {error ? (
        <p className="mt-4 rounded-xl border border-slate-200 bg-slate-50 px-4 py-3 text-xs leading-5 text-slate-600">
          Learning evidence is temporarily unavailable. Governance posture above
          remains unaffected.
        </p>
      ) : delta ? (
        hasActivity ? (
          <>
            <div className="mt-5 grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
              <div className="rounded-xl border border-slate-200 bg-slate-50 p-4">
                <div className="text-xs uppercase tracking-wide text-slate-500">
                  Staff with completions
                </div>
                <div className="mt-2 text-sm font-semibold text-slate-900">
                  {delta.total_staff_with_completions}
                </div>
              </div>
              <div className="rounded-xl border border-slate-200 bg-slate-50 p-4">
                <div className="text-xs uppercase tracking-wide text-slate-500">
                  CPD minutes delivered
                </div>
                <div className="mt-2 text-sm font-semibold text-slate-900">
                  {delta.total_cpd_minutes_delivered}
                </div>
              </div>
              <div className="rounded-xl border border-slate-200 bg-slate-50 p-4">
                <div className="text-xs uppercase tracking-wide text-slate-500">
                  Bias-detection completions
                </div>
                <div className="mt-2 text-sm font-semibold text-slate-900">
                  {delta.bias_detection_completions}
                </div>
              </div>
              <div className="rounded-xl border border-slate-200 bg-slate-50 p-4">
                <div className="text-xs uppercase tracking-wide text-slate-500">
                  Modules in catalogue
                </div>
                <div className="mt-2 text-sm font-semibold text-slate-900">
                  {delta.module_catalogue_count}
                </div>
              </div>
            </div>

            <div className="mt-4 rounded-xl border border-slate-200 bg-slate-50 p-4">
              <div className="text-xs uppercase tracking-wide text-slate-500">
                Most recent completion
              </div>
              <div className="mt-2 text-sm font-medium text-slate-900">
                {formatDate(delta.last_completion_at ?? undefined)}
              </div>
            </div>

            {roleRates.length > 0 ? (
              <div className="mt-4">
                <p className="text-xs font-semibold uppercase tracking-[0.16em] text-slate-500">
                  Completion rate by role
                </p>
                <div className="mt-2 grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
                  {roleRates.map(([role, rate]) => (
                    <div
                      key={role}
                      className="rounded-xl border border-slate-200 bg-slate-50 px-4 py-3"
                    >
                      <div className="text-xs capitalize text-slate-500">
                        {role.replaceAll("_", " ")}
                      </div>
                      <div className="mt-1 text-sm font-semibold text-slate-900">
                        {Math.round(rate * 100)}%
                      </div>
                    </div>
                  ))}
                </div>
                <p className="mt-2 text-[11px] leading-5 text-slate-500">
                  Role rates use ANCHOR access-control roles, not clinical job titles.
                </p>
              </div>
            ) : null}
          </>
        ) : (
          <p className="mt-4 rounded-xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-600">
            No completed AI literacy modules recorded yet. Completion activity will
            surface here as metadata-only evidence.
          </p>
        )
      ) : (
        <p className="mt-4 text-sm text-slate-500">Loading learning evidence…</p>
      )}
    </div>
  );
}

// Phase 2A-2.8 Part B - Governance policy evidence tile. Aggregate
// metadata only; no policy body, no user-level rows, no void reasons.
function GovernancePolicyEvidenceCard({
  block,
}: {
  block: GovernancePolicyTrustBlock | null;
}) {
  if (!block) {
    return (
      <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm">
        <p className="text-xs font-medium uppercase tracking-wide text-slate-500">
          Evidence
        </p>
        <h2 className="mt-1 text-lg font-semibold text-slate-900">
          Governance policy evidence
        </h2>
        <p className="mt-2 text-sm leading-6 text-slate-600">
          Governance policy evidence is not available yet.
        </p>
      </div>
    );
  }

  const coveragePct = Math.round((block.average_coverage_rate ?? 0) * 100);

  return (
    <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm">
      <div>
        <p className="text-xs font-medium uppercase tracking-wide text-slate-500">
          Evidence
        </p>
        <h2 className="mt-1 text-lg font-semibold text-slate-900">
          Governance policy evidence
        </h2>
        <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-600">
          Active AI-use policy versions and staff acknowledgement coverage,
          shown as metadata-only governance evidence.
        </p>
      </div>

      <div className="mt-5 grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <div className="rounded-xl border border-slate-200 bg-slate-50 p-4">
          <div className="text-xs uppercase tracking-wide text-slate-500">
            Active policies
          </div>
          <div className="mt-2 text-sm font-semibold text-slate-900">
            {block.active_policy_count}
          </div>
        </div>
        <div className="rounded-xl border border-slate-200 bg-slate-50 p-4">
          <div className="text-xs uppercase tracking-wide text-slate-500">
            Acknowledgements
          </div>
          <div className="mt-2 text-sm font-semibold text-slate-900">
            {block.total_attestation_count}
          </div>
        </div>
        <div className="rounded-xl border border-slate-200 bg-slate-50 p-4">
          <div className="text-xs uppercase tracking-wide text-slate-500">
            Average coverage
          </div>
          <div className="mt-2 text-sm font-semibold text-slate-900">
            {coveragePct}%
          </div>
        </div>
        <div className="rounded-xl border border-slate-200 bg-slate-50 p-4">
          <div className="text-xs uppercase tracking-wide text-slate-500">
            Outstanding users
          </div>
          <div className="mt-2 text-sm font-semibold text-slate-900">
            {block.outstanding_user_count} of {block.expected_user_count}
          </div>
        </div>
      </div>

      <div className="mt-4 grid gap-4 sm:grid-cols-2">
        <div className="rounded-xl border border-slate-200 bg-slate-50 p-4">
          <div className="text-xs uppercase tracking-wide text-slate-500">
            Last policy update
          </div>
          <div className="mt-2 text-sm font-medium text-slate-900">
            {formatDate(block.last_policy_update_at ?? undefined)}
          </div>
        </div>
        <div className="rounded-xl border border-slate-200 bg-slate-50 p-4">
          <div className="text-xs uppercase tracking-wide text-slate-500">
            Most recent acknowledgement
          </div>
          <div className="mt-2 text-sm font-medium text-slate-900">
            {formatDate(block.most_recent_acknowledged_at ?? undefined)}
          </div>
        </div>
      </div>

      <div className="mt-4 rounded-xl border border-slate-200 bg-slate-50 p-4">
        <div className="text-xs uppercase tracking-wide text-slate-500">
          Raw policy body stored in this Trust view
        </div>
        <div className="mt-2 text-sm font-medium text-slate-900">No</div>
      </div>

      {block.active_policies && block.active_policies.length > 0 ? (
        <div className="mt-4">
          <p className="text-xs font-semibold uppercase tracking-[0.16em] text-slate-500">
            Active policies
          </p>
          <ul className="mt-2 space-y-2">
            {block.active_policies.map((policy) => (
              <GovernancePolicyEvidenceRow
                key={policy.clinic_policy_version_id}
                policy={policy}
              />
            ))}
          </ul>
        </div>
      ) : null}

      <div className="mt-4 flex flex-wrap gap-2">
        <Link
          href="/settings/policy-acknowledgements"
          className="rounded-xl border border-slate-300 px-3 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-50"
        >
          My acknowledgements
        </Link>
      </div>

      <p className="mt-3 text-[11px] leading-5 text-slate-500">
        Policy evidence is metadata-only. It supports review of governance
        posture and staff acknowledgement coverage.
      </p>
    </div>
  );
}

function GovernancePolicyEvidenceRow({
  policy,
}: {
  policy: GovernancePolicyTrustActivePolicy;
}) {
  const coveragePct = Math.round(
    (policy.attestation_coverage?.coverage_rate ?? 0) * 100,
  );
  return (
    <li className="rounded-xl border border-slate-200 bg-slate-50 px-4 py-3">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div className="min-w-0">
          <p className="text-sm font-semibold text-slate-900">{policy.title}</p>
          <p className="mt-1 text-xs text-slate-500">
            Version v{policy.clinic_policy_version}
            {policy.template_slug ? ` - ${policy.template_slug}` : ""}
          </p>
        </div>
        <span className="inline-flex items-center rounded-full border border-emerald-200 bg-emerald-50 px-2 py-0.5 text-xs font-medium text-emerald-700">
          {coveragePct}% coverage
        </span>
      </div>
      <div className="mt-2 flex flex-wrap gap-x-6 gap-y-1 text-xs text-slate-600">
        <span>Activated: {formatDate(policy.activated_at ?? undefined)}</span>
        <span>
          Outstanding users: {policy.attestation_coverage?.outstanding_user_count ?? 0}
        </span>
      </div>
    </li>
  );
}

// Phase 2A-3.6 - RCVS-aligned self-assessment evidence tile. Aggregate
// metadata only; no raw answers, no staff identifiers, no scoring, no
// pass/fail. Sourced from the existing Trust posture snapshot block.
function SelfAssessmentEvidenceCard({
  block,
}: {
  block: TrustSelfAssessmentBlock | null;
}) {
  if (!block) {
    return (
      <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm">
        <p className="text-xs font-medium uppercase tracking-wide text-slate-500">
          Evidence
        </p>
        <h2 className="mt-1 text-lg font-semibold text-slate-900">
          RCVS-aligned AI Governance Self-Assessment
        </h2>
        <p className="mt-2 text-sm leading-6 text-slate-600">
          Self-assessment evidence is not available yet.
        </p>
      </div>
    );
  }

  const firstTemplate = block.templates?.[0] ?? null;
  const status = firstTemplate?.assessment_status ?? "none";
  const isNone = status === "none";

  const readinessRows: { key: keyof TrustSelfAssessmentBlock["templates"][number]["readiness_summary_counts"]; label: string }[] = [
    { key: "yes", label: "Yes" },
    { key: "partial", label: "Partial" },
    { key: "planned", label: "Planned" },
    { key: "no", label: "No" },
    { key: "not_applicable", label: "Not applicable" },
  ];

  const evidenceRows: { key: keyof TrustSelfAssessmentBlock["templates"][number]["linked_evidence_counts"]; label: string }[] = [
    { key: "policy_library", label: "Policy library" },
    { key: "staff_attestation", label: "Staff attestation" },
    { key: "learn_cpd", label: "Learn / CPD activity" },
    { key: "assistant_receipts", label: "Assistant receipts" },
    { key: "trust_posture", label: "Trust posture" },
    { key: "manual_review", label: "Manual review" },
  ];

  return (
    <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <p className="text-xs font-medium uppercase tracking-wide text-slate-500">
            Evidence
          </p>
          <h2 className="mt-1 text-lg font-semibold text-slate-900">
            RCVS-aligned AI Governance Self-Assessment
          </h2>
          <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-600">
            Metadata-only self-assessment evidence supporting governance review
            and readiness evidence. Human review remains required.
          </p>
        </div>
        <Link
          href="/settings/self-assessment"
          className="rounded-xl border border-slate-300 px-3 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-50"
        >
          Open self-assessment
        </Link>
      </div>

      <div className="mt-5 grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <div className="rounded-xl border border-slate-200 bg-slate-50 p-4">
          <div className="text-xs uppercase tracking-wide text-slate-500">
            Assessment status
          </div>
          <div className="mt-2 text-sm font-semibold capitalize text-slate-900">
            {status.replaceAll("_", " ")}
          </div>
        </div>
        <div className="rounded-xl border border-slate-200 bg-slate-50 p-4">
          <div className="text-xs uppercase tracking-wide text-slate-500">
            Latest submitted
          </div>
          <div className="mt-2 text-sm font-medium text-slate-900">
            {block.latest_submitted_at
              ? formatDate(block.latest_submitted_at)
              : "Not submitted yet"}
          </div>
        </div>
        <div className="rounded-xl border border-slate-200 bg-slate-50 p-4">
          <div className="text-xs uppercase tracking-wide text-slate-500">
            Submitted records
          </div>
          <div className="mt-2 text-sm font-semibold text-slate-900">
            {block.submitted_assessment_count}
          </div>
        </div>
        <div className="rounded-xl border border-slate-200 bg-slate-50 p-4">
          <div className="text-xs uppercase tracking-wide text-slate-500">
            Answered
          </div>
          <div className="mt-2 text-sm font-semibold text-slate-900">
            {firstTemplate
              ? `${firstTemplate.answered_questions} of ${firstTemplate.total_questions}`
              : "—"}
          </div>
        </div>
      </div>

      <div className="mt-4 grid gap-4 sm:grid-cols-2 xl:grid-cols-3">
        <div className="rounded-xl border border-slate-200 bg-slate-50 p-4">
          <div className="text-xs uppercase tracking-wide text-slate-500">
            Gap count
          </div>
          <div className="mt-2 text-sm font-semibold text-slate-900">
            {firstTemplate?.gap_count ?? 0}
          </div>
        </div>
        <div className="rounded-xl border border-slate-200 bg-slate-50 p-4">
          <div className="text-xs uppercase tracking-wide text-slate-500">
            Raw answers included
          </div>
          <div className="mt-2 text-sm font-medium text-slate-900">No</div>
        </div>
        <div className="rounded-xl border border-slate-200 bg-slate-50 p-4">
          <div className="text-xs uppercase tracking-wide text-slate-500">
            Staff identifiers included
          </div>
          <div className="mt-2 text-sm font-medium text-slate-900">No</div>
        </div>
      </div>

      {firstTemplate ? (
        <div className="mt-4 rounded-xl border border-slate-200 bg-slate-50 p-4">
          <div className="flex flex-wrap items-start justify-between gap-2">
            <div className="min-w-0">
              <p className="text-sm font-semibold text-slate-900">
                {firstTemplate.title}
              </p>
              <p className="mt-1 text-xs text-slate-500">
                Template v{firstTemplate.template_version}
                {firstTemplate.clinic_assessment_version != null
                  ? ` - clinic version v${firstTemplate.clinic_assessment_version}`
                  : ""}
              </p>
            </div>
            <span className="inline-flex items-center rounded-full border border-slate-200 bg-white px-2 py-0.5 text-xs font-medium capitalize text-slate-700">
              {firstTemplate.assessment_status.replaceAll("_", " ")}
            </span>
          </div>
          <div className="mt-2 flex flex-wrap gap-x-6 gap-y-1 text-xs text-slate-600">
            <span>
              Answered: {firstTemplate.answered_questions} of{" "}
              {firstTemplate.total_questions}
            </span>
            <span>Gap count: {firstTemplate.gap_count}</span>
            <span>
              Last updated: {formatDate(firstTemplate.last_updated_at ?? undefined)}
            </span>
          </div>
        </div>
      ) : null}

      {isNone ? (
        <p className="mt-4 rounded-xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-600">
          No submitted self-assessment yet.
        </p>
      ) : null}

      {firstTemplate ? (
        <div className="mt-4">
          <p className="text-xs font-semibold uppercase tracking-[0.16em] text-slate-500">
            Readiness summary
          </p>
          <div className="mt-2 grid gap-3 sm:grid-cols-2 xl:grid-cols-5">
            {readinessRows.map((row) => (
              <div
                key={row.key}
                className="rounded-xl border border-slate-200 bg-slate-50 px-4 py-3"
              >
                <div className="text-xs text-slate-500">{row.label}</div>
                <div className="mt-1 text-sm font-semibold text-slate-900">
                  {firstTemplate.readiness_summary_counts[row.key] ?? 0}
                </div>
              </div>
            ))}
          </div>
        </div>
      ) : null}

      {firstTemplate ? (
        <div className="mt-4">
          <p className="text-xs font-semibold uppercase tracking-[0.16em] text-slate-500">
            Linked evidence
          </p>
          <div className="mt-2 grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
            {evidenceRows.map((row) => (
              <div
                key={row.key}
                className="rounded-xl border border-slate-200 bg-slate-50 px-4 py-3"
              >
                <div className="text-xs text-slate-500">{row.label}</div>
                <div className="mt-1 text-sm font-semibold text-slate-900">
                  {firstTemplate.linked_evidence_counts[row.key] ?? 0}
                </div>
              </div>
            ))}
          </div>
        </div>
      ) : null}

      {block.templates && block.templates.length > 1 ? (
        <p className="mt-3 text-[11px] leading-5 text-slate-500">
          {block.templates.length} self-assessment templates available. Summary
          above reflects the first template.
        </p>
      ) : null}

      <p className="mt-3 text-[11px] leading-5 text-slate-500">
        {block.governance_note ||
          "Self-assessment evidence is metadata-only and supports governance review and readiness evidence. Human review remains required."}
      </p>
    </div>
  );
}
