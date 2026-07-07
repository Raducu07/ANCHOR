"use client";

// Fable roadmap-completion experiment - Slice F3 (M4.6 Learn Maturity,
// internal preview).
//
// Role-based learning paths, renewal reminders for the signed-in user,
// leadership learning overview (clinic-admin roles), and the per-clinic
// renewal cadence setting.
//
// Non-certifying doctrine: everything here is learning reinforcement
// and completion evidence - never competence assessment, certification,
// accreditation, or approved CPD. The backend self_check_note is shown
// verbatim. Metadata-only: aggregate counts, timestamps, statuses.

import Link from "next/link";
import { useEffect, useState, useSyncExternalStore } from "react";
import { Button } from "@/components/ui/Button";
import { Card } from "@/components/ui/Card";
import {
  InternalPreviewBadge,
  InternalPreviewGate,
  previewAwareErrorMessage,
} from "@/components/experiment/InternalPreviewGate";
import {
  SESSION_SERVER_SNAPSHOT,
  getSessionUserSnapshot,
  subscribeSessionStorage,
} from "@/lib/auth";
import {
  getMyRenewals,
  getRenewalOverview,
  listLearningPaths,
  setRenewalPolicy,
} from "@/lib/learnMaturity";
import type {
  LearningPathListResponse,
  MyRenewalsResponse,
  RenewalOverviewResponse,
  RenewalStatus,
} from "@/lib/learnMaturity";

const ADMIN_ROLES = new Set(["admin", "owner", "practice_manager"]);

function formatTag(value: string) {
  return value.replace(/[_-]+/g, " ");
}

function formatDate(value?: string | null): string {
  if (!value) return "—";
  try {
    return new Date(value).toLocaleDateString();
  } catch {
    return value;
  }
}

const RENEWAL_TONE: Record<RenewalStatus, string> = {
  current: "border border-emerald-200 bg-emerald-50 text-emerald-700",
  due_soon: "border border-amber-200 bg-amber-50 text-amber-700",
  overdue: "border border-rose-200 bg-rose-50 text-rose-700",
};

const RENEWAL_LABEL: Record<RenewalStatus, string> = {
  current: "Current",
  due_soon: "Refresh due soon",
  overdue: "Refresh overdue",
};

function RenewalBadge({ status }: { status: RenewalStatus }) {
  return (
    <span
      className={[
        "inline-flex items-center rounded-full px-2.5 py-1 text-xs font-medium tracking-wide",
        RENEWAL_TONE[status],
      ].join(" ")}
    >
      {RENEWAL_LABEL[status]}
    </span>
  );
}

export function LearnMaturitySurface() {
  return (
    <InternalPreviewGate title="Learning paths and renewal">
      <LearnMaturityContent />
    </InternalPreviewGate>
  );
}

function LearnMaturityContent() {
  const user = useSyncExternalStore(
    subscribeSessionStorage,
    getSessionUserSnapshot,
    SESSION_SERVER_SNAPSHOT,
  );
  const isAdmin = Boolean(user && ADMIN_ROLES.has(user.role));

  return (
    <div className="space-y-6">
      <div>
        <div className="flex flex-wrap items-center gap-3">
          <p className="text-sm font-medium text-slate-500">ANCHOR Learn</p>
          <InternalPreviewBadge />
        </div>
        <h1 className="text-2xl font-semibold tracking-tight text-slate-900">
          Learning paths and renewal
        </h1>
        <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-600">
          Role-based learning paths, renewal reminders, and leadership visibility over
          learning-reinforcement evidence. This is learning reinforcement and metadata-only
          completion evidence — not competence assessment or certification.
        </p>
      </div>

      <PathsSection />
      <MyRenewalsSection />
      {isAdmin ? <LeadershipSection /> : null}
    </div>
  );
}

function PathsSection() {
  const [paths, setPaths] = useState<LearningPathListResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;

    async function load() {
      setLoading(true);
      setError(null);
      try {
        const response = await listLearningPaths();
        if (!active) return;
        setPaths(response);
      } catch (err: unknown) {
        if (!active) return;
        setPaths(null);
        setError(previewAwareErrorMessage(err, "Unable to load learning paths."));
      } finally {
        if (active) setLoading(false);
      }
    }

    void load();
    return () => {
      active = false;
    };
  }, []);

  return (
    <Card variant="native">
      <SectionTitle
        title="Role-based learning paths"
        description="Curated module sequences per clinic role, with your completion evidence per path."
      />

      {loading ? (
        <Notice tone="neutral">Loading learning paths…</Notice>
      ) : error ? (
        <Notice tone="error">{error}</Notice>
      ) : paths && paths.paths.length > 0 ? (
        <>
          <div className="mt-4 grid gap-4 xl:grid-cols-2">
            {paths.paths.map((path) => {
              const percent =
                path.total_count > 0
                  ? Math.round((path.completed_count / path.total_count) * 100)
                  : 0;
              return (
                <div
                  key={path.path_id}
                  className="rounded-xl border border-slate-200 bg-white p-5 shadow-[0_8px_24px_rgba(42,52,57,0.05)]"
                >
                  <div className="flex items-start justify-between gap-3">
                    <h3 className="text-base font-semibold text-slate-900">{path.title}</h3>
                    <span className="inline-flex items-center rounded-full border border-slate-200 bg-slate-50 px-2 py-0.5 text-xs font-medium text-slate-500">
                      v{path.version}
                    </span>
                  </div>
                  <p className="mt-2 text-sm leading-6 text-slate-600">{path.summary}</p>

                  {path.role_applicability.length > 0 ? (
                    <div className="mt-3 flex flex-wrap gap-2">
                      {path.role_applicability.map((role) => (
                        <span
                          key={role}
                          className="inline-flex items-center rounded-full border border-slate-200 bg-slate-50 px-2.5 py-1 text-xs font-medium capitalize text-slate-700"
                        >
                          {formatTag(role)}
                        </span>
                      ))}
                    </div>
                  ) : null}

                  <div className="mt-4">
                    <div className="flex items-center justify-between text-xs text-slate-500">
                      <span>
                        {path.completed_count} of {path.total_count} modules complete
                      </span>
                      <span>{percent}%</span>
                    </div>
                    <div className="mt-1.5 h-2 w-full overflow-hidden rounded-full bg-slate-100">
                      <div
                        className="h-full rounded-full bg-slate-900"
                        style={{ width: `${percent}%` }}
                      />
                    </div>
                  </div>

                  <div className="mt-4 space-y-1.5">
                    {path.module_slugs.map((slug) => {
                      const done = path.completed_module_slugs.includes(slug);
                      return (
                        <div key={slug} className="flex items-center justify-between gap-3 text-sm">
                          <Link
                            href={`/learn/${slug}`}
                            className="capitalize text-slate-700 underline-offset-4 hover:underline"
                          >
                            {formatTag(slug)}
                          </Link>
                          <span
                            className={[
                              "text-xs font-medium",
                              done ? "text-emerald-700" : "text-slate-400",
                            ].join(" ")}
                          >
                            {done ? "Complete" : "Not yet recorded"}
                          </span>
                        </div>
                      );
                    })}
                  </div>
                </div>
              );
            })}
          </div>
          <p className="mt-4 max-w-3xl text-xs leading-5 text-slate-500">
            {paths.self_check_note}
          </p>
        </>
      ) : (
        <Notice tone="neutral">No learning paths are published yet.</Notice>
      )}
    </Card>
  );
}

function MyRenewalsSection() {
  const [renewals, setRenewals] = useState<MyRenewalsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;

    async function load() {
      setLoading(true);
      setError(null);
      try {
        const response = await getMyRenewals();
        if (!active) return;
        setRenewals(response);
      } catch (err: unknown) {
        if (!active) return;
        setRenewals(null);
        setError(previewAwareErrorMessage(err, "Unable to load renewal reminders."));
      } finally {
        if (active) setLoading(false);
      }
    }

    void load();
    return () => {
      active = false;
    };
  }, []);

  return (
    <Card variant="native">
      <SectionTitle
        title="My renewal reminders"
        description="When your recorded module completions come due for a refresh, based on the clinic renewal cadence."
      />

      {loading ? (
        <Notice tone="neutral">Loading renewal reminders…</Notice>
      ) : error ? (
        <Notice tone="error">{error}</Notice>
      ) : renewals ? (
        <>
          <p className="mt-4 text-sm leading-6 text-slate-600">
            Clinic renewal cadence:{" "}
            <span className="font-semibold text-slate-900">
              every {renewals.renewal_months} month{renewals.renewal_months === 1 ? "" : "s"}
            </span>
          </p>

          {renewals.entries.length > 0 ? (
            <div className="mt-4 space-y-4">
              {renewals.entries.map((entry) => (
                <div
                  key={entry.module_id}
                  className="grid gap-2 border-b border-slate-100 pb-4 last:border-b-0 last:pb-0 md:grid-cols-[1fr_auto]"
                >
                  <div>
                    <Link
                      href={`/learn/${entry.module_slug}`}
                      className="text-sm font-semibold text-slate-900 underline-offset-4 hover:underline"
                    >
                      {entry.title}
                    </Link>
                    <p className="mt-1 text-sm leading-6 text-slate-600">
                      Last recorded {formatDate(entry.latest_completed_at)} · refresh due{" "}
                      {formatDate(entry.due_at)}
                    </p>
                  </div>
                  <div className="md:text-right">
                    <RenewalBadge status={entry.status} />
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <Notice tone="neutral">
              No completion evidence recorded yet. Complete a module in Learn to start your
              renewal record.
            </Notice>
          )}
          <p className="mt-4 max-w-3xl text-xs leading-5 text-slate-500">
            {renewals.self_check_note}
          </p>
        </>
      ) : null}
    </Card>
  );
}

function LeadershipSection() {
  const [overview, setOverview] = useState<RenewalOverviewResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [cadenceInput, setCadenceInput] = useState("");
  const [saving, setSaving] = useState(false);
  const [saveFeedback, setSaveFeedback] = useState<
    { kind: "success" | "error"; message: string } | null
  >(null);

  useEffect(() => {
    let active = true;

    async function load() {
      setLoading(true);
      setError(null);
      try {
        const response = await getRenewalOverview();
        if (!active) return;
        setOverview(response);
        setCadenceInput(String(response.renewal_months));
      } catch (err: unknown) {
        if (!active) return;
        setOverview(null);
        setError(
          previewAwareErrorMessage(err, "Unable to load the leadership overview."),
        );
      } finally {
        if (active) setLoading(false);
      }
    }

    void load();
    return () => {
      active = false;
    };
  }, []);

  async function handleSaveCadence() {
    const months = Number(cadenceInput);
    if (!Number.isInteger(months) || months < 1 || months > 60) {
      setSaveFeedback({
        kind: "error",
        message: "Renewal cadence must be a whole number of months between 1 and 60.",
      });
      return;
    }
    setSaving(true);
    setSaveFeedback(null);
    try {
      const response = await setRenewalPolicy(months);
      setSaveFeedback({
        kind: "success",
        message: `Renewal cadence set to every ${response.renewal_months} month${
          response.renewal_months === 1 ? "" : "s"
        }.`,
      });
    } catch (err: unknown) {
      setSaveFeedback({
        kind: "error",
        message: previewAwareErrorMessage(err, "Unable to update the renewal cadence."),
      });
    } finally {
      setSaving(false);
    }
  }

  return (
    <Card variant="native">
      <SectionTitle
        title="Leadership learning overview"
        description="Clinic-wide renewal posture across team members, as aggregate metadata-only counts."
      />

      {loading ? (
        <Notice tone="neutral">Loading the leadership overview…</Notice>
      ) : error ? (
        <Notice tone="error">{error}</Notice>
      ) : overview ? (
        <>
          <div className="mt-4 grid gap-3 sm:grid-cols-3">
            <CountTile label="Current" value={overview.total_current} />
            <CountTile label="Refresh due soon" value={overview.total_due_soon} />
            <CountTile label="Refresh overdue" value={overview.total_overdue} />
          </div>

          {overview.users.length > 0 ? (
            <div className="mt-4 overflow-x-auto">
              <table className="w-full text-left text-sm">
                <thead>
                  <tr className="border-b border-slate-200 text-xs uppercase tracking-wide text-slate-500">
                    <th className="py-2 pr-4 font-semibold">Team member</th>
                    <th className="py-2 pr-4 font-semibold">Modules recorded</th>
                    <th className="py-2 pr-4 font-semibold">Current</th>
                    <th className="py-2 pr-4 font-semibold">Due soon</th>
                    <th className="py-2 font-semibold">Overdue</th>
                  </tr>
                </thead>
                <tbody>
                  {overview.users.map((row) => (
                    <tr key={row.user_id} className="border-b border-slate-100 last:border-b-0">
                      <td className="py-2.5 pr-4 font-mono text-xs text-slate-600">
                        {row.user_id.slice(0, 8)}…
                      </td>
                      <td className="py-2.5 pr-4 text-slate-900">{row.modules_completed}</td>
                      <td className="py-2.5 pr-4 text-slate-600">{row.current_count}</td>
                      <td className="py-2.5 pr-4 text-slate-600">{row.due_soon_count}</td>
                      <td className="py-2.5 text-slate-600">{row.overdue_count}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <Notice tone="neutral">No completion evidence recorded for this clinic yet.</Notice>
          )}

          <div className="mt-6 border-t border-slate-100 pt-5">
            <h3 className="text-sm font-semibold text-slate-900">Renewal cadence</h3>
            <p className="mt-1 max-w-3xl text-sm leading-6 text-slate-600">
              How often recorded completions come due for a refresh in this clinic. Renewal
              reminders are guidance, not a competence requirement.
            </p>
            <div className="mt-3 flex flex-wrap items-end gap-3">
              <label className="flex flex-col text-xs font-medium text-slate-500">
                Months between refreshes (1–60)
                <input
                  type="number"
                  min={1}
                  max={60}
                  value={cadenceInput}
                  onChange={(event) => setCadenceInput(event.target.value)}
                  className="mt-1 w-40 rounded-xl border border-slate-300 bg-white px-3 py-2 text-sm font-normal text-slate-900"
                />
              </label>
              <Button onClick={handleSaveCadence} loading={saving} variant="secondary">
                Save cadence
              </Button>
            </div>
            {saveFeedback ? (
              <div
                className={[
                  "mt-3 rounded-xl border px-4 py-3 text-sm",
                  saveFeedback.kind === "success"
                    ? "border-emerald-200 bg-emerald-50 text-emerald-700"
                    : "border-rose-200 bg-rose-50 text-rose-700",
                ].join(" ")}
              >
                {saveFeedback.message}
              </div>
            ) : null}
          </div>

          <p className="mt-4 max-w-3xl text-xs leading-5 text-slate-500">
            {overview.self_check_note}
          </p>
        </>
      ) : null}
    </Card>
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
      {description ? (
        <p className="mt-1 text-sm leading-6 text-slate-600">{description}</p>
      ) : null}
    </div>
  );
}

function Notice({
  tone,
  children,
}: {
  tone: "neutral" | "error";
  children: React.ReactNode;
}) {
  const toneClass =
    tone === "error"
      ? "border-rose-200 bg-rose-50 text-rose-700"
      : "border-slate-200 bg-slate-50 text-slate-600";
  return (
    <div className={`mt-4 rounded-xl border px-4 py-3 text-sm ${toneClass}`}>{children}</div>
  );
}

function CountTile({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
      <p className="text-xs font-semibold uppercase tracking-[0.16em] text-slate-500">{label}</p>
      <p className="mt-1 text-2xl font-semibold text-slate-900">{value}</p>
    </div>
  );
}
