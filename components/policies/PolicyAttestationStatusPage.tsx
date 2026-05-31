"use client";

// Phase 2A-2.8 Part A - Admin attestation status page (admin-only).
//
// Metadata-only doctrine:
//   * No raw policy body text, staff names, staff emails, void reasons,
//     staff reflections, clinical content, prompts/outputs/transcripts,
//     legal-approval status, compliance status, competence grade, or
//     pass/fail are rendered.
//   * Rows show governance metadata only: short ids, policy title
//     snapshot, version, statement version, acknowledgement method,
//     timestamps, and voided/recorded status.
//   * Admin gate is UX hardening only; backend is the authority.

import { useCallback, useEffect, useMemo, useState, useSyncExternalStore } from "react";
import Link from "next/link";
import { ApiError } from "@/lib/api";
import {
  SESSION_SERVER_SNAPSHOT,
  getSessionUserSnapshot,
  subscribeSessionStorage,
} from "@/lib/auth";
import { Button } from "@/components/ui/Button";
import { Card } from "@/components/ui/Card";
import { StatusBadge } from "@/components/ui/StatusBadge";
import {
  listActiveClinicPolicies,
  listClinicPolicyAttestations,
  voidPolicyAttestation,
} from "@/lib/governancePolicy";
import type {
  ClinicPolicyVersion,
  PolicyAttestation,
} from "@/lib/types";

const POLICY_ADMIN_ROLES = new Set(["admin", "owner", "practice_manager"]);

const LIMIT_OPTIONS = [25, 50, 100, 200] as const;

function formatDateTime(value?: string | null): string {
  if (!value) return "Not set";
  try {
    return new Date(value).toLocaleString();
  } catch {
    return value;
  }
}

function shortenId(value: string | null | undefined): string {
  if (!value) return "-";
  if (value.length <= 14) return value;
  return `${value.slice(0, 8)}...${value.slice(-4)}`;
}

function errorMessageFromUnknown(err: unknown, fallback: string): string {
  if (err instanceof ApiError) return err.message;
  if (err instanceof Error) return err.message;
  return fallback;
}

type Feedback = { kind: "success" | "error"; message: string } | null;

export function PolicyAttestationStatusPage() {
  const sessionUser = useSyncExternalStore(
    subscribeSessionStorage,
    getSessionUserSnapshot,
    SESSION_SERVER_SNAPSHOT,
  );
  const isAdmin = Boolean(
    sessionUser?.role && POLICY_ADMIN_ROLES.has(sessionUser.role),
  );

  const [activePolicies, setActivePolicies] = useState<
    ClinicPolicyVersion[] | null
  >(null);

  const [attestations, setAttestations] = useState<PolicyAttestation[] | null>(
    null,
  );
  const [attestationsLoading, setAttestationsLoading] = useState(false);
  const [attestationsError, setAttestationsError] = useState<string | null>(
    null,
  );

  const [includeVoided, setIncludeVoided] = useState(false);
  const [policyVersionFilter, setPolicyVersionFilter] = useState<string>("");
  const [limit, setLimit] = useState<number>(100);

  const [voidEditId, setVoidEditId] = useState<string | null>(null);
  const [voidReason, setVoidReason] = useState("");
  const [voidSubmitting, setVoidSubmitting] = useState(false);
  const [feedback, setFeedback] = useState<Feedback>(null);

  const loadActive = useCallback(async () => {
    try {
      const result = await listActiveClinicPolicies();
      setActivePolicies(result.policies ?? []);
    } catch {
      // Non-blocking: the dropdown will just show "All policy versions".
      setActivePolicies([]);
    }
  }, []);

  const loadAttestations = useCallback(async () => {
    setAttestationsLoading(true);
    setAttestationsError(null);
    try {
      const result = await listClinicPolicyAttestations({
        includeVoided,
        limit,
        clinicPolicyVersionId: policyVersionFilter || undefined,
      });
      setAttestations(result.attestations ?? []);
    } catch (err) {
      setAttestations(null);
      setAttestationsError(
        errorMessageFromUnknown(
          err,
          "Policy attestation status could not be loaded.",
        ),
      );
    } finally {
      setAttestationsLoading(false);
    }
  }, [includeVoided, limit, policyVersionFilter]);

  useEffect(() => {
    if (!isAdmin) return;
    void loadActive();
  }, [isAdmin, loadActive]);

  useEffect(() => {
    if (!isAdmin) return;
    void loadAttestations();
  }, [isAdmin, loadAttestations]);

  const summary = useMemo(() => {
    if (!attestations) {
      return {
        recorded: 0,
        voided: 0,
        mostRecent: null as string | null,
        distinctPolicies: 0,
      };
    }
    let recorded = 0;
    let voided = 0;
    let mostRecent: string | null = null;
    const distinct = new Set<string>();
    for (const a of attestations) {
      if (a.is_voided) voided++;
      else recorded++;
      distinct.add(a.clinic_policy_version_id);
      if (!mostRecent || a.acknowledged_at > mostRecent) {
        mostRecent = a.acknowledged_at;
      }
    }
    return {
      recorded,
      voided,
      mostRecent,
      distinctPolicies: distinct.size,
    };
  }, [attestations]);

  function openVoid(id: string) {
    setVoidEditId(id);
    setVoidReason("");
    setFeedback(null);
  }

  function cancelVoid() {
    setVoidEditId(null);
    setVoidReason("");
  }

  async function submitVoid(attestation: PolicyAttestation) {
    const trimmed = voidReason.trim();
    if (!trimmed) return;
    setVoidSubmitting(true);
    setFeedback(null);
    try {
      await voidPolicyAttestation(attestation.attestation_id, {
        void_reason: trimmed,
      });
      setFeedback({
        kind: "success",
        message: "Acknowledgement voided.",
      });
      setVoidEditId(null);
      setVoidReason("");
      await loadAttestations();
    } catch (err) {
      setFeedback({
        kind: "error",
        message: errorMessageFromUnknown(
          err,
          "Attestation could not be voided.",
        ),
      });
    } finally {
      setVoidSubmitting(false);
    }
  }

  if (!isAdmin) {
    return (
      <div className="space-y-6">
        <div>
          <p className="text-sm font-medium text-slate-500">
            Clinic administration
          </p>
          <h1 className="text-2xl font-semibold tracking-tight text-slate-900">
            Policy attestation status
          </h1>
        </div>
        <Card variant="native">
          <p className="text-sm leading-6 text-slate-700">
            Policy attestation status is available to clinic administrators
            only.
          </p>
        </Card>
      </div>
    );
  }

  const activePolicyCount = activePolicies?.length ?? 0;

  return (
    <div className="space-y-6">
      <div>
        <p className="text-sm font-medium text-slate-500">Clinic administration</p>
        <h1 className="text-2xl font-semibold tracking-tight text-slate-900">
          Policy attestation status
        </h1>
        <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-600">
          Review metadata-only staff acknowledgement coverage for active clinic
          AI-use policy versions.
        </p>
        <p className="mt-2 max-w-3xl text-xs leading-5 text-slate-500">
          Attestation status records governance metadata only. It is not CPD
          completion, legal advice, regulatory certification, evidence of
          professional competence, or a guarantee of regulatory compliance.
        </p>
      </div>

      {feedback ? (
        <div
          className={[
            "rounded-xl border px-4 py-3 text-sm",
            feedback.kind === "success"
              ? "border-emerald-200 bg-emerald-50 text-emerald-700"
              : "border-rose-200 bg-rose-50 text-rose-700",
          ].join(" ")}
          role="status"
        >
          {feedback.message}
        </div>
      ) : null}

      <Card variant="native">
        <SectionTitle title="Summary" />
        <div className="mt-4 grid gap-3 sm:grid-cols-2 xl:grid-cols-5">
          <SummaryTile
            label="Active policies"
            value={String(activePolicyCount)}
          />
          <SummaryTile
            label="Recorded acknowledgements"
            value={String(summary.recorded)}
          />
          <SummaryTile
            label="Voided acknowledgements"
            value={String(summary.voided)}
          />
          <SummaryTile
            label="Most recent acknowledgement"
            value={
              summary.mostRecent ? formatDateTime(summary.mostRecent) : "None"
            }
          />
          <SummaryTile
            label="Policies with acknowledgements"
            value={String(summary.distinctPolicies)}
          />
        </div>
      </Card>

      <Card variant="native">
        <SectionTitle title="Filters" />
        <div className="mt-4 flex flex-wrap items-end gap-4">
          <label className="flex items-center gap-2 text-sm text-slate-700">
            <input
              type="checkbox"
              checked={includeVoided}
              onChange={(e) => setIncludeVoided(e.target.checked)}
              className="h-4 w-4 rounded border-slate-300"
            />
            Include voided
          </label>

          <label className="flex flex-col text-[10px] font-bold uppercase tracking-[0.18em] text-slate-500">
            Policy version
            <select
              value={policyVersionFilter}
              onChange={(e) => setPolicyVersionFilter(e.target.value)}
              className="mt-1 rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm font-normal normal-case tracking-normal text-slate-900"
            >
              <option value="">All policy versions</option>
              {(activePolicies ?? []).map((policy) => (
                <option
                  key={policy.clinic_policy_version_id}
                  value={policy.clinic_policy_version_id}
                >
                  {policy.title_snapshot} - v{policy.clinic_policy_version}
                </option>
              ))}
            </select>
          </label>

          <label className="flex flex-col text-[10px] font-bold uppercase tracking-[0.18em] text-slate-500">
            Limit
            <select
              value={String(limit)}
              onChange={(e) => setLimit(Number(e.target.value))}
              className="mt-1 rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm font-normal normal-case tracking-normal text-slate-900"
            >
              {LIMIT_OPTIONS.map((opt) => (
                <option key={opt} value={opt}>
                  {opt}
                </option>
              ))}
            </select>
          </label>
        </div>
      </Card>

      <Card variant="native">
        <SectionTitle
          title="Acknowledgements"
          description="Clinic-wide staff acknowledgements as governance metadata."
        />
        {attestationsLoading && attestations === null ? (
          <p className="mt-4 rounded-xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-600">
            Loading attestation status...
          </p>
        ) : attestationsError ? (
          <p className="mt-4 rounded-xl border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-700">
            {attestationsError}
          </p>
        ) : !attestations || attestations.length === 0 ? (
          <p className="mt-4 rounded-xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-600">
            No acknowledgements recorded for the current filters.
          </p>
        ) : (
          <ul className="mt-4 space-y-3">
            {attestations.map((a) => {
              const isEditingVoid = voidEditId === a.attestation_id;
              const titleLine = a.policy_title_snapshot
                ? a.policy_title_snapshot
                : `Policy ${shortenId(a.clinic_policy_version_id)}`;
              const versionLine =
                typeof a.policy_clinic_policy_version === "number"
                  ? `Version v${a.policy_clinic_policy_version}`
                  : `Version ${shortenId(a.clinic_policy_version_id)}`;
              return (
                <li
                  key={a.attestation_id}
                  className="rounded-xl border border-slate-200 bg-slate-50 p-4"
                >
                  <div className="flex flex-wrap items-start justify-between gap-2">
                    <div className="min-w-0">
                      <p className="text-sm font-semibold text-slate-900">
                        {titleLine}
                      </p>
                      <p className="mt-1 text-xs text-slate-500">
                        {versionLine}
                        {a.template_slug ? ` - ${a.template_slug}` : ""}
                      </p>
                    </div>
                    <StatusBadge value={a.is_voided ? "voided" : "recorded"} />
                  </div>
                  <div className="mt-3 space-y-1">
                    <DetailLine
                      label="Acknowledged"
                      value={formatDateTime(a.acknowledged_at)}
                    />
                    <DetailLine
                      label="User"
                      value={shortenId(a.user_id)}
                      mono
                    />
                    <DetailLine
                      label="Statement version"
                      value={a.attestation_statement_version}
                    />
                    <DetailLine
                      label="Method"
                      value={a.acknowledgement_method}
                    />
                    {a.is_voided ? (
                      <DetailLine
                        label="Voided"
                        value={formatDateTime(a.voided_at)}
                      />
                    ) : null}
                  </div>
                  {!a.is_voided ? (
                    isEditingVoid ? (
                      <div className="mt-4 rounded-lg border border-slate-200 bg-white p-3">
                        <p className="text-xs font-semibold text-slate-900">
                          Void acknowledgement
                        </p>
                        <p className="mt-1 text-xs leading-5 text-slate-500">
                          Reason required for correction record.
                        </p>
                        <textarea
                          value={voidReason}
                          onChange={(e) => setVoidReason(e.target.value)}
                          rows={3}
                          disabled={voidSubmitting}
                          placeholder="Reason for voiding this acknowledgement"
                          className="mt-2 block w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm text-slate-900 disabled:cursor-not-allowed disabled:opacity-60"
                        />
                        <div className="mt-3 flex flex-wrap gap-2">
                          <Button
                            onClick={() => void submitVoid(a)}
                            loading={voidSubmitting}
                            disabled={voidSubmitting || !voidReason.trim()}
                          >
                            Confirm void
                          </Button>
                          <Button
                            variant="secondary"
                            onClick={cancelVoid}
                            disabled={voidSubmitting}
                          >
                            Cancel
                          </Button>
                        </div>
                      </div>
                    ) : (
                      <div className="mt-4">
                        <Button
                          variant="secondary"
                          onClick={() => openVoid(a.attestation_id)}
                        >
                          Void
                        </Button>
                      </div>
                    )
                  ) : null}
                </li>
              );
            })}
          </ul>
        )}
      </Card>

      <Card variant="native">
        <SectionTitle title="Related governance policy surfaces" />
        <div className="mt-4 flex flex-wrap gap-3">
          <Link
            href="/settings/policies"
            className="rounded-xl border border-slate-200 bg-white px-3 py-1.5 text-sm font-medium text-slate-900 shadow-sm transition hover:border-slate-300"
          >
            Manage policy library
          </Link>
          <Link
            href="/trust/posture"
            className="rounded-xl border border-slate-200 bg-white px-3 py-1.5 text-sm font-medium text-slate-900 shadow-sm transition hover:border-slate-300"
          >
            View Trust posture
          </Link>
        </div>
      </Card>
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
      {description ? (
        <p className="mt-1 text-sm leading-6 text-slate-600">{description}</p>
      ) : null}
    </div>
  );
}

function SummaryTile({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-xl border border-slate-200 bg-slate-50 p-4">
      <div className="text-xs uppercase tracking-wide text-slate-500">
        {label}
      </div>
      <div className="mt-2 text-sm font-semibold text-slate-900">{value}</div>
    </div>
  );
}

function DetailLine({
  label,
  value,
  mono = false,
}: {
  label: string;
  value: string;
  mono?: boolean;
}) {
  return (
    <div className="flex flex-wrap items-baseline gap-x-2 text-xs text-slate-600">
      <span className="font-medium text-slate-500">{label}:</span>
      <span
        className={[
          "text-slate-700",
          mono ? "font-mono break-all" : "",
        ].join(" ")}
      >
        {value}
      </span>
    </div>
  );
}
