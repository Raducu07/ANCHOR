"use client";

// Phase 2A-2.7 - Staff-facing Governance Policy Acknowledgement UI.
//
// Metadata-only doctrine:
//   * No raw policy body text is rendered or fetched. Outstanding and
//     active policies expose only metadata: title, summary, version,
//     activation timestamp, content reference path, content hash
//     truncated.
//   * Acknowledgement records metadata: a statement version and an
//     acknowledgement method string. No staff reflections, free-text,
//     names, emails, clinical content, scores, pass/fail, or competence
//     grading are sent or stored client-side.
//   * Acknowledgement is NOT Learn completion and does NOT create CPD
//     minutes. It also is not certification, legal approval, or proof
//     of professional competence.
//   * This page is staff-facing; AppShell already gates unauthenticated
//     access via its redirect-to-login behaviour, so no additional role
//     gate is added here.

import { useCallback, useEffect, useState, useSyncExternalStore } from "react";
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
  attestToClinicPolicy,
  listActiveClinicPolicies,
  listMyPolicyAttestations,
  listOutstandingPolicyAttestations,
} from "@/lib/governancePolicy";
import type {
  ClinicPolicyVersion,
  PolicyAttestation,
} from "@/lib/types";

const ATTESTATION_STATEMENT_VERSION = "attestation_statement_v1";
const ACKNOWLEDGEMENT_METHOD = "in_app_button_click";

// Frontend-only navigation gate; backend remains the real authority.
const POLICY_ADMIN_ROLES = new Set(["admin", "owner", "practice_manager"]);

function formatDateTime(value?: string | null): string {
  if (!value) return "Not set";
  try {
    return new Date(value).toLocaleString();
  } catch {
    return value;
  }
}

function shortHash(value: string | null | undefined): string {
  if (!value) return "None";
  if (value.length <= 14) return value;
  return `${value.slice(0, 8)}...${value.slice(-4)}`;
}

function shortenId(value: string | null | undefined): string {
  if (!value) return "-";
  if (value.length <= 14) return value;
  return `${value.slice(0, 8)}...${value.slice(-4)}`;
}

function mapAttestErrorMessage(err: unknown): string {
  const message =
    err instanceof ApiError
      ? err.message
      : err instanceof Error
        ? err.message
        : "";
  if (message.includes("attestation_previously_voided")) {
    return "This previous acknowledgement was voided. A clinic administrator must issue a new policy version before you can acknowledge it again.";
  }
  if (message.includes("governance_policy_not_active")) {
    return "This policy version is no longer active.";
  }
  return "Policy acknowledgement could not be recorded.";
}

type Feedback = { kind: "success" | "error"; message: string } | null;

export function PolicyAcknowledgementsPage() {
  const sessionUser = useSyncExternalStore(
    subscribeSessionStorage,
    getSessionUserSnapshot,
    SESSION_SERVER_SNAPSHOT,
  );
  const isAdmin = Boolean(
    sessionUser?.role && POLICY_ADMIN_ROLES.has(sessionUser.role),
  );

  const [outstanding, setOutstanding] = useState<ClinicPolicyVersion[] | null>(
    null,
  );
  const [outstandingLoading, setOutstandingLoading] = useState(false);
  const [outstandingError, setOutstandingError] = useState<string | null>(null);

  const [activePolicies, setActivePolicies] = useState<
    ClinicPolicyVersion[] | null
  >(null);
  const [activeLoading, setActiveLoading] = useState(false);
  const [activeError, setActiveError] = useState<string | null>(null);

  const [attestations, setAttestations] = useState<PolicyAttestation[] | null>(
    null,
  );
  const [attestationsLoading, setAttestationsLoading] = useState(false);
  const [attestationsError, setAttestationsError] = useState<string | null>(
    null,
  );

  const [acknowledgedSet, setAcknowledgedSet] = useState<Set<string>>(
    new Set(),
  );
  const [attestingId, setAttestingId] = useState<string | null>(null);
  const [feedback, setFeedback] = useState<Feedback>(null);

  const loadOutstanding = useCallback(async () => {
    setOutstandingLoading(true);
    setOutstandingError(null);
    try {
      const result = await listOutstandingPolicyAttestations();
      setOutstanding(result.policies ?? []);
    } catch (err) {
      setOutstanding(null);
      setOutstandingError(
        err instanceof ApiError
          ? err.message
          : "Outstanding policy acknowledgements could not be loaded.",
      );
    } finally {
      setOutstandingLoading(false);
    }
  }, []);

  const loadActive = useCallback(async () => {
    setActiveLoading(true);
    setActiveError(null);
    try {
      const result = await listActiveClinicPolicies();
      setActivePolicies(result.policies ?? []);
    } catch (err) {
      setActivePolicies(null);
      setActiveError(
        err instanceof ApiError
          ? err.message
          : "Active clinic policies could not be loaded.",
      );
    } finally {
      setActiveLoading(false);
    }
  }, []);

  const loadAttestations = useCallback(async () => {
    setAttestationsLoading(true);
    setAttestationsError(null);
    try {
      const result = await listMyPolicyAttestations({
        includeVoided: true,
        limit: 50,
      });
      setAttestations(result.attestations ?? []);
    } catch (err) {
      setAttestations(null);
      setAttestationsError(
        err instanceof ApiError
          ? err.message
          : "Your acknowledgement history could not be loaded.",
      );
    } finally {
      setAttestationsLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadOutstanding();
    void loadActive();
    void loadAttestations();
  }, [loadOutstanding, loadActive, loadAttestations]);

  function toggleAcknowledged(id: string, checked: boolean) {
    setAcknowledgedSet((prev) => {
      const next = new Set(prev);
      if (checked) next.add(id);
      else next.delete(id);
      return next;
    });
  }

  async function handleAcknowledge(policy: ClinicPolicyVersion) {
    setAttestingId(policy.clinic_policy_version_id);
    setFeedback(null);
    try {
      await attestToClinicPolicy(policy.clinic_policy_version_id, {
        attestation_statement_version: ATTESTATION_STATEMENT_VERSION,
        acknowledgement_method: ACKNOWLEDGEMENT_METHOD,
      });
      setFeedback({
        kind: "success",
        message: "Policy acknowledgement recorded.",
      });
      // Clear local checkbox state for this row before refresh so the
      // row reappearing would not retain a stale tick.
      setAcknowledgedSet((prev) => {
        if (!prev.has(policy.clinic_policy_version_id)) return prev;
        const next = new Set(prev);
        next.delete(policy.clinic_policy_version_id);
        return next;
      });
      await Promise.all([loadOutstanding(), loadAttestations(), loadActive()]);
    } catch (err) {
      setFeedback({ kind: "error", message: mapAttestErrorMessage(err) });
    } finally {
      setAttestingId(null);
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <p className="text-sm font-medium text-slate-500">Clinic governance</p>
        <h1 className="text-2xl font-semibold tracking-tight text-slate-900">
          Policy acknowledgements
        </h1>
        <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-600">
          Review active clinic AI-use policy metadata and acknowledge the
          versions assigned to your account.
        </p>
        <p className="mt-2 max-w-3xl text-xs leading-5 text-slate-500">
          Acknowledgement records metadata-only governance evidence. It is not
          CPD completion, legal advice, regulatory certification, evidence of
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
        <SectionTitle
          title="Outstanding acknowledgements"
          description="Active clinic policy versions that have not yet been acknowledged on your account."
        />
        {outstandingLoading && outstanding === null ? (
          <p className="mt-4 rounded-xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-600">
            Loading policy acknowledgements...
          </p>
        ) : outstandingError ? (
          <p className="mt-4 rounded-xl border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-700">
            {outstandingError}
          </p>
        ) : !outstanding || outstanding.length === 0 ? (
          <p className="mt-4 rounded-xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-600">
            No outstanding policy acknowledgements.
          </p>
        ) : (
          <ul className="mt-4 space-y-3">
            {outstanding.map((policy) => {
              const id = policy.clinic_policy_version_id;
              const acknowledged = acknowledgedSet.has(id);
              const busy = attestingId === id;
              return (
                <li
                  key={id}
                  className="rounded-xl border border-slate-200 bg-slate-50 p-4"
                >
                  <div className="flex flex-wrap items-start justify-between gap-2">
                    <div className="min-w-0">
                      <p className="text-sm font-semibold text-slate-900">
                        {policy.title_snapshot}
                      </p>
                      <p className="mt-1 text-xs text-slate-500">
                        Version v{policy.clinic_policy_version}
                        {policy.template_slug
                          ? ` - from ${policy.template_slug}`
                          : ""}
                      </p>
                    </div>
                    <StatusBadge value="active" />
                  </div>
                  {policy.summary_snapshot ? (
                    <p className="mt-2 text-sm leading-6 text-slate-600">
                      {policy.summary_snapshot}
                    </p>
                  ) : null}
                  <div className="mt-3 space-y-1">
                    <DetailLine
                      label="Activated"
                      value={formatDateTime(policy.activated_at)}
                    />
                    <DetailLine
                      label="Content hash"
                      value={shortHash(policy.content_sha256_snapshot)}
                      mono
                    />
                  </div>
                  <label className="mt-4 flex items-start gap-2 text-xs leading-5 text-slate-700">
                    <input
                      type="checkbox"
                      checked={acknowledged}
                      onChange={(e) =>
                        toggleAcknowledged(id, e.target.checked)
                      }
                      disabled={busy}
                      className="mt-0.5 h-4 w-4 rounded border-slate-300"
                    />
                    <span>
                      I acknowledge that I have reviewed this clinic AI-use
                      policy version metadata and understand that human
                      professional judgement remains required.
                    </span>
                  </label>
                  <div className="mt-3">
                    <Button
                      onClick={() => void handleAcknowledge(policy)}
                      loading={busy}
                      disabled={!acknowledged || busy}
                    >
                      Acknowledge policy version
                    </Button>
                  </div>
                </li>
              );
            })}
          </ul>
        )}
      </Card>

      <Card variant="native">
        <SectionTitle
          title="Active clinic policies"
          description="These are the active AI-use policy versions for this clinic. Acknowledgement records that you reviewed the policy metadata shown here."
        />
        {activeLoading && activePolicies === null ? (
          <p className="mt-4 rounded-xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-600">
            Loading active clinic policies...
          </p>
        ) : activeError ? (
          <p className="mt-4 rounded-xl border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-700">
            {activeError}
          </p>
        ) : !activePolicies || activePolicies.length === 0 ? (
          <p className="mt-4 rounded-xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-600">
            No active clinic AI-use policies are currently available.
          </p>
        ) : (
          <ul className="mt-4 space-y-3">
            {activePolicies.map((policy) => (
              <li
                key={policy.clinic_policy_version_id}
                className="rounded-xl border border-slate-200 bg-slate-50 p-4"
              >
                <div className="flex flex-wrap items-start justify-between gap-2">
                  <div className="min-w-0">
                    <p className="text-sm font-semibold text-slate-900">
                      {policy.title_snapshot}
                    </p>
                    <p className="mt-1 text-xs text-slate-500">
                      Version v{policy.clinic_policy_version}
                      {policy.template_slug
                        ? ` - from ${policy.template_slug}`
                        : ""}
                    </p>
                  </div>
                  <StatusBadge value="active" />
                </div>
                <div className="mt-3 space-y-1">
                  <DetailLine
                    label="Activated"
                    value={formatDateTime(policy.activated_at)}
                  />
                  <DetailLine
                    label="Content hash"
                    value={shortHash(policy.content_sha256_snapshot)}
                    mono
                  />
                </div>
              </li>
            ))}
          </ul>
        )}
      </Card>

      <Card variant="native">
        <SectionTitle
          title="My acknowledgement history"
          description="Your previous acknowledgements, including voided records."
        />
        {attestationsLoading && attestations === null ? (
          <p className="mt-4 rounded-xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-600">
            Loading policy acknowledgements...
          </p>
        ) : attestationsError ? (
          <p className="mt-4 rounded-xl border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-700">
            {attestationsError}
          </p>
        ) : !attestations || attestations.length === 0 ? (
          <p className="mt-4 rounded-xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-600">
            No policy acknowledgements recorded yet.
          </p>
        ) : (
          <ul className="mt-4 space-y-3">
            {attestations.map((a) => (
              <li
                key={a.attestation_id}
                className="rounded-xl border border-slate-200 bg-slate-50 p-4"
              >
                <div className="flex flex-wrap items-start justify-between gap-2">
                  <div className="min-w-0">
                    <p className="text-sm font-semibold text-slate-900">
                      Acknowledged {formatDateTime(a.acknowledged_at)}
                    </p>
                    <p className="mt-1 text-xs text-slate-500">
                      Policy version {shortenId(a.clinic_policy_version_id)}
                    </p>
                  </div>
                  <StatusBadge value={a.is_voided ? "voided" : "recorded"} />
                </div>
                <div className="mt-3 space-y-1">
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
              </li>
            ))}
          </ul>
        )}
      </Card>

      <Card variant="native">
        <SectionTitle title="Related governance surfaces" />
        <div className="mt-4 flex flex-wrap gap-3">
          <Link
            href="/trust/posture"
            className="rounded-xl border border-slate-200 bg-white px-3 py-1.5 text-sm font-medium text-slate-900 shadow-sm transition hover:border-slate-300"
          >
            View Trust posture
          </Link>
          {isAdmin ? (
            <Link
              href="/settings/policies"
              className="rounded-xl border border-slate-200 bg-white px-3 py-1.5 text-sm font-medium text-slate-900 shadow-sm transition hover:border-slate-300"
            >
              Manage policy library
            </Link>
          ) : null}
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
