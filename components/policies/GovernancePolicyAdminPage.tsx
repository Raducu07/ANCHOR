"use client";

// Phase 2A-2.6 - Governance Policy Library admin page (admin-only).
//
// Metadata-only doctrine:
//   * No raw policy body text is rendered. Templates and clinic policy
//     versions expose only metadata: title, summary, category, version,
//     timestamps, content reference path, content hash (truncated).
//   * No staff names/emails, clinical content, prompts/outputs/
//     transcripts, staff reflections, legal-approval status, scoring,
//     pass/fail, or competence grading.
//   * Frontend admin gate is UX hardening only; backend remains the
//     real authorization control.

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
  activateClinicPolicy,
  archiveClinicPolicy,
  createClinicPolicy,
  listActiveClinicPolicies,
  listClinicPolicies,
  listPolicyTemplates,
} from "@/lib/governancePolicy";
import type { ClinicPolicyVersion, PolicyTemplate } from "@/lib/types";

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

function errorMessageFromUnknown(err: unknown, fallback: string): string {
  if (err instanceof ApiError) return err.message;
  if (err instanceof Error) return err.message;
  return fallback;
}

type ActionFeedback = { kind: "success" | "error"; message: string } | null;

export function GovernancePolicyAdminPage() {
  const sessionUser = useSyncExternalStore(
    subscribeSessionStorage,
    getSessionUserSnapshot,
    SESSION_SERVER_SNAPSHOT,
  );
  const isAdmin = Boolean(
    sessionUser?.role && POLICY_ADMIN_ROLES.has(sessionUser.role),
  );

  const [templates, setTemplates] = useState<PolicyTemplate[] | null>(null);
  const [templatesLoading, setTemplatesLoading] = useState(false);
  const [templatesError, setTemplatesError] = useState<string | null>(null);

  const [clinicPolicies, setClinicPolicies] = useState<
    ClinicPolicyVersion[] | null
  >(null);
  const [clinicPoliciesLoading, setClinicPoliciesLoading] = useState(false);
  const [clinicPoliciesError, setClinicPoliciesError] = useState<string | null>(
    null,
  );

  const [activePolicies, setActivePolicies] = useState<
    ClinicPolicyVersion[] | null
  >(null);
  const [activePoliciesLoading, setActivePoliciesLoading] = useState(false);
  const [activePoliciesError, setActivePoliciesError] = useState<string | null>(
    null,
  );

  const [creatingFromSlug, setCreatingFromSlug] = useState<string | null>(null);
  const [actingOnPolicyId, setActingOnPolicyId] = useState<string | null>(null);
  const [feedback, setFeedback] = useState<ActionFeedback>(null);

  const loadTemplates = useCallback(async () => {
    setTemplatesLoading(true);
    setTemplatesError(null);
    try {
      const result = await listPolicyTemplates();
      setTemplates(result.templates ?? []);
    } catch (err) {
      setTemplates(null);
      setTemplatesError(
        errorMessageFromUnknown(err, "Policy templates could not be loaded."),
      );
    } finally {
      setTemplatesLoading(false);
    }
  }, []);

  const loadClinicPolicies = useCallback(async () => {
    setClinicPoliciesLoading(true);
    setClinicPoliciesError(null);
    try {
      const result = await listClinicPolicies({ limit: 100 });
      setClinicPolicies(result.policies ?? []);
    } catch (err) {
      setClinicPolicies(null);
      setClinicPoliciesError(
        errorMessageFromUnknown(
          err,
          "Clinic policy versions could not be loaded.",
        ),
      );
    } finally {
      setClinicPoliciesLoading(false);
    }
  }, []);

  const loadActivePolicies = useCallback(async () => {
    setActivePoliciesLoading(true);
    setActivePoliciesError(null);
    try {
      const result = await listActiveClinicPolicies();
      setActivePolicies(result.policies ?? []);
    } catch (err) {
      setActivePolicies(null);
      setActivePoliciesError(
        errorMessageFromUnknown(
          err,
          "Active clinic policies could not be loaded.",
        ),
      );
    } finally {
      setActivePoliciesLoading(false);
    }
  }, []);

  useEffect(() => {
    if (!isAdmin) return;
    void loadTemplates();
    void loadClinicPolicies();
    void loadActivePolicies();
  }, [isAdmin, loadTemplates, loadClinicPolicies, loadActivePolicies]);

  async function handleCreateFromTemplate(template: PolicyTemplate) {
    setCreatingFromSlug(template.template_slug);
    setFeedback(null);
    try {
      await createClinicPolicy({
        template_slug: template.template_slug,
        template_version: template.template_version,
      });
      setFeedback({
        kind: "success",
        message: "Draft clinic policy version created.",
      });
      await loadClinicPolicies();
    } catch (err) {
      setFeedback({
        kind: "error",
        message: errorMessageFromUnknown(
          err,
          "Unable to create draft clinic policy version.",
        ),
      });
    } finally {
      setCreatingFromSlug(null);
    }
  }

  async function handleActivate(policy: ClinicPolicyVersion) {
    setActingOnPolicyId(policy.clinic_policy_version_id);
    setFeedback(null);
    try {
      await activateClinicPolicy(policy.clinic_policy_version_id);
      setFeedback({
        kind: "success",
        message:
          "Policy version activated. Staff attestation can be requested in the next workflow step.",
      });
      await Promise.all([loadClinicPolicies(), loadActivePolicies()]);
    } catch (err) {
      setFeedback({
        kind: "error",
        message: errorMessageFromUnknown(
          err,
          "Unable to activate this policy version.",
        ),
      });
    } finally {
      setActingOnPolicyId(null);
    }
  }

  async function handleArchive(policy: ClinicPolicyVersion) {
    setActingOnPolicyId(policy.clinic_policy_version_id);
    setFeedback(null);
    try {
      await archiveClinicPolicy(policy.clinic_policy_version_id);
      setFeedback({
        kind: "success",
        message: "Policy version archived.",
      });
      await Promise.all([loadClinicPolicies(), loadActivePolicies()]);
    } catch (err) {
      setFeedback({
        kind: "error",
        message: errorMessageFromUnknown(
          err,
          "Unable to archive this policy version.",
        ),
      });
    } finally {
      setActingOnPolicyId(null);
    }
  }

  if (!isAdmin) {
    return (
      <div className="space-y-6">
        <div>
          <p className="text-sm font-medium text-slate-500">Clinic administration</p>
          <h1 className="text-2xl font-semibold tracking-tight text-slate-900">
            Governance Policy Library
          </h1>
        </div>
        <Card variant="native">
          <p className="text-sm leading-6 text-slate-700">
            Policy Library is available to clinic administrators only. Contact
            your clinic administrator if you need access.
          </p>
        </Card>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div>
        <p className="text-sm font-medium text-slate-500">Clinic administration</p>
        <h1 className="text-2xl font-semibold tracking-tight text-slate-900">
          Governance Policy Library
        </h1>
        <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-600">
          Create and manage clinic AI-use policy versions from ANCHOR templates.
        </p>
        <p className="mt-2 max-w-3xl text-xs leading-5 text-slate-500">
          Policy Library records metadata-only governance evidence. It is not
          legal advice, regulatory certification, or a guarantee of regulatory
          compliance.
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
          title="Policy templates"
          description="ANCHOR-curated templates available to your clinic."
        />
        {templatesLoading && templates === null ? (
          <p className="mt-4 rounded-xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-600">
            Loading policy templates...
          </p>
        ) : templatesError ? (
          <p className="mt-4 rounded-xl border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-700">
            {templatesError}
          </p>
        ) : !templates || templates.length === 0 ? (
          <p className="mt-4 rounded-xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-600">
            No policy templates are available yet.
          </p>
        ) : (
          <div className="mt-4 grid gap-4 xl:grid-cols-2">
            {templates.map((template) => (
              <div
                key={template.template_id}
                className="rounded-xl border border-slate-200 bg-slate-50 p-4"
              >
                <div className="flex flex-wrap items-start justify-between gap-2">
                  <h3 className="text-sm font-semibold text-slate-900">
                    {template.title}
                  </h3>
                  <StatusBadge value={template.is_active ? "active" : "inactive"} />
                </div>
                <p className="mt-2 text-sm leading-6 text-slate-600">
                  {template.summary}
                </p>
                <div className="mt-3 flex flex-wrap gap-2">
                  <Pill label={`Category: ${formatTag(template.category)}`} />
                  <Pill label={`v${template.template_version}`} />
                </div>
                {template.role_applicability.length > 0 ? (
                  <PillGroup
                    label="Audience"
                    items={template.role_applicability.map(formatTag)}
                  />
                ) : null}
                {template.jurisdiction_tags.length > 0 ? (
                  <PillGroup
                    label="Jurisdiction"
                    items={template.jurisdiction_tags.map(formatTag)}
                  />
                ) : null}
                {template.source_basis.length > 0 ? (
                  <PillGroup
                    label="Source basis"
                    items={template.source_basis.map(formatTag)}
                  />
                ) : null}
                <div className="mt-3 space-y-1">
                  <DetailLine
                    label="Content reference"
                    value={template.content_reference}
                    mono
                  />
                  <DetailLine
                    label="Content hash"
                    value={shortHash(template.content_sha256)}
                    mono
                  />
                </div>
                <div className="mt-4">
                  <Button
                    onClick={() => void handleCreateFromTemplate(template)}
                    loading={creatingFromSlug === template.template_slug}
                    disabled={
                      !template.is_active ||
                      creatingFromSlug === template.template_slug
                    }
                  >
                    Create clinic policy version
                  </Button>
                </div>
              </div>
            ))}
          </div>
        )}
      </Card>

      <Card variant="native">
        <SectionTitle
          title="Clinic policy versions"
          description="All draft, active, superseded, and archived clinic policy versions."
        />
        {clinicPoliciesLoading && clinicPolicies === null ? (
          <p className="mt-4 rounded-xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-600">
            Loading clinic policy versions...
          </p>
        ) : clinicPoliciesError ? (
          <p className="mt-4 rounded-xl border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-700">
            {clinicPoliciesError}
          </p>
        ) : !clinicPolicies || clinicPolicies.length === 0 ? (
          <p className="mt-4 rounded-xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-600">
            No clinic policy versions have been created yet. Create a draft from
            a template to begin.
          </p>
        ) : (
          <ul className="mt-4 space-y-3">
            {clinicPolicies.map((policy) => {
              const canActivate = policy.status === "draft";
              const canArchive =
                policy.status === "draft" || policy.status === "superseded";
              const busy =
                actingOnPolicyId === policy.clinic_policy_version_id;
              return (
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
                        {` - template v${policy.template_version_snapshot}`}
                      </p>
                    </div>
                    <StatusBadge value={policy.status} />
                  </div>
                  <div className="mt-3 space-y-1">
                    <DetailLine
                      label="Created"
                      value={formatDateTime(policy.created_at)}
                    />
                    <DetailLine
                      label="Activated"
                      value={formatDateTime(policy.activated_at)}
                    />
                    <DetailLine
                      label="Superseded"
                      value={formatDateTime(policy.superseded_at)}
                    />
                    <DetailLine
                      label="Content hash"
                      value={shortHash(policy.content_sha256_snapshot)}
                      mono
                    />
                  </div>
                  {canActivate || canArchive ? (
                    <div className="mt-4 flex flex-wrap gap-2">
                      {canActivate ? (
                        <Button
                          onClick={() => void handleActivate(policy)}
                          loading={busy}
                          disabled={busy}
                        >
                          Activate
                        </Button>
                      ) : null}
                      {canArchive ? (
                        <Button
                          variant="secondary"
                          onClick={() => void handleArchive(policy)}
                          loading={busy}
                          disabled={busy}
                        >
                          Archive
                        </Button>
                      ) : null}
                    </div>
                  ) : null}
                </li>
              );
            })}
          </ul>
        )}
      </Card>

      <Card variant="native">
        <SectionTitle
          title="Active clinic policies"
          description="These are the active AI-use policy versions for this clinic. Staff acknowledgement is handled separately."
        />
        {activePoliciesLoading && activePolicies === null ? (
          <p className="mt-4 rounded-xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-600">
            Loading active clinic policies...
          </p>
        ) : activePoliciesError ? (
          <p className="mt-4 rounded-xl border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-700">
            {activePoliciesError}
          </p>
        ) : !activePolicies || activePolicies.length === 0 ? (
          <p className="mt-4 rounded-xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-600">
            No active clinic AI-use policies yet.
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
        <SectionTitle title="Related governance policy surfaces" />
        <div className="mt-4 flex flex-wrap gap-3">
          <Link
            href="/settings/policy-acknowledgements"
            className="rounded-xl border border-slate-200 bg-white px-3 py-1.5 text-sm font-medium text-slate-900 shadow-sm transition hover:border-slate-300"
          >
            View policy acknowledgements
          </Link>
          <Link
            href="/settings/policy-attestations"
            className="rounded-xl border border-slate-200 bg-white px-3 py-1.5 text-sm font-medium text-slate-900 shadow-sm transition hover:border-slate-300"
          >
            View attestation status
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

function Pill({ label }: { label: string }) {
  return (
    <span className="inline-flex items-center rounded-full border border-slate-200 bg-white px-2 py-0.5 text-xs font-medium capitalize text-slate-600">
      {label}
    </span>
  );
}

function PillGroup({ label, items }: { label: string; items: string[] }) {
  return (
    <div className="mt-3">
      <p className="text-xs font-semibold uppercase tracking-[0.16em] text-slate-500">
        {label}
      </p>
      <div className="mt-2 flex flex-wrap gap-2">
        {items.map((item) => (
          <span
            key={item}
            className="inline-flex items-center rounded-full border border-slate-200 bg-white px-2.5 py-1 text-xs font-medium capitalize text-slate-700"
          >
            {item}
          </span>
        ))}
      </div>
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

function formatTag(value: string): string {
  return value.replace(/[_-]+/g, " ");
}
