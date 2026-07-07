"use client";

// Fable roadmap-completion experiment - Slice F2 (M5.7 Assisted
// Onboarding, internal preview).
//
// Doctrine:
//   * Read-only, metadata-only: readiness counts, invite lifecycle
//     status, and guidance strings. No token material is requested,
//     received, or displayed.
//   * This is not clinic activation. No public signup, no paid pilot
//     activation, no billing behaviour. The checklist does not certify
//     readiness or compliance; the backend governance note is shown
//     verbatim.
//   * Frontend admin gate mirrors the backend role set for
//     discoverability only; backend remains the real authority.

import Link from "next/link";
import { useEffect, useState, useSyncExternalStore } from "react";
import { Card } from "@/components/ui/Card";
import { StatusBadge } from "@/components/ui/StatusBadge";
import {
  InternalPreviewBadge,
  InternalPreviewGate,
  PreviewBackendUnavailableCard,
  isPreviewEndpointUnavailable,
  previewAwareErrorMessage,
} from "@/components/experiment/InternalPreviewGate";
import { ApiError } from "@/lib/api";
import {
  SESSION_SERVER_SNAPSHOT,
  getSessionUserSnapshot,
  subscribeSessionStorage,
} from "@/lib/auth";
import {
  getOnboardingChecklist,
  listOnboardingInvites,
} from "@/lib/portalOnboarding";
import type {
  OnboardingChecklistResponse,
  OnboardingInviteListResponse,
} from "@/lib/portalOnboarding";

const ADMIN_ROLES = new Set(["admin", "owner", "practice_manager"]);

const FIRST_RUN_GUIDANCE: { title: string; body: string; href: string }[] = [
  {
    title: "Activate an AI use policy",
    body: "Open the Governance Policy Library and activate a clinic AI-use policy version so staff have a current version to read and attest to.",
    href: "/settings/policies",
  },
  {
    title: "Record staff attestations",
    body: "Each staff acknowledgement is metadata-only evidence that the active policy has been read and understood.",
    href: "/settings/policy-acknowledgements",
  },
  {
    title: "Build AI literacy evidence",
    body: "CPD-recordable AI literacy modules in Learn build metadata-only learning evidence for the team.",
    href: "/learn",
  },
  {
    title: "Submit the governance self-assessment",
    body: "The RCVS-aligned self-assessment snapshots where the clinic stands against governance readiness themes.",
    href: "/settings/self-assessment",
  },
  {
    title: "Publish a client transparency statement",
    body: "A plain-language statement describes how the clinic uses AI within governed boundaries. Human review remains required.",
    href: "/settings/client-transparency",
  },
];

function formatDateTime(value?: string | null): string {
  if (!value) return "—";
  try {
    return new Date(value).toLocaleString();
  } catch {
    return value;
  }
}

function roleLabel(role: string) {
  return role.replace(/[_-]+/g, " ");
}

export function OnboardingReadinessSurface() {
  return (
    <InternalPreviewGate title="Assisted onboarding">
      <OnboardingReadinessContent />
    </InternalPreviewGate>
  );
}

function OnboardingReadinessContent() {
  const user = useSyncExternalStore(
    subscribeSessionStorage,
    getSessionUserSnapshot,
    SESSION_SERVER_SNAPSHOT,
  );
  const isAdmin = Boolean(user && ADMIN_ROLES.has(user.role));

  const [checklist, setChecklist] = useState<OnboardingChecklistResponse | null>(null);
  const [checklistError, setChecklistError] = useState<string | null>(null);
  const [checklistLoading, setChecklistLoading] = useState(true);
  const [backendAbsent, setBackendAbsent] = useState(false);

  const [invites, setInvites] = useState<OnboardingInviteListResponse | null>(null);
  const [invitesError, setInvitesError] = useState<string | null>(null);
  const [invitesLoading, setInvitesLoading] = useState(false);

  useEffect(() => {
    let active = true;

    async function load() {
      setChecklistLoading(true);
      setChecklistError(null);
      try {
        const result = await getOnboardingChecklist();
        if (!active) return;
        setChecklist(result);
      } catch (err: unknown) {
        if (!active) return;
        setChecklist(null);
        // FIX 3: against a backend without the experiment endpoints,
        // 404/503 is the expected posture, not an error.
        if (isPreviewEndpointUnavailable(err)) {
          setBackendAbsent(true);
        } else {
          setChecklistError(
            err instanceof Error ? err.message : "Unable to load the onboarding checklist.",
          );
        }
      } finally {
        if (active) setChecklistLoading(false);
      }
    }

    void load();
    return () => {
      active = false;
    };
  }, []);

  useEffect(() => {
    if (!isAdmin) return;
    let active = true;

    async function load() {
      setInvitesLoading(true);
      setInvitesError(null);
      try {
        const result = await listOnboardingInvites();
        if (!active) return;
        setInvites(result);
      } catch (err: unknown) {
        if (!active) return;
        setInvites(null);
        if (err instanceof ApiError && (err.status === 401 || err.status === 403)) {
          setInvitesError("Invite lifecycle visibility requires a clinic admin role.");
        } else {
          setInvitesError(
            previewAwareErrorMessage(err, "Unable to load invite lifecycle status."),
          );
        }
      } finally {
        if (active) setInvitesLoading(false);
      }
    }

    void load();
    return () => {
      active = false;
    };
  }, [isAdmin]);

  if (backendAbsent) {
    return <PreviewBackendUnavailableCard surface="Assisted onboarding" />;
  }

  return (
    <div className="space-y-6">
      <div>
        <div className="flex flex-wrap items-center gap-3">
          <p className="text-sm font-medium text-slate-500">Clinic administration</p>
          <InternalPreviewBadge />
        </div>
        <h1 className="text-2xl font-semibold tracking-tight text-slate-900">
          Assisted onboarding
        </h1>
        <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-600">
          Metadata-only readiness guidance for setting up governed AI use in this clinic
          workspace. This surface reads existing governance evidence; it activates nothing
          and does not certify readiness.
        </p>
      </div>

      <Card variant="native">
        <SectionTitle
          title="Onboarding readiness checklist"
          description="The governance surfaces a new clinic works through, read as metadata-only counts."
        />

        {checklistLoading ? (
          <Notice tone="neutral">Loading onboarding readiness…</Notice>
        ) : checklistError ? (
          <Notice tone="error">{checklistError}</Notice>
        ) : checklist ? (
          <>
            <p className="mt-4 text-sm font-semibold text-slate-900">
              {checklist.completed_count} of {checklist.total_count} readiness items in place
            </p>
            <div className="mt-4 space-y-4">
              {checklist.items.map((item) => (
                <div
                  key={item.key}
                  className="grid gap-2 border-b border-slate-100 pb-4 last:border-b-0 last:pb-0 md:grid-cols-[1fr_auto]"
                >
                  <div>
                    <p className="text-sm font-semibold text-slate-900">{item.title}</p>
                    <p className="mt-1 text-sm leading-6 text-slate-600">{item.guidance}</p>
                    {item.available && item.count !== null ? (
                      <p className="mt-1 text-xs text-slate-500">
                        {item.count} record{item.count === 1 ? "" : "s"} for this clinic
                      </p>
                    ) : null}
                  </div>
                  <div className="md:text-right">
                    <StatusBadge
                      value={!item.available ? "unavailable" : item.done ? "ready" : "next"}
                    />
                  </div>
                </div>
              ))}
            </div>
            <p className="mt-4 max-w-3xl text-xs leading-5 text-slate-500">
              {checklist.governance_note}
            </p>
          </>
        ) : null}
      </Card>

      <Card variant="native">
        <SectionTitle
          title="Invite lifecycle and setup-token status"
          description="Lifecycle visibility for clinic invites. ANCHOR never displays invite token material — only pending, used, or expired status."
        />

        {!isAdmin ? (
          <Notice tone="neutral">
            Invite lifecycle visibility requires a clinic admin role. Ask your governance
            owner if a pending invite needs attention.
          </Notice>
        ) : invitesLoading ? (
          <Notice tone="neutral">Loading invite lifecycle status…</Notice>
        ) : invitesError ? (
          <Notice tone="error">{invitesError}</Notice>
        ) : invites ? (
          <>
            <div className="mt-4 grid gap-3 sm:grid-cols-3">
              <CountTile label="Pending" value={invites.pending_count} />
              <CountTile label="Used" value={invites.used_count} />
              <CountTile label="Expired" value={invites.expired_count} />
            </div>

            {invites.invites.length > 0 ? (
              <div className="mt-4 overflow-x-auto">
                <table className="w-full text-left text-sm">
                  <thead>
                    <tr className="border-b border-slate-200 text-xs uppercase tracking-wide text-slate-500">
                      <th className="py-2 pr-4 font-semibold">Email</th>
                      <th className="py-2 pr-4 font-semibold">Role</th>
                      <th className="py-2 pr-4 font-semibold">Status</th>
                      <th className="py-2 pr-4 font-semibold">Invited</th>
                      <th className="py-2 pr-4 font-semibold">Token expires</th>
                      <th className="py-2 font-semibold">Used</th>
                    </tr>
                  </thead>
                  <tbody>
                    {invites.invites.map((invite) => (
                      <tr key={invite.invite_id} className="border-b border-slate-100 last:border-b-0">
                        <td className="py-2.5 pr-4 text-slate-900">{invite.email || "—"}</td>
                        <td className="py-2.5 pr-4 capitalize text-slate-600">
                          {roleLabel(invite.role) || "—"}
                        </td>
                        <td className="py-2.5 pr-4">
                          <StatusBadge value={invite.status} />
                        </td>
                        <td className="py-2.5 pr-4 text-slate-600">{formatDateTime(invite.created_at)}</td>
                        <td className="py-2.5 pr-4 text-slate-600">{formatDateTime(invite.expires_at)}</td>
                        <td className="py-2.5 text-slate-600">{formatDateTime(invite.used_at)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <Notice tone="neutral">No invites have been created for this clinic yet.</Notice>
            )}
            <p className="mt-4 max-w-3xl text-xs leading-5 text-slate-500">
              Invite links carry expiring setup tokens. Token material is never returned to
              this portal; lifecycle status above is the complete visible record.
            </p>
          </>
        ) : null}
      </Card>

      <Card variant="native">
        <SectionTitle
          title="First-run governance guidance"
          description="A suggested order of setup for a new clinic. Each step links to an existing governance surface."
        />
        <ol className="mt-4 space-y-4">
          {FIRST_RUN_GUIDANCE.map((step, index) => (
            <li
              key={step.title}
              className="grid gap-2 border-b border-slate-100 pb-4 last:border-b-0 last:pb-0 md:grid-cols-[1fr_auto]"
            >
              <div>
                <p className="text-sm font-semibold text-slate-900">
                  {index + 1}. {step.title}
                </p>
                <p className="mt-1 text-sm leading-6 text-slate-600">{step.body}</p>
              </div>
              <div className="md:text-right">
                <Link
                  href={step.href}
                  className="text-sm font-medium text-slate-900 underline underline-offset-4"
                >
                  Open
                </Link>
              </div>
            </li>
          ))}
        </ol>
      </Card>

      <Card variant="native">
        <SectionTitle
          title="Activation posture"
          description="What this workspace can truthfully represent right now."
        />
        <div className="mt-4 space-y-4">
          <PostureRow
            title="Workspace posture"
            status="internal_demo"
            note="This clinic workspace operates in an internal/demo posture. Paid pilots and real clinic onboarding are not enabled."
          />
          <PostureRow
            title="Billing"
            status="sandbox_only"
            note="Billing foundations are sandbox-only. No live billing, no charges, and no activation of paid service."
          />
        </div>
        <p className="mt-4 text-sm leading-6 text-slate-600">
          The current sandbox billing state is visible on the{" "}
          <Link
            href="/settings/billing"
            className="font-medium text-slate-900 underline underline-offset-4"
          >
            billing foundations
          </Link>{" "}
          surface.
        </p>
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

function PostureRow({
  title,
  status,
  note,
}: {
  title: string;
  status: string;
  note: string;
}) {
  return (
    <div className="grid gap-2 border-b border-slate-100 pb-4 last:border-b-0 last:pb-0 md:grid-cols-[1fr_auto]">
      <div>
        <p className="text-sm font-semibold text-slate-900">{title}</p>
        <p className="mt-1 text-sm leading-6 text-slate-600">{note}</p>
      </div>
      <div className="md:text-right">
        <StatusBadge value={status} />
      </div>
    </div>
  );
}
