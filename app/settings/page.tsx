"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { AppShell } from "@/components/shell/AppShell";
import { Card } from "@/components/ui/Card";
import { StatusBadge } from "@/components/ui/StatusBadge";
import { getSessionUser } from "@/lib/auth";
import type { SessionUser } from "@/lib/types";

function roleLabel(role: string) {
  return role
    .replace(/_/g, " ")
    .toLowerCase()
    .replace(/\b\w/g, (char) => char.toUpperCase());
}

export default function SettingsPage() {
  const [user, setUser] = useState<SessionUser | null>(null);

  useEffect(() => {
    setUser(getSessionUser());
  }, []);

  const email = user?.email ?? "Signed-in session";
  const role = user ? roleLabel(user.role) : "Clinic user";
  const clinicSlug = user?.clinicSlug ?? "Current clinic workspace";

  return (
    <AppShell>
      <div className="space-y-6">
        <div>
          <p className="text-sm font-medium text-slate-500">Clinic administration</p>
          <h1 className="text-2xl font-semibold tracking-tight text-slate-900">Settings</h1>
          <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-600">
            A lightweight settings surface for clinic context, connected guidance, and the
            boundaries of the current ANCHOR administration experience.
          </p>
        </div>

        <div className="grid gap-4 xl:grid-cols-[1.2fr_0.8fr]">
          <Card>
            <SectionTitle
              title="Account summary"
              description="The current signed-in session and role context for this workspace."
            />
            <dl className="mt-4 space-y-4 text-sm">
              <Detail label="Signed-in email" value={email} />
              <Detail label="Current role" value={role} />
              <Detail label="Sign-out" value="Managed from the shared shell in the top-right account menu." />
            </dl>
          </Card>

          <Card>
            <SectionTitle
              title="Workspace context"
              description="Clinic-scoped access remains central to ANCHOR’s operating model."
            />
            <dl className="mt-4 space-y-4 text-sm">
              <Detail label="Clinic workspace" value={clinicSlug} />
              <Detail label="Access model" value="Clinic-scoped session with governance-first product surfaces." />
              <Detail label="Current posture" value="Metadata-only accountability and review-oriented oversight." />
            </dl>
          </Card>
        </div>

        <div className="grid gap-4 xl:grid-cols-[1fr_1fr]">
          <Card>
            <SectionTitle
              title="Related admin surfaces"
              description="Go directly to the adjacent product areas that matter most from Settings today."
            />
            <div className="mt-4 space-y-3">
              <QuickLink
                href="/privacy-policy"
                title="Privacy / Policy"
                description="Review the current privacy posture, policy direction, and governance boundaries."
              />
              <QuickLink
                href="/support"
                title="Support"
                description="Get practical guidance on what ANCHOR supports today and where to go next."
              />
            </div>
          </Card>

          <Card>
            <SectionTitle
              title="Current settings scope"
              description="What this page can truthfully represent in the current product."
            />
            <div className="mt-4 space-y-4">
              <ScopeRow
                title="Session visibility"
                status="ready"
                note="Useful now for orienting a signed-in clinic user without implying hidden admin controls."
              />
              <ScopeRow
                title="Editable preferences"
                status="next"
                note="Future-facing only. Preference controls should be added only when endpoint behavior and ownership are verified."
              />
              <ScopeRow
                title="Clinic-level configuration"
                status="next"
                note="Should stay clearly bounded until there is real backend support for safe editing and audit-friendly change visibility."
              />
            </div>
          </Card>
        </div>

        <Card>
          <SectionTitle
            title="Future preferences"
            description="Intentionally labeled as future-facing so this surface stays honest."
          />
          <div className="mt-4 grid gap-4 md:grid-cols-3">
            <FutureCard
              title="Notification preferences"
              body="Future clinic-facing control for alert noise, digest rhythm, and governance signal preferences."
            />
            <FutureCard
              title="Profile display details"
              body="Future refinement for display name, avatar, and role presentation once product ownership is explicit."
            />
            <FutureCard
              title="Workspace defaults"
              body="Future clinic-level defaults only when they can be surfaced without overstating current product maturity."
            />
          </div>
        </Card>
      </div>
    </AppShell>
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
      {description ? <p className="mt-1 text-sm leading-6 text-slate-600">{description}</p> : null}
    </div>
  );
}

function Detail({
  label,
  value,
}: {
  label: string;
  value: string;
}) {
  return (
    <div className="grid grid-cols-[140px_1fr] gap-4 border-b border-slate-100 pb-4 last:border-b-0 last:pb-0">
      <dt className="text-slate-500">{label}</dt>
      <dd className="text-slate-900">{value}</dd>
    </div>
  );
}

function QuickLink({
  href,
  title,
  description,
}: {
  href: string;
  title: string;
  description: string;
}) {
  return (
    <Link
      href={href}
      className="block rounded-2xl border border-slate-200 bg-slate-50 p-4 transition hover:border-slate-300 hover:bg-white"
    >
      <p className="text-sm font-semibold text-slate-900">{title}</p>
      <p className="mt-1 text-sm leading-6 text-slate-600">{description}</p>
    </Link>
  );
}

function ScopeRow({
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

function FutureCard({
  title,
  body,
}: {
  title: string;
  body: string;
}) {
  return (
    <div className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
      <p className="text-sm font-semibold text-slate-900">{title}</p>
      <p className="mt-2 text-sm leading-6 text-slate-600">{body}</p>
    </div>
  );
}
