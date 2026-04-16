"use client";

import Link from "next/link";
import { AppShell } from "@/components/shell/AppShell";
import { Card } from "@/components/ui/Card";
import { StatusBadge } from "@/components/ui/StatusBadge";

const postureItems = [
  {
    label: "Metadata-only governance",
    value: "Established",
    helper:
      "ANCHOR surfaces governance metadata for accountability and review without storing raw prompt or output content in the current product doctrine.",
  },
  {
    label: "Tenant isolation",
    value: "Proven",
    helper:
      "Clinic-scoped access and request context remain central to the platform’s operating model and commercial trust posture.",
  },
  {
    label: "Exports",
    value: "Bounded",
    helper:
      "CSV exports remain clinic-scoped and metadata-only, with row caps and window caps enforced server-side.",
  },
  {
    label: "Policy traceability",
    value: "Live",
    helper:
      "Receipts already expose policy versioning, neutrality versioning, and policy hash evidence for audit-friendly review.",
  },
];

const guarantees = [
  {
    title: "Privacy-aware oversight",
    body:
      "Governance surfaces are designed to support operational accountability without turning ANCHOR into a raw-content archive.",
  },
  {
    title: "Clinic-scoped review",
    body:
      "Receipts, governance events, and exports are framed as clinic-scoped operational tools rather than generic AI chat history.",
  },
  {
    title: "Server-side authority",
    body:
      "The backend remains the source of truth for retention, export limits, policy versioning, and enforcement boundaries.",
  },
];

const adminReadiness = [
  {
    item: "Privacy posture summary",
    status: "ready",
    note: "Suitable for clinic-facing display now.",
  },
  {
    item: "Policy version visibility",
    status: "ready",
    note: "Already evidenced through receipts and backend traces.",
  },
  {
    item: "Editable privacy profile controls",
    status: "next",
    note: "Should be wired only after exact endpoint verification.",
  },
  {
    item: "Editable policy admin controls",
    status: "next",
    note: "Planned for a future update after route verification and UX decisions.",
  },
  {
    item: "Exportable trust artifacts",
    status: "later",
    note: "May ultimately belong more naturally within ANCHOR Trust.",
  },
];

export default function PrivacyPolicyPage() {
  return (
    <AppShell>
      <div className="space-y-6">
        <div>
          <p className="text-sm font-medium text-slate-500">Clinic administration</p>
          <h1 className="text-2xl font-semibold tracking-tight text-slate-900">Privacy &amp; Policy</h1>
          <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-600">
            A clinic-facing summary of ANCHOR’s privacy posture, governance boundaries, and policy administration
            direction. This surface is designed to stay commercially credible and operationally clear without implying
            unsupported controls.
          </p>
        </div>

        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
          {postureItems.map((item) => (
            <Card key={item.label}>
              <div className="flex items-start justify-between gap-3">
                <p className="text-sm font-medium text-slate-500">{item.label}</p>
                <StatusBadge value={item.value} />
              </div>
              <p className="mt-3 text-sm leading-6 text-slate-600">{item.helper}</p>
            </Card>
          ))}
        </div>

        <div className="grid gap-4 xl:grid-cols-[1.25fr_0.75fr]">
          <Card>
            <SectionTitle
              title="Current platform posture"
              description="What this clinic-facing page should communicate clearly today."
            />
            <dl className="mt-4 space-y-4 text-sm">
              <Detail
                label="Privacy model"
                value="Metadata-only accountability surface under current ANCHOR product doctrine."
              />
              <Detail
                label="Stored review data"
                value="Governance metadata, operational traces, policy evidence, and privacy-aware indicators."
              />
              <Detail
                label="Excluded by design"
                value="Raw prompt and output content are intentionally excluded from this operational surface."
              />
              <Detail
                label="Audit expression"
                value="Receipts, governance events, and exports provide clinic-scoped evidence without exposing content."
              />
              <Detail
                label="Commercial framing"
                value="Governance, trust, and learning infrastructure for safe AI use in veterinary clinics."
              />
            </dl>
          </Card>

          <Card>
            <SectionTitle
              title="Quick links"
              description="Jump directly into the strongest current evidence surfaces."
            />
            <div className="mt-4 space-y-3">
              <QuickLink
                href="/receipts"
                title="Receipt viewer"
                description="Inspect governance receipts by request ID."
              />
              <QuickLink
                href="/governance-events"
                title="Governance events"
                description="Review recent clinic-scoped governance activity."
              />
              <QuickLink
                href="/exports"
                title="Metadata-only exports"
                description="Generate bounded CSV exports for operational review."
              />
              <QuickLink
                href="/dashboard"
                title="Dashboard"
                description="Return to the clinic trust-oriented overview."
              />
            </div>
          </Card>
        </div>

        <div className="grid gap-4 xl:grid-cols-2">
          <Card>
            <SectionTitle
              title="Operational guarantees"
              description="The core promises this surface should reinforce for clinic users and leadership."
            />
            <div className="mt-4 space-y-4">
              {guarantees.map((item) => (
                <div key={item.title} className="border-b border-slate-100 pb-4 last:border-b-0 last:pb-0">
                  <h3 className="text-sm font-semibold text-slate-900">{item.title}</h3>
                  <p className="mt-2 text-sm leading-6 text-slate-600">{item.body}</p>
                </div>
              ))}
            </div>
          </Card>

          <Card>
            <SectionTitle
              title="Admin surface readiness"
            description="What is available now versus what may be added in a future update."
            />
            <div className="mt-4 space-y-4">
              {adminReadiness.map((item) => (
                <div
                  key={item.item}
                  className="grid gap-2 border-b border-slate-100 pb-4 last:border-b-0 last:pb-0 md:grid-cols-[1fr_auto]"
                >
                  <div>
                    <p className="text-sm font-semibold text-slate-900">{item.item}</p>
                    <p className="mt-1 text-sm leading-6 text-slate-600">{item.note}</p>
                  </div>
                  <div className="md:text-right">
                    <StatusBadge value={item.status} />
                  </div>
                </div>
              ))}
            </div>
          </Card>
        </div>

        <Card>
          <SectionTitle
            title="Implementation note"
            description="Why this page is intentionally restrained in the current pass."
          />
          <div className="mt-4 space-y-3 text-sm leading-6 text-slate-600">
            <p>
              This page is intentionally positioned as a trustworthy summary surface first, not as an over-claimed admin
              console. The backend already contains the real governance and policy foundations; the next UI pass should
              connect editable controls only where endpoint behavior is verified and institution-grade UX can be
              maintained.
            </p>
            <p>
              That keeps ANCHOR commercially credible: calm, precise, and governance-first rather than pretending to
              expose controls that are not yet fully productized.
            </p>
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
    <div className="grid grid-cols-[150px_1fr] gap-4 border-b border-slate-100 pb-4 last:border-b-0 last:pb-0">
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
      className="block rounded-2xl border border-slate-200 px-4 py-4 transition hover:border-slate-300 hover:bg-slate-50"
    >
      <p className="text-sm font-semibold text-slate-900">{title}</p>
      <p className="mt-1 text-sm leading-6 text-slate-600">{description}</p>
    </Link>
  );
}
