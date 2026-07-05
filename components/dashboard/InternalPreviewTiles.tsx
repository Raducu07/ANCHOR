"use client";

// Fable roadmap-completion experiment - Slice F8 (Trust/Dashboard
// integration, internal preview).
//
// A single flag-gated dashboard section with one tile per experimental
// surface. Renders null when NEXT_PUBLIC_ANCHOR_INTERNAL_PREVIEW is off
// (the default), so the shipped dashboard is unchanged in every
// deployed environment and no experimental fetch is made.
//
// Each tile fetches independently and soft-fails to an honest
// "unavailable" state - a missing backend surface can never take the
// dashboard down. Nothing here implies public readiness; the section
// is visibly labelled as an internal preview.
//
// The Trust posture page (/trust/posture) is deliberately untouched:
// its Assistant receipt evidence card and counts are a stable
// contract. The sustainability trust summary is surfaced here instead.

import Link from "next/link";
import { useEffect, useState } from "react";
import { Card } from "@/components/ui/Card";
import { InternalPreviewBadge } from "@/components/experiment/InternalPreviewGate";
import { ApiError } from "@/lib/api";
import { INTERNAL_PREVIEW_ENABLED } from "@/lib/internalPreview";
import { getOnboardingChecklist } from "@/lib/portalOnboarding";
import { getMyRenewals } from "@/lib/learnMaturity";
import { getBillingState } from "@/lib/billingFoundations";
import { getSustainabilityTrustSummary } from "@/lib/sustainability";
import { getAmbientSummary } from "@/lib/ambientGovernance";

type TileState =
  | { kind: "loading" }
  | { kind: "unavailable" }
  | { kind: "ready"; headline: string; detail: string };

function formatLabel(value: string) {
  return value.replace(/[_-]+/g, " ");
}

export function InternalPreviewTiles() {
  if (!INTERNAL_PREVIEW_ENABLED) return null;
  return <InternalPreviewTilesContent />;
}

function InternalPreviewTilesContent() {
  return (
    <Card variant="native" className="border-amber-200/80">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <span className="block text-[10px] font-bold uppercase tracking-[0.18em] text-slate-500">
            Internal preview (experiment)
          </span>
          <h2 className="mt-2 text-base font-semibold text-slate-900">
            Gated build-ahead surfaces
          </h2>
          <p className="mt-1 max-w-3xl text-sm leading-6 text-slate-600">
            Experimental governance surfaces built ahead of any launch decision. Internal
            visibility only — nothing here implies public readiness or activation.
          </p>
        </div>
        <InternalPreviewBadge />
      </div>

      <div className="mt-5 grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
        <OnboardingTile />
        <LearningMaturityTile />
        <BillingTile />
        <SustainabilityTile />
        <AmbientTile />
        <ProviderPostureTile />
      </div>
    </Card>
  );
}

function TileShell({
  href,
  title,
  state,
}: {
  href: string;
  title: string;
  state: TileState;
}) {
  return (
    <Link
      href={href}
      className="block rounded-2xl border border-slate-200 bg-slate-50 p-4 transition hover:border-slate-300 hover:bg-white"
    >
      <p className="text-xs font-semibold uppercase tracking-[0.16em] text-slate-500">{title}</p>
      {state.kind === "loading" ? (
        <p className="mt-2 text-sm text-slate-500">Loading…</p>
      ) : state.kind === "unavailable" ? (
        <p className="mt-2 text-sm text-slate-500">
          Unavailable — backend surface not reachable from this environment.
        </p>
      ) : (
        <>
          <p className="mt-2 text-sm font-semibold text-slate-900">{state.headline}</p>
          <p className="mt-1 text-sm leading-6 text-slate-600">{state.detail}</p>
        </>
      )}
    </Link>
  );
}

function OnboardingTile() {
  const [state, setState] = useState<TileState>({ kind: "loading" });

  useEffect(() => {
    let active = true;

    async function load() {
      try {
        const checklist = await getOnboardingChecklist();
        if (!active) return;
        setState({
          kind: "ready",
          headline: `${checklist.completed_count} of ${checklist.total_count} readiness items in place`,
          detail: "Metadata-only readiness checklist and invite lifecycle.",
        });
      } catch {
        if (!active) return;
        setState({ kind: "unavailable" });
      }
    }

    void load();
    return () => {
      active = false;
    };
  }, []);

  return <TileShell href="/settings/onboarding" title="Onboarding readiness" state={state} />;
}

function LearningMaturityTile() {
  const [state, setState] = useState<TileState>({ kind: "loading" });

  useEffect(() => {
    let active = true;

    async function load() {
      try {
        const renewals = await getMyRenewals();
        if (!active) return;
        const dueSoon = renewals.entries.filter((entry) => entry.status === "due_soon").length;
        const overdue = renewals.entries.filter((entry) => entry.status === "overdue").length;
        setState({
          kind: "ready",
          headline: `${renewals.entries.length} module${
            renewals.entries.length === 1 ? "" : "s"
          } with completion evidence`,
          detail:
            dueSoon + overdue > 0
              ? `${dueSoon} refresh due soon · ${overdue} overdue.`
              : "All recorded completions are current.",
        });
      } catch {
        if (!active) return;
        setState({ kind: "unavailable" });
      }
    }

    void load();
    return () => {
      active = false;
    };
  }, []);

  return <TileShell href="/learn/maturity" title="Learning maturity" state={state} />;
}

function BillingTile() {
  const [state, setState] = useState<TileState>({ kind: "loading" });

  useEffect(() => {
    let active = true;

    async function load() {
      try {
        const billing = await getBillingState();
        if (!active) return;
        setState({
          kind: "ready",
          headline: `Activation: ${formatLabel(billing.activation_status)}`,
          detail: `Readiness: ${formatLabel(billing.billing_readiness)} · sandbox-only, no live billing.`,
        });
      } catch {
        if (!active) return;
        setState({ kind: "unavailable" });
      }
    }

    void load();
    return () => {
      active = false;
    };
  }, []);

  return <TileShell href="/settings/billing" title="Billing readiness" state={state} />;
}

function SustainabilityTile() {
  const [state, setState] = useState<TileState>({ kind: "loading" });

  useEffect(() => {
    let active = true;

    async function load() {
      try {
        const summary = await getSustainabilityTrustSummary();
        if (!active) return;
        const evidenceCount =
          summary.energy_reading_count +
          summary.waste_event_count +
          summary.footprint_estimate_count;
        setState({
          kind: "ready",
          headline: `${evidenceCount} evidence record${evidenceCount === 1 ? "" : "s"} · ${
            summary.report_count
          } report${summary.report_count === 1 ? "" : "s"}`,
          detail: summary.reporting_enabled
            ? "Reporting enabled for this clinic. Governance evidence, not a carbon audit."
            : "Reporting not enabled (default). Governance evidence, not a carbon audit.",
        });
      } catch {
        if (!active) return;
        setState({ kind: "unavailable" });
      }
    }

    void load();
    return () => {
      active = false;
    };
  }, []);

  return (
    <TileShell href="/settings/sustainability" title="Sustainability evidence" state={state} />
  );
}

function AmbientTile() {
  const [state, setState] = useState<TileState>({ kind: "loading" });

  useEffect(() => {
    let active = true;

    async function load() {
      try {
        const summary = await getAmbientSummary();
        if (!active) return;
        setState({
          kind: "ready",
          headline: `${summary.pending_review_count} event${
            summary.pending_review_count === 1 ? "" : "s"
          } pending review`,
          detail: "Metadata-only governance shell. No transcripts, no audio, no note content.",
        });
      } catch (err: unknown) {
        if (!active) return;
        if (err instanceof ApiError && err.status === 503) {
          setState({
            kind: "ready",
            headline: "Ingestion disabled",
            detail: "The default posture. Governance shell only — no transcripts, ever.",
          });
        } else {
          setState({ kind: "unavailable" });
        }
      }
    }

    void load();
    return () => {
      active = false;
    };
  }, []);

  return (
    <TileShell href="/settings/ambient-governance" title="Ambient governance" state={state} />
  );
}

function ProviderPostureTile() {
  // Static by design: no portal API exposes provider posture.
  return (
    <TileShell
      href="/settings/provider-posture"
      title="Provider posture"
      state={{
        kind: "ready",
        headline: "Live generation production-off",
        detail:
          "Live path Anthropic-coupled; provider switching disabled. Architected for vendor-neutrality.",
      }}
    />
  );
}
