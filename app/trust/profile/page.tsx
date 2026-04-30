"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { AppShell } from "@/components/shell/AppShell";
import { getTrustProfile } from "@/lib/trust";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type AnyRecord = Record<string, any>;

function sanitizeClinicName(value: unknown, fallback = "Your clinic") {
  const text = typeof value === "string" ? value.trim() : "";
  if (!text) return fallback;
  if (text === "M4 Portal Test Clinic") return fallback;
  return text;
}

function formatDate(value?: string) {
  if (!value) return "—";
  try {
    return new Date(value).toLocaleString();
  } catch {
    return value;
  }
}

function titleCase(value?: string | null) {
  if (!value) return "—";
  return value
    .replaceAll("_", " ")
    .replace(/\b\w/g, (m) => m.toUpperCase());
}

function boolLabel(value: unknown, truthy = "Active", falsy = "Not active") {
  return value ? truthy : falsy;
}

function toneForTrustState(value?: string | null) {
  switch ((value || "").toLowerCase()) {
    case "green":
      return "bg-emerald-100 text-emerald-800 border-emerald-200";
    case "yellow":
      return "bg-amber-100 text-amber-800 border-amber-200";
    default:
      return "bg-rose-100 text-rose-800 border-rose-200";
  }
}

function openInNewTab(path: string) {
  if (typeof window !== "undefined") {
    window.open(path, "_blank", "noopener,noreferrer");
  }
}

function normalizeLearningValue(value: unknown): string {
  if (value == null) return "Governance receipts and policy explainers.";

  if (typeof value === "string") {
    const trimmed = value.trim();
    return trimmed || "Governance receipts and policy explainers.";
  }

  if (Array.isArray(value)) {
    const items = value
      .map((item) => normalizeLearningValue(item))
      .filter(Boolean)
      .filter((item) => item !== "Governance receipts and policy explainers.");

    return items.length > 0
      ? items.join("; ")
      : "Governance receipts and policy explainers.";
  }

  if (typeof value === "object") {
    const record = value as Record<string, unknown>;

    const candidates = [
      record.title,
      record.label,
      record.name,
      record.summary,
      record.text,
      record.recommended_learning,
      record.recommended_focus,
      record.focus,
    ];

    for (const candidate of candidates) {
      if (typeof candidate === "string" && candidate.trim()) {
        return candidate.trim();
      }
    }

    return "Governance receipts and policy explainers.";
  }

  return String(value);
}

export default function TrustProfilePage() {
  const [data, setData] = useState<AnyRecord | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function load(showRefreshing = false) {
    try {
      if (showRefreshing) {
        setRefreshing(true);
      } else {
        setLoading(true);
      }

      setError(null);
      const response = await getTrustProfile();
      setData((response as AnyRecord) ?? null);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to load trust profile.");
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }

  useEffect(() => {
    load();
  }, []);

  const view = useMemo(() => {
    const root = data ?? {};
    const profile = (root.profile ?? root.trust_profile ?? root) as AnyRecord;
    const snapshot = (root.snapshot ?? profile.snapshot ?? {}) as AnyRecord;

    const clinic = (profile.clinic ?? snapshot.clinic ?? {}) as AnyRecord;
    const governance = (profile.governance ?? snapshot.governance ?? {}) as AnyRecord;
    const operations = (profile.operations ?? snapshot.operations ?? {}) as AnyRecord;
    const tenancy = (profile.tenancy ?? snapshot.tenancy ?? {}) as AnyRecord;
    const privacy = (profile.privacy ?? snapshot.privacy ?? {}) as AnyRecord;
    const learning = (profile.learning ?? snapshot.learning ?? {}) as AnyRecord;

    const clinicName = sanitizeClinicName(
      clinic.clinic_name ??
        clinic.name ??
        profile.clinic_name ??
        root.clinic_name,
      "Your clinic"
    );

    const trustState =
      operations.trust_state ??
      profile.trust_state ??
      snapshot.trust_state ??
      root.trust_state ??
      "—";

    const postureScore =
      profile.posture_score ??
      root.posture_score ??
      operations.posture_score ??
      snapshot.posture_score ??
      "—";

    const policyVersion =
      governance.policy_version ??
      profile.policy_version ??
      root.policy_version ??
      "—";

    const evidenceHours =
      snapshot?.evidence_window?.hours ??
      profile?.evidence_window?.hours ??
      root?.evidence_window?.hours ??
      "—";

    const generatedAt =
      profile.generated_at ??
      root.generated_at ??
      snapshot.generated_at ??
      operations.generated_at;

    const signalQuality =
      operations.signal_quality ??
      profile.signal_quality ??
      root.signal_quality ??
      "—";

    const headline =
      profile.headline ??
      root.headline ??
      "Trust Center";

    const summary =
      profile.summary ??
      root.summary ??
      "Governance-first trust surface for leadership review, evidence interpretation, and exportable trust artifacts.";

    const rawRecommendedLearning =
      learning.recommended_learning ??
      learning.recommended_focus ??
      learning.recommended_learning_focus ??
      profile.recommended_learning;

    const recommendedLearning = normalizeLearningValue(rawRecommendedLearning);

    return {
      clinicName,
      trustState,
      postureScore,
      policyVersion,
      evidenceHours,
      generatedAt,
      signalQuality,
      headline,
      summary,
      governance,
      operations,
      tenancy,
      privacy,
      learning,
      recommendedLearning,
    };
  }, [data]);

  function handlePrint() {
    if (typeof window !== "undefined") {
      const clinicName = view.clinicName?.trim();
      document.title = clinicName
        ? `ANCHOR Trust Center - ${clinicName}`
        : "ANCHOR Trust Center";
      window.print();
    }
  }

  const trustStateTone = useMemo(
    () => toneForTrustState(String(view.trustState)),
    [view.trustState]
  );

  const artifactCards = [
    {
      title: "Trust Profile",
      subtitle: "Executive front door",
      body:
        "High-level overview of current trust posture, evidence basis, communication boundaries, and next-step artifact access.",
      audience: "Leadership",
      href: "/trust/profile",
      cta: "Current page",
      primary: true,
    },
    {
      title: "Governance Posture",
      subtitle: "Controls and signal interpretation",
      body:
        "Detailed explanation of governance posture, signal quality, controls, and operating assumptions behind the current trust state.",
      audience: "Leadership / internal review",
      href: "/trust/posture",
      cta: "View governance posture",
    },
    {
      title: "Trust Pack",
      subtitle: "Printable leadership artifact",
      body:
        "Board-shareable trust summary designed for print / Save-as-PDF, combining posture, operational context, evidence basis, and limitations.",
      audience: "Leadership / external review",
      href: "/trust/pack",
      cta: "Open Trust Pack",
    },
    {
      title: "Trust Materials",
      subtitle: "Reusable language surface",
      body:
        "Reusable trust language for procurement, website copy, leadership updates, and other external trust communications.",
      audience: "Procurement / website / leadership",
      href: "/trust/materials",
      cta: "Open Trust Materials",
    },
  ];

  const bundleCards = [
    {
      title: "Leadership Review Bundle",
      audience: "Leadership / owners / internal sponsors",
      body:
        "Use this bundle when a decision-maker needs a concise trust overview plus a shareable artifact for review or circulation.",
      whenToUse:
        "Best for board-style review, clinic leadership alignment, or internal trust briefings.",
      artifacts: ["Trust Center", "Trust Pack"],
      actions: [
        { label: "Open Trust Center", href: "/trust/profile", primary: true },
        { label: "Open Trust Pack", href: "/trust/pack" },
      ],
    },
    {
      title: "External Trust Communication Bundle",
      audience: "Procurement / website / partner communication",
      body:
        "Use this bundle when you need reusable wording and a supporting artifact for external trust conversations.",
      whenToUse:
        "Best for procurement responses, partner conversations, website copy, and stakeholder trust communication.",
      artifacts: ["Trust Materials", "Trust Pack"],
      actions: [
        { label: "Open Trust Materials", href: "/trust/materials", primary: true },
        { label: "Open Trust Pack", href: "/trust/pack" },
      ],
    },
    {
      title: "Governance Evidence Review Bundle",
      audience: "Internal review / governance leads",
      body:
        "Use this bundle when a reviewer needs to understand how the current trust posture is supported by controls, signals, and evidence assumptions.",
      whenToUse:
        "Best for internal governance review, implementation confidence, and deeper trust interpretation.",
      artifacts: ["Governance Posture", "Trust Center"],
      actions: [
        { label: "Open Governance Posture", href: "/trust/posture", primary: true },
        { label: "Open Trust Center", href: "/trust/profile" },
      ],
    },
  ];

  return (
    <AppShell>
      <>
        <style jsx global>{`
          @media print {
            html,
            body {
              background: #ffffff !important;
            }

            aside,
            nav,
            header,
            .no-print,
            .print-hide,
            [class*="sidebar"],
            [class*="topbar"] {
              display: none !important;
            }

            main,
            [role="main"] {
              width: 100% !important;
              max-width: 100% !important;
              margin: 0 !important;
              padding: 0 !important;
            }

            .trust-profile-root {
              max-width: 100% !important;
              padding: 0 !important;
              margin: 0 !important;
            }

            .print-surface {
              border: 1px solid #e2e8f0 !important;
              box-shadow: none !important;
              background: #ffffff !important;
            }

            .print-avoid-break {
              break-inside: avoid;
              page-break-inside: avoid;
            }

            .print-force-break-after {
              break-after: page;
              page-break-after: always;
            }

            .print-cover {
              min-height: 0;
              padding-top: 0;
            }

            a {
              color: inherit !important;
              text-decoration: none !important;
            }

            @page {
              size: A4;
              margin: 14mm;
            }
          }
        `}</style>

        <div className="trust-profile-root mx-auto max-w-7xl space-y-6 p-6">
          <div className="no-print flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
            <div className="min-w-0">
              <p className="text-sm font-medium uppercase tracking-wide text-slate-500">
                Trust
              </p>
              <h1 className="text-2xl font-semibold text-slate-900">
                {view.headline}
              </h1>
              <p className="mt-2 max-w-3xl text-sm text-slate-600">
                {view.summary}
              </p>
              <p className="mt-2 text-xs text-slate-500">
                For the cleanest PDF export, open Print settings and disable browser
                headers and footers.
              </p>
            </div>

            <div className="flex flex-wrap items-center gap-3">
              <button
                onClick={handlePrint}
                className="rounded-xl bg-slate-900 px-4 py-2 text-sm font-medium text-white hover:bg-slate-800"
                disabled={loading || !!error}
              >
                Print / Save PDF
              </button>

              <button
                onClick={() => load(true)}
                className="rounded-xl border border-slate-300 px-4 py-2 text-sm font-medium text-slate-700 hover:bg-slate-50"
                disabled={refreshing}
              >
                {refreshing ? "Refreshing..." : "Refresh"}
              </button>
            </div>
          </div>

          {loading ? (
            <div className="rounded-2xl border border-slate-200 bg-white p-6 text-sm text-slate-600 shadow-sm">
              Loading trust profile...
            </div>
          ) : error ? (
            <div className="rounded-2xl border border-rose-200 bg-rose-50 p-6 text-sm text-rose-700 shadow-sm">
              {error}
            </div>
          ) : (
            <>
              <section className="print-cover print-force-break-after print-surface print-avoid-break rounded-3xl border border-slate-200 bg-white p-8 shadow-sm">
                <div className="flex flex-wrap items-start justify-between gap-4">
                  <div className="space-y-3">
                    <p className="text-xs font-semibold uppercase tracking-[0.18em] text-slate-500">
                      ANCHOR Trust
                    </p>
                    <h2 className="max-w-4xl text-3xl font-semibold tracking-tight text-slate-900">
                      Trust Center
                    </h2>
                    <p className="max-w-3xl text-base leading-7 text-slate-600">
                      Governance-first trust surface for leadership review, evidence
                      interpretation, and exportable trust artifacts.
                    </p>
                  </div>

                  <span
                    className={`rounded-full border px-3 py-1 text-xs font-medium ${trustStateTone}`}
                  >
                    Trust state: {String(view.trustState)}
                  </span>
                </div>

                <div className="mt-8 grid gap-4 md:grid-cols-2 xl:grid-cols-5">
                  <div className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
                    <div className="text-xs uppercase tracking-wide text-slate-500">
                      Clinic
                    </div>
                    <div className="mt-2 text-sm font-semibold text-slate-900">
                      {view.clinicName}
                    </div>
                  </div>

                  <div className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
                    <div className="text-xs uppercase tracking-wide text-slate-500">
                      Trust state
                    </div>
                    <div className="mt-2 text-sm font-semibold text-slate-900">
                      {String(view.trustState)}
                    </div>
                  </div>

                  <div className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
                    <div className="text-xs uppercase tracking-wide text-slate-500">
                      Policy version
                    </div>
                    <div className="mt-2 text-sm font-semibold text-slate-900">
                      v{String(view.policyVersion)}
                    </div>
                  </div>

                  <div className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
                    <div className="text-xs uppercase tracking-wide text-slate-500">
                      Evidence window
                    </div>
                    <div className="mt-2 text-sm font-semibold text-slate-900">
                      {String(view.evidenceHours)}h
                    </div>
                  </div>

                  <div className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
                    <div className="text-xs uppercase tracking-wide text-slate-500">
                      Generated
                    </div>
                    <div className="mt-2 text-sm font-semibold text-slate-900">
                      {formatDate(view.generatedAt)}
                    </div>
                  </div>
                </div>

                <div className="mt-8 grid gap-6 xl:grid-cols-[1.35fr_minmax(320px,0.65fr)]">
                  <div className="rounded-2xl border border-slate-200 bg-white p-6">
                    <p className="text-xs font-medium uppercase tracking-wide text-slate-500">
                      Executive summary
                    </p>
                    <h3 className="mt-2 text-lg font-semibold text-slate-900">
                      Leadership-facing trust front door
                    </h3>
                    <p className="mt-3 text-sm leading-7 text-slate-700">
                      This Trust Center packages ANCHOR’s governance-first trust layer
                      into a leadership-facing overview. It brings together current trust
                      posture, evidence basis, communication boundaries, and access to
                      exportable trust artifacts without reframing ANCHOR as a clinical
                      decision-making product.
                    </p>
                  </div>

                  <div className="rounded-2xl border border-slate-200 bg-slate-50 p-6">
                    <p className="text-xs font-medium uppercase tracking-wide text-slate-500">
                      Communication boundaries
                    </p>
                    <h3 className="mt-2 text-lg font-semibold text-slate-900">
                      Framing guardrails
                    </h3>
                    <div className="mt-4 space-y-3">
                      {[
                        "Governance-first and non-clinical.",
                        "Operational trust surface, not legal certification.",
                        "Metadata-only accountability, not raw prompt/output review.",
                        "Clinic-scoped review and hard tenancy remain core assumptions.",
                      ].map((item, idx) => (
                        <div
                          key={idx}
                          className="rounded-xl border border-slate-200 bg-white p-4"
                        >
                          <p className="text-sm leading-6 text-slate-700">{item}</p>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              </section>

              <section className="no-print print-surface print-avoid-break rounded-3xl border border-slate-200 bg-white p-6 shadow-sm">
                <div className="flex flex-wrap items-start justify-between gap-4">
                  <div>
                    <p className="text-xs font-medium uppercase tracking-wide text-slate-500">
                      Executive trust overview
                    </p>
                    <h2 className="mt-2 text-xl font-semibold text-slate-900">
                      {view.clinicName}
                    </h2>
                    <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-600">
                      ANCHOR provides governance, trust, and learning infrastructure for
                      safe AI use in veterinary clinics, with metadata-only accountability,
                      clinic-scoped review, and leadership-facing trust surfaces.
                    </p>
                  </div>

                  <span
                    className={`rounded-full border px-3 py-1 text-xs font-medium ${trustStateTone}`}
                  >
                    Trust state: {String(view.trustState)}
                  </span>
                </div>

                <div className="mt-6 grid gap-4 sm:grid-cols-2 xl:grid-cols-5">
                  <div className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
                    <div className="text-xs uppercase tracking-wide text-slate-500">
                      Trust state
                    </div>
                    <div className="mt-2 text-sm font-semibold text-slate-900">
                      {String(view.trustState)}
                    </div>
                  </div>

                  <div className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
                    <div className="text-xs uppercase tracking-wide text-slate-500">
                      Posture score
                    </div>
                    <div className="mt-2 text-sm font-semibold text-slate-900">
                      {String(view.postureScore)}
                    </div>
                  </div>

                  <div className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
                    <div className="text-xs uppercase tracking-wide text-slate-500">
                      Policy version
                    </div>
                    <div className="mt-2 text-sm font-semibold text-slate-900">
                      v{String(view.policyVersion)}
                    </div>
                  </div>

                  <div className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
                    <div className="text-xs uppercase tracking-wide text-slate-500">
                      Evidence window
                    </div>
                    <div className="mt-2 text-sm font-semibold text-slate-900">
                      {String(view.evidenceHours)}h
                    </div>
                  </div>

                  <div className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
                    <div className="text-xs uppercase tracking-wide text-slate-500">
                      Generated
                    </div>
                    <div className="mt-2 text-sm font-semibold text-slate-900">
                      {formatDate(view.generatedAt)}
                    </div>
                  </div>
                </div>
              </section>

              <section className="grid gap-6 xl:grid-cols-4">
                {artifactCards.map((card) => (
                  <div
                    key={card.title}
                    className="print-surface print-avoid-break rounded-2xl border border-slate-200 bg-white p-6 shadow-sm flex h-full flex-col"
                  >
                    <div className="space-y-1.5">
                      <div className="text-xs font-medium uppercase tracking-wide text-slate-500">
                        {card.subtitle}
                      </div>
                      <span className="rounded-full border border-slate-200 bg-slate-50 px-2.5 py-1 text-[11px] font-medium text-slate-700 whitespace-nowrap">
                        {card.audience}
                      </span>
                    </div>

                    <h3 className="mt-3 text-lg font-semibold text-slate-900">
                      {card.title}
                    </h3>
                    <p className="mt-3 text-sm leading-6 text-slate-700">
                      {card.body}
                    </p>

                    <div className="no-print mt-auto pt-5">
                      {card.primary ? (
                        <span className="inline-flex rounded-xl border border-slate-300 px-4 py-2 text-sm font-medium text-slate-500">
                          {card.cta}
                        </span>
                      ) : (
                        <Link
                          href={card.href}
                          className="inline-flex rounded-xl border border-slate-300 px-4 py-2 text-sm font-medium text-slate-700 hover:bg-slate-50"
                        >
                          {card.cta}
                        </Link>
                      )}
                    </div>
                  </div>
                ))}
              </section>

              <section className="print-surface print-avoid-break rounded-2xl border border-slate-200 bg-white p-6 shadow-sm">
                <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
                  <div>
                    <p className="text-xs font-medium uppercase tracking-wide text-slate-500">
                      Trust Bundle
                    </p>
                    <h2 className="mt-2 text-lg font-semibold text-slate-900">
                      Choose the right bundle for the conversation
                    </h2>
                    <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-600">
                      These bundles group the trust artifacts into clearer handoff paths
                      for leadership review, external trust communication, and deeper
                      governance evidence review.
                    </p>
                  </div>
                </div>

                <div className="mt-6 grid gap-6 xl:grid-cols-3">
                  {bundleCards.map((bundle) => (
                    <div
                      key={bundle.title}
                      className="rounded-2xl border border-slate-200 bg-slate-50 p-6 flex h-full flex-col"
                    >
                      <div className="space-y-1.5">
                        <p className="text-xs font-medium uppercase tracking-wide text-slate-500">
                          Bundle
                        </p>
                        <span className="rounded-full border border-slate-200 bg-white px-2.5 py-1 text-[11px] font-medium text-slate-700 whitespace-nowrap">
                          {bundle.audience}
                        </span>
                      </div>

                      <h3 className="mt-3 text-lg font-semibold text-slate-900">
                        {bundle.title}
                      </h3>

                      <div className="mt-3 flex flex-1 flex-col gap-4">
                        <p className="text-sm leading-6 text-slate-700">
                          {bundle.body}
                        </p>

                        <div>
                          <div className="text-xs font-medium uppercase tracking-wide text-slate-500">
                            Included artifacts
                          </div>
                          <div className="mt-2 flex flex-wrap gap-2">
                            {bundle.artifacts.map((artifact) => (
                              <span
                                key={artifact}
                                className="rounded-full border border-slate-200 bg-white px-2.5 py-1 text-[11px] font-medium text-slate-700"
                              >
                                {artifact}
                              </span>
                            ))}
                          </div>
                        </div>

                        <div>
                          <div className="text-xs font-medium uppercase tracking-wide text-slate-500">
                            When to use
                          </div>
                          <p className="mt-2 text-sm leading-6 text-slate-700">
                            {bundle.whenToUse}
                          </p>
                        </div>
                      </div>

                      <div className="no-print mt-auto pt-6 flex flex-col items-start gap-3">
                        {bundle.actions.map((action) =>
                          action.primary ? (
                            <Link
                              key={action.label}
                              href={action.href}
                              className="rounded-xl bg-slate-900 px-4 py-2 text-sm font-medium text-white hover:bg-slate-800"
                            >
                              {action.label}
                            </Link>
                          ) : (
                            <Link
                              key={action.label}
                              href={action.href}
                              className="rounded-xl border border-slate-300 px-4 py-2 text-sm font-medium text-slate-700 hover:bg-slate-50"
                            >
                              {action.label}
                            </Link>
                          )
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </section>

              <section className="grid gap-6 xl:grid-cols-[1.2fr_minmax(320px,0.8fr)]">
                <div className="print-surface print-avoid-break rounded-2xl border border-slate-200 bg-white p-6 shadow-sm">
                  <p className="text-xs font-medium uppercase tracking-wide text-slate-500">
                    Evidence basis
                  </p>
                  <h2 className="mt-2 text-lg font-semibold text-slate-900">
                    What the current trust view is based on
                  </h2>

                  <div className="mt-4 grid gap-4 sm:grid-cols-2">
                    <div className="rounded-xl border border-slate-200 bg-slate-50 p-4">
                      <div className="text-xs text-slate-500">
                        Metadata-only accountability
                      </div>
                      <div className="mt-1 text-sm font-medium text-slate-900">
                        {boolLabel(
                          view.governance.metadata_only_accountability,
                          "Active",
                          "Not active"
                        )}
                      </div>
                    </div>

                    <div className="rounded-xl border border-slate-200 bg-slate-50 p-4">
                      <div className="text-xs text-slate-500">
                        Governance receipts
                      </div>
                      <div className="mt-1 text-sm font-medium text-slate-900">
                        {boolLabel(
                          view.governance.governance_receipts_active,
                          "Active",
                          "Not active"
                        )}
                      </div>
                    </div>

                    <div className="rounded-xl border border-slate-200 bg-slate-50 p-4">
                      <div className="text-xs text-slate-500">Raw content storage</div>
                      <div className="mt-1 text-sm font-medium text-slate-900">
                        {boolLabel(
                          view.governance.stores_raw_content,
                          "Enabled",
                          "Disabled"
                        )}
                      </div>
                    </div>

                    <div className="rounded-xl border border-slate-200 bg-slate-50 p-4">
                      <div className="text-xs text-slate-500">Tenant isolation</div>
                      <div className="mt-1 text-sm font-medium text-slate-900">
                        {boolLabel(view.tenancy.rls_forced, "FORCE RLS", "Not reported")}
                      </div>
                    </div>

                    <div className="rounded-xl border border-slate-200 bg-slate-50 p-4">
                      <div className="text-xs text-slate-500">Signal quality</div>
                      <div className="mt-1 text-sm font-medium text-slate-900">
                        {titleCase(view.signalQuality)}
                      </div>
                    </div>

                    <div className="rounded-xl border border-slate-200 bg-slate-50 p-4">
                      <div className="text-xs text-slate-500">Recommended learning</div>
                      <div className="mt-1 text-sm font-medium text-slate-900">
                        {view.recommendedLearning}
                      </div>
                    </div>
                  </div>
                </div>

                <div className="print-surface print-avoid-break rounded-2xl border border-slate-200 bg-white p-6 shadow-sm">
                  <p className="text-xs font-medium uppercase tracking-wide text-slate-500">
                    Communication boundaries
                  </p>
                  <h2 className="mt-2 text-lg font-semibold text-slate-900">
                    What this trust layer is and is not claiming
                  </h2>

                  <div className="mt-4 space-y-3">
                    {[
                      "ANCHOR is governance-first and remains non-clinical.",
                      "This surface summarises operational trust posture and supporting evidence; it is not a formal certification or legal attestation.",
                      "Trust reporting is derived from metadata-only accountability signals rather than stored raw prompts or outputs.",
                      "Hard multi-tenancy, clinic-scoped review, governance receipts, and privacy-aware controls remain core trust assumptions.",
                      "Trust artifacts are designed to support leadership understanding, procurement communication, and safe AI-use oversight.",
                    ].map((item, idx) => (
                      <div
                        key={idx}
                        className="rounded-xl border border-slate-200 bg-slate-50 p-4"
                      >
                        <p className="text-sm leading-6 text-slate-700">{item}</p>
                      </div>
                    ))}
                  </div>
                </div>
              </section>

              <section className="no-print rounded-2xl border border-slate-200 bg-white p-6 shadow-sm">
                <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
                  <div>
                    <p className="text-xs font-medium uppercase tracking-wide text-slate-500">
                      Quick actions
                    </p>
                    <h2 className="mt-2 text-lg font-semibold text-slate-900">
                      Open the right trust artifact quickly
                    </h2>
                  </div>

                  <div className="flex flex-wrap gap-3">
                    <Link
                      href="/trust/pack"
                      className="rounded-xl bg-slate-900 px-4 py-2 text-sm font-medium text-white hover:bg-slate-800"
                    >
                      Open Trust Pack
                    </Link>

                    <Link
                      href="/trust/materials"
                      className="rounded-xl border border-slate-300 px-4 py-2 text-sm font-medium text-slate-700 hover:bg-slate-50"
                    >
                      Open Trust Materials
                    </Link>

                    <button
                      type="button"
                      onClick={() => openInNewTab("/trust/pack")}
                      className="rounded-xl border border-slate-300 px-4 py-2 text-sm font-medium text-slate-700 hover:bg-slate-50"
                    >
                      Open printable Trust Pack
                    </button>

                    <button
                      type="button"
                      onClick={() => openInNewTab("/trust/materials")}
                      className="rounded-xl border border-slate-300 px-4 py-2 text-sm font-medium text-slate-700 hover:bg-slate-50"
                    >
                      Open printable Trust Materials
                    </button>
                  </div>
                </div>
              </section>
            </>
          )}
        </div>
      </>
    </AppShell>
  );
}




