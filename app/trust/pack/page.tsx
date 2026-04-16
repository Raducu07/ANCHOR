"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { AppShell } from "@/components/shell/AppShell";
import { getTrustPack } from "@/lib/trust";
import type { TrustPackResponse } from "@/lib/types";

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

function getSectionEyebrow(sectionId: string) {
  const normalized = (sectionId || "").trim().toLowerCase();

  // Hide the awkward "COVER" label in the printed/exported artifact.
  if (normalized === "cover") return null;

  return sectionId.replaceAll("_", " ");
}

export default function TrustPackPage() {
  const [data, setData] = useState<TrustPackResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [copying, setCopying] = useState(false);
  const [copied, setCopied] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function load(showRefreshing = false) {
    try {
      if (showRefreshing) {
        setRefreshing(true);
      } else {
        setLoading(true);
      }
      setError(null);
      const response = await getTrustPack();
      setData(response);
    } catch (err: any) {
      setError(err?.message || "Failed to load trust pack.");
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }

  useEffect(() => {
    load();
  }, []);

  async function handleCopyLink() {
    try {
      setCopying(true);
      await navigator.clipboard.writeText(window.location.href);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1600);
    } catch {
      setCopied(false);
    } finally {
      setCopying(false);
    }
  }

  function handlePrint() {
    if (typeof window !== "undefined") {
      const clinicName = data?.pack?.clinic_name?.trim();
      document.title = clinicName
        ? `ANCHOR Trust Pack - ${clinicName}`
        : "ANCHOR Trust Pack";
      window.print();
    }
  }

  const trustStateTone = useMemo(() => {
    switch (data?.pack?.trust_state) {
      case "green":
        return "bg-emerald-100 text-emerald-800 border-emerald-200";
      case "yellow":
        return "bg-amber-100 text-amber-800 border-amber-200";
      default:
        return "bg-rose-100 text-rose-800 border-rose-200";
    }
  }, [data?.pack?.trust_state]);

  const evidenceBasis = useMemo(() => {
    if (!data) return [];

    const packAny = data.pack as any;
    if (Array.isArray(packAny?.evidence_basis) && packAny.evidence_basis.length > 0) {
      return packAny.evidence_basis as string[];
    }

    return [
      `Generated from ANCHOR metadata-only trust signals at ${formatDate(data.pack.generated_at)}.`,
      `Evidence window: ${data.pack.evidence_window.hours} hours.`,
      `Governance policy version: v${data.snapshot.governance.policy_version}.`,
      `Operational signal quality: ${titleCase(data.snapshot.operations.signal_quality)}.`,
      `Recent activity volume: ${data.snapshot.operations.events_24h} events in the last 24 hours.`,
      `Top operating mode in the last 24 hours: ${data.snapshot.operations.top_mode_24h ?? "—"}.`,
      "Trust Pack content is derived from governance, privacy, tenancy, operations, and learning metadata rather than stored raw prompts or model outputs.",
    ];
  }, [data]);

  const limitations = useMemo(() => {
    if (!data) return [];

    const packAny = data.pack as any;
    if (Array.isArray(packAny?.limitations) && packAny.limitations.length > 0) {
      return packAny.limitations as string[];
    }

    const items = [
      "This artifact is a leadership-facing governance and trust summary, not a clinical decision-support output.",
      "Evidence may reflect a light-signal operating state when recent event volumes are limited.",
      "The Trust Pack is derived from metadata-only accountability signals and does not reproduce raw prompts or outputs.",
      "Point-in-time trust posture should be interpreted alongside the evidence window shown on this artifact.",
    ];

    if ((data.snapshot.operations.events_24h ?? 0) <= 0) {
      items.push(
        "No recent 24-hour activity was detected, so current operational signals should be treated as structurally limited."
      );
    }

    if (!data.snapshot.operations.top_mode_24h) {
      items.push(
        "No dominant operating mode was detected in the current evidence window."
      );
    }

    return items;
  }, [data]);

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

            .trust-pack-root {
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

        <div className="trust-pack-root mx-auto max-w-7xl space-y-6 p-6">
          <div className="no-print flex items-start justify-between gap-4">
            <div>
              <p className="text-sm font-medium uppercase tracking-wide text-slate-500">
                Trust
              </p>
              <h1 className="text-2xl font-semibold text-slate-900">Trust Pack</h1>
              <p className="mt-2 max-w-3xl text-sm text-slate-600">
                Leadership-facing trust artifact generated from ANCHOR’s metadata-only
                governance, privacy, tenancy, operations, and learning evidence.
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
                onClick={handleCopyLink}
                className="rounded-xl border border-slate-300 px-4 py-2 text-sm font-medium text-slate-700 hover:bg-slate-50"
                disabled={copying}
              >
                {copied ? "Link copied" : copying ? "Copying..." : "Copy link"}
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
            <div className="print-surface rounded-2xl border border-slate-200 bg-white p-6 text-sm text-slate-600 shadow-sm">
              Loading trust pack...
            </div>
          ) : error ? (
            <div className="print-surface rounded-2xl border border-rose-200 bg-rose-50 p-6 text-sm text-rose-700 shadow-sm">
              {error}
            </div>
          ) : data ? (
            <>
              <section className="print-cover print-force-break-after print-surface print-avoid-break rounded-3xl border border-slate-200 bg-white p-8 shadow-sm">
                <div className="flex flex-wrap items-start justify-between gap-4">
                  <div className="space-y-3">
                    <p className="text-xs font-semibold uppercase tracking-[0.18em] text-slate-500">
                      ANCHOR Trust
                    </p>
                    <h2 className="max-w-4xl text-3xl font-semibold tracking-tight text-slate-900">
                      Leadership Trust Pack
                    </h2>
                    <p className="max-w-3xl text-base leading-7 text-slate-600">
                      Governance, trust, and learning infrastructure for safe AI use in
                      veterinary clinics.
                    </p>
                  </div>

                  <span
                    className={`rounded-full border px-3 py-1 text-xs font-medium ${trustStateTone}`}
                  >
                    Trust state: {data.pack.trust_state}
                  </span>
                </div>

                <div className="mt-8 grid gap-4 md:grid-cols-2 xl:grid-cols-4">
                  <div className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
                    <div className="text-xs uppercase tracking-wide text-slate-500">
                      Clinic
                    </div>
                    <div className="mt-2 text-sm font-semibold text-slate-900">
                      {data.pack.clinic_name}
                    </div>
                  </div>

                  <div className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
                    <div className="text-xs uppercase tracking-wide text-slate-500">
                      Generated
                    </div>
                    <div className="mt-2 text-sm font-semibold text-slate-900">
                      {formatDate(data.pack.generated_at)}
                    </div>
                  </div>

                  <div className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
                    <div className="text-xs uppercase tracking-wide text-slate-500">
                      Evidence window
                    </div>
                    <div className="mt-2 text-sm font-semibold text-slate-900">
                      {data.pack.evidence_window.hours}h
                    </div>
                  </div>

                  <div className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
                    <div className="text-xs uppercase tracking-wide text-slate-500">
                      Policy version
                    </div>
                    <div className="mt-2 text-sm font-semibold text-slate-900">
                      v{data.snapshot.governance.policy_version}
                    </div>
                  </div>
                </div>

                <div className="mt-8 grid gap-6 xl:grid-cols-[1.35fr_minmax(320px,0.65fr)]">
                  <div className="rounded-2xl border border-slate-200 bg-white p-6">
                    <p className="text-xs font-medium uppercase tracking-wide text-slate-500">
                      Executive summary
                    </p>
                    <h3 className="mt-2 text-lg font-semibold text-slate-900">
                      Governance-first, metadata-only trust artifact
                    </h3>
                    <p className="mt-3 text-sm leading-7 text-slate-700">
                      This Trust Pack summarises current ANCHOR trust posture using
                      metadata-only governance, privacy-aware controls, tenancy assurance,
                      operations signals, and learning-linked evidence. It is designed as a
                      leadership-facing artifact that can be reviewed, shared, and exported
                      without exposing underlying prompt or output content.
                    </p>
                  </div>

                  <div className="rounded-2xl border border-slate-200 bg-slate-50 p-6">
                    <p className="text-xs font-medium uppercase tracking-wide text-slate-500">
                      Current signal quality
                    </p>
                    <h3 className="mt-2 text-lg font-semibold text-slate-900">
                      Operational context
                    </h3>
                    <div className="mt-4 space-y-3">
                      <div className="rounded-xl border border-slate-200 bg-white p-4">
                        <div className="text-xs uppercase tracking-wide text-slate-500">
                          Signal quality
                        </div>
                        <div className="mt-1 text-sm font-medium capitalize text-slate-900">
                          {data.snapshot.operations.signal_quality}
                        </div>
                      </div>

                      <div className="rounded-xl border border-slate-200 bg-white p-4">
                        <div className="text-xs uppercase tracking-wide text-slate-500">
                          Events (24h)
                        </div>
                        <div className="mt-1 text-sm font-medium text-slate-900">
                          {data.snapshot.operations.events_24h}
                        </div>
                      </div>

                      <div className="rounded-xl border border-slate-200 bg-white p-4">
                        <div className="text-xs uppercase tracking-wide text-slate-500">
                          Top mode (24h)
                        </div>
                        <div className="mt-1 text-sm font-medium text-slate-900">
                          {data.snapshot.operations.top_mode_24h ?? "—"}
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              </section>

              <div className="no-print flex flex-wrap gap-3">
                <Link
                  href="/trust/profile"
                  className="rounded-xl bg-slate-900 px-4 py-2 text-sm font-medium text-white hover:bg-slate-800"
                >
                  Back to trust profile
                </Link>
                <Link
                  href="/trust/posture"
                  className="rounded-xl border border-slate-300 px-4 py-2 text-sm font-medium text-slate-700 hover:bg-slate-50"
                >
                  View governance posture
                </Link>
                <Link
                  href="/trust/materials"
                  className="rounded-xl border border-slate-300 px-4 py-2 text-sm font-medium text-slate-700 hover:bg-slate-50"
                >
                  View trust materials
                </Link>
              </div>

              <div className="grid gap-6">
                {data.pack.sections.map((section) => {
                  const eyebrow = getSectionEyebrow(section.id);

                  return (
                    <section
                      key={section.id}
                      className="print-surface print-avoid-break rounded-2xl border border-slate-200 bg-white p-6 shadow-sm"
                    >
                      {eyebrow ? (
                        <div className="text-xs font-medium uppercase tracking-wide text-slate-500">
                          {eyebrow}
                        </div>
                      ) : null}

                      <h2 className="mt-2 text-lg font-semibold text-slate-900">
                        {section.title}
                      </h2>

                      <p className="mt-3 text-sm leading-7 text-slate-700">
                        {section.body}
                      </p>

                      <div className="mt-4 grid gap-3">
                        {section.bullets.map((bullet, idx) => (
                          <div
                            key={idx}
                            className="rounded-xl border border-slate-200 bg-slate-50 px-4 py-3"
                          >
                            <p className="text-sm leading-6 text-slate-700">{bullet}</p>
                          </div>
                        ))}
                      </div>
                    </section>
                  );
                })}

                <section className="print-surface print-avoid-break rounded-2xl border border-slate-200 bg-white p-6 shadow-sm">
                  <div className="text-xs font-medium uppercase tracking-wide text-slate-500">
                    Evidence basis
                  </div>
                  <h2 className="mt-2 text-lg font-semibold text-slate-900">
                    How this artifact was derived
                  </h2>

                  <div className="mt-4 grid gap-3">
                    {evidenceBasis.map((item, idx) => (
                      <div
                        key={idx}
                        className="rounded-xl border border-slate-200 bg-slate-50 px-4 py-3"
                      >
                        <p className="text-sm leading-6 text-slate-700">{item}</p>
                      </div>
                    ))}
                  </div>
                </section>

                <section className="print-surface print-avoid-break rounded-2xl border border-slate-200 bg-white p-6 shadow-sm">
                  <div className="text-xs font-medium uppercase tracking-wide text-slate-500">
                    Limitations
                  </div>
                  <h2 className="mt-2 text-lg font-semibold text-slate-900">
                    Interpretation boundaries
                  </h2>

                  <div className="mt-4 grid gap-3">
                    {limitations.map((item, idx) => (
                      <div
                        key={idx}
                        className="rounded-xl border border-slate-200 bg-slate-50 px-4 py-3"
                      >
                        <p className="text-sm leading-6 text-slate-700">{item}</p>
                      </div>
                    ))}
                  </div>
                </section>

                <section className="print-surface print-avoid-break rounded-2xl border border-slate-200 bg-slate-50 p-6 shadow-sm">
                  <div className="text-xs font-medium uppercase tracking-wide text-slate-500">
                    Artifact notes
                  </div>
                  <h2 className="mt-2 text-lg font-semibold text-slate-900">
                    Intended use
                  </h2>
                  <p className="mt-3 text-sm leading-7 text-slate-700">
                    This Trust Pack is intended for leadership review, trust communication,
                    internal governance conversations, and print or PDF export. It is not a
                    clinical AI output and should not be interpreted as diagnosis, treatment
                    guidance, or patient-specific decision support.
                  </p>
                </section>
              </div>
            </>
          ) : null}
        </div>
      </>
    </AppShell>
  );
}
