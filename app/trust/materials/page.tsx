"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { AppShell } from "@/components/shell/AppShell";
import { getTrustMaterials } from "@/lib/trust";
import type { TrustMaterialsResponse } from "@/lib/types";

function formatDate(value?: string) {
  if (!value) return "—";
  try {
    return new Date(value).toLocaleString();
  } catch {
    return value;
  }
}

function formatLabel(value: string) {
  return value.replaceAll("_", " ");
}

function buildMaterialText(item: { title: string; body: string }) {
  return [item.title, "", item.body].join("\n").trim();
}

type MaterialItem = {
  id: string;
  title: string;
  body: string;
};

type AudienceFilter =
  | "All"
  | "Leadership"
  | "Website"
  | "Procurement"
  | "Privacy"
  | "Staff enablement";

const AUDIENCE_OPTIONS: AudienceFilter[] = [
  "All",
  "Leadership",
  "Website",
  "Procurement",
  "Privacy",
  "Staff enablement",
];

function getAudienceTag(item: { id: string; title?: string }) {
  const source = `${item.id || ""} ${item.title || ""}`.trim().toLowerCase();

  if (
    source.includes("short trust") ||
    source.includes("leadership faq") ||
    source.includes("executive") ||
    source.includes("leadership")
  ) {
    return "Leadership" as const;
  }

  if (
    source.includes("website") ||
    source.includes("brochure") ||
    source.includes("web copy")
  ) {
    return "Website" as const;
  }

  if (
    source.includes("procurement") ||
    source.includes("partnership") ||
    source.includes("rfp") ||
    source.includes("vendor")
  ) {
    return "Procurement" as const;
  }

  if (
    source.includes("privacy") ||
    source.includes("data handling") ||
    source.includes("confidentiality")
  ) {
    return "Privacy" as const;
  }

  if (
    source.includes("safe adoption") ||
    source.includes("enablement") ||
    source.includes("staff") ||
    source.includes("learning")
  ) {
    return "Staff enablement" as const;
  }

  if (source.includes("responsible ai operations")) {
    return "Leadership" as const;
  }

  return "Leadership" as const;
}

function getAudienceTagTone(tag: AudienceFilter | "External trust") {
  switch (tag) {
    case "Leadership":
      return "bg-slate-100 text-slate-700 border-slate-200";
    case "Website":
      return "bg-blue-50 text-blue-700 border-blue-200";
    case "Procurement":
      return "bg-violet-50 text-violet-700 border-violet-200";
    case "Privacy":
      return "bg-emerald-50 text-emerald-700 border-emerald-200";
    case "Staff enablement":
      return "bg-amber-50 text-amber-700 border-amber-200";
    default:
      return "bg-slate-50 text-slate-700 border-slate-200";
  }
}

function buildVisibleMaterialsText(
  data: TrustMaterialsResponse,
  items: MaterialItem[],
  selectedAudience: AudienceFilter
) {
  const header = [
    "ANCHOR Trust Materials",
    data.snapshot?.clinic?.clinic_name
      ? `Clinic: ${data.snapshot.clinic.clinic_name}`
      : null,
    data.generated_at ? `Generated: ${formatDate(data.generated_at)}` : null,
    selectedAudience !== "All" ? `Audience: ${selectedAudience}` : null,
    "Reusable trust language for leadership, procurement, website copy, and external trust communications.",
  ]
    .filter(Boolean)
    .join("\n");

  const blocks = items.map((item) => buildMaterialText(item)).join("\n\n---\n\n");

  return `${header}\n\n${blocks}`.trim();
}

export default function TrustMaterialsPage() {
  const [data, setData] = useState<TrustMaterialsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [copyingAll, setCopyingAll] = useState(false);
  const [copiedAll, setCopiedAll] = useState(false);
  const [copyingId, setCopyingId] = useState<string | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [selectedAudience, setSelectedAudience] = useState<AudienceFilter>("All");
  const [error, setError] = useState<string | null>(null);

  async function load(showRefreshing = false) {
    try {
      if (showRefreshing) {
        setRefreshing(true);
      } else {
        setLoading(true);
      }
      setError(null);
      const response = await getTrustMaterials();
      setData(response);
    } catch (err: any) {
      setError(err?.message || "Failed to load trust materials.");
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }

  useEffect(() => {
    load();
  }, []);

  function handlePrint() {
    if (typeof window !== "undefined") {
      const clinicName = data?.snapshot?.clinic?.clinic_name?.trim();
      const suffix = selectedAudience !== "All" ? ` - ${selectedAudience}` : "";
      document.title = clinicName
        ? `ANCHOR Trust Materials - ${clinicName}${suffix}`
        : `ANCHOR Trust Materials${suffix}`;
      window.print();
    }
  }

  const audienceCounts = useMemo(() => {
    const counts: Record<AudienceFilter, number> = {
      All: 0,
      Leadership: 0,
      Website: 0,
      Procurement: 0,
      Privacy: 0,
      "Staff enablement": 0,
    };

    if (!data) return counts;

    counts.All = data.materials.length;

    for (const item of data.materials) {
      const tag = getAudienceTag(item);
      counts[tag] += 1;
    }

    return counts;
  }, [data]);

  const filteredMaterials = useMemo(() => {
    if (!data) return [];

    if (selectedAudience === "All") {
      return data.materials;
    }

    return data.materials.filter(
      (item) => getAudienceTag(item) === selectedAudience
    );
  }, [data, selectedAudience]);

  async function handleCopyAll() {
    if (!data || filteredMaterials.length <= 0) return;

    try {
      setCopyingAll(true);
      setCopiedAll(false);
      await navigator.clipboard.writeText(
        buildVisibleMaterialsText(
          data,
          filteredMaterials as MaterialItem[],
          selectedAudience
        )
      );
      setCopiedAll(true);
      window.setTimeout(() => setCopiedAll(false), 1600);
    } catch {
      setCopiedAll(false);
    } finally {
      setCopyingAll(false);
    }
  }

  async function handleCopyItem(item: { id: string; title: string; body: string }) {
    try {
      setCopyingId(item.id);
      setCopiedId(null);
      await navigator.clipboard.writeText(buildMaterialText(item));
      setCopiedId(item.id);
      window.setTimeout(() => {
        setCopiedId((current) => (current === item.id ? null : current));
      }, 1600);
    } catch {
      setCopiedId(null);
    } finally {
      setCopyingId((current) => (current === item.id ? null : current));
    }
  }

  const trustStateTone = useMemo(() => {
    switch (data?.snapshot.operations.trust_state) {
      case "green":
        return "bg-emerald-100 text-emerald-800";
      case "yellow":
        return "bg-amber-100 text-amber-800";
      default:
        return "bg-rose-100 text-rose-800";
    }
  }, [data?.snapshot.operations.trust_state]);

  const copyVisibleLabel = useMemo(() => {
    const count = filteredMaterials.length;

    if (copiedAll) return "Visible materials copied";
    if (copyingAll) return "Copying...";
    if (count <= 0) return "Copy visible materials";
    if (count === 1) return "Copy 1 visible material";
    return `Copy ${count} visible materials`;
  }, [filteredMaterials.length, copiedAll, copyingAll]);

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

            .trust-materials-root {
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

        <div className="trust-materials-root mx-auto max-w-7xl space-y-6 p-6">
          <div className="no-print flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
            <div className="min-w-0">
              <p className="text-sm font-medium uppercase tracking-wide text-slate-500">
                Trust
              </p>
              <h1 className="text-2xl font-semibold text-slate-900">Trust Materials</h1>
              <p className="mt-2 max-w-3xl text-sm text-slate-600">
                Reusable trust language for leadership, procurement, website copy, and
                external trust communications.
              </p>
              <p className="mt-2 text-xs text-slate-500">
                Use the copy actions below to lift blocks directly into decks, RFP answers,
                website pages, and leadership updates.
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
                onClick={handleCopyAll}
                className="rounded-xl bg-slate-900 px-4 py-2 text-sm font-medium text-white hover:bg-slate-800 disabled:cursor-not-allowed disabled:opacity-60"
                disabled={
                  !data || loading || !!error || copyingAll || filteredMaterials.length <= 0
                }
              >
                {copyVisibleLabel}
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
              Loading trust materials...
            </div>
          ) : error ? (
            <div className="rounded-2xl border border-rose-200 bg-rose-50 p-6 text-sm text-rose-700 shadow-sm">
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
                      Trust Materials
                    </h2>
                    <p className="max-w-3xl text-base leading-7 text-slate-600">
                      Reusable trust language for leadership, procurement, website copy,
                      and external trust communications.
                    </p>
                  </div>

                  <span
                    className={`rounded-full px-3 py-1 text-xs font-medium ${trustStateTone}`}
                  >
                    Trust state: {data.snapshot.operations.trust_state}
                  </span>
                </div>

                <div className="mt-8 grid gap-4 md:grid-cols-2 xl:grid-cols-4">
                  <div className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
                    <div className="text-xs uppercase tracking-wide text-slate-500">
                      Clinic
                    </div>
                    <div className="mt-2 text-sm font-semibold text-slate-900">
                      {data.snapshot.clinic.clinic_name}
                    </div>
                  </div>

                  <div className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
                    <div className="text-xs uppercase tracking-wide text-slate-500">
                      Generated
                    </div>
                    <div className="mt-2 text-sm font-semibold text-slate-900">
                      {formatDate(data.generated_at)}
                    </div>
                  </div>

                  <div className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
                    <div className="text-xs uppercase tracking-wide text-slate-500">
                      Audience
                    </div>
                    <div className="mt-2 text-sm font-semibold text-slate-900">
                      {selectedAudience}
                    </div>
                  </div>

                  <div className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
                    <div className="text-xs uppercase tracking-wide text-slate-500">
                      Visible materials
                    </div>
                    <div className="mt-2 text-sm font-semibold text-slate-900">
                      {filteredMaterials.length}
                    </div>
                  </div>
                </div>

                <div className="mt-8 grid gap-6 xl:grid-cols-[1.35fr_minmax(320px,0.65fr)]">
                  <div className="rounded-2xl border border-slate-200 bg-white p-6">
                    <p className="text-xs font-medium uppercase tracking-wide text-slate-500">
                      Executive summary
                    </p>
                    <h3 className="mt-2 text-lg font-semibold text-slate-900">
                      Reusable governance-first trust language
                    </h3>
                    <p className="mt-3 text-sm leading-7 text-slate-700">
                      This materials set provides reusable trust language derived from
                      ANCHOR’s governance-first, metadata-only operating model. It is
                      designed to support leadership updates, procurement responses, website
                      copy, and external trust communications without reframing ANCHOR as a
                      clinical decision-making system.
                    </p>
                  </div>

                  <div className="rounded-2xl border border-slate-200 bg-slate-50 p-6">
                    <p className="text-xs font-medium uppercase tracking-wide text-slate-500">
                      Use with care
                    </p>
                    <h3 className="mt-2 text-lg font-semibold text-slate-900">
                      Communication boundaries
                    </h3>
                    <div className="mt-4 space-y-3">
                      {data.notes.map((note, idx) => (
                        <div
                          key={idx}
                          className="rounded-xl border border-slate-200 bg-white p-4"
                        >
                          <p className="text-sm leading-6 text-slate-700">{note}</p>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              </section>

              <div className="no-print grid gap-6 xl:grid-cols-[1.5fr_minmax(320px,0.8fr)]">
                <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm">
                  <div className="flex flex-wrap items-center justify-between gap-3">
                    <div>
                      <p className="text-xs font-medium uppercase tracking-wide text-slate-500">
                        Materials set
                      </p>
                      <h2 className="mt-1 text-lg font-semibold text-slate-900">
                        {data.snapshot.clinic.clinic_name}
                      </h2>
                    </div>

                    <span
                      className={`rounded-full px-3 py-1 text-xs font-medium ${trustStateTone}`}
                    >
                      Trust state: {data.snapshot.operations.trust_state}
                    </span>
                  </div>

                  <div className="mt-4 grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
                    <div className="rounded-xl border border-slate-200 bg-slate-50 p-4">
                      <div className="text-xs uppercase tracking-wide text-slate-500">
                        Generated
                      </div>
                      <div className="mt-2 text-sm font-medium text-slate-900">
                        {formatDate(data.generated_at)}
                      </div>
                    </div>

                    <div className="rounded-xl border border-slate-200 bg-slate-50 p-4">
                      <div className="text-xs uppercase tracking-wide text-slate-500">
                        Policy version
                      </div>
                      <div className="mt-2 text-sm font-medium text-slate-900">
                        v{data.snapshot.governance.policy_version}
                      </div>
                    </div>

                    <div className="rounded-xl border border-slate-200 bg-slate-50 p-4">
                      <div className="text-xs uppercase tracking-wide text-slate-500">
                        Signal quality
                      </div>
                      <div className="mt-2 text-sm font-medium capitalize text-slate-900">
                        {data.snapshot.operations.signal_quality}
                      </div>
                    </div>

                    <div className="rounded-xl border border-slate-200 bg-slate-50 p-4">
                      <div className="text-xs uppercase tracking-wide text-slate-500">
                        Evidence window
                      </div>
                      <div className="mt-2 text-sm font-medium text-slate-900">
                        {data.snapshot.evidence_window.hours}h
                      </div>
                    </div>
                  </div>

                  <div className="mt-4 flex flex-wrap gap-3">
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
                      href="/trust/pack"
                      className="rounded-xl border border-slate-300 px-4 py-2 text-sm font-medium text-slate-700 hover:bg-slate-50"
                    >
                      View trust pack
                    </Link>
                  </div>
                </div>

                <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm">
                  <p className="text-xs font-medium uppercase tracking-wide text-slate-500">
                    Materials guidance
                  </p>
                  <h2 className="mt-2 text-lg font-semibold text-slate-900">Use with care</h2>
                  <div className="mt-4 space-y-3">
                    {data.notes.map((note, idx) => (
                      <div key={idx} className="rounded-xl border border-slate-200 bg-slate-50 p-4">
                        <p className="text-sm leading-6 text-slate-700">{note}</p>
                      </div>
                    ))}
                  </div>
                </div>
              </div>

              <div className="no-print rounded-2xl border border-slate-200 bg-white p-4 shadow-sm">
                <div className="flex flex-col gap-3">
                  <div>
                    <p className="text-xs font-medium uppercase tracking-wide text-slate-500">
                      Audience filter
                    </p>
                    <p className="mt-1 text-sm text-slate-600">
                      Filter reusable materials by intended audience and copy only what is visible.
                    </p>
                  </div>

                  <div className="-mx-1 overflow-x-auto">
                    <div className="flex min-w-max gap-2 px-1 pb-1">
                      {AUDIENCE_OPTIONS.map((audience) => {
                        const isActive = selectedAudience === audience;
                        const count = audienceCounts[audience];

                        return (
                          <button
                            key={audience}
                            type="button"
                            onClick={() => setSelectedAudience(audience)}
                            className={`rounded-full border px-3 py-1.5 text-xs font-medium transition ${
                              isActive
                                ? "border-slate-900 bg-slate-900 text-white"
                                : "border-slate-300 bg-white text-slate-700 hover:bg-slate-50"
                            }`}
                          >
                            {audience} ({count})
                          </button>
                        );
                      })}
                    </div>
                  </div>
                </div>
              </div>

              <div className="flex flex-col gap-3 rounded-2xl border border-slate-200 bg-white p-4 shadow-sm sm:flex-row sm:items-center sm:justify-between">
                <div className="text-sm text-slate-600">
                  Showing{" "}
                  <span className="font-medium text-slate-900">
                    {filteredMaterials.length}
                  </span>{" "}
                  {filteredMaterials.length === 1 ? "material" : "materials"}
                  {selectedAudience !== "All" ? (
                    <>
                      {" "}
                      for <span className="font-medium text-slate-900">{selectedAudience}</span>
                    </>
                  ) : null}
                  .
                </div>

                {selectedAudience !== "All" ? (
                  <button
                    type="button"
                    onClick={() => setSelectedAudience("All")}
                    className="no-print rounded-xl border border-slate-300 px-3 py-2 text-sm font-medium text-slate-700 hover:bg-slate-50"
                  >
                    Reset to All
                  </button>
                ) : null}
              </div>

              <div className="grid gap-6">
                {filteredMaterials.length > 0 ? (
                  filteredMaterials.map((item) => {
                    const isCopying = copyingId === item.id;
                    const isCopied = copiedId === item.id;
                    const audienceTag = getAudienceTag(item);
                    const audienceTagTone = getAudienceTagTone(audienceTag);

                    return (
                      <div
                        key={item.id}
                        className="print-surface print-avoid-break rounded-2xl border border-slate-200 bg-white p-6 shadow-sm"
                      >
                        <div className="flex flex-wrap items-start justify-between gap-4">
                          <div>
                            <div className="flex flex-wrap items-center gap-2">
                              <div className="text-xs font-medium uppercase tracking-wide text-slate-500">
                                {formatLabel(item.id)}
                              </div>
                              <span
                                className={`rounded-full border px-2.5 py-1 text-[11px] font-medium ${audienceTagTone}`}
                              >
                                {audienceTag}
                              </span>
                            </div>

                            <h2 className="mt-2 text-lg font-semibold text-slate-900">
                              {item.title}
                            </h2>
                          </div>

                          <button
                            onClick={() => handleCopyItem(item)}
                            className="no-print rounded-xl border border-slate-300 px-4 py-2 text-sm font-medium text-slate-700 hover:bg-slate-50"
                            disabled={isCopying}
                          >
                            {isCopied ? "Copied" : isCopying ? "Copying..." : "Copy block"}
                          </button>
                        </div>

                        <p className="mt-3 text-sm leading-7 text-slate-700">{item.body}</p>
                      </div>
                    );
                  })
                ) : (
                  <div className="rounded-2xl border border-slate-200 bg-white p-6 text-sm text-slate-600 shadow-sm">
                    <p>No trust materials match the selected audience.</p>
                    <button
                      type="button"
                      onClick={() => setSelectedAudience("All")}
                      className="no-print mt-4 rounded-xl border border-slate-300 px-4 py-2 text-sm font-medium text-slate-700 hover:bg-slate-50"
                    >
                      Reset to All
                    </button>
                  </div>
                )}
              </div>

              <div className="print-surface print-avoid-break rounded-2xl border border-slate-200 bg-white p-6 shadow-sm">
                <p className="text-xs font-medium uppercase tracking-wide text-slate-500">
                  Evidence basis
                </p>
                <div className="mt-3 grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
                  <div>
                    <div className="text-xs text-slate-500">Metadata-only accountability</div>
                    <div className="mt-1 text-sm font-medium text-slate-900">
                      {data.snapshot.governance.metadata_only_accountability ? "Active" : "Not active"}
                    </div>
                  </div>
                  <div>
                    <div className="text-xs text-slate-500">Governance receipts</div>
                    <div className="mt-1 text-sm font-medium text-slate-900">
                      {data.snapshot.governance.governance_receipts_active ? "Active" : "Not active"}
                    </div>
                  </div>
                  <div>
                    <div className="text-xs text-slate-500">Raw content storage</div>
                    <div className="mt-1 text-sm font-medium text-slate-900">
                      {data.snapshot.governance.stores_raw_content ? "Enabled" : "Disabled"}
                    </div>
                  </div>
                  <div>
                    <div className="text-xs text-slate-500">Tenant isolation</div>
                    <div className="mt-1 text-sm font-medium text-slate-900">
                      {data.snapshot.tenancy.rls_forced ? "FORCE RLS" : "Not reported"}
                    </div>
                  </div>
                </div>
              </div>
            </>
          ) : null}
        </div>
      </>
    </AppShell>
  );
}
