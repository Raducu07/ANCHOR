"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { AppShell } from "@/components/shell/AppShell";
import { getTrustPack } from "@/lib/trust";
import type {
  TrustPackResponse,
  TrustPackSection,
  TrustPackSelfAssessmentTemplate,
} from "@/lib/types";

// Optional payload extras that are not declared on TrustPackResponse but
// may be present on real responses. Each field is typed `unknown[]` so
// the component must narrow with Array.isArray before reading.
type TrustPackOptionalExtras = TrustPackResponse["pack"] & {
  evidence_basis?: unknown[];
  limitations?: unknown[];
};

function sanitizeClinicName(value: unknown, fallback = "Your clinic") {
  const text = typeof value === "string" ? value.trim() : "";
  if (!text) return fallback;
  if (text === "M4 Portal Test Clinic") return fallback;
  return text;
}

function formatDate(value?: string) {
  if (!value) return "-";
  try {
    return new Date(value).toLocaleString();
  } catch {
    return value;
  }
}

function titleCase(value?: string | null) {
  if (!value) return "-";
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
    } catch (err: unknown) {
      const message =
        err instanceof Error ? err.message : "Failed to load trust pack.";
      setError(message);
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
      const clinicName = sanitizeClinicName(data?.pack?.clinic_name, "");
      document.title = clinicName
        ? `ANCHOR Trust Pack - ${clinicName}`
        : "ANCHOR Trust Pack";
      window.print();
    }
  }

  const clinicName = sanitizeClinicName(data?.pack?.clinic_name, "Your clinic");

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

    // The Trust Pack payload may carry optional `evidence_basis` and
    // `limitations` arrays that are not declared on TrustPackResponse.
    // Narrow them as `unknown` then validate before use.
    const packExtras = data.pack as TrustPackOptionalExtras;
    if (
      Array.isArray(packExtras.evidence_basis) &&
      packExtras.evidence_basis.length > 0
    ) {
      return packExtras.evidence_basis.map((item) => String(item));
    }

    return [
      `Generated from ANCHOR metadata-only trust signals at ${formatDate(data.pack.generated_at)}.`,
      `Evidence window: ${data.pack.evidence_window.hours} hours.`,
      `Governance policy version: v${data.snapshot.governance.policy_version}.`,
      `Operational signal quality: ${titleCase(data.snapshot.operations.signal_quality)}.`,
      `Recent activity volume: ${data.snapshot.operations.events_24h} events in the last 24 hours.`,
      `Top operating mode in the last 24 hours: ${data.snapshot.operations.top_mode_24h ?? "-"}.`,
      "Trust Pack content is derived from governance, privacy, tenancy, operations, and learning metadata rather than stored raw prompts or model outputs.",
    ];
  }, [data]);

  const limitations = useMemo(() => {
    if (!data) return [];

    const packExtras = data.pack as TrustPackOptionalExtras;
    if (
      Array.isArray(packExtras.limitations) &&
      packExtras.limitations.length > 0
    ) {
      return packExtras.limitations.map((item) => String(item));
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
                      {clinicName}
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
                          {data.snapshot.operations.top_mode_24h ?? "-"}
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

                      <SelfAssessmentEvidenceTemplates section={section} />
                      <HonestDisclosureRow section={section} />
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

// Honest-disclosure chips for evidence sections. Each flag is optional;
// rendered only when present on the backend section payload. All flags
// are expected to be `false` in the live contract — render as "No".
function HonestDisclosureRow({ section }: { section: TrustPackSection }) {
  const rows: { key: string; label: string; value: boolean | undefined }[] = [
    { key: "raw_content_included", label: "Raw content included", value: section.raw_content_included },
    { key: "raw_policy_body_included", label: "Raw policy body included", value: section.raw_policy_body_included },
    { key: "raw_answers_included", label: "Raw answers included", value: section.raw_answers_included },
    { key: "raw_prompt_included", label: "Raw prompt included", value: section.raw_prompt_included },
    { key: "raw_output_included", label: "Raw output included", value: section.raw_output_included },
    { key: "staff_identifiers_included", label: "Staff identifiers included", value: section.staff_identifiers_included },
    { key: "clinical_content_included", label: "Clinical content included", value: section.clinical_content_included },
    { key: "client_identifiers_included", label: "Client identifiers included", value: section.client_identifiers_included },
    { key: "patient_identifiers_included", label: "Patient identifiers included", value: section.patient_identifiers_included },
  ];
  const present = rows.filter((r) => typeof r.value === "boolean");
  if (present.length === 0) return null;
  return (
    <div className="mt-4">
      <p className="text-xs font-semibold uppercase tracking-[0.16em] text-slate-500">
        Honest disclosure
      </p>
      <div className="mt-2 flex flex-wrap gap-2 text-xs text-slate-700">
        {present.map((r) => (
          <span
            key={r.key}
            className="rounded-full border border-slate-200 bg-slate-50 px-2.5 py-1"
          >
            {r.label}: {r.value ? "Yes" : "No"}
          </span>
        ))}
      </div>
    </div>
  );
}

// Self-assessment evidence template details. Renders only when the
// section actually carries a templates array. Metadata-only; no raw
// answers, no staff identifiers.
function SelfAssessmentEvidenceTemplates({ section }: { section: TrustPackSection }) {
  const templates = section.templates;
  if (!Array.isArray(templates) || templates.length === 0) return null;
  return (
    <div className="mt-4 space-y-3">
      <p className="text-xs font-semibold uppercase tracking-[0.16em] text-slate-500">
        Templates
      </p>
      {templates.map((t) => (
        <SelfAssessmentTemplateCard key={`${t.template_slug}-${t.template_version}`} template={t} />
      ))}
    </div>
  );
}

function SelfAssessmentTemplateCard({
  template,
}: {
  template: TrustPackSelfAssessmentTemplate;
}) {
  const readiness = template.readiness_summary_counts ?? {
    yes: 0,
    partial: 0,
    planned: 0,
    no: 0,
    not_applicable: 0,
  };
  const evidence = template.linked_evidence_counts ?? {
    policy_library: 0,
    staff_attestation: 0,
    learn_cpd: 0,
    assistant_receipts: 0,
    trust_posture: 0,
    manual_review: 0,
  };
  const submittedAt = template.latest_submitted_at
    ? formatDate(template.latest_submitted_at)
    : "Not submitted yet";
  const status =
    typeof template.assessment_status === "string"
      ? template.assessment_status.replaceAll("_", " ")
      : "Not available";
  return (
    <div className="rounded-xl border border-slate-200 bg-slate-50 p-4">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div className="min-w-0">
          <p className="text-sm font-semibold text-slate-900">{template.title}</p>
          <p className="mt-1 text-xs text-slate-500">
            Template v{template.template_version}
          </p>
        </div>
        <span className="inline-flex items-center rounded-full border border-slate-200 bg-white px-2 py-0.5 text-xs font-medium capitalize text-slate-700">
          {status}
        </span>
      </div>
      <div className="mt-2 flex flex-wrap gap-x-6 gap-y-1 text-xs text-slate-600">
        <span>Latest submitted: {submittedAt}</span>
        <span>
          Answered: {template.answered_questions ?? 0} of {template.total_questions ?? 0}
        </span>
        <span>Gap count: {template.gap_count ?? 0}</span>
      </div>
      <div className="mt-3">
        <p className="text-xs font-semibold uppercase tracking-[0.16em] text-slate-500">
          Readiness summary
        </p>
        <div className="mt-1 flex flex-wrap gap-2 text-xs text-slate-700">
          <span className="rounded-full border border-slate-200 bg-white px-2.5 py-1">
            Yes: {readiness.yes ?? 0}
          </span>
          <span className="rounded-full border border-slate-200 bg-white px-2.5 py-1">
            Partial: {readiness.partial ?? 0}
          </span>
          <span className="rounded-full border border-slate-200 bg-white px-2.5 py-1">
            Planned: {readiness.planned ?? 0}
          </span>
          <span className="rounded-full border border-slate-200 bg-white px-2.5 py-1">
            No: {readiness.no ?? 0}
          </span>
          <span className="rounded-full border border-slate-200 bg-white px-2.5 py-1">
            Not applicable: {readiness.not_applicable ?? 0}
          </span>
        </div>
      </div>
      <div className="mt-3">
        <p className="text-xs font-semibold uppercase tracking-[0.16em] text-slate-500">
          Linked evidence
        </p>
        <div className="mt-1 flex flex-wrap gap-2 text-xs text-slate-700">
          <span className="rounded-full border border-slate-200 bg-white px-2.5 py-1">
            Policy library: {evidence.policy_library ?? 0}
          </span>
          <span className="rounded-full border border-slate-200 bg-white px-2.5 py-1">
            Staff attestation: {evidence.staff_attestation ?? 0}
          </span>
          <span className="rounded-full border border-slate-200 bg-white px-2.5 py-1">
            Learn / CPD: {evidence.learn_cpd ?? 0}
          </span>
          <span className="rounded-full border border-slate-200 bg-white px-2.5 py-1">
            Assistant receipts: {evidence.assistant_receipts ?? 0}
          </span>
          <span className="rounded-full border border-slate-200 bg-white px-2.5 py-1">
            Trust posture: {evidence.trust_posture ?? 0}
          </span>
          <span className="rounded-full border border-slate-200 bg-white px-2.5 py-1">
            Manual review: {evidence.manual_review ?? 0}
          </span>
        </div>
      </div>
    </div>
  );
}
