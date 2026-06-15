import type { Metadata } from "next";
import { MarketingShell } from "@/components/marketing/MarketingShell";
import { LegalCardGrid } from "@/components/legal/LegalCardGrid";
import { LEGAL_NON_CLAIM_NOTICE, PLANNED_LEGAL_PAGES, listLegalPages } from "@/lib/legal/legalContent";

export const metadata: Metadata = {
  title: "Legal & Trust Centre | ANCHOR",
  description:
    "ANCHOR's Legal and Trust Centre: legal, data, and AI-governance information for safe AI use in veterinary clinics.",
};

export default function LegalCentrePage() {
  const pages = listLegalPages();
  const cardItems = pages.map((page) => ({
    href: `/legal/${page.slug}`,
    title: page.title,
    subtitle: page.subtitle,
  }));

  return (
    <MarketingShell showAssistant={false}>
      <div className="px-4 py-16 sm:px-6 lg:px-8">
        <div className="mx-auto max-w-5xl">
          <p className="mb-3 text-sm font-bold uppercase tracking-[0.2em] text-slate-500">Legal &amp; Trust</p>
          <h1 className="text-4xl font-bold tracking-tight text-slate-950 md:text-5xl">
            ANCHOR Legal &amp; Trust Centre
          </h1>
          <p className="mt-4 max-w-3xl text-lg leading-8 text-slate-600">
            This is ANCHOR&apos;s Legal and Trust Centre: a single place for the legal, data, and AI-governance
            information that explains how ANCHOR works and where its boundaries sit. ANCHOR is governance and readiness
            infrastructure for safe AI use in veterinary clinics.
          </p>

          <div className="mt-10">
            <LegalCardGrid items={cardItems} />
          </div>

          <div className="mt-12 rounded-xl border border-slate-200 bg-white p-6">
            <h2 className="text-base font-semibold text-slate-900">Planned pages</h2>
            <p className="mt-2 text-sm leading-6 text-slate-600">
              These pages are planned and not yet published. They will be added as drafting and review progress.
            </p>
            <ul className="mt-4 flex flex-wrap gap-2">
              {PLANNED_LEGAL_PAGES.map((label) => (
                <li
                  key={label}
                  className="rounded-full border border-slate-200 bg-slate-50 px-3 py-1 text-xs font-medium text-slate-500"
                >
                  {label}
                </li>
              ))}
            </ul>
          </div>

          <div className="mt-8 rounded-xl border border-slate-200 bg-white p-6">
            <p className="text-xs font-semibold uppercase tracking-[0.18em] text-slate-500">Important notice</p>
            <p className="mt-3 max-w-3xl text-sm leading-6 text-slate-600">{LEGAL_NON_CLAIM_NOTICE}</p>
          </div>
        </div>
      </div>
    </MarketingShell>
  );
}
