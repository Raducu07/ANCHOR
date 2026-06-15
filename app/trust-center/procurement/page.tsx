import type { Metadata } from "next";
import { MarketingShell } from "@/components/marketing/MarketingShell";
import { LegalCardGrid } from "@/components/legal/LegalCardGrid";
import { LEGAL_NON_CLAIM_NOTICE, getSlice2Page } from "@/lib/legal/legalContent";

const meta = getSlice2Page("trust-procurement");

export const metadata: Metadata = {
  title: `${meta.title} | ANCHOR`,
  description: meta.subtitle,
};

const procurementCards = [
  { href: "/legal", title: "Legal Centre", subtitle: "All ANCHOR legal, data, and AI-governance pages." },
  { href: "/legal/terms", title: "Terms of Service", subtitle: "Public terms - solicitor-preparation draft." },
  { href: "/legal/privacy", title: "Privacy Notice", subtitle: "Draft privacy notice." },
  { href: "/legal/data-processing", title: "Data Processing", subtitle: "Public summary of data processing on behalf of clinics." },
  { href: "/legal/acceptable-use", title: "Acceptable Use", subtitle: "Permitted and prohibited use." },
  { href: "/legal/ai-governance-boundary", title: "AI Governance Boundary", subtitle: "What ANCHOR is and is not." },
  { href: "/legal/ai-data-use", title: "AI Data Use", subtitle: "How data is and is not used." },
  { href: "/legal/data-roles", title: "Data Roles", subtitle: "Draft data-protection roles." },
  { href: "/legal/data-classification", title: "Data Classification", subtitle: "Classes of data ANCHOR may handle." },
  { href: "/legal/security", title: "Security Posture", subtitle: "High-level posture - not a certification." },
  { href: "/legal/security/toms", title: "Technical and Organisational Measures", subtitle: "Contract-adjacent TOMs summary." },
  { href: "/legal/subprocessors", title: "Subprocessors", subtitle: "Public summary of subprocessors." },
  { href: "/legal/ai-providers", title: "AI Providers", subtitle: "How ANCHOR works with AI providers." },
  { href: "/legal/pilot-terms", title: "Pilot Terms", subtitle: "Public summary of how pilots work." },
  { href: "/legal/cookies", title: "Cookie Notice", subtitle: "Current cookie posture." },
  { href: "/legal/versions", title: "Version History", subtitle: "Version and status of each page." },
  { href: "/security/vulnerability-disclosure", title: "Vulnerability Disclosure", subtitle: "Responsible security reporting." },
  { href: "/trust-center/request-access", title: "Request Access", subtitle: "How to request review materials." },
];

export default function TrustCenterProcurementPage() {
  return (
    <MarketingShell showAssistant={false}>
      <div className="px-4 py-16 sm:px-6 lg:px-8">
        <div className="mx-auto max-w-5xl">
          <p className="mb-3 text-sm font-bold uppercase tracking-[0.2em] text-slate-500">Trust Centre</p>
          <h1 className="text-4xl font-bold tracking-tight text-slate-950 md:text-5xl">Procurement Pack</h1>
          <p className="mt-4 max-w-3xl text-lg leading-8 text-slate-600">
            An index of ANCHOR&apos;s legal, security, privacy, and AI-governance materials for procurement and buyer
            review.
          </p>
          <p className="mt-3 max-w-3xl text-sm leading-6 text-slate-600">
            {meta.stage}.
          </p>

          <div className="mt-10">
            <LegalCardGrid items={procurementCards} />
          </div>

          <div className="mt-12 rounded-xl border border-slate-200 bg-white p-6">
            <h2 className="text-base font-semibold text-slate-900">How to read this pack</h2>
            <ul className="mt-4 space-y-2">
              {[
                "These public summaries are not a substitute for signed agreements.",
                "The final commercial and legal pack, and solicitor-reviewed documents, control over these summaries.",
                "Some artefacts may be request-only or pilot-specific.",
              ].map((point) => (
                <li key={point} className="flex items-start text-sm leading-6 text-slate-600">
                  <span className="mr-3 mt-2 h-1.5 w-1.5 flex-shrink-0 rounded-full bg-slate-400" />
                  <span>{point}</span>
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
