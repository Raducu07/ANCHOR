import type { Metadata } from "next";
import { MarketingShell } from "@/components/marketing/MarketingShell";
import { LegalCardGrid } from "@/components/legal/LegalCardGrid";
import { LEGAL_NON_CLAIM_NOTICE } from "@/lib/legal/legalContent";

export const metadata: Metadata = {
  title: "Trust Centre | ANCHOR",
  description:
    "ANCHOR's Trust Centre brings together legal, security, privacy, AI-governance, and customer-responsibility materials. Draft, prepared for solicitor review.",
};

const trustCenterCards = [
  {
    href: "/legal",
    title: "Legal Centre",
    subtitle: "All ANCHOR legal, data, and AI-governance pages in one place.",
  },
  {
    href: "/legal/ai-governance-boundary",
    title: "AI Governance Boundary",
    subtitle: "What ANCHOR is, what it is not, and what governance receipts do and do not show.",
  },
  {
    href: "/legal/ai-data-use",
    title: "AI Data Use",
    subtitle: "How AI is used in ANCHOR, and how data is and is not used.",
  },
  {
    href: "/legal/data-roles",
    title: "Data Roles",
    subtitle: "Draft data-protection roles, and what may still be personal data.",
  },
  {
    href: "/legal/data-classification",
    title: "Data Classification Register",
    subtitle: "Draft register of the classes of data ANCHOR may handle.",
  },
  {
    href: "/legal/security",
    title: "Security Posture",
    subtitle: "High-level security posture - not a security certification.",
  },
  {
    href: "/legal/privacy",
    title: "Privacy Notice",
    subtitle: "Draft privacy notice - solicitor review pending.",
  },
  {
    href: "/legal/customer-responsibilities",
    title: "Customer Responsibilities",
    subtitle: "What your clinic remains responsible for when using ANCHOR.",
  },
  {
    href: "/legal/versions",
    title: "Legal Version History",
    subtitle: "Version, status, and contractual state of each draft legal page.",
  },
  {
    href: "/security/vulnerability-disclosure",
    title: "Vulnerability Disclosure",
    subtitle: "A responsible route for good-faith security reports.",
  },
];

const deferredPages = [
  "/trust-center/security",
  "/trust-center/privacy",
  "/trust-center/ai-governance",
  "/trust-center/procurement",
  "/trust-center/request-access",
];

export default function TrustCenterPage() {
  return (
    <MarketingShell showAssistant={false}>
      <div className="px-4 py-16 sm:px-6 lg:px-8">
        <div className="mx-auto max-w-5xl">
          <p className="mb-3 text-sm font-bold uppercase tracking-[0.2em] text-slate-500">Trust Centre</p>
          <h1 className="text-4xl font-bold tracking-tight text-slate-950 md:text-5xl">ANCHOR Trust Centre</h1>
          <p className="mt-4 max-w-3xl text-lg leading-8 text-slate-600">
            The ANCHOR Trust Centre brings together our legal, security, privacy, AI-governance, and
            customer-responsibility materials in one place for review.
          </p>
          <p className="mt-3 max-w-3xl text-sm leading-6 text-slate-600">
            These materials are drafts prepared for solicitor review. They are not in force and are not externally
            relied upon until solicitor review and a final wording check are complete.
          </p>

          <div className="mt-10">
            <LegalCardGrid items={trustCenterCards} />
          </div>

          <div className="mt-12 rounded-xl border border-slate-200 bg-white p-6">
            <h2 className="text-base font-semibold text-slate-900">Deeper procurement pages</h2>
            <p className="mt-2 text-sm leading-6 text-slate-600">
              The following deeper procurement pages are planned and not yet published.
            </p>
            <ul className="mt-4 flex flex-wrap gap-2">
              {deferredPages.map((path) => (
                <li
                  key={path}
                  className="rounded-full border border-slate-200 bg-slate-50 px-3 py-1 text-xs font-medium text-slate-500"
                >
                  {path}
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
