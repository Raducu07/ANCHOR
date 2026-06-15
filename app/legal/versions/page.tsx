import type { Metadata } from "next";
import Link from "next/link";
import { LegalPageShell } from "@/components/legal/LegalPageShell";
import { Card } from "@/components/ui/Card";
import { SLICE2_PAGES, listLegalPagesInOrder } from "@/lib/legal/legalContent";

export const metadata: Metadata = {
  title: "Legal Version History | ANCHOR Legal & Trust",
  description:
    "Version, status, and contractual state of each ANCHOR legal and trust page. Register prepared for solicitor review.",
};

const VERSIONS_PAGE_VERSION = "v1.0";
const VERSIONS_PAGE_LAST_UPDATED = "15 June 2026";
const EFFECTIVE_DATE = "Not externally effective";
const CONTRACTUAL_STATUS = "Not contractual unless incorporated by agreement";

const DRAFT_STATUS = "Draft - solicitor review pending";
const DRAFT_CHANGE = "Initial draft created for solicitor review.";
const SLICE2_CHANGE = "Public summary published for review.";

type VersionRow = {
  title: string;
  href: string;
  version: string;
  lastUpdated: string;
  status: string;
  changeSummary: string;
};

export default function LegalVersionsPage() {
  const slice1Rows: VersionRow[] = listLegalPagesInOrder().map((page) => ({
    title: page.title,
    href: `/legal/${page.slug}`,
    version: page.version,
    lastUpdated: page.lastUpdated,
    status: DRAFT_STATUS,
    changeSummary: DRAFT_CHANGE,
  }));

  const slice2Rows: VersionRow[] = Object.values(SLICE2_PAGES).map((page) => ({
    title: page.title,
    href: page.href,
    version: page.version,
    lastUpdated: page.lastUpdated,
    status: page.stage,
    changeSummary: SLICE2_CHANGE,
  }));

  const rows: VersionRow[] = [
    ...slice1Rows,
    ...slice2Rows,
    {
      title: "Legal Version History",
      href: "/legal/versions",
      version: VERSIONS_PAGE_VERSION,
      lastUpdated: VERSIONS_PAGE_LAST_UPDATED,
      status: "Public summary - solicitor reviewed",
      changeSummary: "Register published.",
    },
  ];

  return (
    <LegalPageShell
      title="Legal Version History"
      subtitle="Version, status, and contractual state of each legal and trust page."
      meta={{
        version: VERSIONS_PAGE_VERSION,
        statusLabel: "Public summary",
        stage: "Register - agreement controls",
        lastUpdated: VERSIONS_PAGE_LAST_UPDATED,
      }}
    >
      <p className="text-base leading-7 text-slate-700">
        This register lists the current legal and trust pages and their status. Entries are either drafts prepared for
        solicitor review or public summaries. None are externally effective, and none are contractual unless and until
        incorporated by agreement. This page does not use a backend version store.
      </p>

      <div className="space-y-4">
        {rows.map((row) => (
          <Card key={row.href} variant="native" className="p-6">
            <div className="flex flex-col gap-1 sm:flex-row sm:items-baseline sm:justify-between">
              <Link href={row.href} className="text-base font-semibold text-slate-900 hover:text-slate-700">
                {row.title}
              </Link>
              <span className="text-xs font-medium text-slate-500">{row.href}</span>
            </div>
            <dl className="mt-4 grid gap-3 text-sm sm:grid-cols-2">
              <Row label="Version" value={row.version} />
              <Row label="Last updated" value={row.lastUpdated} />
              <Row label="Effective date" value={EFFECTIVE_DATE} />
              <Row label="Status" value={row.status} />
              <Row label="Contractual status" value={CONTRACTUAL_STATUS} />
              <Row label="Change summary" value={row.changeSummary} />
            </dl>
          </Card>
        ))}
      </div>
    </LegalPageShell>
  );
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex flex-col gap-0.5">
      <dt className="text-xs font-semibold uppercase tracking-[0.14em] text-slate-500">{label}</dt>
      <dd className="text-slate-900">{value}</dd>
    </div>
  );
}
