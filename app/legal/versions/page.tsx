import type { Metadata } from "next";
import Link from "next/link";
import { LegalPageShell } from "@/components/legal/LegalPageShell";
import { Card } from "@/components/ui/Card";
import { listLegalPagesInOrder } from "@/lib/legal/legalContent";

export const metadata: Metadata = {
  title: "Legal Version History | ANCHOR Legal & Trust",
  description:
    "Version, status, and contractual state of each draft ANCHOR legal page. Draft register prepared for solicitor review.",
};

const VERSIONS_PAGE_VERSION = "v0.1 (draft)";
const VERSIONS_PAGE_LAST_UPDATED = "15 June 2026";
const EFFECTIVE_DATE = "Not externally effective";
const REGISTER_STATUS = "Draft - solicitor review pending";
const CONTRACTUAL_STATUS = "Not contractual unless incorporated by agreement";
const CHANGE_SUMMARY = "Initial draft created for solicitor review.";

type VersionRow = {
  title: string;
  href: string;
  version: string;
  lastUpdated: string;
};

export default function LegalVersionsPage() {
  const rows: VersionRow[] = [
    ...listLegalPagesInOrder().map((page) => ({
      title: page.title,
      href: `/legal/${page.slug}`,
      version: page.version,
      lastUpdated: page.lastUpdated,
    })),
    {
      title: "Legal Version History",
      href: "/legal/versions",
      version: VERSIONS_PAGE_VERSION,
      lastUpdated: VERSIONS_PAGE_LAST_UPDATED,
    },
  ];

  return (
    <LegalPageShell
      title="Legal Version History"
      subtitle="Version, status, and contractual state of each draft legal page."
      meta={{
        version: VERSIONS_PAGE_VERSION,
        statusLabel: "Draft",
        stage: "Prepared for solicitor review - not in force",
        lastUpdated: VERSIONS_PAGE_LAST_UPDATED,
      }}
    >
      <p className="text-base leading-7 text-slate-700">
        This register lists the current draft legal pages and their status. All entries are drafts prepared for
        solicitor review. They are not externally effective and are not contractual unless and until incorporated by
        agreement. This page does not use a backend version store.
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
              <Row label="Status" value={REGISTER_STATUS} />
              <Row label="Contractual status" value={CONTRACTUAL_STATUS} />
              <Row label="Change summary" value={CHANGE_SUMMARY} />
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
