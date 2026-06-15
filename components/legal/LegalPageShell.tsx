import type { ReactNode } from "react";
import Link from "next/link";
import { MarketingShell } from "@/components/marketing/MarketingShell";
import { LegalDocumentMeta } from "@/components/legal/LegalDocumentMeta";
import { LEGAL_NON_CLAIM_NOTICE } from "@/lib/legal/legalContent";

type LegalPageShellMeta = {
  version: string;
  statusLabel: string;
  stage: string;
  lastUpdated: string;
};

type LegalPageShellProps = {
  title: string;
  subtitle?: string;
  meta?: LegalPageShellMeta;
  backHref?: string;
  backLabel?: string;
  children: ReactNode;
};

const backLinkClass = "text-sm font-medium text-slate-500 transition-colors hover:text-slate-950";

export function LegalPageShell({
  title,
  subtitle,
  meta,
  backHref = "/legal",
  backLabel = "Back to Legal & Trust Centre",
  children,
}: LegalPageShellProps) {
  return (
    <MarketingShell showAssistant={false}>
      <div className="px-4 py-16 sm:px-6 lg:px-8">
        <div className="mx-auto max-w-3xl">
          <Link href={backHref} className={backLinkClass}>
            {backLabel}
          </Link>

          <h1 className="mt-4 text-3xl font-bold tracking-tight text-slate-950 md:text-4xl">{title}</h1>
          {subtitle ? <p className="mt-3 text-lg leading-8 text-slate-600">{subtitle}</p> : null}

          {meta ? (
            <div className="mt-6">
              <LegalDocumentMeta
                version={meta.version}
                statusLabel={meta.statusLabel}
                stage={meta.stage}
                lastUpdated={meta.lastUpdated}
              />
            </div>
          ) : null}

          <div className="mt-10 space-y-10">{children}</div>

          <div className="mt-12 rounded-xl border border-slate-200 bg-white p-6">
            <p className="text-xs font-semibold uppercase tracking-[0.18em] text-slate-500">Important notice</p>
            <p className="mt-3 text-sm leading-6 text-slate-600">{LEGAL_NON_CLAIM_NOTICE}</p>
          </div>

          <div className="mt-8">
            <Link href={backHref} className={backLinkClass}>
              {backLabel}
            </Link>
          </div>
        </div>
      </div>
    </MarketingShell>
  );
}
