import { StatusBadge } from "@/components/ui/StatusBadge";

type LegalDocumentMetaProps = {
  version: string;
  statusLabel: string;
  stage: string;
  lastUpdated: string;
};

export function LegalDocumentMeta({ version, statusLabel, stage, lastUpdated }: LegalDocumentMetaProps) {
  return (
    <div className="rounded-xl border border-slate-200 bg-white p-5">
      <dl className="grid gap-4 sm:grid-cols-2">
        <Meta label="Status">
          <StatusBadge value={statusLabel} />
        </Meta>
        <Meta label="Version">
          <span className="text-sm text-slate-900">{version}</span>
        </Meta>
        <Meta label="Stage">
          <span className="text-sm text-slate-900">{stage}</span>
        </Meta>
        <Meta label="Last updated">
          <span className="text-sm text-slate-900">{lastUpdated}</span>
        </Meta>
      </dl>
    </div>
  );
}

function Meta({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between gap-3 sm:flex-col sm:items-start sm:justify-start sm:gap-1">
      <dt className="text-xs font-semibold uppercase tracking-[0.16em] text-slate-500">{label}</dt>
      <dd>{children}</dd>
    </div>
  );
}
