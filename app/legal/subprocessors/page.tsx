import type { Metadata } from "next";
import { LegalPageShell } from "@/components/legal/LegalPageShell";
import { Card } from "@/components/ui/Card";
import { StatusBadge } from "@/components/ui/StatusBadge";
import { getSlice2Page } from "@/lib/legal/legalContent";

const meta = getSlice2Page("subprocessors");

export const metadata: Metadata = {
  title: `${meta.title} | ANCHOR`,
  description: meta.subtitle,
};

type Subprocessor = {
  service: string;
  purpose: string;
  dataCategories: string;
  status: string;
  region: string;
  notes: string;
};

const subprocessors: Subprocessor[] = [
  {
    service: "Vercel",
    purpose: "Frontend hosting and deployment",
    dataCategories: "Public website delivery; request metadata and logs possible",
    status: "active",
    region: "Hosting region not asserted here; confirmed in the data processing agreement",
    notes: "Hosts the public ANCHOR frontend.",
  },
  {
    service: "Render",
    purpose: "Backend and API hosting",
    dataCategories: "Governance metadata processed server-side",
    status: "active",
    region: "Hosting region not asserted here; confirmed in the data processing agreement",
    notes: "Hosts the production backend and API.",
  },
  {
    service: "Managed database provider",
    purpose: "Backend data persistence",
    dataCategories: "Governance metadata persisted for the backend",
    status: "to be confirmed",
    region: "Not asserted here; to be confirmed from the deployment architecture",
    notes: "A managed database provider supports backend persistence; the specific provider is to be confirmed from the deployment architecture.",
  },
  {
    service: "Anthropic",
    purpose: "AI generation provider (live Workspace generation)",
    dataCategories: "Transient prompt and output routing, only if live generation is enabled",
    status: "conditional",
    region: "Not asserted here; addressed before any live generation with real data",
    notes: "Relevant only if and when live Workspace generation is enabled. Live generation is production-off by default; Anthropic becomes a subprocessor only when it is enabled and the legal and subprocessor documentation supports it.",
  },
  {
    service: "ImprovMX",
    purpose: "Inbound email forwarding and contact routing",
    dataCategories: "Sender email address, recipient alias, and message headers and content as part of a forwarded email",
    status: "active",
    region: "Region and transfer position not asserted here; subject to provider terms and data processing agreement review",
    notes: "Used for inbound domain email forwarding only. It is not app transactional email, has no SMTP or send-as integration, and has no ANCHOR backend email integration.",
  },
  {
    service: "Analytics or cookie provider",
    purpose: "Website analytics or marketing",
    dataCategories: "None identified in this frontend review",
    status: "to be confirmed",
    region: "Not applicable unless implemented",
    notes: "No analytics or cookie provider was identified in this frontend review.",
  },
];

export default function SubprocessorsPage() {
  return (
    <LegalPageShell
      title={meta.title}
      subtitle={meta.subtitle}
      meta={{ version: meta.version, statusLabel: meta.statusLabel, stage: meta.stage, lastUpdated: meta.lastUpdated }}
    >
      <p className="text-base leading-7 text-slate-700">
        This is a public summary of the subprocessors ANCHOR may use. Entries marked conditional or to be confirmed are
        not active by default. The signed data processing agreement and customer agreement control.
      </p>

      <div className="space-y-4">
        {subprocessors.map((item) => (
          <Card key={item.service} variant="native" className="p-6">
            <div className="flex flex-col gap-1 sm:flex-row sm:items-center sm:justify-between">
              <h2 className="text-base font-semibold text-slate-900">{item.service}</h2>
              <StatusBadge value={item.status} />
            </div>
            <dl className="mt-4 grid gap-3 text-sm sm:grid-cols-2">
              <Field label="Purpose" value={item.purpose} />
              <Field label="Possible data categories" value={item.dataCategories} />
              <Field label="Region / transfer status" value={item.region} />
              <Field label="Notes" value={item.notes} />
            </dl>
          </Card>
        ))}
      </div>

      <section className="space-y-3">
        <h2 className="text-xl font-semibold text-slate-900">How to read this register</h2>
        <ul className="space-y-2">
          {[
            "This subprocessor list is a public summary.",
            "The signed data processing agreement and customer agreement control.",
            "A subprocessor change-notice process may be added later.",
          ].map((point) => (
            <li key={point} className="flex items-start text-sm leading-6 text-slate-600">
              <span className="mr-3 mt-2 h-1.5 w-1.5 flex-shrink-0 rounded-full bg-slate-400" />
              <span>{point}</span>
            </li>
          ))}
        </ul>
      </section>
    </LegalPageShell>
  );
}

function Field({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex flex-col gap-0.5">
      <dt className="text-xs font-semibold uppercase tracking-[0.14em] text-slate-500">{label}</dt>
      <dd className="text-slate-700">{value}</dd>
    </div>
  );
}
