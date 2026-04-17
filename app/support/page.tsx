import Link from "next/link";
import { AppShell } from "@/components/shell/AppShell";
import { Card } from "@/components/ui/Card";

const helpBlocks = [
  {
    href: "/workspace-live",
    title: "Workspace",
    description:
      "Use the Workspace when you need governed drafting flow, review settings, and receipt preview in one place.",
  },
  {
    href: "/receipts",
    title: "Receipts",
    description:
      "Go to Receipts for request-level governance evidence, export-ready metadata, and receipt lookup by request ID.",
  },
  {
    href: "/learn",
    title: "Learn",
    description:
      "Use Learn for practical guidance on safe AI use, privacy-aware handling, and review responsibility.",
  },
  {
    href: "/trust/profile",
    title: "Trust",
    description:
      "Use Trust surfaces for clinic-facing posture, reusable trust language, and operational trust artifacts.",
  },
  {
    href: "/governance-events",
    title: "Governance Events",
    description:
      "Use Governance Events to inspect recent clinic-scoped activity and understand what changed operationally.",
  },
];

export default function SupportPage() {
  return (
    <AppShell>
      <div className="space-y-6">
        <div>
          <p className="text-sm font-medium text-slate-500">Clinic guidance</p>
          <h1 className="text-2xl font-semibold tracking-tight text-slate-900">Support</h1>
          <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-600">
            Practical guidance for using ANCHOR’s current governance, receipts, trust, and
            learning surfaces without overstating what the product does today.
          </p>
        </div>

        <div className="grid gap-4 xl:grid-cols-[1fr_1fr]">
          <Card>
            <SectionTitle
              title="What ANCHOR supports today"
              description="The strongest current product surfaces for real clinic use."
            />
            <ul className="mt-4 space-y-3 text-sm leading-6 text-slate-600">
              <li>Governed drafting and receipt-aware workflow in the Workspace.</li>
              <li>Metadata-only governance evidence through Receipts, Governance Events, and Exports.</li>
              <li>Clinic-scoped trust posture and reusable trust materials.</li>
              <li>Practical learning content for safer day-to-day AI use.</li>
            </ul>
          </Card>

          <Card>
            <SectionTitle
              title="What ANCHOR is not for"
              description="Clear boundaries help this support page stay truthful and commercially credible."
            />
            <ul className="mt-4 space-y-3 text-sm leading-6 text-slate-600">
              <li>Not a live-chat support desk or ticketing system.</li>
              <li>Not a raw prompt or output archive for clinic staff.</li>
              <li>Not a clinical decision-making system or substitute for professional judgment.</li>
              <li>Not a promise of unsupported admin controls that are not yet productized.</li>
            </ul>
          </Card>
        </div>

        <Card>
          <SectionTitle
            title="Get help from the right surface"
            description="Use the product area that best matches the question or task in front of you."
          />
          <div className="mt-4 grid gap-4 md:grid-cols-2 xl:grid-cols-3">
            {helpBlocks.map((item) => (
              <QuickLink
                key={item.href}
                href={item.href}
                title={item.title}
                description={item.description}
              />
            ))}
          </div>
        </Card>

        <div className="grid gap-4 xl:grid-cols-[1.1fr_0.9fr]">
          <Card>
            <SectionTitle
              title="How to get unstuck"
              description="Truthful guidance for the current product state."
            />
            <div className="mt-4 space-y-4 text-sm leading-6 text-slate-600">
              <p>
                Start with the relevant ANCHOR surface first: Workspace for governed drafting,
                Receipts for request evidence, Learn for guidance, and Trust for clinic-facing
                posture and materials.
              </p>
              <p>
                If something looks wrong or incomplete, capture the route you were on, the
                request or receipt identifier if available, and the exact step that failed. That
                context is more useful than a generic “it broke” report.
              </p>
              <p>
                For clinic-specific help, coordinate with your internal clinic administrator or
                operational owner who manages how ANCHOR is being introduced locally.
              </p>
            </div>
          </Card>

          <Card>
            <SectionTitle
              title="Support posture"
              description="What this page can honestly offer right now."
            />
            <div className="mt-4 space-y-4 text-sm leading-6 text-slate-600">
              <p>
                This page currently provides guidance and routing rather than live support tooling.
              </p>
              <p>
                There is no in-product ticket queue, live chat, or SLA-tracked incident console on
                this surface today.
              </p>
              <p>
                When dedicated support operations exist, this page can be expanded deliberately
                without pretending those systems already exist.
              </p>
            </div>
          </Card>
        </div>
      </div>
    </AppShell>
  );
}

function SectionTitle({
  title,
  description,
}: {
  title: string;
  description?: string;
}) {
  return (
    <div>
      <h2 className="text-base font-semibold text-slate-900">{title}</h2>
      {description ? <p className="mt-1 text-sm leading-6 text-slate-600">{description}</p> : null}
    </div>
  );
}

function QuickLink({
  href,
  title,
  description,
}: {
  href: string;
  title: string;
  description: string;
}) {
  return (
    <Link
      href={href}
      className="block rounded-2xl border border-slate-200 bg-slate-50 p-4 transition hover:border-slate-300 hover:bg-white"
    >
      <p className="text-sm font-semibold text-slate-900">{title}</p>
      <p className="mt-1 text-sm leading-6 text-slate-600">{description}</p>
    </Link>
  );
}
