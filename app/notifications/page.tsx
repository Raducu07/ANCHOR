import Link from "next/link";
import { AppShell } from "@/components/shell/AppShell";
import { Card } from "@/components/ui/Card";

const quickLinks = [
  {
    href: "/governance-events",
    title: "Governance Events",
    description: "Review recent clinic-scoped activity when you expect a new governance signal or follow-up need.",
  },
  {
    href: "/receipts",
    title: "Receipts",
    description: "Inspect request-level receipt evidence and recent receipt activity directly.",
  },
  {
    href: "/trust/profile",
    title: "Trust",
    description: "Check the current trust posture and adjacent clinic-facing trust surfaces.",
  },
  {
    href: "/workspace",
    title: "Workspace",
    description: "Return to governed drafting and receipt-aware workflow activity.",
  },
];

export default function NotificationsPage() {
  return (
    <AppShell>
      <div className="space-y-6">
        <div>
          <p className="text-sm font-medium text-slate-500">Clinic guidance</p>
          <h1 className="text-2xl font-semibold tracking-tight text-slate-900">Notifications</h1>
          <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-600">
            A lightweight notification posture page for the current ANCHOR product. This surface
            is intentionally honest about what is and is not available today.
          </p>
        </div>

        <div className="grid gap-4 xl:grid-cols-[1fr_1fr]">
          <Card variant="native">
            <SectionTitle
              title="Current notification posture"
              description="What users can realistically expect right now."
            />
            <div className="mt-4 space-y-3 text-sm leading-6 text-slate-600">
              <p>
                ANCHOR does not currently expose a live in-product notification feed on this page.
              </p>
              <p>
                Today, the strongest operational signals still live in the underlying product
                surfaces themselves: Governance Events, Receipts, Trust, and Workspace.
              </p>
            </div>
          </Card>

          <Card variant="native">
            <SectionTitle
              title="Why this page exists"
              description="A truthful placeholder is better than a dead control."
            />
            <div className="mt-4 space-y-3 text-sm leading-6 text-slate-600">
              <p>
                The bell icon now routes to a real page so signed-in navigation stays coherent
                across the app.
              </p>
              <p>
                When a real clinic-scoped notification system exists, this page can be expanded
                without pretending that feed already exists today.
              </p>
            </div>
          </Card>
        </div>

        <Card variant="native">
          <SectionTitle
            title="Where to check instead"
            description="The most useful current destinations when you are looking for recent activity or follow-up work."
          />
          <div className="mt-4 grid gap-4 md:grid-cols-2 xl:grid-cols-4">
            {quickLinks.map((item) => (
              <QuickLink
                key={item.href}
                href={item.href}
                title={item.title}
                description={item.description}
              />
            ))}
          </div>
        </Card>
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
