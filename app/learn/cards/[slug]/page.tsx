import Link from "next/link";
import { AppShell } from "@/components/shell/AppShell";
import { Card } from "@/components/ui/Card";
import { getLearnCard } from "@/lib/learnCards";

type PageProps = {
  params: Promise<{ slug: string }>;
};

export default async function LearnCardPage({ params }: PageProps) {
  const { slug } = await params;
  const card = getLearnCard(slug);

  return (
    <AppShell>
      <div className="mx-auto max-w-4xl space-y-6">
        <div>
          <div className="mb-2 inline-flex rounded-full border border-slate-200 bg-white/80 px-3 py-1 text-xs font-medium text-slate-600">
            ANCHOR Learn
          </div>
          <h1 className="text-3xl font-semibold tracking-tight text-slate-900">{card.title}</h1>
          <p className="mt-3 max-w-3xl text-sm leading-6 text-slate-600">{card.summary}</p>
        </div>

        <Card>
          <h2 className="text-lg font-semibold text-slate-900">Why this matters</h2>
          <p className="mt-3 text-sm leading-6 text-slate-600">{card.whyThisMatters}</p>
        </Card>

        <Card>
          <h2 className="text-lg font-semibold text-slate-900">Recommended reinforcement</h2>
          <ul className="mt-4 space-y-3 text-sm leading-6 text-slate-600">
            {card.actions.map((item) => (
              <li key={item} className="rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3">
                {item}
              </li>
            ))}
          </ul>
        </Card>

        <div className="grid gap-4 md:grid-cols-2">
          <Card>
            <h3 className="text-sm font-semibold uppercase tracking-[0.16em] text-slate-500">
              Governance-first note
            </h3>
            <p className="mt-3 text-sm leading-6 text-slate-600">
              This learning surface is designed to reinforce safer AI-use behaviours from governance metadata patterns.
              It is not a clinical decision-making tool and does not depend on storing raw prompt or output content.
            </p>
          </Card>

          <Card>
            <h3 className="text-sm font-semibold uppercase tracking-[0.16em] text-slate-500">Next navigation</h3>
            <div className="mt-4 flex flex-col gap-3">
              <Link
                href="/learn"
                className="block rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm font-semibold text-slate-900 transition hover:border-slate-300 hover:bg-white"
              >
                Back to Learn
              </Link>
              <Link
                href="/intelligence"
                className="block rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm font-semibold text-slate-900 transition hover:border-slate-300 hover:bg-white"
              >
                Open Intelligence
              </Link>
              <Link
                href="/governance-events"
                className="block rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm font-semibold text-slate-900 transition hover:border-slate-300 hover:bg-white"
              >
                Review governance events
              </Link>
            </div>
          </Card>
        </div>
      </div>
    </AppShell>
  );
}
