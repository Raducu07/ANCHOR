// app/learn/cards/[slug]/page.tsx

import Link from "next/link";
import { getLearnCard } from "@/lib/learnCards";

type PageProps = {
  params: Promise<{ slug: string }>;
};

export default async function LearnCardPage({ params }: PageProps) {
  const { slug } = await params;
  const card = getLearnCard(slug);

  return (
    <main className="mx-auto max-w-4xl px-6 py-10">
      <div className="mb-6">
        <div className="mb-2 inline-flex rounded-full border px-3 py-1 text-xs font-medium text-neutral-600">
          ANCHOR Learn
        </div>
        <h1 className="text-3xl font-semibold tracking-tight">{card.title}</h1>
        <p className="mt-3 max-w-3xl text-sm leading-6 text-neutral-600">
          {card.summary}
        </p>
      </div>

      <section className="rounded-2xl border bg-white p-6 shadow-sm">
        <h2 className="text-lg font-semibold">Why this matters</h2>
        <p className="mt-3 text-sm leading-6 text-neutral-700">
          {card.whyThisMatters}
        </p>
      </section>

      <section className="mt-6 rounded-2xl border bg-white p-6 shadow-sm">
        <h2 className="text-lg font-semibold">Recommended reinforcement</h2>
        <ul className="mt-4 space-y-3 text-sm leading-6 text-neutral-700">
          {card.actions.map((item) => (
            <li key={item} className="rounded-xl border bg-neutral-50 px-4 py-3">
              {item}
            </li>
          ))}
        </ul>
      </section>

      <section className="mt-6 grid gap-4 md:grid-cols-2">
        <div className="rounded-2xl border bg-white p-6 shadow-sm">
          <h3 className="text-sm font-semibold uppercase tracking-wide text-neutral-500">
            Governance-first note
          </h3>
          <p className="mt-3 text-sm leading-6 text-neutral-700">
            This learning surface is designed to reinforce safer AI-use
            behaviours from governance metadata patterns. It is not a clinical
            decision-making tool and does not depend on storing raw prompt or
            output content.
          </p>
        </div>

        <div className="rounded-2xl border bg-white p-6 shadow-sm">
          <h3 className="text-sm font-semibold uppercase tracking-wide text-neutral-500">
            Next navigation
          </h3>
          <div className="mt-4 flex flex-col gap-3">
            <Link
              href="/learn"
              className="inline-flex items-center justify-center rounded-xl border px-4 py-2 text-sm font-medium hover:bg-neutral-50"
            >
              Back to Learn
            </Link>
            <Link
              href="/intelligence"
              className="inline-flex items-center justify-center rounded-xl border px-4 py-2 text-sm font-medium hover:bg-neutral-50"
            >
              Open Intelligence
            </Link>
            <Link
              href="/governance-events"
              className="inline-flex items-center justify-center rounded-xl border px-4 py-2 text-sm font-medium hover:bg-neutral-50"
            >
              Review governance events
            </Link>
          </div>
        </div>
      </section>
    </main>
  );
}